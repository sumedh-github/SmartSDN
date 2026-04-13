"""Ryu SDN IDS switch with FT-Transformer-based traffic classification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np
import torch
from ryu.base import app_manager
from ryu.controller import handler, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto import ofproto_v1_3

from ml.config import FEATURE_COLUMNS, MODEL_PATH
from ml.model import FTTransformer


class IntelligentIDSSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.datapaths = {}
        self.poll_interval_sec = 5
        self.ids = self._load_artifacts()
        self.monitor_thread = hub.spawn(self._monitor)

    def _load_artifacts(self) -> Dict[str, object]:
        project_root = Path(__file__).resolve().parents[1]
        artifacts_dir = project_root / "ml" / "artifacts"
        scaler_path = artifacts_dir / "scaler.joblib"
        encoder_path = artifacts_dir / "encoder.joblib"
        schema_path = artifacts_dir / "feature_schema.json"
        model_path = MODEL_PATH

        if not model_path.exists():
            model_path = artifacts_dir / "model.pth"

        with schema_path.open("r", encoding="utf-8") as f:
            schema = json.load(f)
        schema_features = schema.get("feature_columns", [])
        if schema_features != FEATURE_COLUMNS:
            raise RuntimeError(
                "Feature mismatch between controller config and schema file. "
                f"Config={FEATURE_COLUMNS}, Schema={schema_features}"
            )

        checkpoint = torch.load(model_path, map_location="cpu")
        model = FTTransformer.from_checkpoint(checkpoint, map_location="cpu")
        scaler = joblib.load(scaler_path)
        encoder = joblib.load(encoder_path)

        self.logger.info("Loaded IDS artifacts from %s", artifacts_dir)
        return {"model": model, "scaler": scaler, "encoder": encoder, "schema": schema}

    def _build_feature_vector(self, stat) -> np.ndarray:
        match = dict(stat.match.items())

        duration_sec = float(getattr(stat, "duration_sec", 0.0))
        duration_nsec = float(getattr(stat, "duration_nsec", 0.0))
        duration = duration_sec + (duration_nsec / 1e9)
        duration = max(duration, 1e-6)

        packet_count = float(getattr(stat, "packet_count", 0.0))
        byte_count = float(getattr(stat, "byte_count", 0.0))
        src_port = float(
            match.get("tcp_src", match.get("udp_src", match.get("sctp_src", 0)))
        )
        dst_port = float(
            match.get("tcp_dst", match.get("udp_dst", match.get("sctp_dst", 0)))
        )
        protocol = float(match.get("ip_proto", 0))

        packets_per_second = packet_count / duration
        bytes_per_second = byte_count / duration
        avg_bytes_per_packet = byte_count / max(packet_count, 1.0)
        packet_byte_ratio = packet_count / max(byte_count, 1.0)

        values = {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration_sec": duration,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "avg_bytes_per_packet": avg_bytes_per_packet,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_byte_ratio": packet_byte_ratio,
        }
        return np.array([[values[name] for name in FEATURE_COLUMNS]], dtype=np.float32)

    def _infer_flow_label(self, stat) -> str:
        feature_vec = self._build_feature_vector(stat)
        scaled = self.ids["scaler"].transform(feature_vec)
        tensor = torch.from_numpy(scaled).float()
        with torch.no_grad():
            probs = self.ids["model"](tensor, return_proba=True)
            pred = torch.argmax(probs, dim=1).item()
            confidence = float(probs[0, pred].item())

        label = self.ids["encoder"].inverse_transform([pred])[0]
        return f"{label} (conf={confidence:.3f})"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info("Registered datapath: %016x", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info("Unregistered datapath: %016x", datapath.id)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(self.poll_interval_sec)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
            if stat.priority == 0:
                continue

            match = dict(stat.match.items())
            src_ip = match.get("ipv4_src", "unknown")
            dst_ip = match.get("ipv4_dst", "unknown")

            try:
                label = self._infer_flow_label(stat)
            except Exception as exc:
                self.logger.error("Inference failed for flow %s -> %s: %s", src_ip, dst_ip, exc)
                continue

            if label.startswith("Normal"):
                self.logger.info("[INFO] Flow %s -> %s classified as %s", src_ip, dst_ip, label)
            else:
                self.logger.warning("[ALERT] Flow %s -> %s classified as %s", src_ip, dst_ip, label)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            self.add_flow(datapath, 1, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

