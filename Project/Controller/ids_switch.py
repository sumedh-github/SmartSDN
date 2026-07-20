"""Ryu SDN IDS switch with FT-Transformer-based traffic classification."""

from __future__ import annotations

import eventlet

eventlet.monkey_patch()

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple
from urllib import error, request

import joblib
import numpy as np
import pandas as pd
import torch
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from ml.config import FEATURE_COLUMNS, MODEL_PATH
from ml.model import FTTransformer


class IntelligentIDSSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    LOW_CONFIDENCE_THRESHOLD = 0.70
    MIN_PACKET_COUNT = 1
    MIN_DURATION_SEC = 0.0
    POLL_INTERVAL_SEC = 2

    FLOW_IDLE_TIMEOUT = 5
    FLOW_HARD_TIMEOUT = 20
    BACKEND_EVENTS_URL = "http://127.0.0.1:8000/events"
    BACKEND_CONTROLLER_STATUS_URL = "http://127.0.0.1:8000/controller/status"
    BACKEND_EMIT_TIMEOUT_SEC = 0.4
    CONTROLLER_STATUS_INTERVAL_SEC = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.datapaths: Dict[int, object] = {}
        self.last_predictions: Dict[str, Tuple[str, float]] = {}
        self.last_counters: Dict[str, Tuple[int, int]] = {}
        self.poll_interval_sec = self.POLL_INTERVAL_SEC
        self.backend_events_url = os.getenv("IDS_BACKEND_EVENTS_URL", self.BACKEND_EVENTS_URL)
        self.backend_controller_status_url = os.getenv(
            "IDS_BACKEND_CONTROLLER_STATUS_URL",
            self.BACKEND_CONTROLLER_STATUS_URL,
        )
        self.backend_emit_timeout_sec = float(
            os.getenv("IDS_BACKEND_EMIT_TIMEOUT_SEC", str(self.BACKEND_EMIT_TIMEOUT_SEC))
        )
        self.ids = self._load_artifacts()
        self.monitor_thread = hub.spawn(self._monitor)
        self.controller_status_thread = hub.spawn(self._controller_status_monitor)

    def _load_artifacts(self) -> Dict[str, object]:
        project_root = Path(__file__).resolve().parents[1]
        artifacts_dir = project_root / "ml" / "artifacts"

        scaler_path = artifacts_dir / "scaler.joblib"
        encoder_path = artifacts_dir / "encoder.joblib"
        schema_path = artifacts_dir / "feature_schema.json"
        model_path = MODEL_PATH

        if not model_path.exists():
            model_path = artifacts_dir / "model.pth"

        if not scaler_path.exists():
            raise FileNotFoundError(f"Missing scaler artifact: {scaler_path}")
        if not encoder_path.exists():
            raise FileNotFoundError(f"Missing encoder artifact: {encoder_path}")
        if not schema_path.exists():
            raise FileNotFoundError(f"Missing feature schema artifact: {schema_path}")
        if not model_path.exists():
            raise FileNotFoundError(f"Missing model artifact: {model_path}")

        with schema_path.open("r", encoding="utf-8") as f:
            schema = json.load(f)

        schema_features = schema.get("feature_columns", [])
        if list(schema_features) != list(FEATURE_COLUMNS):
            raise RuntimeError(
                "Feature mismatch between controller config and schema file. "
                f"Config={FEATURE_COLUMNS}, Schema={schema_features}"
            )

        checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
        model = FTTransformer.from_checkpoint(checkpoint, map_location="cpu")
        scaler = joblib.load(scaler_path)
        encoder = joblib.load(encoder_path)

        self.logger.info("Loaded IDS artifacts from %s", artifacts_dir)
        self.logger.info("Model path: %s", model_path)
        self.logger.info("Feature columns: %s", FEATURE_COLUMNS)
        self.logger.info("Poll interval: %s seconds", self.poll_interval_sec)
        self.logger.info("Controller event endpoint: %s", self.backend_events_url)
        self.logger.info("Controller status endpoint: %s", self.backend_controller_status_url)
        self.logger.info(
            "Flow timeouts: idle=%ss hard=%ss",
            self.FLOW_IDLE_TIMEOUT,
            self.FLOW_HARD_TIMEOUT,
        )

        return {
            "model": model,
            "scaler": scaler,
            "encoder": encoder,
            "schema": schema,
        }

    def _build_feature_values(self, stat) -> Dict[str, float]:
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
        port_gap = abs(src_port - dst_port)

        return {
            "packet_count": packet_count,
            "byte_count": byte_count,
            "duration_sec": duration,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "avg_bytes_per_packet": avg_bytes_per_packet,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "port_gap": port_gap,
        }

    def _infer_flow_label(self, stat) -> Tuple[str, float]:
        feature_values = self._build_feature_values(stat)
        feature_df = pd.DataFrame(
            [[feature_values[name] for name in FEATURE_COLUMNS]],
            columns=FEATURE_COLUMNS,
        )
        scaled = self.ids["scaler"].transform(feature_df)
        tensor = torch.from_numpy(np.asarray(scaled, dtype=np.float32))

        with torch.no_grad():
            probs = self.ids["model"](tensor, return_proba=True)
            pred = torch.argmax(probs, dim=1).item()
            confidence = float(probs[0, pred].item())

        label = self.ids["encoder"].inverse_transform([pred])[0]
        return label, confidence

    def _flow_key(self, stat) -> str:
        match = dict(stat.match.items())
        src_ip = match.get("ipv4_src", "na")
        dst_ip = match.get("ipv4_dst", "na")
        proto = match.get("ip_proto", 0)
        src_port = match.get("tcp_src", match.get("udp_src", 0))
        dst_port = match.get("tcp_dst", match.get("udp_dst", 0))
        return f"{src_ip}|{dst_ip}|{proto}|{src_port}|{dst_port}"

    def _should_classify(self, stat, match: Dict[str, object]) -> bool:
        if "ipv4_src" not in match or "ipv4_dst" not in match:
            return False

        ip_proto = int(match.get("ip_proto", 0))
        if ip_proto not in (6, 17):
            return False

        packet_count = float(getattr(stat, "packet_count", 0.0))
        duration_sec = float(getattr(stat, "duration_sec", 0.0))
        duration_nsec = float(getattr(stat, "duration_nsec", 0.0))
        duration = duration_sec + (duration_nsec / 1e9)

        if packet_count < self.MIN_PACKET_COUNT:
            return False

        if duration < self.MIN_DURATION_SEC:
            return False

        return True

    def _flow_counters_changed(self, stat, flow_key: str) -> bool:
        packet_count = int(getattr(stat, "packet_count", 0))
        byte_count = int(getattr(stat, "byte_count", 0))
        current = (packet_count, byte_count)
        previous = self.last_counters.get(flow_key)

        self.last_counters[flow_key] = current
        return previous != current

    def _proto_name(self, match: Dict[str, object]) -> str:
        proto = int(match.get("ip_proto", 0))
        if proto == 6:
            return "TCP"
        if proto == 17:
            return "UDP"
        return f"IP_PROTO_{proto}"

    def _build_event_payload(
        self,
        *,
        flow_key: str,
        switch_id: str,
        datapath_id: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto_name: str,
        label: str,
        confidence: float,
        packet_count: int,
        byte_count: int,
    ) -> dict[str, object]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": proto_name,
            "prediction": label,
            "confidence": float(round(confidence, 6)),
            "packet_count": int(packet_count),
            "byte_count": int(byte_count),
            "direction": f"{src_ip}->{dst_ip}",
            "flow_key": flow_key,
            "switch_id": switch_id,
            "datapath_id": datapath_id,
            "event_source": "controller",
            "classification_source": "ml",
            "notes": "Live controller FT-Transformer inference output.",
        }

    def _emit_event_async(self, payload: dict[str, object]) -> None:
        if not self.backend_events_url:
            return
        hub.spawn(self._post_event_to_backend, payload)

    def _emit_controller_status_async(self) -> None:
        if not self.backend_controller_status_url:
            return
        hub.spawn(self._post_controller_status_to_backend)

    def _post_event_to_backend(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.backend_events_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.backend_emit_timeout_sec) as response:
                if response.status >= 300:
                    self.logger.debug(
                        "Backend event post returned status %s for flow %s",
                        response.status,
                        payload.get("flow_key"),
                    )
        except (error.URLError, TimeoutError, ValueError) as exc:
            self.logger.debug("Backend event post failed: %s", exc)
        except Exception as exc:
            self.logger.debug("Unexpected backend event emission error: %s", exc)

    def _post_controller_status_to_backend(self) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "running": True,
            "polling_active": True,
            "model_loaded": True,
            "mode": "REAL_ML",
            "datapath_count": len(self.datapaths),
            "backend_events_url": self.backend_events_url,
        }
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.backend_controller_status_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.backend_emit_timeout_sec) as response:
                if response.status >= 300:
                    self.logger.debug(
                        "Controller status post returned status %s",
                        response.status,
                    )
        except (error.URLError, TimeoutError, ValueError) as exc:
            self.logger.debug("Controller status post failed: %s", exc)
        except Exception as exc:
            self.logger.debug("Unexpected controller status emission error: %s", exc)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Installed table-miss flow on datapath %016x", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        common_kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": inst,
        }

        if priority > 0:
            common_kwargs["idle_timeout"] = self.FLOW_IDLE_TIMEOUT
            common_kwargs["hard_timeout"] = self.FLOW_HARD_TIMEOUT

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            common_kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**common_kwargs)
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

    def _controller_status_monitor(self):
        while True:
            self._emit_controller_status_async()
            hub.sleep(self.CONTROLLER_STATUS_INTERVAL_SEC)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath_id = f"{ev.msg.datapath.id:016x}"
        switch_id = f"s{ev.msg.datapath.id}"

        for stat in body:
            if stat.priority == 0:
                continue

            match = dict(stat.match.items())

            if not self._should_classify(stat, match):
                continue

            flow_key = self._flow_key(stat)
            if not self._flow_counters_changed(stat, flow_key):
                continue

            src_ip = match.get("ipv4_src", "unknown")
            dst_ip = match.get("ipv4_dst", "unknown")
            src_port = match.get("tcp_src", match.get("udp_src", 0))
            dst_port = match.get("tcp_dst", match.get("udp_dst", 0))
            proto_name = self._proto_name(match)
            packet_count = int(getattr(stat, "packet_count", 0))
            byte_count = int(getattr(stat, "byte_count", 0))

            try:
                label, confidence = self._infer_flow_label(stat)
            except Exception as exc:
                self.logger.error(
                    "Inference failed for flow %s -> %s: %s",
                    src_ip,
                    dst_ip,
                    exc,
                )
                continue

            rounded_conf = round(confidence, 3)
            previous = self.last_predictions.get(flow_key)
            if previous == (label, rounded_conf):
                continue

            self.last_predictions[flow_key] = (label, rounded_conf)

            if confidence < self.LOW_CONFIDENCE_THRESHOLD:
                self.logger.info(
                    "[UNCERTAIN] %s flow %s:%s -> %s:%s classified as %s (conf=%.3f)",
                    proto_name,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    label,
                    confidence,
                )
            elif label == "Normal":
                self.logger.info(
                    "[INFO] %s flow %s:%s -> %s:%s classified as %s (conf=%.3f)",
                    proto_name,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    label,
                    confidence,
                )
            else:
                self.logger.warning(
                    "[ALERT] %s flow %s:%s -> %s:%s classified as %s (conf=%.3f)",
                    proto_name,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    label,
                    confidence,
                )

            event_payload = self._build_event_payload(
                flow_key=flow_key,
                switch_id=switch_id,
                datapath_id=datapath_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                proto_name=proto_name,
                label=label,
                confidence=confidence,
                packet_count=packet_count,
                byte_count=byte_count,
            )
            self._emit_event_async(event_payload)

    def _build_flow_match(self, parser, in_port, eth_src, eth_dst, ipv4_pkt, tcp_pkt, udp_pkt):
        if ipv4_pkt is not None:
            match_fields = {
                "in_port": in_port,
                "eth_src": eth_src,
                "eth_dst": eth_dst,
                "eth_type": ether_types.ETH_TYPE_IP,
                "ipv4_src": ipv4_pkt.src,
                "ipv4_dst": ipv4_pkt.dst,
                "ip_proto": ipv4_pkt.proto,
            }

            if tcp_pkt is not None:
                match_fields["tcp_src"] = tcp_pkt.src_port
                match_fields["tcp_dst"] = tcp_pkt.dst_port
            elif udp_pkt is not None:
                match_fields["udp_src"] = udp_pkt.src_port
                match_fields["udp_dst"] = udp_pkt.dst_port

            return parser.OFPMatch(**match_fields)

        return parser.OFPMatch(
            in_port=in_port,
            eth_src=eth_src,
            eth_dst=eth_dst,
        )

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

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = self._build_flow_match(
                parser=parser,
                in_port=in_port,
                eth_src=src,
                eth_dst=dst,
                ipv4_pkt=ipv4_pkt,
                tcp_pkt=tcp_pkt,
                udp_pkt=udp_pkt,
            )

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