"""Real Mininet/OVS enforcement service for mitigation apply/retract actions."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

from backend.app.schemas import MitigationEvent


@dataclass
class EnforcementResult:
    ok: bool
    message: str


class EnforcementService:
    """Applies mitigation rules via ovs-ofctl against lab switches."""

    def __init__(self) -> None:
        self._enabled = os.getenv("SOC_ENFORCEMENT_ENABLED", "true").lower() == "true"
        self._bridge_prefix = os.getenv("SOC_OVS_BRIDGE_PREFIX", "s")
        self._source_block_bridge_max = int(os.getenv("SOC_SOURCE_BLOCK_BRIDGE_MAX", "8"))
        configured_ofctl = os.getenv("SOC_OVS_OFCTL_BIN", "ovs-ofctl")
        # Resolve to absolute path so sudoers command matching is reliable.
        self._ovs_ofctl = shutil.which(configured_ofctl) or configured_ofctl
        self._of_proto = os.getenv("SOC_OVS_OPENFLOW_VERSION", "OpenFlow13")
        self._prefer_sudo = os.getenv("SOC_OVS_USE_SUDO", "false").lower() == "true"
        self._flow_table: dict[str, list[tuple[str, str]]] = {}
        self._port_table: dict[str, list[tuple[str, str]]] = {}

    def apply(self, event: MitigationEvent) -> EnforcementResult:
        if not self._enabled:
            return EnforcementResult(ok=False, message="Enforcement disabled by SOC_ENFORCEMENT_ENABLED=false.")
        try:
            if event.action == "block_flow":
                return self._apply_block_flow_pair(event)
            if event.action == "block_source":
                return self._apply_block_source(event)
            if event.action == "isolate_port":
                return self._apply_isolate_port(event)
        except Exception as exc:  # pragma: no cover - defensive in controller lab env.
            return EnforcementResult(ok=False, message=f"Enforcement failed: {exc}")
        return EnforcementResult(ok=False, message=f"Unsupported enforcement action: {event.action}")

    def retract(self, event: MitigationEvent) -> EnforcementResult:
        if not self._enabled:
            return EnforcementResult(ok=False, message="Enforcement disabled by SOC_ENFORCEMENT_ENABLED=false.")
        try:
            if event.action in {"block_flow", "block_source"}:
                flow_records = self._flow_table.pop(event.mitigation_id, None)
                if not flow_records:
                    return EnforcementResult(ok=False, message="No matching active flow rule found for rollback.")
                for bridge, cookie in flow_records:
                    self._run([self._ovs_ofctl, "-O", self._of_proto, "del-flows", bridge, f"cookie={cookie}/-1"])
                return EnforcementResult(ok=True, message="Flow-based mitigation rollback applied.")
            if event.action == "isolate_port":
                port_records = self._port_table.pop(event.mitigation_id, None)
                if not port_records:
                    return EnforcementResult(ok=False, message="No matching isolated port found for rollback.")
                for bridge, port_id in port_records:
                    self._run_allow_missing_port(
                        [self._ovs_ofctl, "-O", self._of_proto, "mod-port", bridge, port_id, "up"]
                    )
                return EnforcementResult(ok=True, message="Port re-enabled successfully.")
        except Exception as exc:  # pragma: no cover
            return EnforcementResult(ok=False, message=f"Rollback enforcement failed: {exc}")
        return EnforcementResult(ok=False, message=f"Unsupported rollback action: {event.action}")

    def _apply_block_flow_pair(self, event: MitigationEvent) -> EnforcementResult:
        if not event.src_ip or not event.dst_ip:
            return EnforcementResult(
                ok=False,
                message="Flow pair mitigation requires src_ip and dst_ip.",
            )
        bridge = self._bridge_for(event.switch_id)
        proto = event.protocol.strip().upper() if event.protocol else "ALL"
        if proto == "TCP":
            match_fragments = ["tcp"]
        elif proto == "UDP":
            match_fragments = ["udp"]
        elif proto == "ICMP":
            match_fragments = ["icmp"]
        elif proto == "ALL":
            match_fragments = ["ip"]
        else:
            return EnforcementResult(ok=False, message=f"Unsupported protocol for flow pair block: {proto}")
        cookie = self._cookie_for(event.mitigation_id)
        flow_expr = ",".join(
            [
                f"cookie={cookie}",
                "priority=41000",
                *match_fragments,
                f"nw_src={event.src_ip}",
                f"nw_dst={event.dst_ip}",
                "actions=drop",
            ]
        )
        self._run([self._ovs_ofctl, "-O", self._of_proto, "add-flow", bridge, flow_expr])
        self._flow_table[event.mitigation_id] = [(bridge, cookie)]
        return EnforcementResult(
            ok=True,
            message=f"Applied flow-pair block ({event.src_ip} -> {event.dst_ip}, {proto}) on {bridge}.",
        )

    def _apply_block_source(self, event: MitigationEvent) -> EnforcementResult:
        if not event.src_ip:
            return EnforcementResult(ok=False, message="Source host mitigation requires src_ip.")
        cookie = self._cookie_for(event.mitigation_id)
        # Block IPv4 from source host only, leaving ARP unaffected.
        flow_expr = f"cookie={cookie},priority=40000,ip,nw_src={event.src_ip},actions=drop"
        bridges = self._candidate_source_block_bridges(event.switch_id)
        applied: list[tuple[str, str]] = []
        for bridge in bridges:
            if self._run_allow_missing_bridge(
                [self._ovs_ofctl, "-O", self._of_proto, "add-flow", bridge, flow_expr]
            ):
                applied.append((bridge, cookie))

        if not applied:
            return EnforcementResult(
                ok=False,
                message=(
                    f"No matching switch bridges found for source block {event.src_ip}. "
                    "Adjust SOC_OVS_BRIDGE_PREFIX or SOC_SOURCE_BLOCK_BRIDGE_MAX."
                ),
            )

        self._flow_table[event.mitigation_id] = applied
        bridge_list = ", ".join(bridge for bridge, _ in applied)
        return EnforcementResult(
            ok=True,
            message=f"Blocked IPv4 traffic from source host {event.src_ip} on bridges: {bridge_list}.",
        )

    def _apply_isolate_port(self, event: MitigationEvent) -> EnforcementResult:
        if event.port_id is None:
            return EnforcementResult(ok=False, message="Port isolation requires port_id.")
        bridge = self._bridge_for(event.switch_id)
        if event.port_id == 0:
            ports = self._list_bridge_ports(bridge)
            isolated: list[tuple[str, str]] = []
            for port in ports:
                if self._run_allow_missing_port(
                    [self._ovs_ofctl, "-O", self._of_proto, "mod-port", bridge, port, "down"]
                ):
                    isolated.append((bridge, port))
            if not isolated:
                return EnforcementResult(
                    ok=False,
                    message=f"No usable switch ports found on {bridge} for all-port isolation.",
                )
            self._port_table[event.mitigation_id] = isolated
            return EnforcementResult(
                ok=True,
                message=f"Isolated {len(isolated)} switch ports on {bridge}.",
            )
        port_id = str(event.port_id)
        self._run([self._ovs_ofctl, "-O", self._of_proto, "mod-port", bridge, port_id, "down"])
        self._port_table[event.mitigation_id] = [(bridge, port_id)]
        return EnforcementResult(ok=True, message=f"Port {port_id} on {bridge} moved to down state.")

    def _bridge_for(self, switch_id: str | None) -> str:
        if switch_id:
            return switch_id
        return f"{self._bridge_prefix}1"

    def _cookie_for(self, mitigation_id: str) -> str:
        # 32-bit cookie from mitigation id to support precise rollback.
        return hex(abs(hash(mitigation_id)) % (2**32))

    def _list_bridge_ports(self, bridge: str) -> list[str]:
        output = self._run_capture([self._ovs_ofctl, "-O", self._of_proto, "dump-ports-desc", bridge])
        ports: list[str] = []
        for line in output.splitlines():
            match = re.match(r"^\s*(\d+)\(([^)]+)\):", line)
            if not match:
                continue
            port_no = int(match.group(1))
            # Skip OVS local/internal pseudo ports.
            if port_no >= 65534:
                continue
            # Use OpenFlow numeric port identifier for mod-port reliability.
            ports.append(str(port_no))
        return ports

    def _candidate_source_block_bridges(self, switch_id: str | None) -> list[str]:
        candidates = [f"{self._bridge_prefix}{index}" for index in range(1, self._source_block_bridge_max + 1)]
        if switch_id and switch_id not in candidates:
            candidates.insert(0, switch_id)
        return candidates

    def _run_allow_missing_bridge(self, command: list[str]) -> bool:
        try:
            self._run(command)
            return True
        except RuntimeError as exc:
            detail = str(exc).lower()
            if (
                "is not a bridge or a socket" in detail
                or "no bridge named" in detail
                or "no such file or directory" in detail
            ):
                return False
            raise

    def _run_allow_missing_port(self, command: list[str]) -> bool:
        try:
            self._run(command)
            return True
        except RuntimeError as exc:
            detail = str(exc).lower()
            if "couldn't find port" in detail or "no port named" in detail:
                return False
            raise

    def _run_capture(self, command: list[str]) -> str:
        proc = self._exec(command)
        if proc.returncode == 0:
            return proc.stdout or ""

        stderr = proc.stderr.strip() or "unknown command error"
        needs_permission = "permission denied" in stderr.lower()
        if needs_permission and os.geteuid() != 0 and shutil.which("sudo") and self._prefer_sudo:
            sudo_proc = self._exec(["sudo", "-n", *command])
            if sudo_proc.returncode == 0:
                return sudo_proc.stdout or ""
            sudo_err = sudo_proc.stderr.strip() or "unknown sudo error"
            raise RuntimeError(
                "OVS command permission denied. Sudo fallback also failed: "
                f"{sudo_err}. Configure passwordless sudo for ovs-ofctl or run backend as root."
            )
        raise RuntimeError(f"{' '.join(command)} failed ({proc.returncode}): {stderr}")

    def _run(self, command: list[str]) -> None:
        proc = self._exec(command)
        if proc.returncode == 0:
            return

        stderr = proc.stderr.strip() or "unknown command error"
        needs_permission = "permission denied" in stderr.lower()

        # Optional privileged fallback for lab setups where backend runs unprivileged.
        if needs_permission and os.geteuid() != 0 and shutil.which("sudo"):
            if self._prefer_sudo:
                sudo_proc = self._exec(["sudo", "-n", *command])
                if sudo_proc.returncode == 0:
                    return
                sudo_err = sudo_proc.stderr.strip() or "unknown sudo error"
                raise RuntimeError(
                    "OVS command permission denied. Sudo fallback also failed: "
                    f"{sudo_err}. Configure passwordless sudo for ovs-ofctl or run backend as root."
                )
            raise RuntimeError(
                f"{' '.join(command)} failed ({proc.returncode}): {stderr}. "
                "Permission denied on OVS socket. Either run backend with sudo, "
                "or grant the backend user OVS socket access "
                "(e.g., add user to openvswitch group and re-login). "
                "You can also set SOC_OVS_USE_SUDO=true to retry with sudo -n."
            )

        if proc.returncode != 0:
            raise RuntimeError(f"{' '.join(command)} failed ({proc.returncode}): {stderr}")

    def _exec(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
