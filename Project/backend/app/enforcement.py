"""Real Mininet/OVS enforcement service for mitigation apply/retract actions."""

from __future__ import annotations

import os
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
        configured_ofctl = os.getenv("SOC_OVS_OFCTL_BIN", "ovs-ofctl")
        # Resolve to absolute path so sudoers command matching is reliable.
        self._ovs_ofctl = shutil.which(configured_ofctl) or configured_ofctl
        self._prefer_sudo = os.getenv("SOC_OVS_USE_SUDO", "false").lower() == "true"
        self._flow_table: dict[str, tuple[str, str]] = {}
        self._port_table: dict[str, tuple[str, str]] = {}

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
                flow_record = self._flow_table.pop(event.mitigation_id, None)
                if flow_record is None:
                    return EnforcementResult(ok=False, message="No matching active flow rule found for rollback.")
                bridge, cookie = flow_record
                self._run([self._ovs_ofctl, "del-flows", bridge, f"cookie={cookie}/-1"])
                return EnforcementResult(ok=True, message="Flow-based mitigation rollback applied.")
            if event.action == "isolate_port":
                port_record = self._port_table.pop(event.mitigation_id, None)
                if port_record is None:
                    return EnforcementResult(ok=False, message="No matching isolated port found for rollback.")
                bridge, port_id = port_record
                self._run([self._ovs_ofctl, "mod-port", bridge, port_id, "up"])
                return EnforcementResult(ok=True, message="Port re-enabled successfully.")
        except Exception as exc:  # pragma: no cover
            return EnforcementResult(ok=False, message=f"Rollback enforcement failed: {exc}")
        return EnforcementResult(ok=False, message=f"Unsupported rollback action: {event.action}")

    def _apply_block_flow_pair(self, event: MitigationEvent) -> EnforcementResult:
        if not event.src_ip or not event.dst_ip or not event.protocol:
            return EnforcementResult(
                ok=False,
                message="Flow pair mitigation requires src_ip, dst_ip, and protocol.",
            )
        bridge = self._bridge_for(event.switch_id)
        proto = event.protocol.strip().upper()
        if proto == "TCP":
            proto_match = "tcp"
        elif proto == "UDP":
            proto_match = "udp"
        else:
            return EnforcementResult(ok=False, message=f"Unsupported protocol for flow pair block: {proto}")
        cookie = self._cookie_for(event.mitigation_id)
        flow_expr = (
            f"cookie={cookie},priority=41000,ip,{proto_match},"
            f"nw_src={event.src_ip},nw_dst={event.dst_ip},actions=drop"
        )
        self._run([self._ovs_ofctl, "add-flow", bridge, flow_expr])
        self._flow_table[event.mitigation_id] = (bridge, cookie)
        return EnforcementResult(
            ok=True,
            message=f"Applied flow-pair block ({event.src_ip} -> {event.dst_ip}, {proto}) on {bridge}.",
        )

    def _apply_block_source(self, event: MitigationEvent) -> EnforcementResult:
        if not event.src_ip:
            return EnforcementResult(ok=False, message="Source host mitigation requires src_ip.")
        bridge = self._bridge_for(event.switch_id)
        cookie = self._cookie_for(event.mitigation_id)
        # Block IPv4 from source host only, leaving ARP unaffected.
        flow_expr = f"cookie={cookie},priority=40000,ip,nw_src={event.src_ip},actions=drop"
        self._run([self._ovs_ofctl, "add-flow", bridge, flow_expr])
        self._flow_table[event.mitigation_id] = (bridge, cookie)
        return EnforcementResult(ok=True, message=f"Blocked IPv4 traffic from source host {event.src_ip} on {bridge}.")

    def _apply_isolate_port(self, event: MitigationEvent) -> EnforcementResult:
        if event.port_id is None:
            return EnforcementResult(ok=False, message="Port isolation requires port_id.")
        bridge = self._bridge_for(event.switch_id)
        port_id = str(event.port_id)
        self._run([self._ovs_ofctl, "mod-port", bridge, port_id, "down"])
        self._port_table[event.mitigation_id] = (bridge, port_id)
        return EnforcementResult(ok=True, message=f"Port {port_id} on {bridge} moved to down state.")

    def _bridge_for(self, switch_id: str | None) -> str:
        if switch_id:
            return switch_id
        return f"{self._bridge_prefix}1"

    def _cookie_for(self, mitigation_id: str) -> str:
        # 32-bit cookie from mitigation id to support precise rollback.
        return hex(abs(hash(mitigation_id)) % (2**32))

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
