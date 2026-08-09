from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from docker.errors import DockerException


@dataclass(frozen=True, order=True)
class PublishedPort:
    protocol: str
    host_port: int
    host_ip: str
    container_id: str
    container_name: str

    @property
    def public(self) -> bool:
        return self.host_ip not in {"127.0.0.1", "::1"}


@dataclass
class IsolationStatus:
    enabled: bool = True
    available: bool = False
    secure: bool = False
    managed: bool = False
    containers: list[str] = field(default_factory=list)
    protected_ports: list[str] = field(default_factory=list)
    redirected_ports: list[str] = field(default_factory=list)
    loopback_ports: list[str] = field(default_factory=list)
    error: str = ""

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)


class ContainerFirewall:
    """Owns an isolated iptables chain that blocks direct Docker published ports."""

    CHAIN = "INLOCK_GUARD"

    def __init__(
        self, docker_url: str, enabled: bool = True, gateway_port: int = 14900,
        runner: Runner = _run,
    ):
        self.docker_url = docker_url
        self.enabled = enabled
        self.gateway_port = gateway_port
        self.runner = runner
        self._lock = threading.RLock()
        self._routes: dict[int, str] = {}
        self._status = IsolationStatus(enabled=enabled, secure=not enabled)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self._status.model_dump()

    def project_slug_for_port(self, port: int | None) -> str | None:
        with self._lock:
            return self._routes.get(port) if port else None

    def _published_ports(self, container_ids: set[str]) -> tuple[list[PublishedPort], list[str]]:
        if not container_ids:
            return [], []
        import docker

        client = docker.DockerClient(base_url=self.docker_url, timeout=4)
        ports: list[PublishedPort] = []
        names: list[str] = []
        try:
            client.ping()
            for container_id in sorted(container_ids):
                container = client.containers.get(container_id)
                names.append(container.name)
                bindings_by_port = container.attrs.get("NetworkSettings", {}).get("Ports") or {}
                for private, bindings in bindings_by_port.items():
                    if not bindings:
                        continue
                    protocol = private.rsplit("/", 1)[-1].lower()
                    if protocol not in {"tcp", "udp"}:
                        continue
                    for binding in bindings:
                        ports.append(PublishedPort(
                            protocol=protocol,
                            host_port=int(binding["HostPort"]),
                            host_ip=binding.get("HostIp") or "0.0.0.0",
                            container_id=container.id,
                            container_name=container.name,
                        ))
        finally:
            client.close()
        return sorted(set(ports)), names

    def _command(self, binary: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.runner([binary, "-w", "3", *arguments])

    def _owned_chain_exists(self, binary: str) -> bool:
        return self._command(binary, "-S", self.CHAIN).returncode == 0

    def _apply_family(self, binary: str, ports: list[PublishedPort]) -> None:
        docker_chain = self._command(binary, "-S", "DOCKER-USER")
        if docker_chain.returncode != 0:
            raise RuntimeError(f"{binary}: cadeia DOCKER-USER indisponível")

        created = self._command(binary, "-N", self.CHAIN)
        if created.returncode != 0:
            existing = self._command(binary, "-S", self.CHAIN)
            if existing.returncode != 0:
                raise RuntimeError(existing.stderr.strip() or f"não foi possível criar {self.CHAIN}")

        jump = self._command(binary, "-C", "DOCKER-USER", "-j", self.CHAIN)
        if jump.returncode != 0:
            inserted = self._command(binary, "-I", "DOCKER-USER", "1", "-j", self.CHAIN)
            if inserted.returncode != 0:
                raise RuntimeError(inserted.stderr.strip() or "não foi possível ativar a cadeia Inlock")

        flushed = self._command(binary, "-F", self.CHAIN)
        if flushed.returncode != 0:
            raise RuntimeError(flushed.stderr.strip() or "não foi possível atualizar a cadeia Inlock")

        # Localhost remains the private path used by the Inlock proxy itself.
        local = self._command(binary, "-A", self.CHAIN, "-i", "lo", "-j", "RETURN")
        if local.returncode != 0:
            raise RuntimeError(local.stderr.strip() or "não foi possível liberar o proxy local")

        for port in ports:
            result = self._command(
                binary,
                "-A", self.CHAIN,
                "-p", port.protocol,
                "-m", "conntrack",
                "--ctdir", "ORIGINAL",
                "--ctorigdstport", str(port.host_port),
                "-m", "comment", "--comment", f"inlock:{port.container_name}",
                "-j", "DROP",
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or f"falha ao proteger porta {port.host_port}")

        self._apply_redirects(binary, [port for port in ports if port.protocol == "tcp"])

    def _apply_redirects(self, binary: str, ports: list[PublishedPort]) -> None:
        table = ("-t", "nat")
        prerouting = self._command(binary, *table, "-S", "PREROUTING")
        if prerouting.returncode != 0:
            raise RuntimeError(f"{binary}: tabela nat/PREROUTING indisponível")

        created = self._command(binary, *table, "-N", "INLOCK_REDIRECT")
        if created.returncode != 0:
            existing = self._command(binary, *table, "-S", "INLOCK_REDIRECT")
            if existing.returncode != 0:
                raise RuntimeError(existing.stderr.strip() or "não foi possível criar INLOCK_REDIRECT")

        jump = self._command(binary, *table, "-C", "PREROUTING", "-j", "INLOCK_REDIRECT")
        if jump.returncode != 0:
            inserted = self._command(
                binary, *table, "-I", "PREROUTING", "1", "-j", "INLOCK_REDIRECT"
            )
            if inserted.returncode != 0:
                raise RuntimeError(inserted.stderr.strip() or "não foi possível ativar o redirecionamento Inlock")

        flushed = self._command(binary, *table, "-F", "INLOCK_REDIRECT")
        if flushed.returncode != 0:
            raise RuntimeError(flushed.stderr.strip() or "não foi possível atualizar INLOCK_REDIRECT")

        for port in ports:
            result = self._command(
                binary, *table,
                "-A", "INLOCK_REDIRECT",
                "-p", "tcp",
                "-m", "addrtype", "--dst-type", "LOCAL",
                "--dport", str(port.host_port),
                "-m", "comment", "--comment", f"inlock:{port.container_name}",
                "-j", "REDIRECT", "--to-ports", str(self.gateway_port),
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or f"falha ao redirecionar porta {port.host_port}")

    def reconcile(self, projects: list[dict[str, Any]]) -> dict[str, Any]:
        with self._lock:
            return self._reconcile(projects)

    def _reconcile(self, projects: list[dict[str, Any]]) -> dict[str, Any]:
        container_ids = {
            project["docker_container_id"]
            for project in projects
            if project.get("docker_container_id")
        }
        project_by_container = {
            project["docker_container_id"]: project["slug"]
            for project in projects
            if project.get("docker_container_id") and project.get("slug")
        }
        if not self.enabled:
            self._status = IsolationStatus(enabled=False, secure=False, managed=bool(container_ids), error="isolamento desativado")
            return self.status()

        try:
            ports, names = self._published_ports(container_ids)
        except (DockerException, OSError, ValueError) as exc:
            # Preserve the existing firewall rules when Docker cannot be inspected.
            self._status = IsolationStatus(
                enabled=True, secure=False, managed=bool(container_ids),
                containers=sorted(container_ids), error=f"Docker indisponível: {exc}",
            )
            return self.status()

        public_ports = [port for port in ports if port.public]
        loopback_ports = [port for port in ports if not port.public]
        binaries: list[tuple[str, list[PublishedPort]]] = []
        ipv4_ports = [port for port in public_ports if ":" not in port.host_ip]
        ipv6_ports = [port for port in public_ports if ":" in port.host_ip]
        has_iptables = bool(shutil.which("iptables"))
        has_ip6tables = bool(shutil.which("ip6tables"))
        missing_family = (ipv4_ports and not has_iptables) or (ipv6_ports and not has_ip6tables)
        if missing_family:
            self._status = IsolationStatus(
                enabled=True, secure=False, managed=bool(container_ids), containers=names,
                protected_ports=[f"{p.protocol}/{p.host_port}" for p in public_ports],
                redirected_ports=[f"tcp/{p.host_port}" for p in public_ports if p.protocol == "tcp"],
                loopback_ports=[f"{p.protocol}/{p.host_port}" for p in loopback_ports],
                error="iptables/ip6tables necessário para bloquear todas as portas públicas",
            )
            return self.status()
        if has_iptables and (ipv4_ports or self._owned_chain_exists("iptables")):
            binaries.append(("iptables", ipv4_ports))
        if has_ip6tables and (ipv6_ports or self._owned_chain_exists("ip6tables")):
            binaries.append(("ip6tables", ipv6_ports))
        if not binaries:
            self._status = IsolationStatus(
                enabled=True, secure=not public_ports, managed=bool(container_ids), containers=names,
                loopback_ports=[f"{p.protocol}/{p.host_port}" for p in loopback_ports],
                error="iptables não está instalado" if public_ports else "",
            )
            return self.status()

        try:
            for binary, family_ports in binaries:
                self._apply_family(binary, family_ports)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            self._status = IsolationStatus(
                enabled=True, secure=False, managed=bool(container_ids), containers=names,
                protected_ports=[f"{p.protocol}/{p.host_port}" for p in public_ports],
                redirected_ports=[f"tcp/{p.host_port}" for p in public_ports if p.protocol == "tcp"],
                loopback_ports=[f"{p.protocol}/{p.host_port}" for p in loopback_ports], error=str(exc),
            )
            return self.status()

        self._status = IsolationStatus(
            enabled=True, available=True, secure=True, managed=bool(container_ids), containers=names,
            protected_ports=[f"{p.protocol}/{p.host_port}" for p in public_ports],
            redirected_ports=[f"tcp/{p.host_port}" for p in public_ports if p.protocol == "tcp"],
            loopback_ports=[f"{p.protocol}/{p.host_port}" for p in loopback_ports],
        )
        self._routes = {
            port.host_port: project_by_container[port.container_id]
            for port in public_ports
            if port.protocol == "tcp" and port.container_id in project_by_container
        }
        return self.status()
