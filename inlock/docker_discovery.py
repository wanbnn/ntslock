from __future__ import annotations

from typing import Any


def discover_containers(docker_url: str) -> dict[str, Any]:
    try:
        import docker

        client = docker.DockerClient(base_url=docker_url, timeout=3)
        client.ping()
        containers = []
        for container in client.containers.list(all=True):
            attrs = container.attrs
            ports = []
            networks = attrs.get("NetworkSettings", {}).get("Networks") or {}
            container_ip = next(
                (network.get("IPAddress") for network in networks.values() if network.get("IPAddress")),
                "",
            )
            for private, bindings in (attrs.get("NetworkSettings", {}).get("Ports") or {}).items():
                private_port = private.split("/", 1)[0]
                if bindings:
                    for binding in bindings:
                        host_ip = binding.get("HostIp") or "127.0.0.1"
                        if host_ip in {"0.0.0.0", "::"}:
                            host_ip = "127.0.0.1"
                        ports.append({
                            "private": int(private_port),
                            "host": int(binding["HostPort"]),
                            "url": f"http://{host_ip}:{binding['HostPort']}",
                        })
                else:
                    ports.append({
                        "private": int(private_port), "host": None,
                        "url": f"http://{container_ip or container.name}:{private_port}",
                    })
            image = str(attrs.get("Config", {}).get("Image") or "").strip()
            if not image:
                image = str(attrs.get("Image") or "").removeprefix("sha256:")[:12]
            containers.append({
                "id": container.id,
                "short_id": container.short_id,
                "name": container.name,
                # Não consulta /images/{id}: o Coolify pode remover uma imagem
                # antiga enquanto o container ainda existe, e isso não deve
                # invalidar toda a descoberta do daemon.
                "image": image or "imagem indisponível",
                "status": container.status,
                "ports": ports,
                "labels": container.labels,
            })
        return {"available": True, "containers": containers}
    except (docker.errors.DockerException, OSError) as exc:
        return {"available": False, "containers": [], "error": str(exc)}
