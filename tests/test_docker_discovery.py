import sys
from types import SimpleNamespace

from inlock.docker_discovery import discover_containers


def test_discovery_does_not_fetch_image_resource(monkeypatch):
    class Container:
        id = "container-id"
        short_id = "container-id"[:12]
        name = "journey"
        status = "running"
        labels = {}
        attrs = {
            "Config": {"Image": "journeycx-demo:latest"},
            "NetworkSettings": {"Networks": {}, "Ports": {}},
        }

        @property
        def image(self):
            raise AssertionError("a descoberta não deve consultar a imagem removida")

    client = SimpleNamespace(
        ping=lambda: True,
        containers=SimpleNamespace(list=lambda all: [Container()]),
    )
    fake_docker = SimpleNamespace(
        DockerClient=lambda **_kwargs: client,
        errors=SimpleNamespace(DockerException=RuntimeError),
    )
    monkeypatch.setitem(sys.modules, "docker", fake_docker)

    result = discover_containers("unix:///var/run/docker.sock")

    assert result["available"] is True
    assert result["containers"][0]["image"] == "journeycx-demo:latest"
