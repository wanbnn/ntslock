import subprocess

from inlock.container_firewall import ContainerFirewall, PublishedPort


def result(returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, "", stderr)


def test_reconcile_builds_owned_drop_rules(monkeypatch):
    commands = []

    def runner(command):
        commands.append(command)
        if "-N" in command:
            return result(1)
        return result()

    firewall = ContainerFirewall("unused", runner=runner)
    monkeypatch.setattr(firewall, "_published_ports", lambda ids: ([
        PublishedPort("tcp", 8088, "0.0.0.0", "abc", "website"),
        PublishedPort("tcp", 9090, "127.0.0.1", "def", "private-api"),
    ], ["website", "private-api"]))
    monkeypatch.setattr("inlock.container_firewall.shutil.which", lambda name: f"/usr/sbin/{name}" if name == "iptables" else None)

    status = firewall.reconcile([{"docker_container_id": "abc", "slug": "website"}])

    assert status["secure"] and status["available"]
    assert status["protected_ports"] == ["tcp/8088"]
    drop = next(command for command in commands if "--ctorigdstport" in command)
    assert drop[drop.index("--ctorigdstport") + 1] == "8088"
    assert drop[-1] == "DROP"
    assert any("lo" in command and "RETURN" in command for command in commands)
    assert not any("9090" in command for command in commands)
    redirect = next(command for command in commands if "--to-ports" in command)
    assert redirect[redirect.index("--dport") + 1] == "8088"
    assert redirect[redirect.index("--to-ports") + 1] == "14900"
    assert any("INLOCK_OUTPUT" in command and "--uid-owner" in command for command in commands)
    assert any("INLOCK_OUTPUT" in command and "--to-ports" in command for command in commands)
    assert firewall.project_slug_for_port(8088) == "website"


def test_docker_failure_preserves_rules_and_reports_insecure(monkeypatch):
    firewall = ContainerFirewall("unused", runner=lambda command: result())

    def unavailable(_ids):
        raise OSError("socket negado")

    monkeypatch.setattr(firewall, "_published_ports", unavailable)
    status = firewall.reconcile([{"docker_container_id": "abc"}])
    assert not status["secure"]
    assert "socket negado" in status["error"]


def test_loopback_binding_needs_no_drop_rule(monkeypatch):
    firewall = ContainerFirewall("unused", runner=lambda command: result())
    monkeypatch.setattr(firewall, "_published_ports", lambda ids: ([
        PublishedPort("tcp", 8088, "127.0.0.1", "abc", "website"),
    ], ["website"]))
    monkeypatch.setattr("inlock.container_firewall.shutil.which", lambda name: None)
    status = firewall.reconcile([{"docker_container_id": "abc"}])
    assert status["secure"]
    assert status["loopback_ports"] == ["tcp/8088"]
