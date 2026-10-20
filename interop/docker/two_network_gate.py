#!/usr/bin/env python3
"""STY-G1g: actual direct Iroh/Bao across two separate Docker network namespaces.

Laboratory only. No Akula vault, no File Gate, no sensitive user file, no
durable resume, and NOT proof of two physical PCs or Internet connectivity.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid

LINE_TIMEOUT = 75
EXIT_TIMEOUT = 100


def command(*args, timeout=90):
    process = subprocess.run(
        list(args), capture_output=True, text=True, timeout=timeout
    )
    if process.returncode:
        raise RuntimeError(
            f"command {args[:2]} failed ({process.returncode}); "
            f"stderr={process.stderr[-1200:]}"
        )
    return process.stdout.strip()


class Child:
    def __init__(self, name, cmd):
        self.name = name
        self.out = []
        self.err = []
        self.lines = queue.Queue()
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=1, text=True
        )
        threading.Thread(target=self._collect_stdout, daemon=True).start()
        threading.Thread(target=self._collect_stderr, daemon=True).start()

    def _collect_stdout(self):
        try:
            for line in self.proc.stdout:
                data = line.rstrip("\r\n")
                self.out.append(data)
                self.lines.put(data)
        finally:
            self.lines.put(None)

    def _collect_stderr(self):
        for line in self.proc.stderr:
            if len(self.err) < 250:
                self.err.append(line.rstrip("\r\n")[:400])

    def next_line(self):
        try:
            line = self.lines.get(timeout=LINE_TIMEOUT)
        except queue.Empty as exc:
            raise AssertionError(f"{self.name}: no protocol line; stderr={self.err[-8:]}") from exc
        if line is None:
            raise AssertionError(
                f"{self.name}: unexpected exit {self.proc.poll()}; stderr={self.err[-8:]}"
            )
        if len(line) > 8192:
            raise AssertionError(f"{self.name}: unbounded protocol output")
        return line

    def send(self, line):
        if len(line) > 8192:
            raise AssertionError("unbounded invitation")
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def close_stdin(self):
        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()

    def wait(self):
        try:
            return self.proc.wait(timeout=EXIT_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"{self.name}: child hung; stderr={self.err[-8:]}") from exc

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


def inspect(name, network):
    data = json.loads(command("docker", "inspect", name))[0]
    assert data["HostConfig"]["NetworkMode"] == network, "not isolated Docker bridge"
    address = data["NetworkSettings"]["Networks"][network]["IPAddress"]
    namespace = data["NetworkSettings"].get("SandboxKey")
    assert address and not address.startswith("127."), f"no routable bridge IP: {address}"
    assert namespace, f"{name} lacks a Docker network namespace"
    return address, namespace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant", choices=("release", "fork"), required=True)
    args = parser.parse_args()
    assert sys.platform.startswith("linux"), "this gate requires Linux Docker bridge"
    binary = args.binary.resolve(strict=True)
    if not os.access(binary, os.X_OK):
        raise AssertionError("compiled pinned Iroh CLI is not executable")

    unique = uuid.uuid4().hex[:12]
    network = f"staya-g1g-{unique}"
    image = f"staya-g1g:{unique}"
    containers = [f"staya-allowed-{unique}", f"staya-provider-{unique}",
                  f"staya-unknown-{unique}"]
    children = []
    network_created = False
    image_created = False

    with tempfile.TemporaryDirectory(prefix="staya-g1g-") as tmp:
        temp = Path(tmp)
        build = temp / "image"
        build.mkdir()
        shutil.copy2(binary, build / "staya-direct-preview")
        # Keep CI-only shell alive after successful CLI exit: stopping the
        # Docker container would otherwise discard its ephemeral /tmp.
        (build / "entrypoint.sh").write_text(
            "#!/bin/sh\n"
            '"/usr/local/bin/staya-direct-preview" "$@"\n'
            "status=$?\n"
            'if [ "$status" -eq 0 ] && [ "$1" = "receive" ]; then\n'
            "  printf 'CONTAINER_STAGE_READY\\n'\n"
            "  loops=0\n"
            "  while [ ! -f /tmp/staya-g1g-ack ]; do\n"
            "    loops=$((loops + 1))\n"
            "    if [ $loops -ge 900 ]; then exit 42; fi\n"
            "    sleep 0.1\n"
            "  done\n"
            "fi\n"
            'exit "$status"\n',
            encoding="utf-8",
        )
        (build / "entrypoint.sh").chmod(0o755)
        (build / "Dockerfile").write_text(
            "FROM ubuntu:24.04\n"
            "COPY staya-direct-preview /usr/local/bin/staya-direct-preview\n"
            "COPY entrypoint.sh /usr/local/bin/entrypoint.sh\n"
            "USER 65532:65532\n"
            'ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]\n',
            encoding="utf-8",
        )
        fixture = temp / "synthetic-payload.bin"
        payload = bytes(((index * 43 + 17) % 251) for index in range(1024 * 1024 + 17))
        fixture.write_bytes(payload)
        fixture.chmod(0o644)  # Docker non-root sender reads ONLY this synthetic file.
        try:
            command("docker", "build", "--quiet", "--tag", image, str(build), timeout=210)
            image_created = True
            command("docker", "network", "create", "--driver", "bridge", "--internal", network)
            network_created = True

            def spawn(name, role, read_source=False):
                argv = [
                    "docker", "run", "--name", name, "--network", network, "--interactive",
                    "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--pids-limit", "128",
                ]
                if read_source:
                    argv.extend(["--volume", f"{fixture}:/synthetic.bin:ro"])
                argv.extend([image, *role])
                child = Child(name, argv)
                children.append(child)
                return child

            authorized = spawn(containers[0], ["receive"])
            peer = authorized.next_line()
            assert peer.startswith("PEER_ID "), "no authenticated ephemeral receiver ID"
            peer_id = peer.split()[1]

            provider = spawn(containers[1], ["serve", "/synthetic.bin", peer_id], True)
            invitation = provider.next_line()
            fields = invitation.split()
            assert len(fields) == 4 and fields[0] == "CONNECT", invitation[:180]
            assert int(fields[3]) == len(payload), "unexpected claimed file size"
            assert len(fields[2]) == 64, "missing immutable trusted BLAKE3 root"

            allowed_ip, allowed_ns = inspect(containers[0], network)
            provider_ip, provider_ns = inspect(containers[1], network)
            assert allowed_ip != provider_ip, "two peers share a network IP"
            assert allowed_ns != provider_ns, "sender and receiver share network namespace"

            outsider = spawn(containers[2], ["receive"])
            outsider_id = outsider.next_line()
            assert outsider_id.startswith("PEER_ID ")
            assert outsider_id != peer, "peer identities unexpectedly equal"
            outsider_ip, outsider_ns = inspect(containers[2], network)
            assert outsider_ip not in (allowed_ip, provider_ip)
            assert outsider_ns not in (allowed_ns, provider_ns)
            outsider.send(invitation)
            outsider.close_stdin()
            denied_code = outsider.wait()
            assert denied_code != 0, "unknown peer was not rejected"
            assert not any(x.startswith("STAGED ") for x in outsider.out), (
                "unknown peer staged unapproved bytes"
            )
            error = " ".join(outsider.err).lower()
            assert any(word in error for word in ("permission", "connection lost", "closed by peer")), (
                f"unlisted peer failed for a nonauthorization reason: {error[-500:]}"
            )

            authorized.send(invitation)
            authorized.close_stdin()
            report = authorized.next_line()
            assert report.startswith("STAGED ") and report.endswith("NOT_APPLIED=true"), report
            assert f"ROOT={fields[2]}" in report, "staged root not tied to trusted ticket"
            assert f"SIZE={len(payload)}" in report, "staged size not tied to trusted ticket"
            ready = authorized.next_line()
            assert ready == "CONTAINER_STAGE_READY", (
                "real receiver did not finish successfully before tmpfs readback"
            )
            path = report[len("STAGED "):].split(" ROOT=", 1)[0]
            assert path.startswith("/tmp/staya-direct-preview-receiver-")
            assert path.endswith("/verified-staged.bin")

            received = temp / "received.bin"
            command("docker", "cp", f"{containers[0]}:{path}", str(received))
            content = received.read_bytes()
            assert content == payload, "network-isolated receiver staged incorrect bytes"
            # Only release the CI wrapper after independently reading the
            # actual file while the receiver's private tmpfs remains mounted.
            command("docker", "exec", containers[0], "touch", "/tmp/staya-g1g-ack")
            assert authorized.wait() == 0, f"receiver wrapper failed: {authorized.err[-8:]}"

            provider.send("")
            provider.close_stdin()
            assert provider.wait() == 0, f"provider did not close: {provider.err[-8:]}"

            args.output.mkdir(parents=True, exist_ok=True)
            sha = hashlib.sha256(content).hexdigest()
            (args.output / "inventory.txt").write_text(
                f"payload_sha256={sha}\n"
                f"trusted_blake3={fields[2]}\n"
                f"bytes={len(content)}\n"
                "docker_bridge_internal=true\n"
                "separate_network_namespaces=true\n"
                "three_distinct_ipv4_addresses=true\n"
                "third_peer_denied_by_server=true\n"
                "direct_quic=true\n"
                "physical_bao_staging_readback=true\n"
                "akula_file_gate=false\n"
                "applied=false\n",
                encoding="ascii",
            )
            print(
                "STY_G1G direct_docker_bridge=true distinct_network_namespaces=3 "
                "unauthorized_denied=true trusted_Bao=true stage_only=true"
            )
        finally:
            for child in reversed(children):
                child.stop()
            for name in containers:
                subprocess.run(["docker", "rm", "--force", name],
                               capture_output=True, check=False, timeout=20)
            if network_created:
                subprocess.run(["docker", "network", "rm", network],
                               capture_output=True, check=False, timeout=20)
            if image_created:
                subprocess.run(["docker", "image", "rm", "--force", image],
                               capture_output=True, check=False, timeout=20)


if __name__ == "__main__":
    main()
