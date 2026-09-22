#!/usr/bin/env python3
"""Own one isolated synthetic storage deployment; never manage the Docker daemon.

Requires an explicitly selected DOCKER_HOST. State and generated credentials stay
under ignored artifacts/, mode 0600. Every mutation checks a per-run owner label.
No host bind mounts, shared volumes, daemon restart, global prune or cloud calls.
"""
import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "client": "rust@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e",
    "postgres": "postgres@sha256:efedf3595f1d6f415c08568ba171029bf54052e754cc9f030e3f2412b21f3d67",
    "valkey": "valkey/valkey@sha256:081c2f5cb575efc901aa80ff9cdbd1ec6a301682fd35e1ebb4b0990a4a4a8507",
    "seaweed": "chrislusf/seaweedfs@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882",
    "config": "debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251",
}
LABEL = "org.llull.buzz.local-stack"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def docker(*args, data=None, check=True):
    p = subprocess.run(["docker", *args], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=180)
    if check and p.returncode:
        # Neither command arguments nor Docker stderr are safe to publish: a
        # failed initialization command could contain generated test credentials.
        raise RuntimeError(f"Docker {args[0]} failed (exit {p.returncode})")
    return p


def save(path, value):
    temporary = path.with_suffix(".tmp")
    with open(temporary, "w", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as f:
        json.dump(value, f, indent=2)
        f.write("\n")
    temporary.replace(path)


class Stack:
    def __init__(self, directory):
        if not os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
            raise RuntimeError("Set DOCKER_HOST explicitly and unset DOCKER_CONTEXT")
        self.directory = directory.resolve()
        self.directory.relative_to(ROOT / "artifacts")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "state.json"
        if self.path.exists():
            self.state = json.loads(self.path.read_text())
            if self.state["docker_host"] != os.environ["DOCKER_HOST"]:
                raise RuntimeError("State belongs to a different Docker host")
        else:
            token = uuid.uuid4().hex
            self.state = {"owner": token, "prefix": "bz-completion-" + token[:12],
                          "docker_host": os.environ["DOCKER_HOST"], "resources": [],
                          "passwords": {k: secrets.token_hex(24) for k in
                                        ["admin", "provider", "native", "filer", "media", "valkey"]},
                          "images": IMAGES, "stage": "created"}
            self.persist()
        if self.state["images"] != IMAGES:
            raise RuntimeError("Image configuration changed: use a new state directory")
        version = docker("version", "--format", "{{.Server.Version}}").stdout.decode().strip()
        if version != "29.8.1":
            raise RuntimeError("This qualification selects Docker Engine 29.8.1")

    def persist(self):
        save(self.path, self.state)

    def name(self, suffix):
        return self.state["prefix"] + "-" + suffix

    def label(self):
        return LABEL + "=" + self.state["owner"]

    def inspect(self, kind, name):
        p = docker(kind, "inspect", name, check=False)
        if p.returncode:
            return None
        record = json.loads(p.stdout)[0]
        labels = record.get("Config", {}).get("Labels") if kind == "container" else record.get("Labels")
        if not labels or labels.get(LABEL) != self.state["owner"]:
            raise RuntimeError("Resource collision: owner label differs")
        return record

    def remember(self, kind, name):
        item = {"kind": kind, "name": name}
        if item not in self.state["resources"]:
            self.state["resources"].append(item)
            self.persist()

    def create(self, kind, suffix, *args):
        name = self.name(suffix)
        self.remember(kind, name)  # Crash recovery can identify creation in flight.
        if not self.inspect(kind, name):
            docker(kind, "create", "--label", self.label(), *args, name)
        return name

    def run(self, suffix, image, options, command):
        name = self.name(suffix)
        self.remember("container", name)
        info = self.inspect("container", name)
        recipe = hashlib.sha256(json.dumps([image, options, command]).encode()).hexdigest()
        if info:
            if info["Config"]["Labels"].get(LABEL + ".recipe") != recipe:
                raise RuntimeError("Container configuration changed; remove this owned stack before recreating it")
            if not info["State"]["Running"]:
                docker("start", name)
        else:
            docker("run", "-d", "--name", name, "--label", self.label(), "--label", LABEL + ".recipe=" + recipe,
                   "--network", self.name("storage"), "--network-alias", suffix,
                   "--security-opt", "no-new-privileges:true", "--pids-limit", "256",
                   "--memory", "768m", *options, image, *command)
        return name

    def envfile(self, name, values):
        path = self.directory / (name + ".env")
        with open(path, "w", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as f:
            for key, value in values.items():
                require("\n" not in value, "Environment values cannot contain newlines")
                f.write(key + "=" + value + "\n")
        return str(path)

    def configuration(self, files):
        volume = self.create("volume", "config")
        # Populate a task-owned named volume through stdin, never a host mount.
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w") as tar:
            for name, text in files.items():
                data = text.encode()
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(data), 0o600
                entry.uid = entry.gid = 65532
                tar.addfile(entry, io.BytesIO(data))
        name = self.name("configure")
        self.remember("container", name)
        if self.inspect("container", name):
            docker("rm", "-f", name)
        docker("run", "--rm", "-i", "--name", name, "--label", self.label(),
               "--network", "none", "--mount", f"type=volume,src={volume},dst=/config",
               "--entrypoint", "tar", IMAGES["config"], "-xpf", "-", "-C", "/config",
               data=content.getvalue())
        return volume

    def data_owner(self, volume):
        name = self.name("data-owner")
        self.remember("container", name)
        if self.inspect("container", name):
            docker("rm", "-f", name)
        docker("run", "--rm", "--name", name, "--label", self.label(),
               "--network", "none", "--mount", f"type=volume,src={volume},dst=/data",
               "--entrypoint", "sh", IMAGES["config"], "-c",
               "chown 65532:65532 /data && touch /data/.llull-volume-initialized")

    def up(self):
        self.create("network", "storage", "--internal")
        pgdata = self.create("volume", "pgdata")
        pw = self.state["passwords"]
        env = self.envfile("postgres", {"POSTGRES_USER": "bz_admin", "POSTGRES_PASSWORD": pw["admin"]})
        pg = self.run("postgres", IMAGES["postgres"],
                      ["--env-file", env, "--mount",
                       f"type=volume,src={pgdata},dst=/var/lib/postgresql/data"], [])
        deadline = time.monotonic() + 120
        while docker("exec", pg, "pg_isready", "-h", "127.0.0.1", "-U", "bz_admin", check=False).returncode:
            if time.monotonic() > deadline:
                raise RuntimeError("PostgreSQL did not become ready")
            time.sleep(1)
        for role, database in [("provider", "bz_foundation_test"), ("native", "bz_native"), ("filer", "bz_filer")]:
            sql = rf"""SELECT 'CREATE ROLE bz_{role} LOGIN PASSWORD ''{pw[role]}''' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='bz_{role}')\gexec
SELECT 'CREATE DATABASE {database} OWNER bz_{role}' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='{database}')\gexec
REVOKE ALL ON DATABASE {database} FROM PUBLIC;
"""
            docker("exec", "-i", pg, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "bz_admin", "-d", "postgres", data=sql.encode())
        config = self.configuration({
            "filer.toml": f'''[leveldb2]
enabled = false
[postgres]
enabled = true
createTable = true
hostname = "postgres"
port = 5432
username = "bz_filer"
password = "{pw['filer']}"
database = "bz_filer"
schema = "public"
sslmode = "disable"
connection_max_idle = 4
connection_max_lifetime_seconds = 300
enableUpsert = true
''',
            "s3.json": json.dumps({"identities": [{"name": "synthetic-media", "credentials": [{"accessKey": "bz-media", "secretKey": pw["media"]}], "actions": ["Read:buzz-media", "Write:buzz-media", "List:buzz-media", "Tagging:buzz-media"]}]}),
            "valkey.conf": f"bind 0.0.0.0\nprotected-mode yes\nrequirepass {pw['valkey']}\nsave \"\"\nappendonly no\nmaxmemory 128mb\nmaxmemory-policy noeviction\n",
        })
        self.run("valkey", IMAGES["valkey"],
                 ["--user", "65532:65532", "--cap-drop", "ALL", "--read-only",
                  "--mount", f"type=volume,src={config},dst=/config,readonly"],
                 ["valkey-server", "/config/valkey.conf"])
        media = self.create("volume", "media")
        self.data_owner(media)
        self.run("seaweed", IMAGES["seaweed"],
                 ["--user", "65532:65532", "--cap-drop", "ALL", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                  "--mount", f"type=volume,src={config},dst=/etc/seaweedfs,readonly",
                  "--mount", f"type=volume,src={media},dst=/data,volume-nocopy", "--entrypoint", "weed"],
                 ["server", "-ip=seaweed", "-ip.bind=0.0.0.0", "-dir=/data", "-filer",
                  "-s3", "-s3.config=/etc/seaweedfs/s3.json", "-s3.autoCreateBucket=false", "-s3.iam=false",
                  "-s3.port.iceberg=0", "-s3.port.lance=0", "-filer.exposeDirectoryData=false",
                  "-master.volumeSizeLimitMB=256", "-volume.max=16", "-master.telemetry=false"])
        deadline = time.monotonic() + 90
        while True:
            info = self.inspect("container", self.name("seaweed"))
            if not info["State"]["Running"]:
                raise RuntimeError("SeaweedFS exited during readiness; inspect its owned container log")
            ready = docker("exec", pg, "psql", "-XAt", "-U", "bz_admin", "-d", "bz_filer",
                           "-c", "SELECT count(*) FROM filemeta", check=False)
            if not ready.returncode:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Seaweed PostgreSQL filer did not become ready")
            time.sleep(1)
        pong = docker("exec", "-i", self.name("valkey"), "sh", "-c",
                      "read -r REDISCLI_AUTH; export REDISCLI_AUTH; exec valkey-cli ping",
                      data=(pw["valkey"] + "\n").encode())
        if pong.stdout.strip() != b"PONG":
            raise RuntimeError("Valkey authentication/readiness failed")
        self.state["stage"] = "storage-started"
        self.persist()
        self.status()

    def status(self):
        status = {"owner": self.state["owner"], "stage": self.state["stage"], "resources": []}
        for resource in self.state["resources"]:
            info = self.inspect(resource["kind"], resource["name"])
            record = dict(resource, exists=info is not None)
            if info and resource["kind"] == "container":
                record.update(running=info["State"]["Running"], image=info["Image"],
                              ports=info["NetworkSettings"]["Ports"])
            status["resources"].append(record)
        save(self.directory / "status.json", status)
        print(json.dumps(status, indent=2))

    def storage_request(self, method, path, body=b"", signed=True, extra=None):
        """Use curl's SigV4 and HTTP transport as a trusted maintenance client."""
        values = {"url": "http://seaweed:8333" + path, "max-time": "20", "noproxy": "*"}
        if signed:
            values.update({"aws-sigv4": "aws:amz:us-east-1:s3",
                           "user": "bz-media:" + self.state["passwords"]["media"]})
        if method == "PUT":
            values["upload-file"] = "/tmp/body"
        else:
            values["request"] = method
        # JSON escaping matches curl's quoted ASCII config-string escapes used
        # here. Credentials travel only through stdin, never argv or a host mount.
        config = "silent\nshow-error\ninclude\n" + "".join(k + " = " + json.dumps(v) + "\n" for k, v in values.items())
        for key, value in (extra or {}).items():
            config += "header = " + json.dumps(key + ": " + value) + "\n"
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for name, data in [("request.conf", config.encode()), ("body", body)]:
                item = tarfile.TarInfo(name)
                item.uid = item.gid = 65532
                item.mode = 0o600
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
        self.inspect("network", self.name("storage"))
        response = docker("run", "--rm", "-i", "--network", self.name("storage"),
                          "--label", self.label(), "--user", "65532:65532", "--read-only",
                          "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                          "--tmpfs", "/tmp:rw,noexec,nosuid,size=1m", "--entrypoint", "sh",
                          IMAGES["client"], "-c", "tar -xpf - -C /tmp && exec curl --config /tmp/request.conf",
                          data=archive.getvalue())
        class Socket:
            def makefile(self, *args, **kwargs):
                return io.BytesIO(response.stdout)
        decoded = http.client.HTTPResponse(Socket())
        decoded.begin()
        return decoded.status, decoded.read()

    def check_storage(self):
        require(self.inspect("network", self.name("storage"))["Internal"], "Storage network must be internal")
        for part in ["postgres", "seaweed", "valkey"]:
            info = self.inspect("container", self.name(part))
            if not info or not info["State"]["Running"]:
                raise RuntimeError(part + " is not running")
            require(all(m["Type"] == "volume" for m in info["Mounts"]), "Unexpected bind mount")
            require(not any(info["NetworkSettings"]["Ports"].values()), "Storage port exposed to host")
            if part != "postgres":
                require(info["Config"]["User"] == "65532:65532", "Storage process must use configured unprivileged UID")
                require(info["HostConfig"]["ReadonlyRootfs"], "Writable storage root filesystem")
                require(info["HostConfig"]["CapDrop"] == ["ALL"], "Unexpected storage capabilities")
        # Exercise real DB ACLs independently of network isolation.
        denied = docker("exec", self.name("postgres"), "psql", "-XAt", "-U", "bz_native", "-d", "bz_filer", "-c", "SELECT 1", check=False)
        require(denied.returncode != 0 and b"permission denied" in denied.stderr, "Database role boundary did not deny access")
        # The S3 data identity cannot create buckets. Trusted local maintenance
        # creates exactly the synthetic test bucket through Seaweed's own CLI.
        shell = docker("exec", "-i", self.name("seaweed"), "weed", "shell",
                       "-master=seaweed:9333", "-filer=seaweed:8888",
                       data=b"s3.bucket.create -name buzz-media\n")
        with open(self.directory / "bucket-setup.log", "wb", opener=lambda p, f: os.open(p, f, 0o600)) as f:
            f.write(shell.stdout + shell.stderr)
        body = b"Synthetic retained media; no operational data.\n"
        digest = hashlib.sha256(body).hexdigest()
        path = "/buzz-media/qualification/" + digest
        status, _ = self.storage_request("PUT", path, body)
        require(status == 200, f"private authenticated S3 PUT returned {status}")
        status, data = self.storage_request("GET", path)
        require(status == 200 and data == body, "S3 retained bytes differ")
        status, data = self.storage_request("GET", path, extra={"range": "bytes=0-8"})
        require(status == 206 and data == body[:9], "S3 byte-range result differs")
        status, _ = self.storage_request("GET", path, signed=False)
        require(status == 403, f"anonymous S3 read returned {status}")
        status, _ = self.storage_request("GET", "/another-bucket/qualification/" + digest)
        require(status == 403, f"cross-bucket S3 read returned {status}")
        report = {"engine": "29.8.1", "images": IMAGES, "owner": self.state["owner"],
                  "object_sha256": digest, "private_network": True, "host_bind_mounts": False,
                  "database_role_cross_access_denied": True, "authenticated_s3_write_read_range": True,
                  "anonymous_read_denied": True, "cross_bucket_read_denied": True,
                  "scope": "storage component only; native/media disclosure gates are separate"}
        save(self.directory / "storage-check.json", report)
        print(json.dumps(report, indent=2))

    def down(self):
        # Reverse dependency order, containers first. Never discover by wildcard.
        for kind in ["container", "network", "volume"]:
            for r in reversed(self.state["resources"]):
                if r["kind"] == kind and self.inspect(kind, r["name"]):
                    docker(kind, "rm", *(["-f"] if kind == "container" else []), r["name"])
        self.state["stage"] = "removed"
        self.persist()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["up-storage", "check-storage", "status", "down"])
    parser.add_argument("--state", type=Path, default=ROOT / "artifacts/completion/stack")
    args = parser.parse_args()
    stack = Stack(args.state)
    {"up-storage": stack.up, "check-storage": stack.check_storage, "status": stack.status, "down": stack.down}[args.action]()


if __name__ == "__main__":
    main()
