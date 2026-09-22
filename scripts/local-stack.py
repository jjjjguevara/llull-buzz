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
import re
import secrets
import struct
import subprocess
import tarfile
import time
import uuid
import zlib

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

    def run(self, suffix, image, options, command, aliases=(), memory="768m", recipe_extra=None):
        name = self.name(suffix)
        self.remember("container", name)
        info = self.inspect("container", name)
        identity = [image, options, command]
        if aliases or memory != "768m":
            identity.extend([list(aliases), memory])
        if recipe_extra is not None:
            identity.append(recipe_extra)
        recipe = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        if info:
            if info["Config"]["Labels"].get(LABEL + ".recipe") != recipe:
                raise RuntimeError("Container configuration changed; remove this owned stack before recreating it")
            if not info["State"]["Running"]:
                docker("start", name)
        else:
            docker("run", "-d", "--name", name, "--label", self.label(), "--label", LABEL + ".recipe=" + recipe,
                   "--network", self.name("storage"), "--network-alias", suffix,
                   *(part for alias in aliases for part in ("--network-alias", alias)),
                   "--security-opt", "no-new-privileges:true", "--pids-limit", "256",
                   "--memory", memory, *options, image, *command)
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

    def native_keys(self):
        path = self.directory / "native-identities.json"
        def generate():
            result = docker("run", "--rm", "--network", "none", "--label", self.label(),
                            "--entrypoint", "/opt/llull/upstream/buzz-admin",
                            "llull-buzz-completion-upstream:01b6174", "generate-key")
            matches = dict(re.findall(r"(?m)^(Public key|Secret key):\s+([0-9a-f]{64})$", result.stdout.decode()))
            require(set(matches) == {"Public key", "Secret key"}, "Pinned upstream key generator output changed")
            return {"public": matches["Public key"], "secret": matches["Secret key"]}
        keys = json.loads(path.read_text()) if path.exists() else {}
        for identity in ["owner", "relay", "bot", "outsider", "service"]:
            if identity not in keys:
                keys[identity] = generate()
        save(path, keys)
        return keys

    def up_native(self):
        require(self.state["stage"] in {"storage-started", "native-started"}, "Start and check storage first")
        image = "llull-buzz-completion-upstream:01b6174"
        inspected = docker("image", "inspect", image)
        built = json.loads(inspected.stdout)[0]
        labels = built["Config"]["Labels"]
        require(labels.get("org.llull.buzz.upstream") == "01b6174a1cbad249e93f31df97d4b2ed1d0e8638"
                and labels.get("org.llull.buzz.recipe") == "983ff79",
                "Upstream image is not the pinned local recipe")
        require(built["Os"] == "linux" and built["Architecture"] == "arm64", "Selected local VM requires Linux arm64 image")
        keys = self.native_keys()
        pw = self.state["passwords"]
        values = {
            "DATABASE_URL": f"postgresql://bz_native:{pw['native']}@postgres:5432/bz_native?sslmode=disable",
            "REDIS_URL": f"redis://:{pw['valkey']}@valkey:6379",
            "BUZZ_RELAY_PRIVATE_KEY": keys["relay"]["secret"],
            "RELAY_OWNER_PUBKEY": keys["owner"]["public"],
            "RELAY_URL": ("wss://buzz-relay.synthetic.invalid" if self.state.get("native_public_wss")
                          else "ws://buzz-relay.synthetic.invalid:3000"),
            "BUZZ_BIND_ADDR": "0.0.0.0:3000",
            "BUZZ_REQUIRE_RELAY_MEMBERSHIP": "true",
            "BUZZ_AUTO_MIGRATE": "true",
            "BUZZ_PUSH_ENABLED": "false",
            "BUZZ_AUDIT_ENABLED": "true",
            "BUZZ_DB_POOL_SIZE": "8",
            "BUZZ_REDIS_POOL_SIZE": "4",
            "BUZZ_S3_ENDPOINT": "http://seaweed:8333",
            "BUZZ_S3_ACCESS_KEY": "bz-media",
            "BUZZ_S3_SECRET_KEY": pw["media"],
            "BUZZ_S3_BUCKET": "buzz-media",
            "BUZZ_S3_REGION": "us-east-1",
            "BUZZ_S3_ADDRESSING_STYLE": "path",
            "BUZZ_MEDIA_BASE_URL": "https://buzz-relay.synthetic.invalid/media",
            "BUZZ_GIT_REPO_PATH": "/work/task/git-repos",
            "BUZZ_GIT_PACK_CACHE_PATH": "/work/task/git-cache",
            "BUZZ_GIT_HOOK_HMAC_SECRET": pw["provider"],
            "RUST_LOG": "buzz_relay=info",
        }
        env = self.envfile("native", values)
        data = self.create("volume", "relay-data")
        self.data_owner(data)
        self.run("relay", image,
                 ["--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
                  "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--env-file", env,
                  "--mount", f"type=volume,src={data},dst=/work/task,volume-nocopy"],
                 ["/opt/llull/upstream/buzz-relay"], aliases=("buzz-relay.synthetic.invalid",), memory="2g",
                 recipe_extra="wss-public-origin" if self.state.get("native_public_wss") else None)
        self.state["stage"] = "native-started"
        self.state["upstream_image_id"] = built["Id"]
        self.persist()
        print(json.dumps({"stage":"native-started", "upstream_image_id":built["Id"],
                          "relay_public_key":keys["relay"]["public"],
                          "owner_public_key":keys["owner"]["public"],
                          "bot_public_key":keys["bot"]["public"]}, indent=2))

    def native_client(self, identity, *args, check=True):
        require(identity in {"owner", "bot", "outsider"}, "Unknown synthetic native identity")
        keys = self.native_keys()
        env = self.envfile("native-client-" + identity, {
            "BUZZ_RELAY_URL": "http://buzz-relay.synthetic.invalid:3000",
            "BUZZ_PRIVATE_KEY": keys[identity]["secret"],
        })
        return docker("run", "--rm", "--network", self.name("storage"),
                      "--label", self.label(), "--user", "65532:65532",
                      "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges:true",
                      "--env-file", env, "--entrypoint", "/opt/llull/upstream/buzz",
                      "llull-buzz-completion-upstream:01b6174", *args, check=check)

    def native_admin(self, *args):
        env = str(self.directory / "native.env")
        require(Path(env).is_file(), "Native relay environment is missing")
        return docker("run", "--rm", "--network", self.name("storage"),
                      "--label", self.label(), "--user", "65532:65532",
                      "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges:true",
                      "--env-file", env, "--entrypoint", "/opt/llull/upstream/buzz-admin",
                      "llull-buzz-completion-upstream:01b6174", *args)

    def native_file_client(self, identity, body, *args):
        require(identity in {"owner", "bot"}, "Unknown synthetic native file identity")
        env = self.envfile("native-client-" + identity, {
            "BUZZ_RELAY_URL": "http://buzz-relay.synthetic.invalid:3000",
            "BUZZ_PRIVATE_KEY": self.native_keys()[identity]["secret"],
        })
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            item = tarfile.TarInfo("synthetic.png")
            item.uid = item.gid = 65532
            item.mode = 0o600
            item.size = len(body)
            tar.addfile(item, io.BytesIO(body))
        return docker("run", "--rm", "-i", "--network", self.name("storage"),
                      "--label", self.label(), "--user", "65532:65532",
                      "--cap-drop", "ALL", "--read-only", "--security-opt", "no-new-privileges:true",
                      "--tmpfs", "/tmp:rw,noexec,nosuid,size=1m", "--env-file", env,
                      "--entrypoint", "sh", "llull-buzz-completion-upstream:01b6174",
                      "-c", "tar -xpf - -C /tmp && exec /opt/llull/upstream/buzz \"$@\"", "buzz", *args,
                      data=archive.getvalue(), check=False)

    def probe_media(self):
        require((self.directory / "native-check.json").is_file(), "Check native client first")
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        body = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(b"\x00\x32\x64\x96\xff")) + chunk(b"IEND", b""))
        upload = self.native_file_client("owner", body, "upload", "file", "--file", "/tmp/synthetic.png")
        require(upload.returncode == 0, "Native media upload failed")
        uploaded = json.loads(upload.stdout)
        digest = hashlib.sha256(body).hexdigest()
        require(uploaded["sha256"] == digest and uploaded["size"] == len(body), "Native media upload descriptor differs")
        channel_id = json.loads((self.directory / "native-check.json").read_text())["channel_id"]
        attached = self.native_file_client("owner", body, "messages", "send", "--channel", channel_id,
                                           "--content", "synthetic private media attachment",
                                           "--file", "/tmp/synthetic.png")
        require(attached.returncode == 0, "Private attachment message failed")
        attached_result = json.loads(attached.stdout)
        require(attached_result.get("accepted") is True, "Private attachment event was not accepted")
        attached_events = json.loads(self.native_client("owner", "messages", "get", "--channel", channel_id).stdout)
        signed_attachment = next((e for e in attached_events if e.get("id") == attached_result.get("event_id")), None)
        require(signed_attachment is not None and any(
            tag[0] == "imeta" and any(digest in field for field in tag[1:])
            for tag in signed_attachment.get("tags", []) if tag
        ), "Original signed private event lacks this attachment digest")
        owner = self.native_client("owner", "media", "get", digest)
        require(owner.stdout == body, "Native owner media read differs")
        outsider = self.native_client("outsider", "media", "get", digest, check=False)
        require(outsider.returncode != 0, "Unenrolled native identity read media")
        # The bot is relay-enrolled but deliberately has no access to the
        # private channel. Observe the upstream artifact gate without assuming
        # that relay membership and attachment disclosure are equivalent.
        bot = self.native_client("bot", "media", "get", digest, check=False)
        report = {"blob_sha256": digest, "native_upload_and_owner_read": True,
                  "private_attachment_registered": True,
                  "private_attachment_event_id": attached_result["event_id"],
                  "unenrolled_read_denied": True, "enrolled_nonchannel_read_denied": bot.returncode != 0,
                  "enrolled_nonchannel_received_exact_bytes": bot.returncode == 0 and bot.stdout == body,
                  "scope": "isolated pinned upstream media path; provider artifact gate not yet in place"}
        save(self.directory / "media-probe.json", report)
        print(json.dumps(report, indent=2))
        require(report["enrolled_nonchannel_read_denied"],
                "Pinned upstream media disclosure is not artifact-scoped")

    def restart_native(self):
        prior = json.loads((self.directory / "native-check.json").read_text())
        media = json.loads((self.directory / "media-probe.json").read_text())
        relay_name = self.name("relay")
        before = self.inspect("container", relay_name)
        require(before and before["State"]["Running"], "Owned native relay is not running")
        started_before = before["State"]["StartedAt"]
        docker("restart", "--time", "10", relay_name)
        deadline = time.monotonic() + 90
        while True:
            current = self.inspect("container", relay_name)
            require(current and current["State"]["Running"], "Native relay exited on restart")
            recovered = self.native_client("owner", "messages", "get", "--channel", prior["channel_id"], check=False)
            if recovered.returncode == 0:
                events = json.loads(recovered.stdout)
                if any(e.get("id") == prior["message_event_id"] for e in events):
                    break
            if time.monotonic() > deadline:
                raise RuntimeError("Original signed native message unavailable after restart")
            time.sleep(2)
        require(current["State"]["StartedAt"] != started_before, "Native process did not restart")
        blob = self.native_client("owner", "media", "get", media["blob_sha256"])
        require(hashlib.sha256(blob.stdout).hexdigest() == media["blob_sha256"],
                "Original private media bytes unavailable after restart")
        report = {"relay_restarted": True, "original_message_event_recovered": True,
                  "original_media_digest_recovered": True, "upstream_image_id": self.state["upstream_image_id"],
                  "scope": "owned relay process restart; not PostgreSQL/media backup restoration"}
        save(self.directory / "native-restart.json", report)
        print(json.dumps(report, indent=2))

    def provider_secrets(self, native_config, service_key):
        volume = self.create("volume", "provider-secrets")
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for name, body in [("native.json", json.dumps(native_config).encode()),
                               ("service.key", (service_key + "\n").encode())]:
                item = tarfile.TarInfo(name)
                item.uid = item.gid = 65532
                item.mode = 0o600
                item.size = len(body)
                tar.addfile(item, io.BytesIO(body))
        name = self.name("provider-configure")
        self.remember("container", name)
        if self.inspect("container", name):
            docker("rm", "-f", name)
        docker("run", "--rm", "-i", "--name", name, "--label", self.label(),
               "--network", "none", "--mount", f"type=volume,src={volume},dst=/config",
               "--entrypoint", "tar", IMAGES["config"], "-xpf", "-", "-C", "/config",
               data=archive.getvalue())
        return volume

    def switch_native_wss(self):
        require(self.state["stage"] == "provider-started", "Enroll the native service before switching public TLS posture")
        checked = json.loads((self.directory / "native-check.json").read_text())
        require(self.state.get("native_service_channel") == checked["channel_id"],
                "Native service channel enrollment is not recorded")
        relay = self.inspect("container", self.name("relay"))
        require(relay and relay["State"]["Running"], "Owned relay is not running")
        docker("rm", "-f", self.name("relay"))
        self.state["native_public_wss"] = True
        self.state["stage"] = "native-started"
        self.persist()
        self.up_native()
        self.state["stage"] = "provider-started"
        self.persist()
        print(json.dumps({"native_public_wss": True,
                          "internal_origin": "http://buzz-relay.synthetic.invalid:3000",
                          "public_signing_origin": "https://buzz-relay.synthetic.invalid",
                          "scope": "relay public URL posture; external TLS terminator not yet deployed"}, indent=2))

    def up_provider(self, source_sha):
        require(self.state["stage"] in {"native-started", "provider-started"},
                "Qualify native relay before provider deployment")
        require(source_sha and re.fullmatch(r"[0-9a-f]{40}", source_sha), "Full provider source SHA required")
        image = "llull-buzz-completion-provider:" + source_sha[:12]
        built = json.loads(docker("image", "inspect", image).stdout)[0]
        require(built["Config"]["Labels"].get("org.opencontainers.image.revision") == source_sha,
                "Provider image source label differs")
        require(built["Os"] == "linux" and built["Architecture"] == "arm64", "Provider image architecture differs")
        keys = self.native_keys()
        service = keys["service"]
        self.native_admin("add-member", "--pubkey", service["public"])
        channel_id = json.loads((self.directory / "native-check.json").read_text())["channel_id"]
        if self.state.get("native_public_wss"):
            require(self.state.get("native_service_channel") == channel_id,
                    "WSS relay requires prior service channel enrollment")
        else:
            members = json.loads(self.native_client("owner", "channels", "members", "--channel", channel_id).stdout)
            if not any(member.get("pubkey") == service["public"] for member in members):
                self.native_client("owner", "channels", "add-member", "--channel", channel_id,
                                   "--pubkey", service["public"], "--role", "bot")
            self.state["native_service_channel"] = channel_id
            self.persist()
        volume = self.provider_secrets({
            "community_id": "synthetic-community",
            "private_origin": "http://buzz-relay.synthetic.invalid:3000",
            "public_origin": "https://buzz-relay.synthetic.invalid",
            "service_key_file": "/run/bz-provider/service.key",
            "relay_public_key": keys["relay"]["public"],
        }, service["secret"])
        pw = self.state["passwords"]
        env = self.envfile("provider", {
            "DATABASE_URL": f"postgresql://bz_provider:{pw['provider']}@postgres:5432/bz_foundation_test?sslmode=disable",
            "PUBLIC_ORIGIN": "https://provider.synthetic.invalid",
            "EXTERNAL_RECOVERY_EPOCH": "1",
            "NATIVE_ORIGIN_CONFIG": "/run/bz-provider/native.json",
            "BIND_ADDR": "0.0.0.0:8080",
        })
        common = ["--network", self.name("storage"), "--label", self.label(),
                  "--user", "65532:65532", "--cap-drop", "ALL", "--read-only",
                  "--security-opt", "no-new-privileges:true", "--env-file", env,
                  "--mount", f"type=volume,src={volume},dst=/run/bz-provider,readonly"]
        docker("run", "--rm", *common, image, "migrate")
        existing = self.inspect("container", self.name("provider"))
        if existing and self.state.get("provider_source_sha") != source_sha:
            # Only this exactly labeled task-owned provider is replaced.
            docker("rm", "-f", self.name("provider"))
        self.run("provider", image,
                 ["--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
                  "--env-file", env, "--mount",
                  f"type=volume,src={volume},dst=/run/bz-provider,readonly"],
                 ["serve"], aliases=("provider.synthetic.invalid",), memory="1g")
        self.state.update(stage="provider-started", provider_source_sha=source_sha,
                          provider_image_id=built["Id"])
        self.persist()
        print(json.dumps({"stage": "provider-started", "provider_image_id": built["Id"],
                          "provider_source_sha": source_sha, "native_service_pubkey": service["public"]}, indent=2))

    def check_provider(self):
        require(self.state["stage"] == "provider-started", "Start provider first")
        info = self.inspect("container", self.name("provider"))
        require(info and info["State"]["Running"], "Provider container is not running")
        require(not any(info["NetworkSettings"]["Ports"].values()), "Provider port exposed to host")
        response = docker("run", "--rm", "--network", self.name("storage"), "--label", self.label(),
                          "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
                          "--entrypoint", "curl", IMAGES["client"], "--fail", "--silent", "--show-error",
                          "--max-time", "10", "http://provider.synthetic.invalid:8080/healthz")
        health = json.loads(response.stdout)
        require(health["restricted_profile_active"] is False and health["qualification"] == "in-progress",
                "Provider reported an unsupported qualification state")
        require(health["configured"]["native_intake"] and health["configured"]["publication_delivery"],
                "Native adapters were not configured")
        report = {"provider_source_sha": self.state["provider_source_sha"],
                  "provider_image_id": self.state["provider_image_id"], "health": health,
                  "private_network": True, "host_ports": False,
                  "scope": "configured service boot; signed native request and consumer path remain separate"}
        save(self.directory / "provider-check.json", report)
        print(json.dumps(report, indent=2))

    def probe_provider_origin(self):
        require(self.state["stage"] == "provider-started", "Start provider first")
        image = "llull-buzz-completion-provider:" + self.state["provider_source_sha"][:12]
        checked = json.loads((self.directory / "native-check.json").read_text())
        secret_volume = self.name("provider-secrets")
        self.inspect("volume", secret_volume)
        attempt = docker("run", "--rm", "--network", self.name("storage"),
                         "--label", self.label(), "--user", "65532:65532", "--read-only",
                         "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                         "--env-file", str(self.directory / "provider.env"), "--mount",
                         f"type=volume,src={secret_volume},dst=/run/bz-provider,readonly",
                         "--entrypoint", "/opt/llull/bin/llull-buzz-provider", image,
                         "native-probe", checked["channel_id"], checked["message_event_id"], check=False)
        with open(self.directory / "provider-origin-probe.log", "wb", opener=lambda p, f: os.open(p, f, 0o600)) as f:
            f.write(attempt.stdout + attempt.stderr)
        require(attempt.returncode == 0, "Fixed-origin provider adapter could not read pinned native event and audience")
        report = json.loads(attempt.stdout)
        require(report["native_event_id"] == checked["message_event_id"] and report["audience_member_count"] >= 2,
                "Fixed-origin native identity or audience differs")
        save(self.directory / "provider-origin-probe.json", report)
        print(json.dumps(report, indent=2))

    def check_native(self):
        require(self.state["stage"] == "native-started", "Start native relay first")
        relay = self.inspect("container", self.name("relay"))
        require(relay and relay["State"]["Running"], "Pinned native relay is not running")
        require(not any(relay["NetworkSettings"]["Ports"].values()), "Native relay port exposed to host")
        require(relay["Config"]["User"] == "65532:65532", "Native relay must use configured unprivileged UID")
        require(relay["HostConfig"]["ReadonlyRootfs"], "Native relay root filesystem is writable")
        require(relay["HostConfig"]["CapDrop"] == ["ALL"], "Native relay has unexpected capabilities")
        name = "synthetic-restricted-" + self.state["owner"][:12]
        found = self.native_client("owner", "channels", "search", "--query", name, "--exact")
        channels = json.loads(found.stdout)
        if channels:
            require(len(channels) == 1, "Synthetic channel name is ambiguous")
            channel_id = channels[0]["channel_id"]
        else:
            created = self.native_client("owner", "channels", "create", "--name", name,
                                         "--type", "stream", "--visibility", "private")
            channel_id = json.loads(created.stdout)["channel_id"]
        require(re.fullmatch(r"[0-9a-f-]{36}", channel_id) is not None, "Native channel ID is invalid")
        # Distinguish relay enrollment from private-channel membership.
        outsider = self.native_client("outsider", "messages", "get", "--channel", channel_id, check=False)
        require(outsider.returncode != 0 and b"relay_membership_required" in outsider.stderr,
                "Unenrolled native identity was not denied")
        bot_public = self.native_keys()["bot"]["public"]
        self.native_admin("add-member", "--pubkey", bot_public)
        members = json.loads(self.native_client("owner", "channels", "members", "--channel", channel_id).stdout)
        if any(member.get("pubkey") == bot_public for member in members):
            self.native_client("owner", "channels", "remove-member", "--channel", channel_id,
                               "--pubkey", bot_public)
        denied = self.native_client("bot", "messages", "get", "--channel", channel_id, check=False)
        require(denied.returncode == 0 and json.loads(denied.stdout) == [],
                "Enrolled nonmember discovered private channel messages")
        hidden = self.native_client("bot", "channels", "get", "--channel", channel_id)
        require(json.loads(hidden.stdout) is None, "Private channel metadata was visible to nonmember")
        marker = "synthetic retained native message " + self.state["owner"][:12]
        sent = self.native_client("owner", "messages", "send", "--channel", channel_id,
                                  "--content", marker)
        message = json.loads(sent.stdout)
        require(message.get("accepted") is True, "Native relay did not accept signed message")
        denied_after = self.native_client("bot", "messages", "get", "--channel", channel_id, check=False)
        require(denied_after.returncode == 0 and json.loads(denied_after.stdout) == [],
                "Nonmember recovered private message")
        read = self.native_client("owner", "messages", "get", "--channel", channel_id)
        events = json.loads(read.stdout)
        require(any(e.get("content") == marker for e in events), "Owner could not recover native message")
        self.native_client("owner", "channels", "add-member", "--channel", channel_id,
                           "--pubkey", bot_public, "--role", "bot")
        bot_read = json.loads(self.native_client("bot", "messages", "get", "--channel", channel_id).stdout)
        require(any(e.get("content") == marker for e in bot_read), "New member could not recover retained message")
        self.native_client("owner", "channels", "remove-member", "--channel", channel_id,
                           "--pubkey", bot_public)
        denied_revoked = self.native_client("bot", "messages", "get", "--channel", channel_id, check=False)
        require(denied_revoked.returncode == 0 and json.loads(denied_revoked.stdout) == [],
                "Removed member retained private channel read access")
        report = {"upstream_image_id": self.state["upstream_image_id"],
                  "relay_running": True, "private_network": True, "host_ports": False,
                  "native_client_create_private_channel": True,
                  "native_client_unenrolled_identity_denied": True,
                  "native_client_nonmember_read_denied": True,
                  "native_client_signed_message_send_and_recover": True,
                  "native_client_member_grant_and_revocation": True,
                  "channel_id": channel_id, "message_event_id": message.get("event_id"),
                  "scope": "native relay/client path only; provider mediation and media authorization separate"}
        save(self.directory / "native-check.json", report)
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
    parser.add_argument("action", choices=["up-storage", "check-storage", "up-native", "check-native", "probe-media", "restart-native", "up-provider", "check-provider", "probe-provider-origin", "switch-native-wss", "status", "down"])
    parser.add_argument("--state", type=Path, default=ROOT / "artifacts/completion/stack")
    parser.add_argument("--provider-source", help="Exact committed 40-hex provider image source")
    args = parser.parse_args()
    stack = Stack(args.state)
    {"up-storage": stack.up, "check-storage": stack.check_storage, "up-native": stack.up_native,
     "check-native": stack.check_native,
     "probe-media": stack.probe_media,
     "restart-native": stack.restart_native,
     "up-provider": lambda: stack.up_provider(args.provider_source),
     "check-provider": stack.check_provider,
     "probe-provider-origin": stack.probe_provider_origin,
     "switch-native-wss": stack.switch_native_wss,
     "status": stack.status, "down": stack.down}[args.action]()


if __name__ == "__main__":
    main()
