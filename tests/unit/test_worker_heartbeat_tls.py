"""Worker heartbeats use the master's stable certificate hostname."""

from types import SimpleNamespace

from lattice.worker.heartbeat import HeartbeatSender


async def test_heartbeat_uses_paired_master_mdns_hostname(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text("test CA")
    monkeypatch.setenv("LATTICE_PKI_DIR", str(pki))
    token = tmp_path / "worker.token"
    token.write_text("w" * 48 + "\n")
    token.chmod(0o600)
    sent = []
    backup_self_repairs = []

    class Client:
        async def post(self, url, **kwargs):
            sent.append((url, kwargs))
            return SimpleNamespace(status_code=200, text="ok")

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "lattice.worker.heartbeat.get_worker_master_endpoint",
        lambda: {"ip": "10.77.0.88", "port": 8443, "hostname": "master-node"},
    )

    verify_context = object()
    seen_client_kwargs = {}

    def make_client(**kwargs):
        seen_client_kwargs.update(kwargs)
        return Client()

    monkeypatch.setattr(
        "lattice.worker.heartbeat.load_node_identity",
        lambda: SimpleNamespace(node_id="worker-node"),
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.ensure_backup_transport_current",
        lambda: backup_self_repairs.append(True),
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.applied_generation",
        lambda *_args: 1,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.applied_config_generation",
        lambda: 1,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.local_storage_candidate_payload",
        lambda _node_id: [],
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.read_local_backup_identity",
        lambda: None,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.ssl.create_default_context",
        lambda **_kwargs: verify_context,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.httpx.AsyncClient",
        make_client,
    )
    config = SimpleNamespace(
        master=SimpleNamespace(ip="10.77.0.88", api_port=8080),
        file_access=SimpleNamespace(enabled=False),
        shell_access=SimpleNamespace(enabled=False),
    )
    sender = HeartbeatSender(
        config,
        SimpleNamespace(check_all=lambda: [{"name": "self", "status": "healthy"}]),
    )
    sender.token_path = str(token)

    await sender.send_heartbeat()

    assert sent[0][0] == "https://master-node.local:8443/api/heartbeat"
    assert sent[0][1]["headers"] == {"Authorization": f"Bearer {'w' * 48}"}
    assert seen_client_kwargs["verify"] is verify_context
    assert backup_self_repairs == [True]


async def test_heartbeat_reports_generation_and_applies_master_update(
    tmp_path,
    monkeypatch,
):
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text("test CA")

    monkeypatch.setenv(
        "LATTICE_PKI_DIR",
        str(pki),
    )

    token = tmp_path / "worker.token"
    token.write_text("w" * 48 + "\n")
    token.chmod(0o600)

    sent = []
    applied = []
    queued = []

    class Response:
        status_code = 200
        text = "ok"

        def json(self):
            return {
                "status": "ok",
                "fleet_generation": 3,
                "fleet_update": {
                    "manifest": {
                        "generation": 3,
                    },
                    "signature": "signed-test",
                },
            }

    class Client:
        async def post(self, url, **kwargs):
            sent.append((url, kwargs))
            return Response()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "get_worker_master_endpoint",
        lambda: {
            "ip": "10.77.0.88",
            "port": 8443,
            "hostname": "master-node",
        },
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "get_cached_fleet_generation",
        lambda: 2,
    )

    def fake_apply(manifest, signature):
        applied.append(
            (manifest, signature)
        )
        return {
            "status": "applied",
            "generation": 3,
            "node_id": "worker-node",
        }

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "apply_signed_manifest",
        fake_apply,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "get_cached_signed_manifest",
        lambda: (
            {"generation": 3},
            "signed-test",
        ),
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "queue_transport_reconcile",
        lambda manifest, signature: queued.append(
            (manifest, signature)
        ),
    )


    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "ssl.create_default_context",
        lambda **_kwargs: object(),
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "httpx.AsyncClient",
        lambda **_kwargs: Client(),
    )

    config = SimpleNamespace(
        master=SimpleNamespace(
            ip="10.77.0.88",
            api_port=8080,
        )
    )

    sender = HeartbeatSender(
        config,
        SimpleNamespace(
            check_all=lambda: [
                {
                    "name": "self",
                    "status": "healthy",
                }
            ]
        ),
    )

    sender.token_path = str(token)

    await sender.send_heartbeat()

    assert sent[0][1]["json"][
        "fleet_generation"
    ] == 2

    assert applied == [
        (
            {"generation": 3},
            "signed-test",
        )
    ]

    assert queued == [
        (
            {"generation": 3},
            "signed-test",
        )
    ]


async def test_worker_heartbeat_applies_trust_bound_mount_plan(
    tmp_path,
    monkeypatch,
):
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text(
        "test CA"
    )

    monkeypatch.setenv(
        "LATTICE_PKI_DIR",
        str(pki),
    )

    token = tmp_path / "worker.token"
    token.write_text(
        "w" * 48 + "\n"
    )
    token.chmod(0o600)

    mount_plans = []

    class Response:
        status_code = 200
        text = "ok"

        def json(self):
            return {
                "status":
                    "ok",
                "fleet_generation":
                    3,
                "mount_plan":
                    {
                        "generation":
                            3,
                        "peers":
                            [],
                    },
            }

    class Client:
        async def post(
            self,
            url,
            **kwargs,
        ):
            return Response()

        async def aclose(
            self,
        ):
            return None

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "get_worker_master_endpoint",
        lambda: {
            "ip":
                "10.77.0.88",
            "port":
                8443,
            "hostname":
                "master-node",
        },
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "get_cached_fleet_generation",
        lambda: 3,
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "get_cached_signed_manifest",
        lambda: None,
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "apply_remote_mount_plan",
        lambda plan: mount_plans.append(
            plan
        ),
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "ssl.create_default_context",
        lambda **kwargs: object(),
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat."
        "httpx.AsyncClient",
        lambda **kwargs: Client(),
    )

    config = SimpleNamespace(
        master=SimpleNamespace(
            ip="10.77.0.88",
            api_port=8080,
        )
    )

    sender = HeartbeatSender(
        config,
        SimpleNamespace(
            check_all=lambda: [
                {
                    "name":
                        "self",
                    "status":
                        "healthy",
                }
            ]
        ),
    )

    sender.token_path = str(
        token
    )

    await sender.send_heartbeat()

    assert mount_plans == [
        {
            "generation":
                3,
            "peers":
                [],
        }
    ]

async def test_heartbeat_falls_back_to_verified_master_ip_on_connect_failure(tmp_path, monkeypatch):
    import httpx
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text("test CA")
    monkeypatch.setenv("LATTICE_PKI_DIR", str(pki))
    token = tmp_path / "worker.token"
    token.write_text("w" * 48 + "\n")
    token.chmod(0o600)
    sent = []

    class Response:
        status_code = 200
        text = "ok"
        def json(self):
            return {}

    class Client:
        async def post(self, url, **kwargs):
            sent.append(url)
            if len(sent) == 1:
                raise httpx.ConnectError("name resolution failed", request=httpx.Request("POST", url))
            return Response()
        async def aclose(self):
            return None

    monkeypatch.setattr("lattice.worker.heartbeat.get_worker_master_endpoint", lambda: {
        "ip": "10.77.0.200", "port": 8080, "hostname": "master-node"
    })
    monkeypatch.setattr("lattice.worker.heartbeat.ssl.create_default_context", lambda **_kwargs: object())
    monkeypatch.setattr("lattice.worker.heartbeat.httpx.AsyncClient", lambda **_kwargs: Client())
    async def no_sleep(*_args, **_kwargs):
        return None
    monkeypatch.setattr("lattice.worker.heartbeat.asyncio.sleep", no_sleep)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.200", api_port=8080))
    sender = HeartbeatSender(config, SimpleNamespace(check_all=lambda: [{"name": "self", "status": "healthy"}]))
    sender.token_path = str(token)

    await sender.send_heartbeat()

    assert sent == [
        "https://master-node.local:8080/api/heartbeat",
        "https://10.77.0.200:8080/api/heartbeat",
    ]


async def test_successful_core_health_reports_lattice_core_healthy(tmp_path, monkeypatch):
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text("test CA")
    monkeypatch.setenv("LATTICE_PKI_DIR", str(pki))

    token = tmp_path / "worker.token"
    token.write_text("w" * 48 + "\n")
    token.chmod(0o600)

    sent = []

    class Response:
        status_code = 200
        text = "ok"

        def json(self):
            return {}

    class Client:
        async def post(self, url, **kwargs):
            sent.append(kwargs["json"])
            return Response()

        async def aclose(self):
            return None

    monkeypatch.setattr(
        "lattice.worker.heartbeat.get_worker_master_endpoint",
        lambda: {
            "ip": "10.77.0.200",
            "port": 8080,
            "hostname": "master-node",
        },
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.get_cached_fleet_generation",
        lambda: 1,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.local_mount_observations",
        lambda: [],
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.load_node_identity",
        lambda: None,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.local_lan_routes",
        lambda: [],
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.ssl.create_default_context",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.httpx.AsyncClient",
        lambda **_kwargs: Client(),
    )

    config = SimpleNamespace(
        master=SimpleNamespace(ip="10.77.0.200", api_port=8080),
        file_access=SimpleNamespace(enabled=False),
        shell_access=SimpleNamespace(enabled=False),
    )

    checker = SimpleNamespace(
        check_all=lambda: [{"name": "sshd", "status": "healthy"}],
        check_core_components=lambda **_kwargs: [
            {"name": "fleet_sync", "status": "healthy"},
        ],
    )

    sender = HeartbeatSender(config, checker)
    sender.token_path = str(token)

    await sender.send_heartbeat()

    services = {
        item["name"]: item["status"]
        for item in sent[0]["services"]
    }

    assert services["fleet_sync"] == "healthy"
    assert services["lattice_core"] == "healthy"
    assert sent[0]["status"] == "healthy"


async def test_heartbeat_stop_awaits_persistent_client_close():
    closed = []

    class Client:
        async def aclose(self):
            closed.append(True)

    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88", api_port=8080))
    sender = HeartbeatSender(
        config,
        SimpleNamespace(check_all=lambda: []),
    )
    sender._client = Client()
    sender._running = True

    await sender.stop()

    assert sender._running is False
    assert sender._client is None
    assert closed == [True]
