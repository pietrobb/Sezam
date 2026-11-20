from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from scripts.e2e_environment import E2EEnvironment
from tests.node_support import node_cmd


ROOT = Path(__file__).resolve().parents[1]
REMEDIATION_DEPLOY_FILES = {
    ".dockerignore",
    "Dockerfile",
    "compose.yaml",
    "server/requirements.txt",
    "server/app/config.py",
    "server/app/database.py",
    "server/app/dependencies.py",
    "server/app/main.py",
    "server/app/models/schemas.py",
    "server/app/routers/auth.py",
    "server/app/routers/recovery.py",
    "server/app/routers/share.py",
    "server/app/routers/sync.py",
    "web/templates/index.html",
    "web/templates/share.html",
    "web/static/css/app.css",
    "web/static/img/bg.jpg",
    "web/static/img/logo.png",
    "web/static/img/panel-clean.png",
    "web/static/icon-192.png",
    "web/static/icon-512.png",
    "web/static/manifest.json",
    "web/static/sw.js",
    "web/static/js/app.js",
    "web/static/js/i18n.js",
    "web/static/js/teamlog.js",
    "web/static/js/argon2-worker.js",
    "web/static/js/share.js",
    "web/static/js/vendor/argon2-bundled.min.js",
    "web/static/js/vendor/libsodium-sumo.min.js",
    "web/static/js/vendor/libsodium-wrappers.min.js",
    "web/static/js/vendor/sezam-sync-core.js",
}


def _load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Channel:
    def __init__(self, status: int):
        self._status = status
        self.shutdown_called = False

    def recv_exit_status(self) -> int:
        return self._status

    def shutdown_write(self) -> None:
        self.shutdown_called = True


class _Stream:
    def __init__(self, value: bytes = b"", status: int = 0):
        self._value = value
        self.channel = _Channel(status)
        self.written = ""

    def read(self) -> bytes:
        return self._value

    def write(self, value: str) -> None:
        self.written += value


class _SSH:
    def __init__(self, status: int, stdout: bytes = b"", stderr: bytes = b""):
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        self.stdin = _Stream()

    def exec_command(self, command: str, timeout: int):
        return self.stdin, _Stream(self.stdout, self.status), _Stream(self.stderr)


class _SFTP:
    def put(self, local: str, remote: str) -> None:
        pass

    def close(self) -> None:
        pass


class _DeploymentSSH(_SSH):
    def __init__(self):
        super().__init__(status=0, stdout=b'{"status":"ok"}')
        self.commands: list[str] = []

    def load_system_host_keys(self) -> None:
        pass

    def load_host_keys(self, path: str) -> None:
        pass

    def set_missing_host_key_policy(self, policy) -> None:
        pass

    def connect(self, *args, **kwargs) -> None:
        pass

    def open_sftp(self) -> _SFTP:
        return _SFTP()

    def exec_command(self, command: str, timeout: int):
        self.commands.append(command)
        return super().exec_command(command, timeout)

    def close(self) -> None:
        pass


@pytest.mark.parametrize("script_name", ["deploy_shamir.py", "deploy_audit_rebuild.py"])
def test_deploy_requires_explicit_target(script_name: str, monkeypatch):
    monkeypatch.delenv("SEZAM_SSH_HOST", raising=False)
    script = _load_script(script_name)

    with pytest.raises(RuntimeError, match="SEZAM_SSH_HOST"):
        script.main()


@pytest.mark.parametrize(
    ("environment", "error"),
    [
        ({}, "SEZAM_DEMO_SERVER"),
        ({"SEZAM_DEMO_SERVER": "https://demo.example.invalid"}, "SEZAM_SSH_HOST"),
        (
            {
                "SEZAM_DEMO_SERVER": "https://demo.example.invalid",
                "SEZAM_SSH_HOST": "192.0.2.10",
                "SEZAM_DEMO_ALLOW_DESTRUCTIVE": "wrong-target",
            },
            "SEZAM_DEMO_ALLOW_DESTRUCTIVE",
        ),
    ],
)
def test_demo_setup_requires_exact_destructive_target(environment, error, monkeypatch):
    for name in (
        "SEZAM_DEMO_SERVER",
        "SEZAM_SSH_HOST",
        "SEZAM_DEMO_ALLOW_DESTRUCTIVE",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match=error):
        _load_script("setup_demo.py")


@pytest.mark.parametrize("script_name", ["deploy_shamir.py", "deploy_audit_rebuild.py"])
def test_deploy_uses_configured_compose_runtime(script_name: str, monkeypatch):
    monkeypatch.setenv("SEZAM_SSH_HOST", "deploy.example.invalid")
    monkeypatch.setenv("SEZAM_PORT", "19000")
    monkeypatch.setenv("SEZAM_DB_CONTAINER_NAME", "custom-sezam-db")
    script = _load_script(script_name)
    ssh = _DeploymentSSH()
    monkeypatch.setattr(script.paramiko, "SSHClient", lambda: ssh)

    script.main()

    assert any("http://127.0.0.1:19000/health" in command for command in ssh.commands)
    if script_name == "deploy_audit_rebuild.py":
        assert any("docker exec -i custom-sezam-db " in command for command in ssh.commands)


@pytest.mark.parametrize("script_name", ["deploy_shamir.py", "deploy_audit_rebuild.py"])
def test_deploy_uploads_complete_remediation_candidate(script_name: str):
    script = _load_script(script_name)

    assert REMEDIATION_DEPLOY_FILES <= set(script.FILES)
    assert all((ROOT / path).is_file() for path in REMEDIATION_DEPLOY_FILES)


def test_web_login_assets_and_guidance_are_complete():
    index = (ROOT / "web/templates/index.html").read_text(encoding="utf-8")
    css = (ROOT / "web/static/css/app.css").read_text(encoding="utf-8")
    manifest = json.loads(
        (ROOT / "web/static/manifest.json").read_text(encoding="utf-8")
    )

    assert "Zadajte svoje existujúce používateľské meno" in index
    assert "Prihlásenie do existujúceho trezoru" not in index
    assert "Nové heslo si na tejto obrazovke nevytvárate" not in index
    assert "Pri bežnom prihlásení túto možnosť nepotrebujete" in index
    assert '/static/css/app.css?v=20261109-1' in index
    assert '/static/js/i18n.js?v=20261120-1' in index
    assert index.index('/static/js/teamlog.js?v=20261113-1') < index.index('/static/js/app.js')
    assert '/static/js/app.js?v=20261120-1' in index
    assert '<details class="backup-import">' in index
    assert index.count('action="about:blank" method="post" autocomplete="on"') == 3
    assert 'id="username" name="username"' in index
    assert 'id="password" name="password"' in index
    assert 'autocomplete="current-password"' in index
    assert index.count('name="username"') == 3
    assert index.count('name="password"') == 3
    assert index.count('name="password-confirmation"') == 2
    assert index.count('autocomplete="new-password"') == 6
    assert 'data-lpignore' not in index
    assert 'data-1p-ignore' not in index
    assert "url('/static/img/bg.jpg')" in css
    assert "url('/static/img/panel-clean.png')" in css
    for asset in (
        "web/static/img/bg.jpg",
        "web/static/img/logo.png",
        "web/static/img/panel-clean.png",
        *("web/static" + icon["src"].removeprefix("/static") for icon in manifest["icons"]),
    ):
        assert (ROOT / asset).is_file(), asset


def test_tree_panel_splitter_is_resizable_accessible_and_persistent():
    index = (ROOT / "web/templates/index.html").read_text(encoding="utf-8")
    css = (ROOT / "web/static/css/app.css").read_text(encoding="utf-8")
    app = (ROOT / "web/static/js/app.js").read_text(encoding="utf-8")
    app_path = json.dumps(str(ROOT / "web/static/js/app.js"))

    assert 'id="tree-splitter"' in index
    assert 'role="separator" tabindex="0"' in index
    assert 'aria-orientation="vertical" aria-controls="tree-panel" aria-valuemin="240"' in index
    assert 'data-i18n-aria-label="vault.resize_tree_panel"' in index
    assert "initTreePanelSplitter();" in app
    assert ".tree-splitter {" in css
    assert "touch-action: none" in css
    assert "body.resizing-tree-panel" in css
    assert "@media (pointer: coarse)" in css
    assert "flex-basis: 24px" in css
    assert "flex-wrap: wrap" in css
    assert "@media (max-width: 768px)" in css
    assert ".tree-splitter { display: none; }" in css
    assert "max-width: none" in css
    assert "flex-basis: auto" in css

    script = r"""
const fs = require('fs');
let storedWidth = '320';
let layoutWidth = 1000;
const handlers = {};
const windowHandlers = {};
const panel = { style: {} };
const splitter = {
    attrs: {},
    captured: null,
    addEventListener(name, handler) { handlers[name] = handler; },
    setAttribute(name, value) { this.attrs[name] = value; },
    setPointerCapture(id) { this.captured = id; },
    hasPointerCapture(id) { return this.captured === id; },
    releasePointerCapture() { this.captured = null; },
};
const mainContent = {
    style: { setProperty(name, value) { this[name] = value; } },
    getBoundingClientRect() { return { width: layoutWidth, left: 10 }; },
};
const bodyClasses = new Set();
globalThis.window = {
    location: { origin: 'https://example.invalid' },
    innerWidth: 1000,
    addEventListener(name, handler) { windowHandlers[name] = handler; },
};
globalThis.document = {
    body: { classList: {
        add(name) { bodyClasses.add(name); },
        remove(name) { bodyClasses.delete(name); },
    } },
    addEventListener() {},
    getElementById(id) {
        if (id === 'tree-panel') return panel;
        if (id === 'tree-splitter') return splitter;
        return null;
    },
    querySelector(selector) { return selector === '.main-content' ? mainContent : null; },
};
globalThis.navigator = {};
globalThis.localStorage = {
    getItem(key) { return key === 'sezam-tree-panel-width' ? storedWidth : null; },
    setItem(key, value) { if (key === 'sezam-tree-panel-width') storedWidth = value; },
};
eval(fs.readFileSync(APP_PATH, 'utf8'));
globalThis.SezamTreePanelSplitter.init();
if (mainContent.style['--tree-panel-width'] !== '320px' || splitter.attrs['aria-valuemax'] !== '450') process.exit(1);
handlers.pointerdown({ button: 0, pointerId: 7, preventDefault() {} });
handlers.pointerdown({ button: 0, pointerId: 8, preventDefault() {} });
handlers.pointermove({ pointerId: 8, clientX: 600 });
if (mainContent.style['--tree-panel-width'] !== '320px') process.exit(2);
handlers.pointermove({ pointerId: 7, clientX: 600 });
if (mainContent.style['--tree-panel-width'] !== '450px' || !bodyClasses.has('resizing-tree-panel')) process.exit(3);
handlers.pointerup({ pointerId: 8 });
if (!bodyClasses.has('resizing-tree-panel') || storedWidth !== '320') process.exit(4);
handlers.lostpointercapture({ pointerId: 7 });
if (storedWidth !== '450' || bodyClasses.has('resizing-tree-panel')) process.exit(5);
handlers.keydown({ key: 'ArrowLeft', preventDefault() {} });
if (mainContent.style['--tree-panel-width'] !== '434px' || storedWidth !== '434') process.exit(6);
handlers.keydown({ key: 'Home', preventDefault() {} });
if (mainContent.style['--tree-panel-width'] !== '240px' || storedWidth !== '240') process.exit(7);
handlers.keydown({ key: 'End', preventDefault() {} });
layoutWidth = 800;
windowHandlers.resize();
if (mainContent.style['--tree-panel-width'] !== '360px' || splitter.attrs['aria-valuemax'] !== '360' || splitter.attrs['aria-valuenow'] !== '360') process.exit(8);
""".replace("APP_PATH", app_path)

    result = subprocess.run(
        [node_cmd(), "-e", script],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_web_password_policy_and_i18n_behavior():
    i18n_path = json.dumps(str(ROOT / "web/static/js/i18n.js"))
    app_path = json.dumps(str(ROOT / "web/static/js/app.js"))
    script = r"""
const fs = require('fs');
globalThis.window = {
    location: { origin: 'https://example.invalid' },
    addEventListener() {},
};
globalThis.document = { addEventListener() {} };
globalThis.navigator = {};
globalThis.localStorage = { getItem() { return null; }, setItem() {} };
eval(fs.readFileSync(I18N_PATH, 'utf8'));
eval(fs.readFileSync(APP_PATH, 'utf8'));
const policy = globalThis.SezamPasswordPolicy;
const translations = globalThis.SezamTranslations;
const rejected = [
    'abcdefghijklmn!',
    'ABCDEFGHIJKLMN!',
    'Abcdefghijklmn',
    'Abcdefghij!',
    'Abcdefghijklmn ',
];
if (policy.minLength !== 14 || rejected.some((password) => policy.meets(password))) {
    process.exit(1);
}
if (!policy.meets('\u017dlt\u00fdK\u00f4\u0148-Be\u017e\u00ed123') || !policy.meets('Abcdefghijklmn!')) {
    process.exit(2);
}
const defaultKeys = Object.keys(translations.sk).sort().join('\n');
for (const [language, messages] of Object.entries(translations)) {
    if (defaultKeys !== Object.keys(messages).sort().join('\n')) process.exit(4);
    for (const key of ['bootstrap.intro', 'password.requirements', 'error.password_policy', 'vault.search_placeholder', 'vault.resize_tree_panel', 'entry.modal.new', 'audit.title', 'admin.users', 'recovery.title', 'recovery.print_heading', 'share.title', 'share.error.modified']) {
        if (!translations[language][key]) process.exit(3);
    }
}
""".replace("I18N_PATH", i18n_path).replace("APP_PATH", app_path)

    result = subprocess.run(
        [node_cmd(), "-e", script],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout

    i18n = (ROOT / 'web/static/js/i18n.js').read_text(encoding='utf-8')
    app = (ROOT / 'web/static/js/app.js').read_text(encoding='utf-8')
    index = (ROOT / 'web/templates/index.html').read_text(encoding='utf-8')
    assert app.count("const meta = await apiFetch('/api/meta');") == 2
    # Login uses the account's own KDF params (per-user, from /api/meta).
    assert "const kdfParams = accountKdfParams(meta);" in app
    assert "deriveKEK(passwordForm, argon2Salt, kdfParams, { exact: true })" in app
    assert "const onboardingKdfParams = normalizeKdfParams(meta.argon2_web_params);" in app
    assert "argon2_params: onboardingKdfParams" in app
    assert 'listLanguages' in i18n
    assert 'resolveLanguage' in i18n
    assert '<option value="sk">' not in index
    assert 'data-i18n="vault.no_selection"' in index


def test_all_web_surfaces_use_the_shared_i18n_catalog():
    index = (ROOT / "web/templates/index.html").read_text(encoding="utf-8")
    share = (ROOT / "web/templates/share.html").read_text(encoding="utf-8")
    app = (ROOT / "web/static/js/app.js").read_text(encoding="utf-8")
    share_js = (ROOT / "web/static/js/share.js").read_text(encoding="utf-8")

    assert 'data-i18n="share.title"' in share
    assert 'data-i18n="share.instructions"' in share
    assert 'data-i18n="share.pin_label"' in share
    assert 'data-i18n="share.open"' in share
    assert '/static/css/app.css?v=20261109-1' in share
    assert '/static/js/i18n.js?v=20260724-3' in share
    assert 'data-i18n="audit.ip"' in index
    for hardcoded in (
        "Nastavit Org Recovery",
        "Generovat kusy",
        "Kusy kluca obnovy",
        "Zrusit",
        "Obnovit pristup",
        "Vytvorene:",
        "'(encrypted entry)'",
    ):
        assert hardcoded not in app
    for hardcoded in (
        "PIN je povinný alebo nesprávny.",
        "Načítavam a dešifrujem záznam…",
        "Záznam bol dešifrovaný iba v tomto prehliadači.",
        "Zdieľaný odkaz sa nepodarilo otvoriť.",
    ):
        assert hardcoded not in share_js
    assert "I18N.applyDocument(document, language)" in app
    assert "I18N.applyDocument(document, language)" in share_js


@pytest.mark.parametrize("script_name", ["deploy_shamir.py", "deploy_audit_rebuild.py"])
def test_remote_command_fails_closed(script_name: str):
    script = _load_script(script_name)
    ssh = _SSH(status=17, stderr=b"deployment failed")

    with pytest.raises(RuntimeError, match="exit 17"):
        script.run_remote(ssh, "false", timeout=30)


@pytest.mark.parametrize("script_name", ["deploy_shamir.py", "deploy_audit_rebuild.py"])
def test_remote_command_returns_output_and_streams_stdin(script_name: str):
    script = _load_script(script_name)
    ssh = _SSH(status=0, stdout=b"ok")

    output = script.run_remote(ssh, "command", timeout=30, input_data="SQL")

    assert output == "ok"
    assert ssh.stdin.written == "SQL"
    assert ssh.stdin.channel.shutdown_called


def test_e2e_environment_requires_explicit_isolated_target():
    with pytest.raises(RuntimeError, match="SEZAM_SERVER"):
        E2EEnvironment.from_environ({})

    local = E2EEnvironment.from_environ({"SEZAM_SERVER": "http://127.0.0.1:18000"})
    assert local.server_url == "http://127.0.0.1:18000"
    assert local.reset_mode == "fresh"

    with pytest.raises(RuntimeError, match="loopback"):
        E2EEnvironment.from_environ({"SEZAM_SERVER": "https://example.invalid"})
    with pytest.raises(RuntimeError, match="plain HTTP"):
        E2EEnvironment.from_environ({"SEZAM_SERVER": "http://127.0.0.1:18000/api"})


def test_e2e_remote_reset_requires_exact_destructive_confirmation():
    base = {
        "SEZAM_SERVER": "https://example.invalid",
        "SEZAM_E2E_RESET_MODE": "ssh",
        "SEZAM_SSH_HOST": "192.0.2.10",
        "SEZAM_SSH_PORT": "2222",
        "SEZAM_DB_CONTAINER_NAME": "custom sezam-db",
        "SEZAM_API_CONTAINER_NAME": "custom sezam-api",
    }
    with pytest.raises(RuntimeError, match="SEZAM_E2E_ALLOW_DESTRUCTIVE"):
        E2EEnvironment.from_environ(base)

    confirmation = f"{base['SEZAM_SERVER']}|{base['SEZAM_SSH_HOST']}"
    confirmed = E2EEnvironment.from_environ(
        {**base, "SEZAM_E2E_ALLOW_DESTRUCTIVE": confirmation}
    )
    assert confirmed.reset_mode == "ssh"
    assert confirmed.ssh_host == "192.0.2.10"
    assert confirmed.ssh_port == 2222
    assert confirmed.database_reset_command() == (
        "docker exec -i 'custom sezam-db' "
        "sh -c 'exec mariadb -usezam -p\"$MARIADB_PASSWORD\" sezam'"
    )
    assert confirmed.api_restart_command() == "docker restart 'custom sezam-api'"


@pytest.mark.parametrize(
    "script_name",
    ["test_e2e_real.py", "test_multiuser_e2e.py", "test_stress.py"],
)
def test_destructive_test_scripts_share_fail_closed_target_boundary(script_name: str):
    source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
    assert "E2EEnvironment.from_environ()" in source
    # Production host name and IP: tests/test_open_source_hygiene.py.
    assert 'E2E_ENV.reset_mode == "fresh"' in source
    assert "port=SSH_PORT" in source
    assert "E2E_ENV.database_reset_command()" in source
    assert "E2E_ENV.api_restart_command()" in source
    assert "docker exec -i sezam-db" not in source
    assert 'docker restart sezam-api' not in source


def test_demo_setup_uses_configured_runtime_targets():
    source = (ROOT / "scripts" / "setup_demo.py").read_text(encoding="utf-8")
    assert "port=SSH_PORT" in source
    assert "shlex.quote(DB_CONTAINER_NAME)" in source
    assert "$MARIADB_PASSWORD" in source
    assert "docker exec -i sezam-db" not in source
    assert "duck" + "dns" not in source.lower()


def test_tracked_compose_is_self_contained_and_requires_secrets():
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "sezam-api:" in compose
    assert "sezam-db:" in compose
    assert "SEZAM_DB_PASSWORD:?" in compose
    assert "SEZAM_HMAC_SECRET:?" in compose
    assert "condition: service_healthy" in compose
    assert "sezam-api-data-init:" in compose
    assert "chown -R sezam:sezam /app/data" in compose
    assert "condition: service_completed_successfully" in compose
    assert "${SEZAM_DB_CONTAINER_NAME:-sezam-db}" in compose
    assert "${SEZAM_API_CONTAINER_NAME:-sezam-api}" in compose
    assert "--require-hashes" in dockerfile
    assert 'USER sezam' in dockerfile
    # Review #12: behind the reverse proxy each client keeps its own IP.
    assert '"--proxy-headers"' in dockerfile



def test_forwarded_for_is_trusted_only_from_the_own_network_gateway():
    """Review 2052248: 172.16.0.0/12 trusted every Docker container, so any
    of them could spoof X-Forwarded-For (PIN limits, audit IPs)."""
    import ipaddress
    import re

    import yaml

    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    api = compose["services"]["sezam-api"]
    default = re.fullmatch(
        r"\$\{SEZAM_FORWARDED_ALLOW_IPS:-([^}]*)\}",
        api["environment"]["FORWARDED_ALLOW_IPS"],
    ).group(1)
    trusted = ipaddress.ip_address(default)  # one address, not a range

    assert api["networks"] == ["sezam-net"]
    (ipam,) = compose["networks"]["sezam-net"]["ipam"]["config"]
    assert trusted == ipaddress.ip_address(ipam["gateway"])
    assert trusted in ipaddress.ip_network(ipam["subnet"])


def test_existing_audit_commit_range_is_migrated_to_text():
    from server.app.database import MIGRATIONS_SQL

    check_sql, migration_sql = next(
        migration
        for migration in MIGRATIONS_SQL
        if "commit_seq_range" in migration[0]
    )
    assert "DATA_TYPE = 'text'" in check_sql
    assert "MODIFY COLUMN commit_seq_range TEXT" in migration_sql


def test_docker_context_excludes_generated_and_conventional_private_keys():
    patterns = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert {"jwt_key.bin", "*.key", "*.pem", "*.p8", "*.p12", "*.pfx", ".env*"} <= set(patterns)


def test_generated_and_conventional_private_keys_are_git_ignored():
    secret_paths = [
        "jwt_key.bin",
        ".env",
        ".env.production",
        "signing.key",
        "signing.pem",
        "signing.p8",
        "signing.p12",
        "signing.pfx",
    ]
    for secret_path in secret_paths:
        result = subprocess.run(
            ["git", "check-ignore", "--quiet", secret_path],
            cwd=ROOT,
            check=False,
        )
        assert result.returncode == 0, secret_path
