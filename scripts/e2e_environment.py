"""Safety boundary for destructive server E2E scripts."""

from __future__ import annotations

from dataclasses import dataclass
import os
import shlex
from urllib.parse import urlsplit


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class E2EEnvironment:
    server_url: str
    reset_mode: str
    ssh_host: str | None
    ssh_port: int
    ssh_user: str
    ssh_password: str | None
    db_container_name: str
    api_container_name: str

    @classmethod
    def from_environ(cls, environ: dict[str, str] | None = None) -> "E2EEnvironment":
        values = os.environ if environ is None else environ
        server_url = values.get("SEZAM_SERVER", "").rstrip("/")
        parsed = urlsplit(server_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("SEZAM_SERVER must explicitly name the isolated E2E server")
        if (parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in {"", "/"}):
            raise RuntimeError("SEZAM_SERVER must be a plain HTTP(S) origin")

        reset_mode = values.get("SEZAM_E2E_RESET_MODE", "fresh")
        if reset_mode not in {"fresh", "ssh"}:
            raise RuntimeError("SEZAM_E2E_RESET_MODE must be 'fresh' or 'ssh'")

        ssh_host = values.get("SEZAM_SSH_HOST")
        try:
            ssh_port = int(values.get("SEZAM_SSH_PORT", "22"))
        except ValueError as exc:
            raise RuntimeError("SEZAM_SSH_PORT must be an integer") from exc
        if not 1 <= ssh_port <= 65535:
            raise RuntimeError("SEZAM_SSH_PORT must be between 1 and 65535")
        db_container_name = values.get("SEZAM_DB_CONTAINER_NAME", "sezam-db")
        if not db_container_name:
            raise RuntimeError("SEZAM_DB_CONTAINER_NAME must not be empty")
        api_container_name = values.get("SEZAM_API_CONTAINER_NAME", "sezam-api")
        if not api_container_name:
            raise RuntimeError("SEZAM_API_CONTAINER_NAME must not be empty")
        if reset_mode == "fresh":
            if parsed.hostname not in _LOCAL_HOSTS:
                raise RuntimeError("fresh E2E mode is restricted to a loopback server")
        else:
            if not ssh_host:
                raise RuntimeError("SEZAM_SSH_HOST is required for remote DB reset")
            confirmation = f"{server_url}|{ssh_host}"
            if values.get("SEZAM_E2E_ALLOW_DESTRUCTIVE") != confirmation:
                raise RuntimeError(
                    "SEZAM_E2E_ALLOW_DESTRUCTIVE must confirm SEZAM_SERVER|SEZAM_SSH_HOST"
                )

        return cls(
            server_url=server_url,
            reset_mode=reset_mode,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_user=values.get("SEZAM_SSH_USER", "root"),
            ssh_password=values.get("SEZAM_SSH_PASSWORD"),
            db_container_name=db_container_name,
            api_container_name=api_container_name,
        )

    def database_reset_command(self) -> str:
        container = shlex.quote(self.db_container_name)
        return (
            f"docker exec -i {container} "
            "sh -c 'exec mariadb -usezam -p\"$MARIADB_PASSWORD\" sezam'"
        )

    def api_restart_command(self) -> str:
        return f"docker restart {shlex.quote(self.api_container_name)}"
