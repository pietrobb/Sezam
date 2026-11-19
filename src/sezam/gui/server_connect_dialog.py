"""Server connection dialog — connect an existing vault to a Sezam server.

Handles all scenarios:
1. Empty server (needs_setup) -> bootstrap as admin, push
2. Existing account -> Path B recovery, sync
3. No account -> invitation token, poll for approval
4. Unreachable server -> error message
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Optional

from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from .background import track as track_worker
from ..usernames import normalize_username
from .styles import COLORS

if TYPE_CHECKING:
    from ..vault.crud import Vault


def _http_request(
    server_url: str,
    method: str,
    path: str,
    body: Optional[dict] = None,
    token: Optional[str] = None,
) -> dict:
    """Make an HTTP request to the Sezam server. Returns parsed JSON."""
    url = server_url.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        from ..vault.sync_common import ServerError

        error_body = e.read().decode("utf-8", errors="replace")
        raise ServerError(e.code, error_body, show_detail=True)


def _with_pull_warnings(result: dict, message: str) -> str:
    """Put a pull's rollback/TOFU warnings in front of the success message."""
    from ..vault.sync_client import pull_warnings

    return "\n\n".join([*pull_warnings(result), message])


class ServerConnectWorker(QThread):
    """Background worker for server connection flow."""

    status_update = Signal(str)
    need_invitation = Signal()       # emitted when invitation token is needed
    need_account_password = Signal()  # password was changed on another device
    waiting_approval = Signal()      # emitted when waiting for admin approval
    finished_ok = Signal(str)        # emitted on success with message
    finished_error = Signal(str)     # emitted on error with message

    def __init__(
        self,
        server_url: str,
        vault: Vault,
        password: str,
        parent=None,
    ):
        super().__init__(parent)
        self._server_url = server_url.rstrip("/")
        self._vault = vault
        self._password = password
        self._invitation_token: Optional[str] = None
        self._account_password: Optional[str] = None
        self._stop_requested = False
        self._connect_snapshot = None

    def set_invitation_token(self, token: str) -> None:
        self._invitation_token = token

    def set_account_password(self, password: str) -> None:
        self._account_password = password

    def request_stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        try:
            self._do_connect()
        except Exception as e:
            self.finished_error.emit(str(e))

    def _do_connect(self) -> None:
        # The auth proof and account KEK come from this password; a typo
        # would bind the account to a password that opens nothing.
        self.status_update.emit("Overujem heslo...")
        if not self._vault.verify_password(self._password):
            self.finished_error.emit("Nespravne master heslo.")
            return

        # Step 1: Check bootstrap status
        self.status_update.emit("Kontrolujem server...")
        try:
            bootstrap_resp = _http_request(
                self._server_url, "GET", "/api/bootstrap-status"
            )
        except Exception:
            self.finished_error.emit("Server nie je dostupny.")
            return

        needs_setup = bootstrap_resp.get("needs_setup", False)

        from ..vault.snapshots import take_snapshot

        self._connect_snapshot = take_snapshot(self._vault.db, "server-connect")

        from ..vault.onboarding import (
            BootstrapKeyMaterialElsewhere,
            bootstrap_upload_pending,
            finish_bootstrap_upload,
        )

        if not needs_setup and bootstrap_upload_pending(self._vault, self._server_url):
            self.status_update.emit("Dokoncujem nahratie klucov z preruseneho bootstrapu...")
            try:
                result = finish_bootstrap_upload(self._vault, self._server_url, self._password)
            except BootstrapKeyMaterialElsewhere:
                self._handle_existing_server()
                return
            self.finished_ok.emit(self._with_org_recovery(
                f"Hotovo! Si administrator. Push: {len(result.get('accepted', []))} objektov."
            ))
            return

        if needs_setup:
            self._handle_bootstrap()
        else:
            self._handle_existing_server()

    def _handle_bootstrap(self) -> None:
        """Empty server — bootstrap as admin and push local data."""
        self.status_update.emit("Server je prazdny. Registrujem ako administrator...")

        kp = self._vault.keypair
        signing_pk_hex = kp.signing_pk.hex()
        encryption_pk_hex = kp.encryption_pk.hex()
        username = self._vault.db.get_meta("username") or "admin"

        # Bootstrap
        resp = _http_request(self._server_url, "POST", "/api/bootstrap", {
            "username": username,
            "signing_pk": signing_pk_hex,
            "encryption_pk": encryption_pk_hex,
        })

        onboarding_token = resp["token"]
        # encrypted_keypair is AAD-bound to user_id: re-wrap before upload.
        self._vault.rebind_server_identity(resp["user_id"])

        # The admin account now exists without key material; if the upload
        # fails, the next connect finishes it instead of getting stuck.
        from ..vault import pending_states

        self._vault.db.set_meta("server_url", self._server_url)
        pending_states.mark_bootstrap_upload_pending(self._vault.db, True)

        # Upload keypair
        self.status_update.emit("Nahravanie klucov na server...")
        self._upload_keypair(onboarding_token)
        pending_states.mark_bootstrap_upload_pending(self._vault.db, False)

        # Push local vault data
        self.status_update.emit("Synchronizujem data na server...")
        from ..vault.sync_client import SyncClient
        user_id = self._vault.db.get_meta("user_id")
        client = SyncClient(
            self._vault.db, self._server_url, self._vault.keypair, user_id
        )
        client.set_dek_manager(self._vault.dek_mgr)
        synced = False
        try:
            client.authenticate()
            result = client.push()
            accepted = len(result.get("accepted", []))
            self.status_update.emit(f"Push: {accepted} objektov.")
            synced = not result.get("conflicts")
        except RuntimeError as e:
            self.status_update.emit(f"Push: {e}")

        # Review 526419e #1: it said so with nothing on the server.
        self.finished_ok.emit(self._with_org_recovery(
            "Hotovo! Si administrator. Data boli synchronizovane." if synced else
            "Si administrator, ale nie vsetky data su na serveri. "
            "Synchronizacia sa skusi znova."
        ))

    def _with_org_recovery(self, message: str) -> str:
        """Org recovery set up before connecting reaches the server now
        (capability review run 91), or the user learns it did not."""
        from ..vault.sync_client import SyncClient

        note = SyncClient.org_recovery_after_connect(self._vault, self._password)
        return f"{message}\n\n{note}" if note else message

    def _handle_existing_server(self) -> None:
        """Server already has users — try recovery, then invitation."""
        username = self._vault.db.get_meta("username") or "admin"
        self.status_update.emit(f"Skusam pripojenie ako '{username}'...")

        # Try Path B recovery
        recovered = False
        try:
            meta_resp = _http_request(
                self._server_url, "GET", f"/api/meta?username={username}"
            )
            if meta_resp and meta_resp.get("argon2_salt"):
                self.status_update.emit("Ucet najdeny. Overujem heslo...")
                from ..vault.crud import (
                    open_server_keypair,
                    recover_refusal,
                    recover_with_password,
                    server_account_kdf,
                )
                argon2_salt = bytes.fromhex(meta_resp["argon2_salt"])
                ap = server_account_kdf(meta_resp, self._vault.db)

                try:
                    _kek, recover_resp = recover_with_password(
                        lambda body: _http_request(
                            self._server_url, "POST", "/api/auth/recover", body=body
                        ),
                        username, self._password, argon2_salt, ap,
                    )
                    try:
                        # /recover returns the account keypair (no token).

                        server_keypair = open_server_keypair(recover_resp or {}, _kek)
                        if server_keypair is not None:
                            self._vault.adopt_account_kek(
                                _kek, argon2_salt, ap,
                                key_epoch=int((recover_resp or {}).get("key_epoch") or 0),
                                connect_snapshot=self._connect_snapshot,
                            )
                    finally:
                        _kek[:] = b"\x00" * len(_kek)
                    if server_keypair is not None:
                        self._vault.rebind_server_identity(
                            recover_resp.get("user_id", ""), server_keypair
                        )
                        self._vault.db.set_meta("server_url", self._server_url)

                        self.status_update.emit("Stiahnutie dat zo servera...")
                        from ..vault.sync_client import SyncClient
                        user_id = self._vault.db.get_meta("user_id")
                        client = SyncClient(
                            self._vault.db,
                            self._server_url,
                            self._vault.keypair,
                            user_id,
                        )
                        client.set_dek_manager(self._vault.dek_mgr)

                        try:
                            client.authenticate()
                            result = client.pull()
                            self.status_update.emit(
                                f"Pull: {result['pulled']} objektov."
                            )
                        except RuntimeError as e:
                            result = {}
                            self.status_update.emit(f"Sync: {e}")

                        self.finished_ok.emit(self._with_org_recovery(
                            _with_pull_warnings(result, "Pripojeny k serveru.")
                        ))
                        recovered = True
                except RuntimeError as exc:
                    refusal = recover_refusal(exc)
                    if refusal is not None:
                        # The account exists; an invitation would make a second one.
                        self.finished_error.emit(refusal)
                        return
        except RuntimeError:
            pass

        if recovered:
            return
        if self._resync_after_remote_password_change():
            return

        # No account — need invitation token
        self.status_update.emit("Na tomto serveri nemas ucet.")
        self.need_invitation.emit()

        # Wait for invitation token to be set
        while self._invitation_token is None and not self._stop_requested:
            time.sleep(0.2)

        if self._stop_requested:
            self.finished_error.emit("Zrusene pouzivatelom.")
            return

        # Register with invitation token
        self.status_update.emit("Registrujem sa na serveri...")
        kp = self._vault.keypair
        signing_pk_hex = kp.signing_pk.hex()
        encryption_pk_hex = kp.encryption_pk.hex()
        username = self._vault.db.get_meta("username") or "user"

        try:
            resp = _http_request(
                self._server_url, "POST", "/api/users/register", {
                    "invitation_token": self._invitation_token,
                    "username": username,
                    "signing_pk": signing_pk_hex,
                    "encryption_pk": encryption_pk_hex,
                },
            )
        except RuntimeError as e:
            self.finished_error.emit(f"Registracia zlyhala: {e}")
            return

        onboarding_token = resp["token"]
        self._vault.rebind_server_identity(resp["user_id"])

        # Upload keypair
        self.status_update.emit("Nahravanie klucov...")
        self._upload_keypair(onboarding_token)
        self._vault.db.set_meta("server_url", self._server_url)

        # Poll for admin approval
        self.status_update.emit("Cakam na schvalenie administratorom...")
        self.waiting_approval.emit()

        from ..vault.sync_client import SyncClient

        while not self._stop_requested:
            time.sleep(5)
            try:
                user_id = self._vault.db.get_meta("user_id")
                client = SyncClient(
                    self._vault.db,
                    self._server_url,
                    self._vault.keypair,
                    user_id,
                )
                client.set_dek_manager(self._vault.dek_mgr)
                client.authenticate()

                # If authenticate succeeds, user is approved
                self.status_update.emit("Schvaleny! Stahujem data...")
                result = client.pull()
                self.finished_ok.emit(_with_pull_warnings(
                    result,
                    f"Schvaleny! Data synchronizovane ({result['pulled']} objektov).",
                ))
                return
            except RuntimeError as e:
                from ..vault.sync_common import server_error

                if server_error(e, 401) or server_error(e, 403):
                    continue
                self.status_update.emit(f"Chyba: {e}")
                continue

        self.finished_error.emit("Zrusene pouzivatelom.")

    def _resync_after_remote_password_change(self) -> bool:
        """A vault already bound to this account whose password changed elsewhere.

        The local password (verified above) no longer opens the account on
        the server, so recovery failed. The device keypair still signs in;
        if the server reports a newer key epoch, ask for the current account
        password and take the rotation over (review 2052248 #1).
        """
        vault = self._vault
        if vault.db.get_meta("server_url") != self._server_url or not vault.db.get_meta(
            "user_id"
        ):
            return False
        from ..vault.sync_client import KeyEpochStale, SyncClient

        client = SyncClient(
            vault.db, self._server_url, vault.keypair, vault.db.get_meta("user_id")
        )
        client.set_dek_manager(vault.dek_mgr)
        try:
            client.authenticate()
            result = client.pull()
        except KeyEpochStale:
            self.status_update.emit(
                "Heslo uctu bolo zmenene na inom zariadeni. Zadaj aktualne heslo uctu."
            )
            self.need_account_password.emit()
            while self._account_password is None and not self._stop_requested:
                time.sleep(0.2)
            password, self._account_password = self._account_password, None
            if self._stop_requested or not password:
                self.finished_error.emit("Zrusene pouzivatelom.")
                return True
            try:
                client.adopt_rotated_key_material(vault, password)
                result = client.pull()
            except RuntimeError as e:
                self.finished_error.emit(f"Prevzatie noveho hesla zlyhalo: {e}")
                return True
            self.finished_ok.emit(_with_pull_warnings(
                result,
                "Prevzate nove heslo uctu; trezor sa odteraz odomyka nim. "
                f"Pull: {result['pulled']} objektov.",
            ))
            return True
        except RuntimeError:
            return False
        self.finished_ok.emit(_with_pull_warnings(
            result, f"Pripojeny k serveru. Pull: {result['pulled']} objektov."
        ))
        return True

    def _upload_keypair(self, onboarding_token: str) -> None:
        """Upload encrypted keypair to server."""
        from ..vault.onboarding import keypair_upload_body

        _http_request(
            self._server_url, "PUT", "/api/me/keypair",
            keypair_upload_body(self._vault, self._password),
            token=onboarding_token,
        )


class ServerConnectDialog(QDialog):
    """Dialog for connecting an existing vault to a Sezam server."""

    def __init__(self, vault: Vault, password: str = "", parent=None):
        super().__init__(parent)
        self._vault = vault
        self._password = password
        self._worker: Optional[ServerConnectWorker] = None

        self.setWindowTitle("Pripojenie k serveru")
        self.setMinimumSize(500, 400)
        self.resize(500, 500)

        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(6)

        # Title
        title = QLabel("Pripojit k serveru")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setStyleSheet(f"color: {COLORS['accent']};")
        layout.addWidget(title)

        # Server URL input
        url_label = QLabel("URL servera:")
        url_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        layout.addWidget(url_label)

        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("https://sezam.firma.sk")
        # Pre-fill from vault_meta if already set
        existing_url = self._vault.db.get_meta("server_url") or ""
        if existing_url:
            self._url_input.setText(existing_url)
        layout.addWidget(self._url_input)

        # Username input
        user_label = QLabel("Pouzivatelske meno:")
        user_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        layout.addWidget(user_label)

        self._username_input = QLineEdit()
        existing_username = self._vault.db.get_meta("username") or "admin"
        self._username_input.setText(existing_username)
        layout.addWidget(self._username_input)

        # Password input (needed for server auth_proof)
        if not self._password:
            pw_label = QLabel("Master heslo:")
            pw_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
            layout.addWidget(pw_label)

            self._password_input = QLineEdit()
            self._password_input.setEchoMode(QLineEdit.Password)
            self._password_input.setPlaceholderText("Heslo pre autentifikaciu na server")
            layout.addWidget(self._password_input)
        else:
            self._password_input = None

        # Invitation token input (hidden initially)
        self._token_label = QLabel("Invitation token (od admina):")
        self._token_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self._token_label.hide()
        layout.addWidget(self._token_label)

        self._token_input = QLineEdit()
        self._token_input.setPlaceholderText("Zadaj invitation token...")
        self._token_input.hide()
        layout.addWidget(self._token_input)

        self._token_submit_btn = QPushButton("Odoslat token")
        self._token_submit_btn.setProperty("cssClass", "accent")
        self._token_submit_btn.hide()
        self._token_submit_btn.clicked.connect(self._on_token_submitted)
        layout.addWidget(self._token_submit_btn)

        # Status label
        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)
        self._status_label.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 12px; padding: 8px 0;"
        )
        layout.addWidget(self._status_label)

        layout.addStretch()

        # Buttons row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self._connect_btn = QPushButton("Pripojit")
        self._connect_btn.setProperty("cssClass", "accent")
        self._connect_btn.setFixedWidth(120)
        self._connect_btn.clicked.connect(self._on_connect)
        btn_row.addWidget(self._connect_btn)

        self._cancel_btn = QPushButton("Zrusit")
        self._cancel_btn.setFixedWidth(100)
        self._cancel_btn.clicked.connect(self._on_cancel)
        btn_row.addWidget(self._cancel_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    @Slot()
    def _on_connect(self) -> None:
        server_url = self._url_input.text().strip()
        if not server_url:
            self._status_label.setText("Zadaj URL servera.")
            self._status_label.setStyleSheet(
                f"color: {COLORS['error']}; font-size: 12px; padding: 8px 0;"
            )
            return

        # Get password from input if not provided
        if not self._password and self._password_input:
            self._password = self._password_input.text()
        if not self._password:
            self._status_label.setText("Zadaj master heslo.")
            self._status_label.setStyleSheet(
                f"color: {COLORS['error']}; font-size: 12px; padding: 8px 0;"
            )
            return

        # Update username in vault_meta
        username = normalize_username(self._username_input.text())
        if username:
            self._vault.db.set_meta("username", username)

        # Disable inputs during connection
        self._url_input.setEnabled(False)
        self._username_input.setEnabled(False)
        if self._password_input:
            self._password_input.setEnabled(False)
        self._connect_btn.setEnabled(False)

        self._status_label.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 12px; padding: 8px 0;"
        )

        # Start background worker
        self._worker = ServerConnectWorker(
            server_url, self._vault, self._password, self
        )
        self._worker.status_update.connect(self._on_status_update)
        self._worker.need_invitation.connect(self._on_need_invitation)
        self._worker.need_account_password.connect(self._on_need_account_password)
        self._worker.waiting_approval.connect(self._on_waiting_approval)
        self._worker.finished_ok.connect(self._on_finished_ok)
        self._worker.finished_error.connect(self._on_finished_error)
        self._worker.start()
        track_worker(self._worker)

    @Slot(str)
    def _on_status_update(self, msg: str) -> None:
        self._status_label.setText(msg)

    @Slot()
    def _on_need_account_password(self) -> None:
        password, ok = QInputDialog.getText(
            self,
            "Heslo bolo zmenene",
            "Heslo uctu bolo zmenene na inom zariadeni.\n"
            "Zadaj aktualne heslo uctu (tento trezor sa potom odomyka nim):",
            QLineEdit.Password,
        )
        if self._worker is not None:
            self._worker.set_account_password(password if ok else "")

    @Slot()
    def _on_need_invitation(self) -> None:
        """Show invitation token input."""
        self._token_label.show()
        self._token_input.show()
        self._token_submit_btn.show()
        self._token_input.setFocus()

    @Slot()
    def _on_token_submitted(self) -> None:
        token = self._token_input.text().strip()
        if not token:
            self._status_label.setText("Zadaj invitation token.")
            self._status_label.setStyleSheet(
                f"color: {COLORS['error']}; font-size: 12px; padding: 8px 0;"
            )
            return
        if self._worker:
            self._worker.set_invitation_token(token)
        self._token_input.setEnabled(False)
        self._token_submit_btn.setEnabled(False)

    @Slot()
    def _on_waiting_approval(self) -> None:
        self._status_label.setText("Cakam na schvalenie administratorom...")
        self._status_label.setStyleSheet(
            f"color: {COLORS['warning']}; font-size: 12px; padding: 8px 0;"
        )

    @Slot(str)
    def _on_finished_ok(self, msg: str) -> None:
        self._status_label.setText(msg)
        self._status_label.setStyleSheet(
            f"color: {COLORS['success']}; font-size: 12px; padding: 8px 0;"
        )
        self._connect_btn.setText("Hotovo")
        self._connect_btn.setEnabled(True)
        self._connect_btn.clicked.disconnect()
        self._connect_btn.clicked.connect(self.accept)
        self._cancel_btn.hide()

    @Slot(str)
    def _on_finished_error(self, msg: str) -> None:
        self._status_label.setText(msg)
        self._status_label.setStyleSheet(
            f"color: {COLORS['error']}; font-size: 12px; padding: 8px 0;"
        )
        # Re-enable inputs for retry
        self._url_input.setEnabled(True)
        self._username_input.setEnabled(True)
        if self._password_input:
            self._password_input.setEnabled(True)
        self._password = ""  # Clear so user can re-enter
        self._connect_btn.setEnabled(True)
        self._connect_btn.setText("Pripojit")

    @Slot()
    def _on_cancel(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.request_stop()
            self._worker.wait(3000)
        self.reject()

    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.request_stop()
            self._worker.wait(3000)
        super().closeEvent(event)
