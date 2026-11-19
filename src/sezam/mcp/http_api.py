"""HTTP/API requests for the AI broker (AI broker TODO, section 9).

For hosting and CMS APIs (application passwords, API tokens). The entry
describes the one API the agent may call:

* ``base_url`` - ``https://host[:port][/base/path]``. ``http://`` only with
  ``allow_plain_http: true``; every result then warns that the credential
  crossed the network unencrypted.
* ``auth_header`` - template such as ``Authorization: Bearer {token}``.
  ``{field}`` is the value of that entry field; ``{basic}`` is
  ``base64(username:password)`` for HTTP Basic. The broker inserts the
  header; the agent never sees it.
* ``allowed_methods`` - default ``GET``.
* ``allowed_path_prefixes`` - required (default deny), relative to the
  base path, matched on whole path segments.
* ``allowed_params`` - optional: the only query and form/multipart body
  parameter names allowed. Names are read as PHP reads them; ``rest_route``
  and method overrides are always refused; front-controller routing names
  (``q``, ``route``, ``r``, ``s``, ``c``, ``m``, ``a``, ``option``, ``task``,
  ``controller``, ``module``, ``action``, ``p``, ``page_id``, ``url``,
  ``eID``, ``fc``, ``cl``, ``fnc``, ``d``, ``do``, ``ctl``, ``act``,
  ``view``) and names starting with ``_`` unless listed here.
* ``path_routing_only`` - ``true`` for an API that routes by path alone
  (not through a front controller): the front-controller names above are
  then ordinary parameters. ``rest_route``, method overrides and ``_``-names
  stay refused.
* ``tls_ca_cert`` - optional PEM trusted instead of the system store.

The request goes to exactly the base URL's host and port. Redirects are
never followed (a 3xx comes back with its status and ``Location``), no
environment proxy is used, the body sent and received is size limited and
the whole call has a deadline. Only a fixed set of response headers is
returned (never ``Set-Cookie``), and the entry's secrets - including every
value the auth header uses - are redacted from body and headers. Errors are
``SSHBrokerError`` so the broker reports them like the SSH and FTP tools.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
import socket
import ssl
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import unquote_to_bytes, urlsplit

from .redact import Redactor, entry_secrets
from .ssh import SSHBrokerError, _first, _normalise_key

DEFAULT_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
# Request headers the agent may set; everything else (Host, Cookie, the
# auth header, hop-by-hop headers) belongs to the broker.
AGENT_HEADERS = {
    "accept": "Accept",
    "content-type": "Content-Type",
    "if-match": "If-Match",
    "if-none-match": "If-None-Match",
}
RESPONSE_HEADERS = (
    "Content-Type", "Content-Length", "Location", "ETag", "Last-Modified",
    "Retry-After", "Link", "X-WP-Total", "X-WP-TotalPages",
)
PLAIN_HTTP_WARNING = (
    "Plain HTTP (allow_plain_http): the credential and all data crossed the "
    "network unencrypted."
)
_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"", "false", "0", "no", "off"}
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
# Path and query: RFC 3986 characters without '#', '\\' and spaces.
_PATH_CHARS = re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@/%?]*$")
# '%25' too (review a159e97): '%252e' is '%2e' to a server that decodes twice.
_ENCODED_SEPARATOR = re.compile(r"%(2e|2f|5c|00|25)", re.IGNORECASE)
_PARAM_NAME = re.compile(r"^[a-z0-9_\-]+$")


def _clean(value: str) -> bool:
    return not any(c in value for c in "\r\n\x00")


def _split_list(value: str) -> list[str]:
    return [item for item in re.split(r"[\s,]+", value.strip()) if item]


def _check_path(path: str, what: str) -> str:
    """A normalised absolute path (no query): no dot segments, no empty
    segments, nothing percent-encoded that could be one."""
    if not path.startswith("/") or not _PATH_CHARS.match(path) or "?" in path:
        raise SSHBrokerError("invalid_path", f"{what} must be an absolute path without '#', '\\\\' or spaces.")
    if _ENCODED_SEPARATOR.search(path):
        raise SSHBrokerError("invalid_path", f"{what} must not percent-encode '.', '/', '\\\\', '%' or NUL.")
    segments = path.split("/")[1:]
    if any(s in (".", "..") for s in segments) or "" in segments[:-1]:
        raise SSHBrokerError("invalid_path", f"{what} must not contain '.', '..' or '//'.")
    return path


def _within(path: str, prefix: str) -> bool:
    base = prefix.rstrip("/")
    return base == "" or path == base or path.startswith(base + "/")


@dataclass(frozen=True)
class HTTPTarget:
    scheme: str
    host: str
    port: int
    base_path: str
    methods: tuple[str, ...]
    prefixes: tuple[str, ...]
    header_name: Optional[str] = None
    header_value: Optional[str] = field(default=None, repr=False)
    ca_pem: Optional[str] = field(default=None, repr=False)
    secrets: tuple[bytes, ...] = field(default=(), repr=False)
    # allowed_params: the only query/form parameter names (case-folded), or None.
    params: Optional[frozenset[str]] = None
    # path_routing_only: the API routes by path, front-controller names are ordinary.
    path_routing_only: bool = False

    def __repr__(self) -> str:  # never the credential
        return f"HTTPTarget({self.scheme}://{self.host}:{self.port}{self.base_path})"

    @property
    def encrypted(self) -> bool:
        return self.scheme == "https"

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}"

    @classmethod
    def from_entry(cls, entry: dict) -> "HTTPTarget":
        raw = {
            _normalise_key(f["key"]): str(f.get("value", "")) for f in entry.get("fields", [])
        }
        base_url = _first(raw, "base_url", "url", "api_url")
        if not base_url:
            raise SSHBrokerError("invalid_entry", "HTTP entry must contain a base_url field.")
        if not _clean(base_url) or any(c.isspace() for c in base_url):
            raise SSHBrokerError("invalid_entry", "base_url is invalid.")
        parts = urlsplit(base_url)
        scheme = parts.scheme.lower()
        plain = raw.get("allow_plain_http", "").strip().lower()
        if plain not in _TRUE | _FALSE:
            raise SSHBrokerError("invalid_entry", "allow_plain_http must be true or false.")
        if scheme == "http" and plain not in _TRUE:
            raise SSHBrokerError(
                "invalid_entry", "base_url must be https://; plain http needs allow_plain_http."
            )
        if scheme not in ("http", "https"):
            raise SSHBrokerError("invalid_entry", "base_url must be an https:// URL.")
        if parts.username or parts.password or parts.query or parts.fragment or not parts.hostname:
            raise SSHBrokerError(
                "invalid_entry", "base_url must be scheme://host[:port][/path] without credentials or query."
            )
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise SSHBrokerError("invalid_entry", "base_url port is invalid.") from exc
        base_path = (parts.path or "").rstrip("/")
        if base_path:
            _check_path(base_path, "base_url path")

        methods_text = raw.get("allowed_methods", "").strip() or "GET"
        methods = tuple(dict.fromkeys(m.upper() for m in _split_list(methods_text)))
        if not methods or any(m not in METHODS for m in methods):
            raise SSHBrokerError(
                "invalid_entry", f"allowed_methods may only list {', '.join(METHODS)}."
            )
        prefixes_text = raw.get("allowed_path_prefixes", "").strip()
        if not prefixes_text:
            raise SSHBrokerError(
                "invalid_entry", "HTTP entry must list allowed_path_prefixes (use / to allow all)."
            )
        prefixes = tuple(_check_path(p, "allowed_path_prefixes") for p in _split_list(prefixes_text))
        params_text = raw.get("allowed_params", "").strip()
        params = None
        if params_text:
            params = frozenset(p.lower() for p in _split_list(params_text))
            if not all(_PARAM_NAME.match(p) for p in params):
                raise SSHBrokerError(
                    "invalid_entry", "allowed_params may only list names of letters, digits, '_' and '-'."
                )

        path_only = raw.get("path_routing_only", "").strip().lower()
        if path_only not in _TRUE | _FALSE:
            raise SSHBrokerError("invalid_entry", "path_routing_only must be true or false.")

        header_name = header_value = None
        used: list[str] = []
        template = raw.get("auth_header", "").strip()
        if template:
            name, sep, value_template = template.partition(":")
            name = name.strip()
            if not sep or not _TOKEN.match(name):
                raise SSHBrokerError("invalid_entry", "auth_header must look like 'Name: value {field}'.")
            if name.lower() in ("host", "content-length", "transfer-encoding", "connection"):
                raise SSHBrokerError("invalid_entry", f"auth_header cannot set {name}.")

            def fill(match: re.Match) -> str:
                key = _normalise_key(match.group(1))
                if key == "basic":
                    user = _first(raw, "username", "user", "login")
                    password = _first(raw, "password", "application_password", "app_password")
                    if not user or not password:
                        raise SSHBrokerError(
                            "invalid_entry", "{basic} needs username and password fields."
                        )
                    encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
                    used.extend([password, encoded])
                    return encoded
                if not raw.get(key):
                    raise SSHBrokerError(
                        "invalid_entry", f"auth_header uses {{{match.group(1)}}}, which the entry lacks."
                    )
                used.append(raw[key])
                return raw[key]

            header_value = _PLACEHOLDER.sub(fill, value_template).strip()
            if not header_value or not _clean(header_value):
                raise SSHBrokerError("invalid_entry", "auth_header value is empty or has a line break.")
            header_name = name
        secrets = entry_secrets(entry) + [v.encode("utf-8") for v in used]
        if header_value:
            secrets.append(header_value.encode("utf-8"))
        if scheme == "https":
            ca_pem = _first(raw, "tls_ca_cert", "https_ca_cert")
        else:
            ca_pem = None
        return cls(
            scheme, parts.hostname, port, base_path, methods, prefixes,
            header_name, header_value, ca_pem, tuple(secrets), params, path_only in _TRUE,
        )

    def check(self, method: str, path: str) -> tuple[str, str]:
        """(METHOD, path-with-query relative to the host) or SSHBrokerError."""
        method = (method or "").upper()
        if method not in self.methods:
            raise SSHBrokerError(
                "method_denied", f"Method {method or '?'} is not allowed for this entry."
            )
        if not isinstance(path, str) or not path:
            raise SSHBrokerError("invalid_path", "path is required.")
        bare, sep, query = path.partition("?")
        _check_path(bare, "path")
        if _PATH_PARAMETER.search(bare):
            # '/allowed/..;/admin': Tomcat/Spring drop ';…' and walk up.
            raise SSHBrokerError("invalid_path", "path must not contain ';' (path parameters).")
        if not _PATH_CHARS.match(query):
            raise SSHBrokerError("invalid_path", "query contains characters that are not allowed.")
        if not any(_within(bare, prefix) for prefix in self.prefixes):
            raise SSHBrokerError("path_denied", "path is outside the entry's allowed_path_prefixes.")
        if query:
            self._check_names(_form_names(query), "query parameter", listed=True)
        return method, self.base_path + bare + (sep + query if sep else "")

    def check_body(self, body: Optional[str], headers: Optional[dict] = None) -> None:
        """The body's parameter names under the same rules as the query's:
        a form or multipart body against allowed_params too, a JSON body's
        keys against the refused names only. ``_method`` is refused in any
        encoding (Laravel, Rails, Symfony read it from the body)."""
        if not body:
            return
        if _BODY_OVERRIDE.search(body):
            raise SSHBrokerError("method_denied", "_method in the body would override the HTTP method.")
        content_type = declared = ""
        for name, value in (headers or {}).items():
            if str(name).strip().lower() == "content-type" and isinstance(value, str):
                declared = value.strip().lower()
                # As PHP's SAPI reads it: cut at the first ';', ',' or space.
                content_type = re.split(r"[;, ]", declared, maxsplit=1)[0]
        # Review 7c10379 (R7-H): Laravel reads a body as JSON when its type
        # merely contains '/json' or '+json' ('text/json', 'text/plain;
        # x=/json'), and the override regex misses '"_m\u0065thod"'. Such a
        # body was checked as a form and DELETE went through an allowed POST.
        # The keys of any JSON-typed body or JSON object body are decoded,
        # besides the check for the type PHP reads.
        if "json" in declared or _is_json_object(body):
            self._check_names(_json_keys(body), "body key", listed=False)
        if content_type == "application/json" or content_type.endswith("+json"):
            return
        if content_type == "multipart/form-data":
            self._check_names(_multipart_names(body), "body field", listed=True)
        else:
            # Form encoded, or no type (some frameworks parse it as a form).
            self._check_names(
                _form_names(body), "body field", listed=content_type == "application/x-www-form-urlencoded"
            )

    def _check_names(self, raw_names, what: str, *, listed: bool) -> None:
        """Every name as PHP may read it: routing and override names refused,
        '_'-names unless the entry lists them, and - where the entry has
        allowed_params and ``listed`` - only the names it lists."""
        for raw, names in raw_names:
            for name in names:
                if name in _ROUTING_PARAMS:
                    raise SSHBrokerError(
                        "path_denied", f"{what} {raw!r} would route around allowed_path_prefixes."
                    )
                if name in _OVERRIDE_PARAMS:
                    raise SSHBrokerError("method_denied", f"{what} {raw!r} would override the HTTP method.")
                listed_here = self.params is not None and name in self.params
                if name in _LISTABLE_ROUTING_PARAMS and not (listed_here or self.path_routing_only):
                    raise SSHBrokerError(
                        "path_denied",
                        f"{what} {raw!r} may route around allowed_path_prefixes; "
                        "list it in allowed_params.",
                    )
                if name.startswith("_") and not listed_here:
                    raise SSHBrokerError(
                        "param_denied", f"{what} {raw!r} starts with '_'; list it in allowed_params."
                    )
                if listed and self.params is not None and not listed_here:
                    raise SSHBrokerError("param_denied", f"{what} {raw!r} is not in allowed_params.")


# Review d615826: the method and the path prefix were enforced on the URL
# only. WordPress routes '?rest_route=/wp/v2/users' to any endpoint, and
# '_method=DELETE' (query, or form/JSON body elsewhere) turns an allowed
# POST into another method. PHP reads 'rest.route', 'rest route' and
# 'rest[route' as 'rest_route', so names are compared the way PHP sees them.
_ROUTING_PARAMS = {"rest_route"}
# Review a159e97: only 'rest_route' was refused. Front controllers route by
# these too (Drupal 7 q, OpenCart route, Yii r, ThinkPHP s/m/c/a, CodeIgniter
# c/m, Joomla option/task, PrestaShop controller, Zend module/action); refused
# unless the entry lists the name in allowed_params.
_LISTABLE_ROUTING_PARAMS = {
    "q", "route", "r", "s", "c", "m", "a", "option", "task", "controller",
    "module", "action",
    # Review 1141a20 M-AI2: Craft/WordPress p and page_id, SilverStripe url,
    # TYPO3 eID, PrestaShop fc, OXID cl/fnc, CodeIgniter d, DokuWiki do,
    # ctl/act dispatchers, Joomla view. An entry for an API that routes by
    # path only says so (path_routing_only) instead.
    "p", "page_id", "url", "eid", "fc", "cl", "fnc", "d", "do", "ctl", "act", "view",
}
_OVERRIDE_PARAMS = {"_method", "x-http-method-override", "x_http_method_override"}
_PATH_PARAMETER = re.compile(r";|%3b", re.IGNORECASE)
# '_method' as a name: form field (raw or percent-encoded, PHP strips leading
# blanks), JSON key, multipart part. 'payment_method' is not one.
_BODY_OVERRIDE = re.compile(
    r"(?:^|&)[ +]*(?:_|%5f)method(?:\[|%5b|=|$)"
    r'|"(?:_|\\u005f)method"\s*:'
    r"|name\s*=\s*[\"']?(?:_|%5f)method\b",
    re.IGNORECASE | re.MULTILINE,
)


# Review 7c10379 H5: names were compared after a plain unquote, so
# '+_method' ('__method' here, '_method' to PHP), 'rest_route%00x' (PHP cuts
# at NUL) and 'rest_route' in a form body went through.
def _php_names(name: str) -> set[str]:
    """The (case-folded) names PHP 7 and 8 may give a decoded field name:
    cut at NUL, leading spaces dropped, ' ' and '.' read as '_', a '[' with a
    later ']' starting an array index, an unmatched '[' read as '_' (PHP 8
    goes on converting after it, PHP 7 keeps the rest as it is)."""
    raw = name.split("\x00", 1)[0].lstrip(" ").lower()
    if not raw:
        return set()
    names = set()
    for php7 in (False, True):
        out = []
        for i, ch in enumerate(raw):
            if ch in " .":
                out.append("_")
            elif ch == "[":
                if "]" in raw[i + 1:]:
                    break
                out.append("_")
                if php7:
                    out.append(raw[i + 1:])
                    break
            else:
                out.append(ch)
        names.add("".join(out))
    return names


def _form_names(text: str) -> list[tuple[str, set[str]]]:
    """Each field of a query or form body: (as sent, PHP names). Split at
    '&' and also ';' (Rack splits there), percent-decoded byte for byte as
    PHP does ('+' is a space)."""
    fields = []
    for pair in re.split(r"[&;]", text):
        sent = pair.partition("=")[0]
        decoded = unquote_to_bytes(sent.replace("+", " ")).decode("latin-1")
        fields.append((sent, _php_names(decoded)))
    return fields


_MULTIPART_NAME = re.compile(r"""\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;]+))""", re.IGNORECASE)


def _multipart_names(body: str) -> list[tuple[str, set[str]]]:
    return [
        (sent, _php_names(sent))
        for sent in (next(g for g in m.groups() if g is not None) for m in _MULTIPART_NAME.finditer(body))
    ]


_JSON_KEY = re.compile(r'"((?:[^"\\]|\\.)*)"\s*:')


def _is_json_object(body: str) -> bool:
    try:
        return isinstance(json.loads(body), dict)
    except (ValueError, RecursionError):
        return False


def _json_keys(body: str) -> list[tuple[str, set[str]]]:
    """The top-level keys of a JSON object body (what a framework reads as
    parameters); every key-like string if it does not parse."""
    try:
        parsed = json.loads(body)
    except (ValueError, RecursionError):
        keys = []
        for m in _JSON_KEY.finditer(body):
            try:
                keys.append(json.loads('"' + m.group(1) + '"'))
            except ValueError:
                keys.append(m.group(1))
    else:
        keys = list(parsed) if isinstance(parsed, dict) else []
    return [(key, _php_names(key)) for key in keys]


def _tls_context(ca_pem: Optional[str]) -> ssl.SSLContext:
    try:
        context = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    except (ssl.SSLError, ValueError) as exc:
        raise SSHBrokerError("invalid_entry", "tls_ca_cert is not a valid PEM certificate.") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _cut(conn, flag: str) -> None:
    """Mark the connection and break whatever read or write it is blocked in."""
    setattr(conn, flag, True)  # before reading conn.sock: see _connect
    sock = getattr(conn, "sock", None)
    if sock is not None:
        # shutdown() wakes a blocked recv on Linux; on Windows only
        # closing the handle does, and the response's makefile()
        # reference would defer a plain close(), so detach first.
        with suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        with suppress(OSError, ValueError):
            fd = sock.detach()
            if fd >= 0:
                socket.close(fd)
    with suppress(Exception):
        conn.close()


def _left(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("HTTP request exceeded its deadline.")
    return left


class _HTTPSConnection(http.client.HTTPSConnection):
    """The TLS handshake gets only what is left of the call's deadline."""

    sezam_deadline = float("inf")

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock.settimeout(min(self.timeout, _left(self.sezam_deadline)))
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        self.sock.settimeout(self.timeout)


class HTTPManager:
    """HTTP(S) requests for the MCP broker. A fresh connection per call."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_request_bytes: int = MAX_REQUEST_BYTES,
    ):
        self._timeout = timeout
        self._max_response = max_response_bytes
        self._max_request = max_request_bytes
        self._lock = threading.Lock()
        self._open: set = set()
        # The broker's kill switch, read once the connection stands: a cut
        # that came while connecting found no socket, one before the
        # connection was registered found nothing (review 7c10379).
        self.cut_check: Optional[Callable[[], bool]] = None

    def close_all(self) -> None:
        """Kill switch: cut every request still running."""
        with self._lock:
            connections = list(self._open)
        for conn in connections:
            _cut(conn, "sezam_cut_off")

    def active_count(self) -> int:
        with self._lock:
            return len(self._open)

    def request(
        self,
        entry: dict,
        method: str,
        path: str,
        *,
        body: Optional[str] = None,
        headers: Optional[dict] = None,
    ) -> dict:
        target = HTTPTarget.from_entry(entry)
        method, url_path = target.check(method, path)
        send_headers = self._agent_headers(headers)
        target.check_body(body, send_headers)
        payload = None
        if body is not None:
            if not isinstance(body, str):
                raise SSHBrokerError("invalid_request", "body must be a string.")
            payload = body.encode("utf-8")
            if len(payload) > self._max_request:
                raise SSHBrokerError("request_too_large", "Request body exceeds the size limit.")
        if target.header_name:
            send_headers[target.header_name] = target.header_value
        redactor = Redactor(target.secrets)

        if target.encrypted:
            conn = _HTTPSConnection(
                target.host, target.port, timeout=self._timeout,
                context=_tls_context(target.ca_pem),
            )
        else:
            conn = http.client.HTTPConnection(target.host, target.port, timeout=self._timeout)
        deadline = time.monotonic() + self._timeout
        conn.sezam_deadline = deadline
        # The socket timeout bounds each recv; a server trickling bytes
        # (headers, chunk-size lines) never trips it. The timer bounds the call.
        timer = threading.Timer(self._timeout, _cut, (conn, "sezam_timed_out"))
        timer.daemon = True
        with self._lock:
            self._open.add(conn)
        try:
            try:
                timer.start()
                conn.connect()
                # The timer may have fired while conn.sock did not exist yet.
                if getattr(conn, "sezam_timed_out", False):
                    raise TimeoutError("HTTP request exceeded its deadline.")
                if getattr(conn, "sezam_cut_off", False) or (self.cut_check is not None and self.cut_check()):
                    conn.sezam_cut_off = True
                    raise self._error(conn, ConnectionAbortedError())
                conn.request(method, url_path, body=payload, headers=send_headers)
                response = conn.getresponse()
                data, truncated = self._read(response, deadline)
                if getattr(conn, "sezam_cut_off", False) or getattr(conn, "sezam_timed_out", False):
                    raise self._error(conn, TimeoutError())
                if not truncated and response.length:
                    # EOF before Content-Length: a cut, not a complete body.
                    raise SSHBrokerError("connection_failed", "HTTP response ended early.")
            except SSHBrokerError:
                raise
            except BaseException as exc:
                raise self._error(conn, exc) from exc
        finally:
            timer.cancel()
            send_headers.pop(target.header_name or "", None)
            with self._lock:
                self._open.discard(conn)
            with suppress(Exception):
                conn.close()

        def wire(text: str) -> str:
            # Review 1141a20 M-AI1: http.client decodes the status line and the
            # headers as latin-1; back to the bytes the server sent before
            # redacting, or a non-ASCII secret no longer matches.
            return redactor.redact(text.encode("latin-1", "replace")).decode("utf-8", "replace")

        out_headers = {}
        for name in RESPONSE_HEADERS:
            value = response.getheader(name)
            if value is not None:
                out_headers[name] = wire(value)
        result = {
            "status": "ok",
            "http_status": response.status,
            # Review a159e97: the server's reason phrase was the last channel
            # that reached the agent unredacted.
            "reason": wire(response.reason or ""),
            "headers": out_headers,
            "body": redactor.redact(data, truncated=truncated).decode("utf-8", "replace"),
            "truncated": truncated,
        }
        if 300 <= response.status < 400 and "Location" in out_headers:
            result["redirect_not_followed"] = True
        if not target.encrypted:
            result["warning"] = PLAIN_HTTP_WARNING
        return result

    @staticmethod
    def _agent_headers(headers: Optional[dict]) -> dict:
        out: dict[str, str] = {}
        for name, value in (headers or {}).items():
            canonical = AGENT_HEADERS.get(str(name).strip().lower())
            if canonical is None:
                raise SSHBrokerError(
                    "header_denied",
                    f"Only these request headers may be set: {', '.join(AGENT_HEADERS.values())}.",
                )
            if not isinstance(value, str) or not _clean(value) or len(value) > 1024:
                raise SSHBrokerError("invalid_request", f"Header {canonical} has an invalid value.")
            out[canonical] = value
        return out

    def _read(self, response, deadline: float) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        while True:
            if time.monotonic() > deadline:
                raise SSHBrokerError("timeout", "HTTP request exceeded its deadline.")
            chunk = response.read1(65536) if hasattr(response, "read1") else response.read(65536)
            if not chunk:
                return b"".join(chunks), False
            chunks.append(chunk)
            size += len(chunk)
            if size > self._max_response:
                return b"".join(chunks)[: self._max_response], True

    @staticmethod
    def _error(conn, exc: BaseException) -> SSHBrokerError:
        if getattr(conn, "sezam_cut_off", False):
            return SSHBrokerError("cut_off", "The HTTP request was cut off ('sezam ai off' or lock).")
        if getattr(conn, "sezam_timed_out", False):
            return SSHBrokerError("timeout", "HTTP request exceeded its deadline.")
        if isinstance(exc, ssl.SSLCertVerificationError):
            return SSHBrokerError("tls_verify_failed", "The server's TLS certificate could not be verified.")
        if isinstance(exc, ssl.SSLError):
            return SSHBrokerError("tls_failed", "TLS handshake with the server failed.")
        if isinstance(exc, (socket.timeout, TimeoutError)):
            return SSHBrokerError("timeout", "HTTP request timed out.")
        if isinstance(exc, (OSError, http.client.HTTPException)):
            return SSHBrokerError("connection_failed", "HTTP request failed.")
        if isinstance(exc, Exception):
            return SSHBrokerError("http_error", "HTTP request failed.")
        raise exc
