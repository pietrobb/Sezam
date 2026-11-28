"""Review 18c300f R16-L3: a padded blob tells only its size class.

Padding (spec 2.6) rounds a blob up to a power of two, but its u16 prefix
holds at most 0xFFFF bytes of padding. On 18c300f padding stopped there, so
every blob above 128 KiB told its exact length (size - 0xFFFF - 2). Share
links were sealed without padding at all. Now: the next power of two, or,
where that needs more padding than the prefix holds, the next multiple of
64 KiB (readable by every earlier client); a share link's JSON is padded with
trailing spaces to the same size. tests/vectors/padding.json is checked here
for Python and the page, and by mobile/test/r16_padding_test.dart.
"""

import base64
import json
import os
import subprocess
import urllib.request
from pathlib import Path

import nacl.bindings
import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.crypto.padding import pad, unpad
from sezam.vault.crud import Vault
from tests.node_support import node_cmd

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "vectors" / "padding.json").read_text(encoding="utf-8"))
SIZES = [n for n, _ in VECTORS["padded_size"]]
EXPECTED = dict(VECTORS["padded_size"])


def test_the_padded_size_is_the_shared_one():
    from sezam.crypto.padding import padded_size

    assert {n: padded_size(n) for n in SIZES} == EXPECTED


@pytest.mark.parametrize("size", [70_000, 131_070, 150_000, 300_000, 1_048_575])
def test_a_large_blob_tells_only_its_size_class(size):
    data = os.urandom(size)
    padded = pad(data)
    assert unpad(padded) == data
    # The next power of two, or the next multiple of 64 KiB: never the length.
    assert len(padded) % 0x10000 == 0, len(padded)
    assert len(padded) - size - 2 <= 0xFFFF


HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const { webcrypto } = require('crypto');
const context = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, Promise,
  WebAssembly, Blob, URL, crypto: webcrypto,
  location: { origin: 'https://sezam.invalid', search: '' },
  addEventListener() {},
  atob: (value) => Buffer.from(value, 'base64').toString('binary'),
  btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
  document: { addEventListener() {} },
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
vm.runInContext(fs.readFileSync(process.argv[3], 'utf8'), context);
context.SezamSyncCore.ready.then(() => {
const out = {};
for (const n of JSON.parse(process.argv[2])) {
  const data = new context.Uint8Array(n).fill(7);
  const padded = context.padPlaintext(data);
  const back = context.unpadPlaintext(padded);
  out[n] = back.length === n && back.every(b => b === 7) ? padded.length : -1;
}
process.stdout.write(JSON.stringify(out));
});
"""


def test_the_page_pads_to_the_shared_size():
    sizes = [n for n in SIZES if n <= 1_048_577]
    out = subprocess.run(
        [node_cmd(), "-e", HARNESS, str(ROOT / "web" / "static" / "js" / "app.js"), json.dumps(sizes),
         str(ROOT / "web" / "static" / "js" / "vendor" / "sezam-sync-core.js")],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    # padPlaintext pads 2 + n bytes (its u16 prefix).
    got = {int(n): size for n, size in json.loads(out.stdout).items()}
    from_python = {n: len(pad(b"\x07" * n)) for n in sizes}
    assert got == from_python
    assert all(size % 0x10000 == 0 for n, size in got.items() if n > 0x10000), got


PARAMS = Argon2Params(time_cost=1, memory_cost=8_192, parallelism=1)


@pytest.mark.parametrize("secret_len", [10, 5_000, 150_000])
def test_a_share_link_tells_only_its_size_class(tmp_path, monkeypatch, secret_len):
    v = Vault.create(tmp_path / "v", "pw-123456789", PARAMS)
    web = v.create_node("Web")
    v.create_entry(web, "bank", [{"key": "password", "value": "x" * secret_len, "sensitive": True}])
    v.db.set_meta("server_url", "https://sync.invalid")
    monkeypatch.setattr(cli, "_open_vault", lambda: v)
    monkeypatch.setattr(cli, "_unlock_vault", lambda *_a, **_k: None)
    monkeypatch.setattr(Vault, "lock", lambda self: None)
    from sezam.vault.sync_client import SyncClient

    monkeypatch.setattr(SyncClient, "authenticate", lambda self: "tok")
    sent = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

    def urlopen(req, timeout=None):
        sent.update(json.loads(req.data))
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    result = CliRunner().invoke(cli.main, ["share", "Web/bank"])
    assert result.exit_code == 0, result.output
    url = next(line for line in result.output.splitlines() if line.startswith("URL: "))[5:]
    share_id, key_b64 = url.rsplit("/", 1)[1].split("#")
    raw_id = base64.urlsafe_b64decode(share_id + "=" * (-len(share_id) % 4))
    key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    blob = base64.b64decode(sent["encrypted_blob"])
    aad = bytes([1, 1, 3]) + raw_id + (1).to_bytes(4, "big")
    plain = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(blob[24:], aad, blob[:24], key)
    # What the share page and the phone read: JSON.parse / jsonDecode.
    entry = json.loads(plain.decode("utf-8"))
    assert entry["fields"][0]["value"] == "x" * secret_len
    size = len(plain)
    assert size & (size - 1) == 0 or size % 0x10000 == 0, size
    assert size - len(plain.rstrip(b" ")) <= 0xFFFF
