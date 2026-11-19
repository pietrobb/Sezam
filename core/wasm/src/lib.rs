//! Web binding of sezam-sync-core: the one JSON entry point, nothing else.
//! Built into web/static/js/vendor/sezam-sync-core.js by core/build_web.py.

use wasm_bindgen::prelude::*;

/// Run one core operation: JSON in, `{"ok": ...}` or `{"error": "..."}` out.
#[wasm_bindgen]
pub fn call(op: &str, input: &str) -> String {
    sync_core::json::call(op, input)
}
