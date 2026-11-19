//! Python binding of sezam-sync-core: the one JSON entry point, nothing else.

use pyo3::prelude::*;

/// Run one core operation: JSON in, `{"ok": ...}` or `{"error": "..."}` out.
#[pyfunction]
fn call(op: &str, input: &str) -> String {
    sync_core::json::call(op, input)
}

#[pymodule]
fn sezam_sync_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(call, m)?)
}
