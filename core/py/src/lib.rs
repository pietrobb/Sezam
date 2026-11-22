//! Python binding of sezam-sync-core: the one JSON entry point, nothing else.

use pyo3::prelude::*;

/// Run one core operation: JSON in, `{"ok": ...}` or `{"error": "..."}` out.
///
/// The core runs without the GIL (review 8bc70f7 M8: a re-key over 40 000
/// keys held it the whole time, and the GUI thread stood still).
#[pyfunction]
fn call(py: Python<'_>, op: String, input: String) -> String {
    py.detach(move || sync_core::json::call(&op, &input))
}

#[pymodule]
fn sezam_sync_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(call, m)?)
}
