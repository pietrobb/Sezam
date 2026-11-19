//! Phone binding of sezam-sync-core (dart:ffi): the one JSON entry point.
//! mobile/hook/build.dart builds it; mobile/lib/services/sync_core.dart
//! calls it.

use std::ffi::{c_char, CStr, CString};

/// Run one core operation: JSON in, `{"ok": ...}` or `{"error": "..."}` out.
/// The answer is owned by the caller and goes back through
/// [`sezam_sync_core_free`].
///
/// # Safety
/// `op` and `input` are NUL-terminated strings valid for the call.
#[no_mangle]
pub unsafe extern "C" fn sezam_sync_core_call(
    op: *const c_char,
    input: *const c_char,
) -> *mut c_char {
    let text = |ptr: *const c_char| {
        if ptr.is_null() {
            None
        } else {
            CStr::from_ptr(ptr).to_str().ok()
        }
    };
    let out = match (text(op), text(input)) {
        (Some(op), Some(input)) => sync_core::json::call(op, input),
        _ => r#"{"error":"op and input must be UTF-8 strings"}"#.to_string(),
    };
    // serde_json never writes a raw NUL (it escapes it as \u0000).
    CString::new(out).expect("JSON has no NUL").into_raw()
}

/// Free an answer of [`sezam_sync_core_call`].
///
/// # Safety
/// `answer` came from `sezam_sync_core_call` and is freed once.
#[no_mangle]
pub unsafe extern "C" fn sezam_sync_core_free(answer: *mut c_char) {
    if !answer.is_null() {
        drop(CString::from_raw(answer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_and_frees() {
        let op = CString::new("next_cursor").unwrap();
        let input = CString::new(r#"{"last_seq":0,"max_commit_seq":7,"gc_floor_seq":10}"#).unwrap();
        unsafe {
            let out = sezam_sync_core_call(op.as_ptr(), input.as_ptr());
            assert_eq!(CStr::from_ptr(out).to_str().unwrap(), r#"{"ok":10}"#);
            sezam_sync_core_free(out);
            let out = sezam_sync_core_call(std::ptr::null(), input.as_ptr());
            assert!(CStr::from_ptr(out)
                .to_str()
                .unwrap()
                .starts_with(r#"{"error""#));
            sezam_sync_core_free(out);
        }
    }
}
