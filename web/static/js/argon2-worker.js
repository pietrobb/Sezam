/**
 * Web Worker for Argon2id WASM — MUST NOT run on main thread.
 *
 * Spec 7.2: Mobile Safari can kill tab for OOM if Argon2id runs on main thread.
 * Hard floor: time=2, mem=64MB (web client never accepts lower from server).
 */

/* global importScripts, argon2, self */

// Workers cannot apply SRI to importScripts, so the pinned Argon2 bundle is
// served from the same origin instead of extending trust to a runtime CDN.
importScripts('/static/js/vendor/argon2-bundled.min.js');

// Verify loaded module has the expected API shape (basic tamper detection)
if (typeof argon2 === 'undefined' ||
    typeof argon2.hash !== 'function' ||
    typeof argon2.ArgonType === 'undefined' ||
    typeof argon2.ArgonType.Argon2id === 'undefined') {
    throw new Error('argon2 module failed integrity check: unexpected API shape');
}

const HARD_FLOOR = {
    time: 2,
    memory: 65536, // 64MB in KiB
};

self.onmessage = async function(e) {
    const { password, salt, params } = e.data;

    // Enforce hard floor (spec 7.2)
    const time = Math.max(params.time || 2, HARD_FLOOR.time);
    const mem = Math.max(params.mem || 131072, HARD_FLOOR.memory);
    const parallelism = params.parallelism || 4;

    try {
        const result = await argon2.hash({
            pass: password,
            salt: salt,
            time: time,
            mem: mem,
            parallelism: parallelism,
            hashLen: 64, // 32B KEK + 32B auth_proof
            type: argon2.ArgonType.Argon2id,
        });
        const derivedKey = result.hash instanceof Uint8Array
            ? result.hash
            : new Uint8Array(result.hash);
        self.postMessage({ kek: derivedKey, error: null }, [derivedKey.buffer]);
    } catch (err) {
        self.postMessage({ kek: null, error: err.message || String(err) });
    }
};
