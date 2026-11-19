'use strict';

const SHARE_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SHARE_NONCE_BYTES = 24;
const SHARE_TAG_BYTES = 16;

const I18N = globalThis.SezamI18n;
let currentLanguage = I18N.defaultLanguage;

function t(key, values = {}) {
    return I18N.translate(currentLanguage, key, values);
}

function applyShareLanguage(language) {
    currentLanguage = I18N.applyDocument(document, language);
    document.title = t('share.page_title');
    const selector = document.getElementById('language-select');
    if (selector) selector.value = currentLanguage;
    localStorage.setItem('sezam-language', currentLanguage);
}

function initShareI18n() {
    const selector = document.getElementById('language-select');
    selector.replaceChildren(...I18N.listLanguages().map(({ code, name }) => {
        const option = document.createElement('option');
        option.value = code;
        option.textContent = name;
        return option;
    }));
    selector.addEventListener('change', (event) => applyShareLanguage(event.target.value));
    applyShareLanguage(localStorage.getItem('sezam-language'));
}

class ShareAccessError extends Error {
    constructor(message, status = 0) {
        super(message);
        this.name = 'ShareAccessError';
        this.status = status;
    }
}

function decodeBase64Url32(value, label) {
    if (!SHARE_ID_PATTERN.test(value)) {
        throw new ShareAccessError(t('share.error.invalid_value', { label }));
    }
    const standard = value.replace(/-/g, '+').replace(/_/g, '/') + '=';
    let binary;
    try {
        binary = atob(standard);
    } catch (_error) {
        throw new ShareAccessError(t('share.error.invalid_value', { label }));
    }
    if (binary.length !== 32) {
        throw new ShareAccessError(t('share.error.invalid_value', { label }));
    }
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function decodeBase64(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
        throw new ShareAccessError(t('share.error.invalid_encrypted'));
    }
    let binary;
    try {
        binary = atob(value);
    } catch (_error) {
        throw new ShareAccessError(t('share.error.invalid_encrypted'));
    }
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function buildShareAAD(rawShareId) {
    if (!(rawShareId instanceof Uint8Array) || rawShareId.length !== 32) {
        throw new ShareAccessError(t('share.error.invalid_id'));
    }
    const aad = new Uint8Array(39);
    aad.set([1, 1, 3], 0);
    aad.set(rawShareId, 3);
    new DataView(aad.buffer).setUint32(35, 1, false);
    return aad;
}

function shareErrorMessage(status) {
    const keys = {
        403: 'share.error.pin',
        404: 'share.error.not_found',
        410: 'share.error.expired',
        423: 'share.error.locked',
        429: 'share.error.rate_limited',
    };
    return t(keys[status] || 'share.load_failed');
}

async function decryptShareBlob(encryptedBlob, rawShareId, shareKey, sodiumApi) {
    const blob = decodeBase64(encryptedBlob);
    if (blob.length < SHARE_NONCE_BYTES + SHARE_TAG_BYTES + 1) {
        throw new ShareAccessError(t('share.error.invalid_encrypted'));
    }
    if (!(shareKey instanceof Uint8Array) || shareKey.length !== 32) {
        throw new ShareAccessError(t('share.error.invalid_key'));
    }
    if (!sodiumApi || !sodiumApi.ready) {
        throw new ShareAccessError(t('share.error.crypto_unavailable'));
    }
    await sodiumApi.ready;

    const nonce = blob.slice(0, SHARE_NONCE_BYTES);
    const ciphertext = blob.slice(SHARE_NONCE_BYTES);
    let plaintext;
    try {
        plaintext = sodiumApi.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null,
            ciphertext,
            buildShareAAD(rawShareId),
            nonce,
            shareKey,
        );
    } catch (_error) {
        throw new ShareAccessError(t('share.error.modified'));
    }

    let parsed;
    try {
        parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    } catch (_error) {
        throw new ShareAccessError(t('share.error.invalid_data'));
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new ShareAccessError(t('share.error.invalid_data'));
    }
    return parsed;
}

async function fetchAndDecryptShare({ shareId, shareKey, pin = '', fetchFn = fetch, sodiumApi = globalThis.sodium }) {
    const rawShareId = decodeBase64Url32(shareId, t('share.label.id'));
    const body = pin ? { pin } : {};
    const response = await fetchFn(`/api/share/${encodeURIComponent(shareId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
    });
    if (!response.ok) {
        throw new ShareAccessError(shareErrorMessage(response.status), response.status);
    }

    let payload;
    try {
        payload = await response.json();
    } catch (_error) {
        throw new ShareAccessError(t('share.error.invalid_response'));
    }
    return decryptShareBlob(payload.encrypted_blob, rawShareId, shareKey, sodiumApi);
}

function parseShareLocation(locationObject) {
    const match = locationObject.pathname.match(/^\/s\/([A-Za-z0-9_-]{43})\/?$/);
    if (!match) throw new ShareAccessError(t('share.error.invalid_url'));
    const fragment = locationObject.hash.startsWith('#') ? locationObject.hash.slice(1) : '';
    return {
        shareId: match[1],
        shareKey: decodeBase64Url32(fragment, t('share.label.key')),
    };
}

function renderSharedEntry(entry) {
    const title = document.getElementById('share-entry-title');
    const data = document.getElementById('share-entry-data');
    title.textContent = typeof entry.name === 'string' && entry.name ? entry.name : t('share.entry_fallback');
    data.textContent = JSON.stringify(entry, null, 2);
    document.getElementById('share-result').classList.remove('hidden');
}

function setShareStatus(message, isError = false) {
    const status = document.getElementById('share-status');
    status.textContent = message;
    status.classList.toggle('error', isError);
    status.classList.toggle('info', !isError);
}

function initSecureShare() {
    const form = document.getElementById('share-form');
    const openButton = document.getElementById('share-open');
    let shareLocation;
    try {
        shareLocation = parseShareLocation(window.location);
        history.replaceState(null, document.title, window.location.pathname + window.location.search);
    } catch (error) {
        setShareStatus(error.message, true);
        openButton.disabled = true;
        return;
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        openButton.disabled = true;
        setShareStatus(t('share.loading'));
        try {
            const entry = await fetchAndDecryptShare({
                shareId: shareLocation.shareId,
                shareKey: shareLocation.shareKey,
                pin: document.getElementById('share-pin').value,
            });
            renderSharedEntry(entry);
            setShareStatus(t('share.decrypted'));
            shareLocation.shareKey.fill(0);
            shareLocation = null;
            form.classList.add('hidden');
        } catch (error) {
            setShareStatus(error instanceof ShareAccessError ? error.message : t('share.open_failed'), true);
            openButton.disabled = false;
        }
    });
}

globalThis.SezamShare = Object.freeze({
    ShareAccessError,
    buildShareAAD,
    decodeBase64Url32,
    decryptShareBlob,
    fetchAndDecryptShare,
    parseShareLocation,
});

document.addEventListener('DOMContentLoaded', () => {
    initShareI18n();
    initSecureShare();
});
