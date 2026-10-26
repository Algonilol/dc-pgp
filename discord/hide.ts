/*
 * DcPgp – hides the raw PGP block of messages that the mod renders itself, and styles that rendering
 * (incl. the blur privacy screen). Pure CSS on Discord's stable element ids; Discord's message objects stay untouched.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

const BASE_CSS = [
    ".dcpgp-plain{font-size:1rem;line-height:1.375rem;white-space:pre-wrap;overflow-wrap:anywhere;user-select:text;color:var(--text-default,var(--text-normal))}",
    ".dcpgp-blur{filter:blur(6px);transition:filter .15s ease}",
    ".dcpgp-blur:hover,.dcpgp-blur:focus-within{filter:none}",
    ".dcpgp-failed{border-left:2px solid var(--status-danger,#f23f43);padding-left:8px}",
    ".dcpgp-badge{display:inline-flex;vertical-align:-2px;margin-left:4px;color:var(--text-muted);cursor:default}",
    ".dcpgp-edited{margin-left:4px;font-size:.625rem;color:var(--text-muted)}",
    ".dcpgp-note{display:flex;flex-wrap:wrap;align-items:center;gap:6px;font-size:.875rem;font-style:italic;color:var(--text-muted)}",
    ".dcpgp-alert{margin:2px 0;font-size:.875rem;font-weight:500;color:var(--text-danger,#f23f43)}",
    ".dcpgp-warning{margin-top:2px;font-size:.8125rem;color:var(--text-warning,#f0b232)}",
    ".dcpgp-unencrypted{display:inline-flex;align-items:center;gap:4px;font-size:.75rem;color:var(--text-warning,#f0b232);cursor:default}",
    ".dcpgp-keycard{display:flex;flex-wrap:wrap;align-items:center;gap:6px 8px;max-width:min(100%,600px);margin:2px 0;padding:8px 10px;border-radius:8px;border-left:3px solid var(--text-muted);background:var(--background-secondary,rgba(127,127,127,.1));font-size:.875rem;color:var(--text-default,var(--text-normal))}",
    ".dcpgp-tone-ok{border-left-color:var(--status-positive,#23a55a)}",
    ".dcpgp-tone-warning{border-left-color:var(--status-warning,#f0b232)}",
    ".dcpgp-tone-danger{border-left-color:var(--status-danger,#f23f43)}",
    ".dcpgp-fpr{flex-basis:100%;font-family:var(--font-code,monospace);font-size:.75rem;color:var(--text-muted);overflow-wrap:anywhere;user-select:text}",
    ".dcpgp-attachments{display:flex;flex-direction:column;align-items:flex-start;gap:6px;margin-top:4px}",
    ".dcpgp-media{display:block;max-width:min(100%,420px);max-height:350px;border-radius:8px;cursor:default}",
    ".dcpgp-file{display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px;max-width:min(100%,420px);padding:8px 10px;border-radius:8px;background:var(--background-secondary,rgba(127,127,127,.1));font-size:.875rem;color:var(--text-default,var(--text-normal))}",
    ".dcpgp-file-name{font-weight:500;overflow-wrap:anywhere}",
    ".dcpgp-file-meta{font-size:.75rem;color:var(--text-muted)}"
].join("");

const hidden = new Map<string, number>();
/** Messages whose encrypted file cards DcPgp replaces with the decrypted files. */
const hiddenCards = new Map<string, number>();
let styleEl: HTMLStyleElement | null = null;
let scheduled = false;
let enabled = false;

const ID = /^\d{1,25}$/;

function flush() {
    scheduled = false;
    if (!enabled) return;
    styleEl ??= Object.assign(document.createElement("style"), { id: "dcpgp-hide-ciphertext" });
    if (!styleEl.isConnected) document.head.appendChild(styleEl);
    const selectors: string[] = [];
    for (const key of hidden.keys()) {
        const [channelId, messageId] = key.split(":");
        selectors.push(`#chat-messages-${channelId}-${messageId} #message-content-${messageId}`);
    }
    // Discord's card for each dcpgp-N.pgp file; never the part that holds DcPgp's own rendering.
    for (const messageId of hiddenCards.keys())
        selectors.push(`#message-accessories-${messageId} > :has(a[href*="/dcpgp-"]):not(:has(.dcpgp-attachments))`);
    styleEl.textContent = BASE_CSS + (selectors.length ? `${selectors.join(",")}{display:none!important}` : "");
}

function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(flush);
}

/** Hides the original content of one message; returns the function that shows it again. */
export function hideOriginalContent(channelId: string, messageId: string): () => void {
    if (!ID.test(channelId) || !ID.test(messageId)) return () => { };
    const key = channelId + ":" + messageId;
    hidden.set(key, (hidden.get(key) ?? 0) + 1);
    schedule();
    return () => {
        const n = (hidden.get(key) ?? 1) - 1;
        if (n <= 0) hidden.delete(key);
        else hidden.set(key, n);
        schedule();
    };
}

/** Hides Discord's cards of a message's encrypted files while DcPgp shows them decrypted. */
export function hideEncryptedFileCards(messageId: string): () => void {
    if (!ID.test(messageId)) return () => { };
    hiddenCards.set(messageId, (hiddenCards.get(messageId) ?? 0) + 1);
    schedule();
    return () => {
        const n = (hiddenCards.get(messageId) ?? 1) - 1;
        if (n <= 0) hiddenCards.delete(messageId);
        else hiddenCards.set(messageId, n);
        schedule();
    };
}

export function startHiding() {
    enabled = true;
    schedule();
}

export function stopHiding() {
    enabled = false;
    hidden.clear();
    hiddenCards.clear();
    styleEl?.remove();
    styleEl = null;
}
