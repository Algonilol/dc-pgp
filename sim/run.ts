/*
 * DcPgp simulation – the whole 1:1 DM flow between two accounts on a simulated Discord, run through the real
 * plugin: setup, key exchange, safety numbers, messages, edits, files, attacks by the server, leak attempts,
 * locking and "Unlock with Windows". At the end it checks that Discord never received any plaintext.
 *
 *     npm run simulate
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./globals";

import { _handlePreEdit, _handlePreSend } from "@api/MessageEvents";

import { isEncryptedFileName } from "../core/attachments";
import { parseContent } from "../core/format";
import { markRepeated } from "../core/receive";
import { WrongPasswordError } from "../core/vault";
import { lockVault, newPassphrase, prepareGeneratedKey, setupVault, setWindowsUnlock, unlockVault } from "../discord/actions";
import { openAttachment } from "../discord/attachments";
import { getDecryption, isRepeatedMessage, whenDecrypted } from "../discord/decrypt";
import { openVerifyDialog, requestKey, setChatEncrypted } from "../discord/keyExchange";
import { contactOf, S } from "../discord/state";
import plugin from "../index";
import * as W from "./world";

// --- output ------------------------------------------------------------------------------------------

const tty = !!process.stdout.isTTY;
const paint = (code: string, s: string) => tty ? `\x1b[${code}m${s}\x1b[0m` : s;
const green = (s: string) => paint("32", s);
const red = (s: string) => paint("31", s);
const dim = (s: string) => paint("2", s);
const bold = (s: string) => paint("1", s);

const results: { name: string; ok: boolean; }[] = [];

function section(title: string) {
    console.log("\n" + bold(title));
}

async function step(name: string, fn: () => Promise<void>) {
    const started = Date.now();
    const logFrom = W.logLines.length;
    try {
        await fn();
        results.push({ name, ok: true });
        console.log(`  ${green("✔")} ${name} ${dim(`${((Date.now() - started) / 1000).toFixed(1)}s`)}`);
    } catch (e) {
        results.push({ name, ok: false });
        console.log(`  ${red("✖")} ${name}`);
        console.log(`      ${red(e instanceof Error ? e.message : String(e))}`);
        for (const line of W.logLines.slice(logFrom).filter(l => /error|warn/.test(l)).slice(-5)) console.log(dim(`      ${line}`));
    }
}

function check(condition: unknown, message: string): asserts condition {
    if (!condition) throw new Error(message);
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

async function until(condition: () => unknown, what: string, timeoutMs = 30_000) {
    const end = Date.now() + timeoutMs;
    while (!condition()) {
        if (Date.now() > end) throw new Error(`Timed out waiting for ${what}`);
        await sleep(15);
    }
}

const short = (s: string) => s.length > 60 ? s.slice(0, 57) + "…" : s;
const bytesOf = (text: string) => new TextEncoder().encode(text);
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const newToasts = (from: number) => W.toasts.slice(from).map(t => t.text);

/** A small PNG-looking file with a marker that must never reach Discord. */
function picture(marker: string): Uint8Array {
    const head = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    return new Uint8Array([...head, ...bytesOf(marker), ...Array.from({ length: 4000 }, (_, i) => (i * 7) % 256)]);
}

// --- the plugin, started the way Vencord starts it ---------------------------------------------------

function startPlugin() {
    for (const [type, fn] of Object.entries(plugin.flux ?? {})) W.FluxDispatcher.subscribe(type, fn as any);
    plugin.start!();
}

function stopPlugin() {
    plugin.stop!();
    for (const [type, fn] of Object.entries(plugin.flux ?? {})) W.FluxDispatcher.unsubscribe(type, fn as any);
    W.releasePowerWaiters();
}

let alicePassword = "";
let bobPassword = "";

/** Switches to an account, opens its DcPgp (Alice: Windows, Bob: password) and hands it what it missed. */
async function as(user: W.SimUser) {
    W.switchAccount(user);
    await until(() => S.phase !== "loading", "the vault to load");
    if (user === W.BOB && S.phase === "locked") await unlockVault({ password: bobPassword });
    await until(() => S.phase === "unlocked", `${user.globalName}'s DcPgp to open`);
    W.deliverQueued();
    await sleep(150);
}

interface Seen {
    text: string;
    trust: string;
    findings: string[];
    repeated: boolean;
    edited: boolean;
    files: { name: string; kind: string; bytes: Uint8Array; }[];
    fileErrors: string[];
    /** Warnings shown with an opened file (its own signature did not check out). */
    fileNotes: string[];
}

/** What the active account sees for a message, from the same functions the message view uses. */
async function read(messageId: string): Promise<Seen> {
    const m = W.clientMessages().get(messageId);
    check(m, `message ${messageId} is not in ${W.currentUser().globalName}'s chat`);
    const parsed = parseContent(m.content);
    check(parsed.kind === "message", "not an encrypted message");
    const entry = await whenDecrypted(m, parsed.armored);
    check(entry.status === "ok" && entry.view, `could not be decrypted (${entry.status})`);
    // As the message view does: a copy gets its warning on top of the decrypted view.
    const repeated = isRepeatedMessage(m, entry.view);
    const view = repeated ? markRepeated(entry.view) : entry.view;
    const files: Seen["files"] = [];
    const fileErrors: string[] = [];
    const fileNotes: string[] = [];
    for (const a of (m.attachments as any[]).filter(x => isEncryptedFileName(x.filename))) {
        const f = await openAttachment(m, view, a, true);
        if (f.status === "ok") {
            files.push({ name: f.name, kind: f.kind, bytes: new Uint8Array(await f.blob.arrayBuffer()) });
            if (f.note) fileNotes.push(f.note);
        } else fileErrors.push(f.status === "error" ? f.message : f.status);
    }
    return { text: view.text, trust: view.trust, findings: view.findings.map(f => f.code), repeated, edited: !!m.editedTimestamp, files, fileErrors, fileNotes };
}

async function openEditBox(messageId: string) {
    W.MessageActions.startEditMessageRecord(W.DM_ID, W.clientMessages().get(messageId));
    await until(() => W.EditMessageStore.isEditing(W.DM_ID, messageId), "the edit box");
    return W.EditMessageStore.getEditingTextValue(W.DM_ID) ?? "";
}

// --- the run -----------------------------------------------------------------------------------------

console.log(bold("DcPgp simulation") + dim(" – two accounts on a simulated Discord, the real plugin"));
const started = Date.now();
startPlugin();

let first = "";
let bobsAnswer = "";
let withFiles = "";
const photo = picture("FILE-SECRET-photo");
const contract = bytesOf("%PDF-1.7\nFILE-SECRET-contract\n" + "x".repeat(2000));

section("Setup");

await step("Alice sets up DcPgp with \"Unlock with Windows\"", async () => {
    await until(() => S.phase === "nosetup", "Alice's empty vault");
    alicePassword = newPassphrase();
    await setupVault({ prepared: await prepareGeneratedKey("Alice"), mode: "stored", password: alicePassword, generatedPassword: alicePassword, keyFileSaved: true, windowsUnlock: true });
    check(S.phase === "unlocked", `not open after setup (${S.phase})`);
    check(S.file?.w, "the vault has no Windows access");
});

await step("Bob sets up DcPgp with a password", async () => {
    W.switchAccount(W.BOB);
    await until(() => S.phase === "nosetup", "Bob's empty vault");
    bobPassword = newPassphrase();
    await setupVault({ prepared: await prepareGeneratedKey("Bob"), mode: "stored", password: bobPassword, generatedPassword: bobPassword, keyFileSaved: true });
    check(S.phase === "unlocked" && !S.file?.w, "wrong vault state after setup");
});

await step("A wrong password does not open Bob's vault", async () => {
    lockVault();
    let rejected = false;
    try {
        await unlockVault({ password: "correct horse battery staple" });
    } catch (e) {
        rejected = e instanceof WrongPasswordError;
    }
    check(rejected, "the wrong password was accepted");
    check(S.phase === "locked", "the vault opened");
});

section("Key exchange");

await step("Alice's DcPgp opens by itself (Windows); she asks Bob for his key", async () => {
    await as(W.ALICE);
    const sends = W.serverStats.sends;
    await requestKey(W.BOB.id);
    check(W.serverStats.sends === sends + 1, "no key request was sent");
    check(parseContent([...W.serverMessages.values()].at(-1).content).kind === "keyreq", "the last message is not a key request");
});

await step("Bob accepts; DcPgp stores Alice's key and answers with his", async () => {
    await as(W.BOB);
    await until(() => contactOf(W.ALICE.id), "Alice's key in Bob's contacts");
    await until(() => [...W.serverMessages.values()].some(m => m.author.id === W.BOB.id && parseContent(m.content).kind === "keyresp"), "Bob's key response");
});

await step("Alice receives Bob's key", async () => {
    await as(W.ALICE);
    await until(() => contactOf(W.BOB.id), "Bob's key in Alice's contacts");
});

await step("Both see the same safety number and verify each other", async () => {
    if (!contactOf(W.BOB.id)?.verified) await openVerifyDialog(W.BOB.id);
    await until(() => contactOf(W.BOB.id)?.verified, "Alice to verify Bob");
    await as(W.BOB);
    if (!contactOf(W.ALICE.id)?.verified) await openVerifyDialog(W.ALICE.id);
    await until(() => contactOf(W.ALICE.id)?.verified, "Bob to verify Alice");
    const seenByAlice = W.safetyNumbers.find(s => s.viewer === W.ALICE.id)?.number ?? "";
    const seenByBob = W.safetyNumbers.find(s => s.viewer === W.BOB.id)?.number ?? "";
    check(seenByAlice.replace(/\D/g, "").length === 60, `not 60 digits: ${seenByAlice}`);
    check(seenByAlice === seenByBob, `different safety numbers: ${seenByAlice} / ${seenByBob}`);
});

await step("Both switch encryption on for their DM", async () => {
    await setChatEncrypted(W.DM_ID, true);
    await as(W.ALICE);
    await setChatEncrypted(W.DM_ID, true);
});

section("Messages");

await step("Alice writes; Discord only gets an encrypted block", async () => {
    const sent = await W.chatSend(W.DM_ID, "Treffen um 18 Uhr? SECRET-1", _handlePreSend);
    check(sent, "the message was not sent: " + newToasts(0).at(-1));
    first = sent.id;
    check(parseContent(sent.content).kind === "message", "Discord got no dcpgp block");
    await sleep(300);
    check(!W.dialogs.some(d => /unencrypted/i.test(d.title)), "the check of her own message reported a leak");
});

await step("Alice sees her own message with a green lock", async () => {
    const r = await read(first);
    check(r.text === "Treffen um 18 Uhr? SECRET-1", `text: ${r.text}`);
    check(r.trust === "verified", `lock: ${r.trust} ${r.findings}`);
});

await step("Bob reads it: right text, green lock, no warnings", async () => {
    await as(W.BOB);
    const r = await read(first);
    check(r.text === "Treffen um 18 Uhr? SECRET-1", `text: ${r.text}`);
    check(r.trust === "verified", `lock: ${r.trust}`);
    check(!r.findings.length, `notes: ${r.findings}`);
    check(!r.repeated, "marked as a copy");
});

await step("Bob answers; Alice reads it with a green lock", async () => {
    const sent = await W.chatSend(W.DM_ID, "Ja, passt! SECRET-2", _handlePreSend);
    check(sent, "Bob's answer was not sent");
    bobsAnswer = sent.id;
    await as(W.ALICE);
    const r = await read(bobsAnswer);
    check(r.text === "Ja, passt! SECRET-2" && r.trust === "verified", `${r.text} · ${r.trust}`);
});

section("Editing");

await step("The edit box shows Alice's text, not the PGP block", async () => {
    const box = await openEditBox(first);
    check(box === "Treffen um 18 Uhr? SECRET-1", `edit box: ${short(box)}`);
});

await step("Saving encrypts the new text; Discord only gets a new block", async () => {
    const edits = W.serverStats.edits;
    const result = await W.saveEdit(W.DM_ID, first, "Treffen um 19 Uhr? SECRET-3", _handlePreEdit);
    check(result === "saved", `edit ${result}: ${newToasts(0).at(-1)}`);
    check(W.serverStats.edits === edits + 1, "Discord got no edit");
    check(parseContent(W.serverMessages.get(first).content).kind === "message", "the edit is not a dcpgp block");
});

await step("Bob sees the edited text with a green lock", async () => {
    await as(W.BOB);
    const r = await read(first);
    check(r.text === "Treffen um 19 Uhr? SECRET-3", `text: ${r.text}`);
    check(r.trust === "verified" && r.edited, `lock: ${r.trust}, edited: ${r.edited}`);
});

await step("An unchanged edit saves nothing", async () => {
    await as(W.ALICE);
    const box = await openEditBox(first);
    const edits = W.serverStats.edits;
    const result = await W.saveEdit(W.DM_ID, first, box, _handlePreEdit);
    check(result === "unchanged" && W.serverStats.edits === edits, `edit ${result}`);
});

section("Files");

await step("Attached files are encrypted before Discord's upload starts", async () => {
    const from = W.seen.length;
    W.attach(W.DM_ID, [new File([photo as Uint8Array<ArrayBuffer>], "urlaub-am-meer.png", { type: "image/png" }), new File([contract as Uint8Array<ArrayBuffer>], "vertrag.pdf", { type: "application/pdf" })]);
    await until(() => W.UploadAttachmentStore.getUploadCount(W.DM_ID, 0) === 2, "two encrypted files in the chat input");
    await until(() => W.seen.slice(from).filter(s => s.what === "file uploaded on attaching").length === 2, "the two uploads");
    const uploads = W.seen.slice(from).filter(s => s.what === "file uploaded on attaching");
    check(uploads.map(u => u.text).join(", ") === "dcpgp-1.pgp, dcpgp-2.pgp", `names Discord got: ${uploads.map(u => u.text)}`);
});

await step("Alice sends them with a text; the signed message lists them", async () => {
    const sent = await W.chatSend(W.DM_ID, "Hier die Fotos SECRET-4", _handlePreSend);
    check(sent, "not sent: " + newToasts(0).at(-1));
    withFiles = sent.id;
    check(sent.attachments.length === 2 && sent.attachments.every((a: any) => isEncryptedFileName(a.filename) && !a.description), "Discord got other names or alt texts");
    const own = await read(withFiles);
    check(own.files.length === 2, `Alice opens ${own.files.length} of her files: ${own.fileErrors}`);
});

await step("Bob opens both: same names, same bytes, the photo as a picture", async () => {
    await as(W.BOB);
    const r = await read(withFiles);
    check(!r.fileErrors.length && !r.fileNotes.length, `errors: ${r.fileErrors} notes: ${r.fileNotes}`);
    const shownPhoto = r.files.find(f => f.name === "urlaub-am-meer.png");
    const shownPdf = r.files.find(f => f.name === "vertrag.pdf");
    check(shownPhoto && shownPhoto.kind === "image" && sameBytes(shownPhoto.bytes, photo), "the photo differs");
    check(shownPdf && shownPdf.kind === "file" && sameBytes(shownPdf.bytes, contract), "the PDF differs");
    check(r.text === "Hier die Fotos SECRET-4" && r.trust === "verified", `${r.text} · ${r.trust}`);
});

await step("A file without text arrives too", async () => {
    W.attach(W.DM_ID, [new File([bytesOf("FILE-SECRET-notes") as Uint8Array<ArrayBuffer>], "notizen.txt")]);
    await until(() => W.UploadAttachmentStore.getUploadCount(W.DM_ID, 0) === 1, "the encrypted file in the chat input");
    const sent = await W.chatSend(W.DM_ID, "", _handlePreSend);
    check(sent && parseContent(sent.content).kind === "message", "no signed message for the file");
    await as(W.ALICE);
    const r = await read(sent.id);
    check(r.text === "" && r.files.length === 1 && r.files[0].name === "notizen.txt" && !r.fileNotes.length, `${r.files.map(f => f.name)} ${r.fileErrors} ${r.fileNotes}`);
});

section("Attacks by Discord");

await step("A file swapped by Discord is rejected", async () => {
    W.attach(W.DM_ID, [new File([picture("FILE-SECRET-second") as Uint8Array<ArrayBuffer>], "zweites-bild.png")]);
    await until(() => W.UploadAttachmentStore.getUploadCount(W.DM_ID, 0) === 1, "the encrypted file in the chat input");
    const sent = await W.chatSend(W.DM_ID, "Noch eins SECRET-5", _handlePreSend);
    check(sent, "not sent");
    W.attacker.swapFile(sent.id, withFiles);
    await as(W.BOB);
    const r = await read(sent.id);
    check(!r.files.length && r.fileErrors.length === 1 && /swapped/.test(r.fileErrors[0]), `files: ${r.files.map(f => f.name)} errors: ${r.fileErrors}`);
});

await step("A message replayed by Discord is flagged as a copy, never green", async () => {
    await read(first);
    const copy = W.attacker.replay(first);
    await sleep(300);
    const r = await read(copy);
    check(r.repeated, "not recognized as a copy");
    check(r.trust !== "verified", "green lock on a copy");
    check(!(await read(first)).repeated, "the original was marked as the copy");
});

section("Leak attempts");

await step("Plaintext sent past the chat input (e.g. by another plugin) is stopped", async () => {
    const sends = W.serverStats.sends;
    await W.MessageActions.sendMessage(W.DM_ID, { content: "SECRET-6 plain text" }, undefined, {});
    check(W.serverStats.sends === sends, "it reached Discord");
});

await step("Text written around a pasted encrypted block is stopped", async () => {
    const sends = W.serverStats.sends;
    const block = W.serverMessages.get(first).content;
    await W.MessageActions.sendMessage(W.DM_ID, { content: block + "\nSECRET-7 my real answer" }, undefined, {});
    check(W.serverStats.sends === sends, "it reached Discord");
});

await step("A poll is stopped", async () => {
    const sends = W.serverStats.sends;
    await W.MessageActions.sendPollMessage(W.DM_ID, { question: { text: "SECRET-8?" }, answers: [] });
    check(W.serverStats.sends === sends, "the poll reached Discord");
});

await step("An unencrypted file sent past the chat input is stopped before its upload", async () => {
    const sends = W.serverStats.sends;
    const upload = new W.FakeUpload({ file: new File([bytesOf("FILE-SECRET-9") as Uint8Array<ArrayBuffer>], "geheim.txt"), platform: 1 }, W.DM_ID);
    await W.MessageActions.sendMessage(W.DM_ID, { content: "" }, undefined, { attachmentsToUpload: [upload] });
    check(W.serverStats.sends === sends && upload.status === "NOT_STARTED", "the file reached Discord");
});

await step("Drafts of the encrypted chat are never written to disk", async () => {
    W.draftState[W.BOB.id] = { [W.DM_ID]: { 0: { draft: "SECRET-10 draft", timestamp: 1 } }, "300000000000000001": { 0: { draft: "harmless", timestamp: 2 } } };
    const persisted = JSON.stringify(W.DraftStore.getState());
    check(!persisted.includes("SECRET") && persisted.includes("harmless"), `persisted: ${short(persisted)}`);
});

await step("Locked: a file is not attached at all, nothing is decrypted, editing is refused", async () => {
    lockVault();
    const from = W.seen.length;
    const toastFrom = W.toasts.length;
    W.attach(W.DM_ID, [new File([bytesOf("FILE-SECRET-11") as Uint8Array<ArrayBuffer>], "geheim.txt")]);
    await sleep(200);
    check(W.UploadAttachmentStore.getUploadCount(W.DM_ID, 0) === 0 && W.seen.length === from, "the file was attached or uploaded");
    check(newToasts(toastFrom).some(t => /NOT attached/.test(t)), "no notice that the file was not attached");
    const m = W.clientMessages().get(bobsAnswer);
    check(getDecryption(m, (parseContent(m.content) as any).armored).status === "locked", "a message was decrypted while locked");
    W.MessageActions.startEditMessageRecord(W.DM_ID, m);
    await sleep(100);
    check(!W.EditMessageStore.isEditing(W.DM_ID, bobsAnswer), "the edit box opened with the PGP block");
});

await step("A broken send hook (after a Discord update) is noticed and stops plaintext", async () => {
    await unlockVault({ password: bobPassword });
    const sends = W.serverStats.sends;
    await W.MessageActions.sendMessage(W.DM_ID, { content: "SECRET-12 hook skipped" }, undefined, { location: "chat_input" });
    check(W.serverStats.sends === sends, "it reached Discord");
    check(!S.hookHealthy, "DcPgp did not notice the broken hook");
});

section("Unlock with Windows");

await step("DcPgp locks with the Windows screen and opens again with it", async () => {
    await as(W.ALICE);
    W.powerEvent("lock-screen");
    await until(() => S.phase === "locked", "DcPgp to lock with the screen");
    W.powerEvent("unlock-screen");
    await until(() => S.phase === "unlocked", "DcPgp to open with Windows");
});

await step("After a Discord restart, Alice's DcPgp opens without a password", async () => {
    stopPlugin();
    check(S.phase !== "unlocked", "still open after stopping");
    startPlugin();
    await until(() => S.phase === "unlocked", "DcPgp to open by itself");
});

await step("Switched off (with her password), DcPgp asks Alice for it again", async () => {
    await setWindowsUnlock(false, alicePassword);
    check(!S.file?.w, "the vault still opens through Windows");
    stopPlugin();
    startPlugin();
    await until(() => S.phase !== "loading", "the vault to load");
    await sleep(300);
    check(S.phase === "locked", `DcPgp is ${S.phase} without a password`);
    await unlockVault({ password: alicePassword });
    check((S.phase as string) === "unlocked", "her password does not open it");
});

await step("Bob's DcPgp (password) stays locked until he types it", async () => {
    W.switchAccount(W.BOB);
    await until(() => S.phase !== "loading", "the vault to load");
    await sleep(300);
    check(S.phase === "locked", `Bob's DcPgp is ${S.phase}`);
});

section("What Discord received");

await step("No plaintext, no file name, no private key ever reached Discord", async () => {
    const markers = ["SECRET-", "FILE-SECRET", "urlaub", "vertrag", "notizen", "zweites", "geheim", "PRIVATE KEY"];
    const leaks = W.seen.filter(s => markers.some(m => s.text.includes(m) || (s.bytes && Buffer.from(s.bytes).includes(m))));
    check(!leaks.length, `leaked: ${leaks.map(l => `${l.what}: ${short(l.text)}`).join(" | ")}`);
    const files = W.seen.filter(s => s.what === "file uploaded on attaching").length;
    console.log(dim(`      Discord received ${W.serverStats.sends} messages, ${W.serverStats.edits} edits and ${files} files – all of them encrypted.`));
});

stopPlugin();

const failed = results.filter(r => !r.ok);
const seconds = ((Date.now() - started) / 1000).toFixed(0);
console.log("");
if (failed.length) {
    console.log(red(bold(`  ${failed.length} of ${results.length} checks failed`)) + dim(` (${seconds}s)`));
    for (const r of failed) console.log(red(`    ✖ ${r.name}`));
    if (process.argv.includes("--verbose")) for (const line of W.logLines) console.log(dim(line));
} else {
    console.log(green(bold(`  All ${results.length} checks passed`)) + dim(` (${seconds}s)`));
}
console.log("");
process.exit(failed.length ? 1 : 0);
