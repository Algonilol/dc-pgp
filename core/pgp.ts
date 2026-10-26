/*
 * DcPgp – OpenPGP operations (OpenPGP.js): reading and checking keys, encryption, signatures
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import * as openpgp from "openpgp";

export type PrivateKey = openpgp.PrivateKey;
export type PublicKey = openpgp.PublicKey;
export type AnyKey = openpgp.PrivateKey | openpgp.PublicKey;

/**
 * SEIPDv1 (no AEAD) keeps every message decryptable by GnuPG/Kleopatra.
 * No compression: exact padding and no compression side channels.
 */
export const PGP_CONFIG: openpgp.PartialConfig = {
    aeadProtect: false,
    preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed,
    preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
    showVersion: false,
    showComment: false,
    minRSABits: 2048,
    maxDecompressedMessageSize: 1024 * 1024,
    enableParsingV5Entities: false
};

/** Key methods (unlike top-level functions) need a complete config object. */
const FULL_CONFIG: openpgp.Config = { ...openpgp.config, ...PGP_CONFIG } as openpgp.Config;

const MAX_ARMORED_MESSAGE = 64 * 1024;
/** Encrypted attachments; a little above the 100 MB DcPgp encrypts, for the OpenPGP overhead. */
export const MAX_BINARY_MESSAGE = 101 * 1024 * 1024;
const MAX_RECIPIENT_PACKETS = 100;
export const KEY_LIFETIME_SECONDS = 2 * 365 * 24 * 60 * 60;
/** Self-/binding signatures per component in the key sent to contacts: each extension adds one (~300 characters). */
const MAX_TRANSFER_SIGNATURES = 2;

export class PgpUserError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "PgpUserError";
    }
}

function translateKeyError(e: unknown): PgpUserError {
    const msg = String((e as Error)?.message ?? e);
    if (/passphrase/i.test(msg)) return new PgpUserError("Wrong passphrase.");
    if (/not of type private key|No secret key|not a private key/i.test(msg))
        return new PgpUserError("The file contains no private key. In Kleopatra: right-click the key → \"Backup Secret Keys…\" (\"Export Secret Keys\" in older versions).");
    if (/Misformed armored text|Unknown ASCII armor|armor/i.test(msg))
        return new PgpUserError("The file is not a valid PGP key file.");
    if (/unknown|unsupported|not supported|Version/i.test(msg))
        return new PgpUserError("This key type is not supported (e.g. Kyber/post-quantum or the v5 format). Please create a Curve25519 key in Kleopatra.");
    return new PgpUserError("The key could not be read: " + msg);
}

function isArmored(input: string) {
    return input.includes("-----BEGIN PGP");
}

/** Reads exactly one private key from armored text or binary data. */
export async function readPrivateKey(input: string | Uint8Array): Promise<PrivateKey> {
    let keys: PrivateKey[];
    try {
        keys = typeof input === "string" && isArmored(input)
            ? await openpgp.readPrivateKeys({ armoredKeys: input, config: PGP_CONFIG })
            : await openpgp.readPrivateKeys({ binaryKeys: typeof input === "string" ? new TextEncoder().encode(input) : input, config: PGP_CONFIG });
    } catch (e) {
        throw translateKeyError(e);
    }
    if (keys.length !== 1)
        throw new PgpUserError(`The file contains ${keys.length} keys. Please export exactly one secret key.`);
    return keys[0];
}

export async function readPublicKey(input: string | Uint8Array): Promise<PublicKey> {
    let keys: openpgp.Key[];
    try {
        keys = typeof input === "string" && isArmored(input)
            ? await openpgp.readKeys({ armoredKeys: input, config: PGP_CONFIG })
            : await openpgp.readKeys({ binaryKeys: typeof input === "string" ? new TextEncoder().encode(input) : input, config: PGP_CONFIG });
    } catch (e) {
        throw translateKeyError(e);
    }
    if (keys.length !== 1) throw new PgpUserError(`Expected exactly one key, found ${keys.length}.`);
    const key = keys[0];
    return key.isPrivate() ? key.toPublic() : key as PublicKey;
}

export function isKeyEncrypted(key: PrivateKey): boolean {
    return !key.isDecrypted();
}

export async function unlockPrivateKey(key: PrivateKey, passphrase: string): Promise<PrivateKey> {
    if (key.isDecrypted()) return key;
    try {
        return await openpgp.decryptKey({ privateKey: key, passphrase, config: PGP_CONFIG });
    } catch (e) {
        throw translateKeyError(e);
    }
}

export async function generatePrivateKey(name: string): Promise<PrivateKey> {
    const { privateKey } = await openpgp.generateKey({
        type: "ecc",
        curve: "curve25519Legacy",
        userIDs: [{ name }],
        keyExpirationTime: KEY_LIFETIME_SECONDS,
        format: "object",
        config: PGP_CONFIG
    });
    return privateKey;
}

/** When the key expires (ms since 1970), or null if it never does or cannot be read. */
export async function keyExpiry(key: AnyKey): Promise<number | null> {
    try {
        const exp = await key.getExpirationTime(undefined, FULL_CONFIG);
        return exp instanceof Date ? exp.getTime() : null;
    } catch {
        return null;
    }
}

/**
 * Adds what `update` has beyond `base` (newer self-signatures, e.g. a later expiry, or a revocation) to a
 * copy of `base`. Same fingerprint only. OpenPGP.js checks those signatures, but it would also copy user ids,
 * third-party certifications and subkeys of `update` unchecked: user ids and certifications are left out,
 * new subkeys only stay with a valid binding. It also keeps just one binding signature per subkey; the
 * older ones of `base` are put back, because a signing subkey needs them to check old messages.
 */
export async function mergeKeyCopies<T extends AnyKey>(base: T, update: AnyKey, now = new Date()): Promise<T> {
    const merged = await (base as openpgp.Key).update(update as PublicKey, now, FULL_CONFIG) as unknown as T;
    const baseUsers = new Map(base.users.map(u => [u.userID ?? u.userAttribute, u]));
    merged.users = merged.users.filter(u => baseUsers.has(u.userID ?? u.userAttribute));
    for (const user of merged.users) {
        const before = baseUsers.get(user.userID ?? user.userAttribute)!;
        user.otherCertifications = user.otherCertifications.filter(sig => before.otherCertifications.includes(sig));
    }
    const kept: openpgp.Subkey[] = [];
    for (const sub of merged.subkeys) {
        const before = base.subkeys.find(s => s.getFingerprint() === sub.getFingerprint());
        if (!before) {
            if (await sub.verify(now, FULL_CONFIG).then(() => true, () => false)) kept.push(sub);
            continue;
        }
        for (const sig of before.bindingSignatures)
            if (!sub.bindingSignatures.includes(sig)) sub.bindingSignatures.push(sig);
        kept.push(sub);
    }
    merged.subkeys = kept;
    return merged;
}

/**
 * A later expiry for the same key: new self-signatures, valid for `lifetimeSeconds` from `now`. Key material
 * and fingerprint stay, so the safety numbers stay too; the old self-signatures stay, so messages signed
 * before remain verifiable. Works for keys that have already expired; revoked keys cannot be extended.
 */
export async function extendKey(key: PrivateKey, now = new Date(), lifetimeSeconds = KEY_LIFETIME_SECONDS): Promise<PrivateKey> {
    const cfg = FULL_CONFIG;
    const expiry = await keyExpiry(key);
    // An expired key: take its components as they were just before it expired.
    const probe = expiry != null && expiry <= now.getTime() ? new Date(expiry - 1000) : now;
    const { user } = await key.getPrimaryUser(probe, undefined, cfg);
    if (!user.userID) throw new PgpUserError("The key has no user id that could be signed again.");
    const keepIds = new Set([
        (await key.getEncryptionKey(undefined, probe, undefined, cfg)).getKeyID().toHex(),
        (await key.getSigningKey(undefined, probe, undefined, cfg)).getKeyID().toHex()
    ]);
    // Only the current parts get new signatures; old or revoked subkeys must not come back to life.
    const current = new openpgp.PacketList<any>();
    current.push(key.keyPacket, user.userID, ...user.selfCertifications);
    for (const sub of key.subkeys)
        if (keepIds.has(sub.getKeyID().toHex())) current.push(sub.keyPacket, ...sub.bindingSignatures);

    const { privateKey: fresh } = await openpgp.reformatKey({
        privateKey: new openpgp.PrivateKey(current),
        // The user id exactly as it is (as "name"), so the new self-signature belongs to the same user id.
        userIDs: [{ name: user.userID.userID }],
        keyExpirationTime: Math.ceil((now.getTime() + lifetimeSeconds * 1000 - key.getCreationTime().getTime()) / 1000),
        date: now,
        format: "object",
        config: PGP_CONFIG
    });
    const extended = await mergeKeyCopies(key, fresh, now);
    if (fingerprintOf(extended) !== fingerprintOf(key)) throw new Error("Extending the key changed its fingerprint");
    await extended.verifyPrimaryKey(now, undefined, cfg);
    await extended.getEncryptionKey(undefined, now, undefined, cfg);
    return extended;
}

/** Passphrase-protected export for Kleopatra/GnuPG (iterated S2K, which GnuPG understands). */
export async function exportProtectedPrivateKey(key: PrivateKey, passphrase: string): Promise<string> {
    const protectedKey = await openpgp.encryptKey({
        privateKey: key,
        passphrase,
        config: { ...PGP_CONFIG, s2kType: openpgp.enums.s2k.iterated, s2kIterationCountByte: 255 }
    });
    return protectedKey.armor(FULL_CONFIG);
}

export function armorKey(key: AnyKey): string {
    return key.armor(FULL_CONFIG);
}

export function fingerprintOf(key: AnyKey): string {
    return key.getFingerprint().toUpperCase();
}

export function formatFingerprint(fpr: string): string {
    const groups = fpr.toUpperCase().match(/.{1,4}/g) ?? [];
    const half = Math.ceil(groups.length / 2);
    return groups.slice(0, half).join(" ") + "  " + groups.slice(half).join(" ");
}

export function keyHasKeyId(key: AnyKey, keyIdHex: string): boolean {
    const id = keyIdHex.toLowerCase();
    return key.getKeys().some(k => k.getKeyID().toHex() === id);
}

function algorithmLabel(info: openpgp.AlgorithmInfo): string {
    switch (info.algorithm) {
        case "eddsaLegacy": return info.curve === "ed25519Legacy" ? "Ed25519" : `EdDSA (${info.curve})`;
        case "ecdh": return info.curve === "curve25519Legacy" ? "Curve25519" : `ECDH (${info.curve})`;
        case "ecdsa": return `ECDSA (${info.curve})`;
        case "ed25519": return "Ed25519";
        case "x25519": return "X25519";
        case "ed448": return "Ed448";
        case "x448": return "X448";
        case "rsaEncryptSign":
        case "rsaEncrypt":
        case "rsaSign": return `RSA ${info.bits ?? "?"}`;
        case "dsa": return `DSA ${info.bits ?? "?"}`;
        case "elgamal": return `ElGamal ${info.bits ?? "?"}`;
        default: return String(info.algorithm);
    }
}

const LARGE_ALGORITHMS = new Set(["rsaEncryptSign", "rsaEncrypt", "rsaSign", "dsa", "elgamal"]);

export interface KeyReport {
    fingerprint: string;
    userIds: string[];
    primaryUserId: string;
    algorithm: string;
    encryptionAlgorithm: string | null;
    created: Date;
    expires: Date | null;
    /** Expired (and nothing else wrong with the primary key): a later expiry would make it usable again. */
    expired: boolean;
    isPrivate: boolean;
    errors: string[];
    warnings: string[];
}

const EMAIL_RE = /<[^<>@\s]+@[^<>@\s]+>|[^\s<>@]+@[^\s<>@]+\.[a-z]{2,}/i;

/** Checks a key for everything the mod needs and collects human-readable problems. */
export async function inspectKey(key: AnyKey, now = new Date()): Promise<KeyReport> {
    const errors: string[] = [];
    const warnings: string[] = [];

    const userIds = key.getUserIDs();
    let primaryUserId = userIds[0] ?? "";
    try {
        const primary = await key.getPrimaryUser(now, undefined, FULL_CONFIG);
        primaryUserId = primary.user.userID?.userID ?? primaryUserId;
    } catch { /* reported by verifyPrimaryKey below */ }

    let expired = false;
    try {
        await key.verifyPrimaryKey(now, undefined, FULL_CONFIG);
    } catch (e) {
        const msg = String((e as Error)?.message ?? e);
        if (/revoked/i.test(msg)) errors.push("The key has been revoked.");
        else if (/expired/i.test(msg)) {
            errors.push("The key has expired.");
            expired = true;
        } else errors.push("The key is invalid: " + msg);
    }

    let encryptionAlgorithm: string | null = null;
    let encryptionIsLarge = false;
    try {
        const encKey = await key.getEncryptionKey(undefined, now, undefined, FULL_CONFIG);
        const info = encKey.getAlgorithmInfo();
        encryptionAlgorithm = algorithmLabel(info);
        encryptionIsLarge = LARGE_ALGORITHMS.has(info.algorithm);
        if (encryptionIsLarge)
            warnings.push("RSA/DSA keys are very large: every message has much less room, and without Nitro the key exchange may not fit into one message. Recommended: Curve25519.");
    } catch {
        errors.push("No valid encryption subkey (missing, expired or revoked).");
    }

    const primaryInfo = key.getAlgorithmInfo();
    if (LARGE_ALGORITHMS.has(primaryInfo.algorithm) && !encryptionIsLarge)
        warnings.push("The primary key is RSA/DSA, which makes signatures and the key exchange large. Recommended: Curve25519.");

    if (key.isPrivate()) {
        const priv = key as PrivateKey;
        if ((priv.keyPacket as openpgp.SecretKeyPacket).isDummy?.())
            errors.push("The secret primary key is missing (smartcard or partial export). Please export the complete secret key.");
        if (priv.isDecrypted()) {
            try {
                const dec = await priv.getDecryptionKeys(undefined, now, undefined, FULL_CONFIG);
                if (!dec.length || dec.every(k => (k.keyPacket as any).isDummy?.()))
                    errors.push("The secret encryption subkey is missing.");
            } catch {
                errors.push("The secret encryption subkey is missing.");
            }
        }
    }

    if (userIds.some(u => EMAIL_RE.test(u)))
        warnings.push("The key contains an email address. It is sent through Discord with every key exchange and links your Discord account to you. Better: a separate key just for Discord, without an email address.");

    let expires: Date | null = null;
    try {
        const exp = await key.getExpirationTime(undefined, FULL_CONFIG);
        if (exp instanceof Date) expires = exp;
    } catch { /* invalid keys are already reported */ }
    if (expires && expires.getTime() - now.getTime() < 30 * 24 * 60 * 60 * 1000 && expires > now)
        warnings.push(`The key expires soon (${expires.toISOString().slice(0, 10)}).`);

    return {
        fingerprint: fingerprintOf(key),
        userIds,
        primaryUserId,
        algorithm: algorithmLabel(primaryInfo),
        encryptionAlgorithm,
        created: key.getCreationTime(),
        expires,
        expired,
        isPrivate: key.isPrivate(),
        errors,
        warnings
    };
}

/**
 * An own key for setup: if it has only expired, it gets a later expiry right away (as the mod does for its
 * keys), so an old export from Kleopatra still works. Any other problem stays in the report.
 */
export async function prepareOwnKey(key: PrivateKey, now = new Date()): Promise<{ key: PrivateKey; report: KeyReport; }> {
    const report = await inspectKey(key, now);
    if (!report.expired) return { key, report };
    try {
        const extended = await extendKey(key, now);
        const fresh = await inspectKey(extended, now);
        if (fresh.errors.length) return { key, report };
        const until = fresh.expires ? ` until ${fresh.expires.toISOString().slice(0, 10)}` : "";
        return { key: extended, report: { ...fresh, warnings: [`The key had expired; DcPgp extended it${until}.`, ...fresh.warnings] } };
    } catch {
        return { key, report };
    }
}

/** The newest `MAX_TRANSFER_SIGNATURES` of them, in their original order. */
function newestSignatures(sigs: openpgp.SignaturePacket[]): openpgp.SignaturePacket[] {
    const keep = new Set([...sigs].sort((a, b) => (b.created?.getTime() ?? 0) - (a.created?.getTime() ?? 0)).slice(0, MAX_TRANSFER_SIGNATURES));
    return sigs.filter(s => keep.has(s));
}

/**
 * The key that travels to contacts: primary key, one user id with its newest self-signatures,
 * the current encryption subkey and the signing subkey. No third-party certifications.
 */
export async function minimalPublicKey(key: PrivateKey, now = new Date()): Promise<PublicKey> {
    const cfg = FULL_CONFIG;
    const pub = key.toPublic();
    const primaryUser = await pub.getPrimaryUser(now, undefined, cfg);
    const keepIds = new Set<string>();
    const encKey = await key.getEncryptionKey(undefined, now, undefined, cfg);
    const sigKey = await key.getSigningKey(undefined, now, undefined, cfg);
    keepIds.add(encKey.getKeyID().toHex());
    keepIds.add(sigKey.getKeyID().toHex());

    const list = new openpgp.PacketList<any>();
    list.push(pub.keyPacket);
    list.push(...pub.revocationSignatures);
    list.push(...((pub as any).directSignatures ?? []));
    const { user } = primaryUser;
    list.push(user.userID!, ...user.revocationSignatures, ...newestSignatures(user.selfCertifications));
    for (const sub of pub.subkeys) {
        if (!keepIds.has(sub.getKeyID().toHex())) continue;
        list.push(sub.keyPacket, ...sub.revocationSignatures, ...newestSignatures(sub.bindingSignatures));
    }

    const minimal = new openpgp.PublicKey(list);
    await minimal.verifyPrimaryKey(now, undefined, cfg);
    await minimal.getEncryptionKey(undefined, now, undefined, cfg);
    return minimal;
}

/** Signs with signer and encrypts to all recipients. Key ids are hidden (wildcard). */
export async function encryptSigned(data: Uint8Array, recipients: PublicKey[], signer: PrivateKey): Promise<string> {
    if (!recipients.length) throw new Error("No recipients");
    const message = await openpgp.createMessage({ binary: data, format: "binary" });
    return openpgp.encrypt({
        message,
        encryptionKeys: recipients,
        signingKeys: signer,
        wildcard: true,
        format: "armored",
        config: PGP_CONFIG
    });
}

/**
 * An encrypted attachment: like a message (signed, hidden key ids), but binary, with the file's name in the
 * literal data. GnuPG opens it too: `gpg --decrypt --use-embedded-filename`.
 */
export async function encryptFileSigned(data: Uint8Array, filename: string, recipients: PublicKey[], signer: PrivateKey): Promise<Uint8Array> {
    if (!recipients.length) throw new Error("No recipients");
    const message = await openpgp.createMessage({ binary: data, filename, format: "binary" });
    return openpgp.encrypt({
        message,
        encryptionKeys: recipients,
        signingKeys: signer,
        wildcard: true,
        format: "binary",
        config: PGP_CONFIG
    }) as Promise<Uint8Array>;
}

/** "expired-key": the stored copy of the signer's key had expired when the message was signed. */
export type SignatureStatus = "valid" | "invalid" | "unknown-key" | "expired-key" | "missing";

export interface DecryptResult {
    data: Uint8Array;
    /** The name in the literal data (attachments carry the original file name there). */
    filename?: string;
    signature: {
        status: SignatureStatus;
        /** Key id (hex) of the key that made the signature, as stated in the signature. */
        keyId?: string;
        /** Fingerprint of the primary key that verified it (only when valid). */
        signerFingerprint?: string;
        created?: Date;
        error?: string;
    };
}

export class NotForUsError extends Error {
    constructor() {
        super("Not encrypted for you");
        this.name = "NotForUsError";
    }
}

/**
 * Step 1 of decryption, kept separate so "none of our keys fits" (NotForUsError) can never be
 * confused with "the message was altered" (an error from step 2).
 */
async function recoverSessionKeys(message: openpgp.Message<any>, decryptionKeys: PrivateKey[]): Promise<openpgp.SessionKey[]> {
    let keys: Awaited<ReturnType<typeof openpgp.decryptSessionKeys>>;
    try {
        keys = await openpgp.decryptSessionKeys({ message, decryptionKeys, config: PGP_CONFIG });
    } catch {
        throw new NotForUsError();
    }
    if (!keys.length) throw new NotForUsError();
    return keys as openpgp.SessionKey[];
}

function checkRecipientCount<T extends openpgp.Message<any>>(message: T): T {
    const pkesk = message.packets.filter(p => (p.constructor as any).tag === openpgp.enums.packet.publicKeyEncryptedSessionKey).length;
    if (pkesk > MAX_RECIPIENT_PACKETS) throw new Error("Too many recipient entries");
    return message;
}

export async function readMessageChecked(armored: string): Promise<openpgp.Message<string>> {
    if (armored.length > MAX_ARMORED_MESSAGE) throw new Error("Message too large");
    return checkRecipientCount(await openpgp.readMessage({ armoredMessage: armored, config: PGP_CONFIG }));
}

async function readBinaryMessageChecked(bytes: Uint8Array): Promise<openpgp.Message<Uint8Array>> {
    if (bytes.length > MAX_BINARY_MESSAGE) throw new Error("File too large");
    return checkRecipientCount(await openpgp.readMessage({ binaryMessage: bytes, config: PGP_CONFIG }));
}

export async function decryptVerified(armored: string, decryptionKeys: PrivateKey[], verificationKeys: PublicKey[]): Promise<DecryptResult> {
    return decryptMessageVerified(await readMessageChecked(armored), decryptionKeys, verificationKeys);
}

/** An encrypted attachment; same checks as for a message. */
export async function decryptFileVerified(bytes: Uint8Array, decryptionKeys: PrivateKey[], verificationKeys: PublicKey[]): Promise<DecryptResult> {
    return decryptMessageVerified(await readBinaryMessageChecked(bytes), decryptionKeys, verificationKeys);
}

async function decryptMessageVerified(message: openpgp.Message<any>, decryptionKeys: PrivateKey[], verificationKeys: PublicKey[]): Promise<DecryptResult> {
    const sessionKeys = await recoverSessionKeys(message, decryptionKeys);
    const result = await openpgp.decrypt({
        message,
        sessionKeys,
        verificationKeys: verificationKeys.length ? verificationKeys : undefined,
        expectSigned: false,
        format: "binary",
        config: PGP_CONFIG
    });

    const data = result.data as Uint8Array;
    const filename = typeof result.filename === "string" ? result.filename : undefined;
    const sigs = result.signatures ?? [];
    if (!sigs.length) return { data, filename, signature: { status: "missing" } };

    const sig = sigs[0];
    const keyId = sig.keyID.toHex();
    let created: Date | undefined;
    try {
        const s = await sig.signature;
        created = (s.packets[0] as any)?.created ?? undefined;
    } catch { /* ignore */ }

    try {
        await sig.verified;
        const signer = verificationKeys.find(k => keyHasKeyId(k, keyId));
        return { data, filename, signature: { status: "valid", keyId, created, signerFingerprint: signer ? fingerprintOf(signer) : undefined } };
    } catch (e) {
        const msg = String((e as Error)?.message ?? e);
        const status: SignatureStatus = /key is expired/i.test(msg) ? "expired-key"
            : /Could not find signing key|signing key with key ID/i.test(msg) ? "unknown-key" : "invalid";
        return { data, filename, signature: { status, keyId, created, error: msg } };
    }
}

/** Unsigned encryption used for the vault's recovery copy. */
export async function encryptToKeys(data: Uint8Array, keys: PublicKey[]): Promise<string> {
    const message = await openpgp.createMessage({ binary: data, format: "binary" });
    return openpgp.encrypt({ message, encryptionKeys: keys, format: "armored", config: PGP_CONFIG });
}

export async function decryptWithKeys(armored: string, keys: PrivateKey[]): Promise<Uint8Array> {
    const message = await readMessageChecked(armored);
    const sessionKeys = await recoverSessionKeys(message, keys);
    const res = await openpgp.decrypt({ message, sessionKeys, format: "binary", config: PGP_CONFIG });
    return res.data as Uint8Array;
}

export function sameKey(a: AnyKey, b: AnyKey): boolean {
    return fingerprintOf(a) === fingerprintOf(b);
}
