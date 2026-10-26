/*
 * DcPgp simulation – a small stand-in for Discord: one server, two accounts on one PC (switched like in the
 * real app), and the stores, actions and flux events the plugin uses. The server records everything it
 * receives, so the run can prove that Discord never got any plaintext.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { hkdfSync, randomBytes } from "node:crypto";

export interface SimUser { id: string; username: string; globalName: string; }

export const ALICE: SimUser = { id: "100000000000000001", username: "alice", globalName: "Alice" };
export const BOB: SimUser = { id: "100000000000000002", username: "bob", globalName: "Bob" };
export const DM_ID = "200000000000000001";
const USERS = [ALICE, BOB];

// --- what Discord received, and what the user saw -------------------------------------------------

export interface Seen { what: string; text: string; bytes?: Uint8Array; }
/** Everything that reached the server: message texts, edits, file names, alt texts, file contents. */
export const seen: Seen[] = [];
const record = (what: string, text: string, bytes?: Uint8Array) => void seen.push({ what, text, bytes });

export const toasts: { kind: string; text: string; }[] = [];
export const dialogs: { title: string; answer: string; }[] = [];
export const logLines: string[] = [];
export const safetyNumbers: { viewer: string; name: string; number: string; }[] = [];

/** Answers for dialogs, by a part of their title; unanswered dialogs are cancelled, as if closed. */
export const answers = new Map<string, string>();
/** How the simulated users answer DcPgp's key dialogs. */
export const policy = { acceptKey: "accept", keyChange: "accept", verify: "match" };

// --- snowflakes -----------------------------------------------------------------------------------

const EPOCH = 1_420_070_400_000n;
let lastMs = 0;
let sequence = 0;

export function snowflake(ms = Date.now()): string {
    if (ms <= lastMs) sequence++;
    else {
        lastMs = ms;
        sequence = 0;
    }
    return String(((BigInt(lastMs) - EPOCH) << 22n) | BigInt(sequence & 0xfff));
}

// --- the PC: storage, device key (DPAPI), power events ----------------------------------------------

const storage = new Map<string, unknown>();
export const DataStoreMock = {
    async get<T = any>(key: string): Promise<T | undefined> {
        return storage.has(key) ? structuredClone(storage.get(key)) as T : undefined;
    },
    async set(key: string, value: unknown) {
        storage.set(key, structuredClone(value));
    },
    async del(key: string) {
        storage.delete(key);
    },
    async keys() {
        return [...storage.keys()];
    }
};

const deviceKey = randomBytes(32);
let deviceKeyCreated = false;
const powerWaiters: Array<(event: string) => void> = [];

/** Windows reports a power event (screen locked or unlocked, standby). */
export function powerEvent(event: "lock-screen" | "unlock-screen" | "suspend") {
    for (const resolve of powerWaiters.splice(0)) resolve(event);
}

/** Ends the plugin's long poll for power events, so nothing is left waiting. */
export function releasePowerWaiters() {
    for (const resolve of powerWaiters.splice(0)) resolve("timeout");
}

const cdn = new Map<string, Uint8Array>();
export const savedFiles = new Map<string, Uint8Array | string>();

/** The plugin's native (main process) part, with the same derivations as native.ts. */
export const nativeMock = {
    async deviceKeyStatus() {
        return deviceKeyCreated ? "ok" : "missing";
    },
    async deriveSlotKey(argonOutput: Uint8Array, salt: Uint8Array) {
        deviceKeyCreated = true;
        return new Uint8Array(hkdfSync("sha256", Buffer.concat([Buffer.from(argonOutput), deviceKey]), Buffer.from(salt), "dcpgp vault slotA v1", 32));
    },
    async deriveWindowsKey(salt: Uint8Array) {
        if (!deviceKeyCreated) throw new Error("DCPGP_DEVICE_MISSING");
        return new Uint8Array(hkdfSync("sha256", deviceKey, Buffer.from(salt), "dcpgp vault slotW v1", 32));
    },
    async guardKey() {
        deviceKeyCreated = true;
        return new Uint8Array(hkdfSync("sha256", deviceKey, Buffer.from("dcpgp"), "dcpgp guard v1", 32));
    },
    async getIdleSeconds() {
        return 0;
    },
    async getIdleState() {
        return "active";
    },
    waitForPowerEvent(_timeoutMs: number) {
        return new Promise<string>(resolve => powerWaiters.push(resolve));
    },
    async clearClipboardIfMatches() {
        return false;
    },
    async clearClipboardIfEquals() {
        return false;
    },
    async saveTextFile(name: string, content: string) {
        savedFiles.set(name, content);
        return "C:\\Users\\sim\\Documents\\" + name;
    },
    async saveBinaryFile(name: string, content: Uint8Array) {
        savedFiles.set(name, content.slice());
        return "C:\\Users\\sim\\Downloads\\" + name;
    },
    async fetchAttachment(url: string) {
        const bytes = cdn.get(url);
        if (!bytes) throw new Error("404 Not Found");
        return bytes.slice();
    }
};

// --- one client per account ---------------------------------------------------------------------------

class Client {
    messages = new Map<string, any>();
    uploads = new Map<string, FakeUpload[]>();
    editing = new Map<string, { messageId: string; textValue: string; }>();
    /** Events the server sent while this account was not the active one. */
    queue: any[] = [];
    constructor(readonly user: SimUser) { }
}

const clients = new Map(USERS.map(u => [u.id, new Client(u)]));
let current = clients.get(ALICE.id)!;

export const currentUser = () => current.user;
export const otherUser = () => current.user.id === ALICE.id ? BOB : ALICE;
export const clientMessages = () => current.messages;

function toRecord(raw: any, state: "SENT" | "SENDING") {
    return {
        id: raw.id,
        channel_id: raw.channel_id,
        author: { ...raw.author },
        content: raw.content,
        attachments: raw.attachments.map((a: any) => ({ ...a })),
        nonce: raw.nonce ?? null,
        type: 0,
        state,
        timestamp: new Date(raw.timestamp),
        editedTimestamp: raw.edited_timestamp ? new Date(raw.edited_timestamp) : null,
        flags: 0
    };
}

// --- flux --------------------------------------------------------------------------------------------

const interceptors: Array<(action: any) => boolean> = [];
const subscriptions = new Map<string, Set<(action: any) => void>>();

export const FluxDispatcher = {
    _interceptors: interceptors,
    addInterceptor(fn: (action: any) => boolean) {
        interceptors.push(fn);
    },
    subscribe(type: string, fn: (action: any) => void) {
        let set = subscriptions.get(type);
        if (!set) subscriptions.set(type, set = new Set());
        set.add(fn);
    },
    unsubscribe(type: string, fn: (action: any) => void) {
        subscriptions.get(type)?.delete(fn);
    },
    /** Like Discord: interceptors first (true drops the action), then the stores, then subscribers. */
    dispatch(action: any): Promise<void> {
        for (const fn of [...interceptors]) if (fn(action)) return Promise.resolve();
        reduce(action);
        for (const fn of [...subscriptions.get(action.type) ?? []]) fn(action);
        return Promise.resolve();
    }
};

const uploadKey = (channelId: string, draftType: unknown) => `${channelId}:${draftType ?? 0}`;
const uploadsOf = (channelId: string, draftType: unknown) => {
    const key = uploadKey(channelId, draftType);
    let list = current.uploads.get(key);
    if (!list) current.uploads.set(key, list = []);
    return list;
};

function reduce(action: any) {
    switch (action.type) {
        case "MESSAGE_CREATE": {
            const m = action.message;
            if (!action.optimistic && m.nonce) current.messages.delete(m.nonce);
            current.messages.set(m.id, toRecord(m, action.optimistic ? "SENDING" : "SENT"));
            break;
        }
        case "MESSAGE_UPDATE": {
            const r = current.messages.get(action.message.id);
            if (r) {
                r.content = action.message.content;
                r.editedTimestamp = new Date(action.message.edited_timestamp);
            }
            break;
        }
        case "MESSAGE_START_EDIT":
            current.editing.set(action.channelId, { messageId: action.messageId, textValue: action.content });
            break;
        case "MESSAGE_END_EDIT":
            current.editing.delete(action.channelId);
            break;
        case "UPLOAD_ATTACHMENT_ADD_FILES": {
            // Like Discord: the upload starts the moment a file is attached.
            const list = uploadsOf(action.channelId, action.draftType);
            for (const item of action.files) {
                const upload = new FakeUpload(item, action.channelId);
                void upload.upload();
                list.push(upload);
            }
            break;
        }
        case "UPLOAD_ATTACHMENT_CLEAR_ALL_FILES":
            current.uploads.set(uploadKey(action.channelId, action.draftType), []);
            break;
    }
}

// --- stores ----------------------------------------------------------------------------------------

function dmChannel() {
    const partner = otherUser().id;
    return {
        id: DM_ID,
        type: 1,
        guild_id: null,
        recipients: [partner],
        isDM: () => true,
        isGroupDM: () => false,
        isMultiUserDM: () => false,
        isThread: () => false,
        isPrivate: () => true,
        getGuildId: () => null,
        getRecipientId: () => partner
    };
}

export const ChannelStore = {
    getChannel: (id: string) => id === DM_ID ? dmChannel() : undefined,
    getDMFromUserId: (userId: string) => USERS.some(u => u.id === userId) && userId !== current.user.id ? DM_ID : undefined
};

export const UserStore = {
    getCurrentUser: () => ({ id: current.user.id, username: current.user.username, globalName: current.user.globalName }),
    getUser: (id: string) => {
        const u = USERS.find(x => x.id === id);
        return u ? { id: u.id, username: u.username, globalName: u.globalName } : undefined;
    }
};

export const MessageStore = {
    getMessage: (_channelId: string, id: string) => current.messages.get(id),
    getMessages: () => ({ toArray: () => [...current.messages.values()] })
};

export const EditMessageStore = {
    isEditing: (channelId: string, messageId: string) => current.editing.get(channelId)?.messageId === messageId,
    isEditingAny: (channelId: string) => current.editing.has(channelId),
    getEditingTextValue: (channelId: string) => current.editing.get(channelId)?.textValue,
    getEditingMessageId: (channelId: string) => current.editing.get(channelId)?.messageId
};

export const UploadAttachmentStore = {
    getUploads: (channelId: string, draftType: unknown) => [...uploadsOf(channelId, draftType)],
    getUploadCount: (channelId: string, draftType: unknown) => uploadsOf(channelId, draftType).length
};

/** Drafts as Discord would persist them: the plugin filters encrypted chats out of this. */
export const draftState: Record<string, Record<string, Record<number, { draft: string; timestamp: number; }>>> = {};
export const DraftStore = {
    getState: () => draftState,
    asyncPersist: () => undefined
};

// --- uploads and the server ---------------------------------------------------------------------------

const uploaded = new Map<string, Uint8Array>();
let uploadSeq = 0;

export class FakeUpload {
    id = String(++uploadSeq);
    filename: string;
    description: string | null = null;
    spoiler = false;
    status = "NOT_STARTED";
    uploadedFilename = "";
    private started: Promise<void> | null = null;

    constructor(readonly item: { file: File; platform?: number; }, readonly channelId: string) {
        this.filename = item.file.name;
    }

    /** POST /attachments with the name, then the bytes: from here on Discord has the file. */
    upload(): Promise<void> {
        this.started ??= (async () => {
            const bytes = new Uint8Array(await this.item.file.arrayBuffer());
            this.uploadedFilename = `${randomBytes(6).toString("hex")}/${this.filename}`;
            uploaded.set(this.uploadedFilename, bytes);
            record("file uploaded on attaching", this.filename, bytes);
            this.status = "COMPLETED";
        })();
        return this.started;
    }
}

export const serverMessages = new Map<string, any>();
export const serverStats = { sends: 0, edits: 0 };

function deliver(event: any) {
    FluxDispatcher.dispatch(structuredClone(event));
    for (const c of clients.values()) if (c !== current) c.queue.push(structuredClone(event));
}

async function serverSend(channelId: string, message: any, options: any = {}) {
    const author = { id: current.user.id, username: current.user.username, global_name: current.user.globalName };
    let content: string = typeof message?.content === "string" ? message.content : "";
    if (content.startsWith("@silent ")) content = content.slice("@silent ".length);
    const uploads: FakeUpload[] = options.attachmentsToUpload ?? [];
    if (!content && !uploads.length && !options.poll) return;

    const nonce = options.nonce ?? snowflake();
    // Discord's local copy while sending: its id is the nonce, its state "SENDING".
    FluxDispatcher.dispatch({
        type: "MESSAGE_CREATE", channelId, optimistic: true,
        message: { id: nonce, nonce, channel_id: channelId, author, content, attachments: [], timestamp: new Date().toISOString(), edited_timestamp: null, state: "SENDING" }
    });
    for (const u of uploads) await u.upload();

    serverStats.sends++;
    record("message", content);
    if (options.poll) record("poll", JSON.stringify(options.poll));
    const attachments = uploads.map(u => {
        const id = snowflake();
        const url = `https://cdn.discordapp.com/attachments/${channelId}/${id}/${u.filename}?ex=0`;
        const bytes = uploaded.get(u.uploadedFilename)!;
        cdn.set(url, bytes);
        record("attachment of a message", `${u.filename} ${u.description ?? ""}`);
        return { id, filename: u.filename, size: bytes.length, url, description: u.description };
    });
    const raw = { id: snowflake(), nonce, channel_id: channelId, author, content, attachments, timestamp: new Date().toISOString(), edited_timestamp: null };
    serverMessages.set(raw.id, raw);
    deliver({ type: "MESSAGE_CREATE", channelId, optimistic: false, message: raw });
    return { body: raw };
}

async function serverEdit(channelId: string, messageId: string, message: any) {
    const raw = serverMessages.get(messageId);
    if (!raw || raw.author.id !== current.user.id) throw new Error("403: Cannot edit a message authored by another user");
    const content: string = message?.content ?? "";
    serverStats.edits++;
    record("edited message", content);
    raw.content = content;
    raw.edited_timestamp = new Date().toISOString();
    deliver({ type: "MESSAGE_UPDATE", channelId, message: structuredClone(raw) });
}

/** Discord's MessageActions; the plugin wraps _sendMessage and editMessage on this very object. */
export const MessageActions: any = {
    sendMessage(channelId: string, message: any, _waitForChannelReady?: boolean, options: any = {}) {
        return MessageActions._sendMessage(channelId, message, options);
    },
    _sendMessage(channelId: string, message: any, options: any = {}) {
        return serverSend(channelId, message, options);
    },
    sendPollMessage(channelId: string, poll: any, options: any = {}) {
        return MessageActions._sendMessage(channelId, { content: "", tts: false, invalidEmojis: [], validNonShortcutEmojis: [] }, { ...options, poll });
    },
    editMessage(channelId: string, messageId: string, message: any) {
        return serverEdit(channelId, messageId, message);
    },
    startEditMessage(channelId: string, messageId: string, content: string, source?: string) {
        FluxDispatcher.dispatch({ type: "MESSAGE_START_EDIT", channelId, messageId, content, source });
    },
    startEditMessageRecord(channelId: string, message: any, source?: string) {
        MessageActions.startEditMessage(channelId, message.id, message.content, source);
    },
    endEditMessage(channelId: string, response?: unknown) {
        FluxDispatcher.dispatch({ type: "MESSAGE_END_EDIT", channelId, response });
    },
    deleteMessage(channelId: string, messageId: string) {
        serverMessages.delete(messageId);
        deliver({ type: "MESSAGE_DELETE", channelId, id: messageId });
    }
};

/** What a compromised or curious Discord could do on its side. */
export const attacker = {
    /** Posts an old message of its author again, as a new message. */
    replay(messageId: string) {
        const old = serverMessages.get(messageId);
        const raw = { ...structuredClone(old), id: snowflake(), nonce: null, timestamp: new Date().toISOString(), edited_timestamp: null };
        serverMessages.set(raw.id, raw);
        deliver({ type: "MESSAGE_CREATE", channelId: raw.channel_id, optimistic: false, message: raw });
        return raw.id as string;
    },
    /** Serves the file of another message in place of this message's first file. */
    swapFile(targetMessageId: string, sourceMessageId: string) {
        const target = serverMessages.get(targetMessageId).attachments[0];
        const source = serverMessages.get(sourceMessageId).attachments[0];
        cdn.set(target.url, cdn.get(source.url)!);
    }
};

// --- accounts --------------------------------------------------------------------------------------

/** Like switching accounts in Discord: the old one logs out, the new one connects. */
export function switchAccount(user: SimUser) {
    FluxDispatcher.dispatch({ type: "LOGOUT" });
    current = clients.get(user.id)!;
    FluxDispatcher.dispatch({ type: "CONNECTION_OPEN" });
}

/** Hands the active account the events it missed, as if it had been online all along. */
export function deliverQueued() {
    for (const event of current.queue.splice(0)) FluxDispatcher.dispatch(event);
}

// --- the chat input -------------------------------------------------------------------------------

export function attach(channelId: string, files: File[]) {
    FluxDispatcher.dispatch({ type: "UPLOAD_ATTACHMENT_ADD_FILES", channelId, draftType: 0, files: files.map(file => ({ file, platform: 1 })) });
}

/** The parts of Discord's chat input the plugin hooks into, in Discord's order. */
export async function chatSend(channelId: string, text: string, handlePreSend: (...args: any[]) => Promise<boolean>) {
    const channel = ChannelStore.getChannel(channelId);
    const uploads = UploadAttachmentStore.getUploads(channelId, 0);
    const message = { content: text, tts: false, invalidEmojis: [], validNonShortcutEmojis: [] };
    const options: any = { location: "chat_input" };
    const props = { channel, content: text, hasStickers: false, hasAttachments: uploads.length > 0, openWarningPopout: () => undefined };
    if (await handlePreSend(channelId, message, options, props)) return null;
    if (uploads.length) {
        options.attachmentsToUpload = uploads;
        options.eagerDispatch = false;
        FluxDispatcher.dispatch({ type: "UPLOAD_ATTACHMENT_CLEAR_ALL_FILES", channelId, draftType: 0 });
    }
    const result = await MessageActions.sendMessage(channelId, message, undefined, options);
    return (result?.body ?? null) as any;
}

/** The edit box: start, then save a new text, as Discord's edit component does. */
export async function saveEdit(channelId: string, messageId: string, text: string, handlePreEdit: (...args: any[]) => Promise<boolean>) {
    const record = current.messages.get(messageId);
    const parsed = { content: text, tts: false, invalidEmojis: [], validNonShortcutEmojis: [] };
    if (await handlePreEdit(channelId, messageId, parsed)) return "cancelled" as const;
    MessageActions.endEditMessage(channelId);
    if (parsed.content === record.content) return "unchanged" as const;
    await MessageActions.editMessage(channelId, messageId, parsed);
    return "saved" as const;
}
