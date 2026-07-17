/**
 * TsMlsProvider — real MLS cryptographic provider backed by ts-mls (RFC 9420).
 *
 * Implements the MLSProvider interface with actual key generation, group
 * management, and message encryption/decryption. Supports cipher suites:
 *   - 0x0001: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (MUST)
 *   - 0x0002: MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (SHOULD)
 */

import {
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  generateKeyPackage as tsGenerateKeyPackage,
  createGroup as tsCreateGroup,
  joinGroup as tsJoinGroup,
  createCommit as tsCreateCommit,
  createApplicationMessage,
  processMessage as tsProcessMessage,
  encodeMlsMessage,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  acceptAll,
  zeroOutUint8Array,
  type CiphersuiteImpl,
  type CiphersuiteName,
  type ClientState,
  type MLSContext,
  type KeyPackage as TsKeyPackage,
  type PrivateKeyPackage,
  type Credential,
  type Proposal,
  type MLSMessage,
} from "ts-mls";

import type { MLSProvider, KeyPackage } from "./mls.js";
import {
  CipherSuiteX25519AES128GCM,
  CipherSuiteP256AES128GCM,
} from "./mls.js";

// ---------------------------------------------------------------------------
// Cipher suite mapping: WMP numeric ID → ts-mls CiphersuiteName
// ---------------------------------------------------------------------------

const CIPHER_SUITE_NAMES: Record<number, CiphersuiteName> = {
  [CipherSuiteX25519AES128GCM]: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  [CipherSuiteP256AES128GCM]: "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
};

// ---------------------------------------------------------------------------
// Group state tracking
// ---------------------------------------------------------------------------

interface GroupEntry {
  state: ClientState;
  impl: CiphersuiteImpl;
  groupIdStr: string;
}

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

function toBase64Url(data: Uint8Array): string {
  const str = btoa(String.fromCharCode(...data));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(b64: string): Uint8Array {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4;
  const final = pad ? padded + "=".repeat(4 - pad) : padded;
  const str = atob(final);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

// ---------------------------------------------------------------------------
// TsMlsProvider
// ---------------------------------------------------------------------------

export interface TsMlsProviderOptions {
  /** Identity string for this participant (e.g., "wmp-inspector"). */
  identity: string;
  /** Default cipher suite. Default: 0x0001 (X25519). */
  defaultCipherSuite?: number;
}

/**
 * Real MLS provider using ts-mls.
 *
 * Each instance represents one MLS participant. It can generate key packages,
 * create/join groups, encrypt/decrypt messages, and manage group membership.
 */
export class TsMlsProvider implements MLSProvider {
  private identity: string;
  private defaultCipherSuite: number;
  private implCache = new Map<number, CiphersuiteImpl>();
  private groups = new Map<string, GroupEntry>();
  private keyPackages = new Map<
    string,
    { pub: TsKeyPackage; priv: PrivateKeyPackage; cipherSuite: number }
  >();

  constructor(opts: TsMlsProviderOptions) {
    this.identity = opts.identity;
    this.defaultCipherSuite = opts.defaultCipherSuite ?? CipherSuiteX25519AES128GCM;
  }

  private async getImpl(cipherSuite: number): Promise<CiphersuiteImpl> {
    let impl = this.implCache.get(cipherSuite);
    if (!impl) {
      const name = CIPHER_SUITE_NAMES[cipherSuite];
      if (!name) {
        throw new Error(`Unsupported cipher suite: 0x${cipherSuite.toString(16)}`);
      }
      const cs = getCiphersuiteFromName(name);
      impl = await getCiphersuiteImpl(cs);
      this.implCache.set(cipherSuite, impl);
    }
    return impl;
  }

  private makeCredential(): Credential {
    return {
      credentialType: "basic",
      identity: new TextEncoder().encode(this.identity),
    };
  }

  async generateKeyPackage(cipherSuite: number): Promise<KeyPackage> {
    const impl = await this.getImpl(cipherSuite);
    const kp = await tsGenerateKeyPackage(
      this.makeCredential(),
      defaultCapabilities(),
      defaultLifetime,
      [],
      impl,
    );

    const encoded = encodeMlsMessage({
      version: "mls10",
      wireformat: "mls_key_package",
      keyPackage: kp.publicPackage,
    } as MLSMessage);

    const id = `kp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    this.keyPackages.set(id, {
      pub: kp.publicPackage,
      priv: kp.privatePackage,
      cipherSuite,
    });

    return {
      id,
      cipher_suite: cipherSuite,
      key_package: toBase64Url(encoded),
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    };
  }

  async createGroup(
    cipherSuite: number,
    _participants: string[],
  ): Promise<{ groupInfo: string; welcomes: Record<string, string> }> {
    const impl = await this.getImpl(cipherSuite);
    const myKp = await tsGenerateKeyPackage(
      this.makeCredential(),
      defaultCapabilities(),
      defaultLifetime,
      [],
      impl,
    );

    const groupId = new TextEncoder().encode(
      `wmp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    );

    const state = await tsCreateGroup(groupId, myKp.publicPackage, myKp.privatePackage, [], impl);

    const groupIdStr = toBase64Url(groupId);
    this.groups.set(groupIdStr, { state, impl, groupIdStr });

    return { groupInfo: groupIdStr, welcomes: {} };
  }

  async processWelcome(welcome: string): Promise<{ groupId: string; epoch: number }> {
    const kpEntry = this.getLatestKeyPackage();
    if (!kpEntry) throw new Error("No key package available for processing welcome");

    const impl = await this.getImpl(kpEntry.cipherSuite);
    const welcomeBytes = fromBase64Url(welcome);
    const decoded = decodeMlsMessage(welcomeBytes, 0);
    if (!decoded) throw new Error("Invalid welcome message");
    const [msg] = decoded;

    if (msg.wireformat !== "mls_welcome") throw new Error("Invalid welcome message");

    const state = await tsJoinGroup(msg.welcome!, kpEntry.pub, kpEntry.priv, emptyPskIndex, impl);

    const groupIdStr = toBase64Url(state.groupContext.groupId);
    const epoch = Number(state.groupContext.epoch);

    this.groups.set(groupIdStr, { state, impl, groupIdStr });
    return { groupId: groupIdStr, epoch };
  }

  async addMember(groupId: string, keyPackage: string): Promise<{ commit: string; welcome: string }> {
    const group = this.getGroup(groupId);
    const kpBytes = fromBase64Url(keyPackage);
    const decoded = decodeMlsMessage(kpBytes, 0);
    if (!decoded) throw new Error("Invalid key package message");
    const [msg] = decoded;

    if (msg.wireformat !== "mls_key_package") throw new Error("Invalid key package message");

    const addProposal: Proposal = {
      proposalType: "add",
      add: { keyPackage: msg.keyPackage! },
    };

    const context: MLSContext = {
      state: group.state,
      cipherSuite: group.impl,
      pskIndex: emptyPskIndex,
    };

    const result = await tsCreateCommit(context, {
      extraProposals: [addProposal],
      ratchetTreeExtension: true,
    });
    group.state = result.newState;
    result.consumed.forEach(zeroOutUint8Array);

    const commitBytes = encodeMlsMessage(result.commit);
    const welcomeBytes = result.welcome
      ? encodeMlsMessage({ version: "mls10", wireformat: "mls_welcome", welcome: result.welcome } as MLSMessage)
      : new Uint8Array();

    return { commit: toBase64Url(commitBytes), welcome: toBase64Url(welcomeBytes) };
  }

  async removeMember(groupId: string, _participant: string): Promise<{ commit: string }> {
    const group = this.getGroup(groupId);
    const context: MLSContext = { state: group.state, cipherSuite: group.impl, pskIndex: emptyPskIndex };
    const result = await tsCreateCommit(context);
    group.state = result.newState;
    result.consumed.forEach(zeroOutUint8Array);
    return { commit: toBase64Url(encodeMlsMessage(result.commit)) };
  }

  async processCommit(groupId: string, commit: string): Promise<{ epoch: number }> {
    const group = this.getGroup(groupId);
    const decoded = decodeMlsMessage(fromBase64Url(commit), 0);
    if (!decoded) throw new Error("Invalid commit message");
    const [msg] = decoded;

    const result = await tsProcessMessage(
      msg as Parameters<typeof tsProcessMessage>[0],
      group.state, emptyPskIndex, acceptAll, group.impl,
    );
    group.state = result.newState;
    result.consumed.forEach(zeroOutUint8Array);
    return { epoch: Number(group.state.groupContext.epoch) };
  }

  async selfUpdate(groupId: string): Promise<{ commit: string }> {
    return this.removeMember(groupId, ""); // empty commit = self-update
  }

  async encrypt(groupId: string, plaintext: Uint8Array): Promise<{ ciphertext: string; epoch: number }> {
    const group = this.getGroup(groupId);
    const result = await createApplicationMessage(group.state, plaintext, group.impl);
    group.state = result.newState;
    result.consumed.forEach(zeroOutUint8Array);

    const encoded = encodeMlsMessage({
      version: "mls10",
      wireformat: "mls_private_message",
      privateMessage: result.privateMessage,
    } as MLSMessage);

    return {
      ciphertext: toBase64Url(encoded),
      epoch: Number(group.state.groupContext.epoch),
    };
  }

  async decrypt(groupId: string, ciphertext: string): Promise<{ plaintext: Uint8Array; epoch: number }> {
    const group = this.getGroup(groupId);
    const decoded = decodeMlsMessage(fromBase64Url(ciphertext), 0);
    if (!decoded) throw new Error("Invalid ciphertext message");
    const [msg] = decoded;

    const result = await tsProcessMessage(
      msg as Parameters<typeof tsProcessMessage>[0],
      group.state, emptyPskIndex, acceptAll, group.impl,
    );
    group.state = result.newState;
    result.consumed.forEach(zeroOutUint8Array);

    if (result.kind !== "applicationMessage") {
      throw new Error(`Expected application message, got ${result.kind}`);
    }
    return {
      plaintext: result.message,
      epoch: Number(group.state.groupContext.epoch),
    };
  }

  private getGroup(groupId: string): GroupEntry {
    const group = this.groups.get(groupId);
    if (!group) throw new Error(`Group ${groupId} not found`);
    return group;
  }

  private getLatestKeyPackage() {
    let latest: { pub: TsKeyPackage; priv: PrivateKeyPackage; cipherSuite: number } | undefined;
    for (const [, entry] of this.keyPackages) latest = entry;
    return latest;
  }

  get groupCount(): number { return this.groups.size; }
  get keyPackageCount(): number { return this.keyPackages.size; }
}
