/**
 * WMP MLS types and handler interface — mirrors go-wmp/pkg/wmp/mls/mls.go.
 *
 * Defines MLS group lifecycle methods, types, and the MLSHandler interface
 * per the wmp-mls spec. Actual MLS cryptographic operations are delegated
 * to an MLSProvider implementation backed by an MLS library.
 */

import type { Metadata } from "./types.js";

// ---------------------------------------------------------------------------
// Method constants
// ---------------------------------------------------------------------------

export const MLSMethod = {
  GroupCreate: "wmp.mls.group.create",
  GroupJoin: "wmp.mls.group.join",
  GroupAdd: "wmp.mls.group.add",
  GroupRemove: "wmp.mls.group.remove",
  GroupUpdate: "wmp.mls.group.update",
  MessageFetch: "wmp.message.fetch",
} as const;

export type MLSMethodName = (typeof MLSMethod)[keyof typeof MLSMethod];

// ---------------------------------------------------------------------------
// Cipher suite constants
// ---------------------------------------------------------------------------

/** MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 — MUST support. */
export const CipherSuiteX25519AES128GCM = 0x0001;

/** MLS_128_DHKEMP256_AES128GCM_SHA256_P256 — SHOULD support. */
export const CipherSuiteP256AES128GCM = 0x0002;

// ---------------------------------------------------------------------------
// MLS credential types
// ---------------------------------------------------------------------------

export const CredentialType = {
  Basic: "basic",
  X509: "x509",
} as const;

// ---------------------------------------------------------------------------
// Param/Result types for MLS methods
// ---------------------------------------------------------------------------

export interface GroupCreateParams {
  wmp: Metadata;
  group_id: string;
  cipher_suite: number;
  accepted_credential_types?: string[];
  accepted_identity_schemes?: string[];
  group_info: string;
  welcomes: Record<string, string>;
}

export interface GroupCreateResult {
  wmp: Metadata;
  group_id: string;
  epoch: number;
}

export interface GroupJoinParams {
  wmp: Metadata;
  welcome_processed: boolean;
}

export interface GroupJoinResult {
  wmp: Metadata;
  group_id: string;
  epoch: number;
}

export interface GroupAddParams {
  wmp: Metadata;
  participant: string;
  commit: string;
  welcome: string;
}

export interface GroupAddResult {
  wmp: Metadata;
  epoch: number;
}

export interface GroupRemoveParams {
  wmp: Metadata;
  participant: string;
  commit: string;
}

export interface GroupRemoveResult {
  wmp: Metadata;
  epoch: number;
}

export interface GroupUpdateParams {
  wmp: Metadata;
  commit: string;
}

export interface MessageFetchParams {
  wmp: Metadata;
  since_epoch?: number;
  sessions?: string[];
}

export interface MessageFetchResult {
  wmp: Metadata;
  messages: unknown[];
  has_more: boolean;
}

// ---------------------------------------------------------------------------
// Key packages
// ---------------------------------------------------------------------------

export interface KeyPackage {
  id: string;
  cipher_suite: number;
  key_package: string; // base64url-encoded
  expires: string;
}

export interface KeyPackagesResponse {
  key_packages: KeyPackage[];
}

// ---------------------------------------------------------------------------
// Encrypted envelope
// ---------------------------------------------------------------------------

export interface EncryptedEnvelope {
  wmp: Metadata;
  ciphertext: string; // base64url-encoded MLSMessage
}

// ---------------------------------------------------------------------------
// MLSHandler interface
// ---------------------------------------------------------------------------

/**
 * MLSHandler processes MLS group lifecycle operations.
 * Implement this to manage MLS groups in your application.
 */
export interface MLSHandler {
  groupCreate(params: GroupCreateParams): Promise<GroupCreateResult>;
  groupJoin(params: GroupJoinParams): Promise<GroupJoinResult>;
  groupAdd(params: GroupAddParams): Promise<GroupAddResult>;
  groupRemove(params: GroupRemoveParams): Promise<GroupRemoveResult>;
  groupUpdate(params: GroupUpdateParams): Promise<void>;
  messageFetch(params: MessageFetchParams): Promise<MessageFetchResult>;
}

// ---------------------------------------------------------------------------
// MLSProvider — abstracts MLS cryptographic engine
// ---------------------------------------------------------------------------

/**
 * MLSProvider abstracts MLS cryptographic operations. Implementations wrap
 * an MLS library to provide key package generation, group management,
 * and message encryption/decryption.
 */
export interface MLSProvider {
  generateKeyPackage(cipherSuite: number): Promise<KeyPackage>;
  createGroup(
    cipherSuite: number,
    participants: string[],
  ): Promise<{ groupInfo: string; welcomes: Record<string, string> }>;
  processWelcome(welcome: string): Promise<{ groupId: string; epoch: number }>;
  addMember(
    groupId: string,
    keyPackage: string,
  ): Promise<{ commit: string; welcome: string }>;
  removeMember(
    groupId: string,
    participant: string,
  ): Promise<{ commit: string }>;
  processCommit(groupId: string, commit: string): Promise<{ epoch: number }>;
  selfUpdate(groupId: string): Promise<{ commit: string }>;
  encrypt(
    groupId: string,
    plaintext: Uint8Array,
  ): Promise<{ ciphertext: string; epoch: number }>;
  decrypt(
    groupId: string,
    ciphertext: string,
  ): Promise<{ plaintext: Uint8Array; epoch: number }>;
}

// ---------------------------------------------------------------------------
// MLS Profile — MethodHandler for WMP registry
// ---------------------------------------------------------------------------

import type { MethodHandler } from "./profile.js";
import { WMPError } from "./jsonrpc.js";
import { ErrorCode } from "./types.js";

/**
 * MLSProfile is a WMP MethodHandler that dispatches wmp.mls.* methods to an
 * MLSHandler. Register it with the peer's registry to enable MLS support:
 *
 *   const mlsProfile = new MLSProfile(handler);
 *   for (const method of mlsMethods()) {
 *     registry.registerMethod(method, mlsProfile);
 *   }
 */
export class MLSProfile implements MethodHandler {
  constructor(private handler: MLSHandler) {}

  methods(): string[] {
    return mlsMethods();
  }

  async handleMethod(method: string, params: unknown): Promise<unknown> {
    const p = params as Record<string, unknown>;

    switch (method) {
      case MLSMethod.GroupCreate:
        return this.handler.groupCreate(p as unknown as GroupCreateParams);
      case MLSMethod.GroupJoin:
        return this.handler.groupJoin(p as unknown as GroupJoinParams);
      case MLSMethod.GroupAdd:
        return this.handler.groupAdd(p as unknown as GroupAddParams);
      case MLSMethod.GroupRemove:
        return this.handler.groupRemove(p as unknown as GroupRemoveParams);
      case MLSMethod.GroupUpdate:
        await this.handler.groupUpdate(p as unknown as GroupUpdateParams);
        return undefined;
      case MLSMethod.MessageFetch:
        return this.handler.messageFetch(p as unknown as MessageFetchParams);
      default:
        throw new WMPError(ErrorCode.MethodNotFound, `Unknown MLS method: ${method}`);
    }
  }
}

/**
 * Returns the list of MLS method names for registration convenience.
 */
export function mlsMethods(): string[] {
  return Object.values(MLSMethod);
}

// ---------------------------------------------------------------------------
// NoopMLSHandler — TLS-only sessions
// ---------------------------------------------------------------------------

/**
 * NoopMLSHandler implements MLSHandler for TLS-only sessions.
 * It accepts group lifecycle operations but performs no actual MLS
 * cryptographic operations. Suitable for point-to-point sessions
 * where transport-level TLS provides sufficient security.
 */
export class NoopMLSHandler implements MLSHandler {
  private groups = new Map<string, { epoch: number; members: Set<string> }>();

  async groupCreate(params: GroupCreateParams): Promise<GroupCreateResult> {
    const members = new Set<string>(Object.keys(params.welcomes));
    if (params.wmp.sender) members.add(params.wmp.sender);
    this.groups.set(params.group_id, { epoch: 0, members });
    return { wmp: params.wmp, group_id: params.group_id, epoch: 0 };
  }

  async groupJoin(params: GroupJoinParams): Promise<GroupJoinResult> {
    return { wmp: params.wmp, group_id: "noop-group", epoch: 0 };
  }

  async groupAdd(params: GroupAddParams): Promise<GroupAddResult> {
    for (const [, g] of this.groups) {
      g.members.add(params.participant);
      g.epoch++;
      return { wmp: params.wmp, epoch: g.epoch };
    }
    throw new WMPError(ErrorCode.MLSError, "No group found");
  }

  async groupRemove(params: GroupRemoveParams): Promise<GroupRemoveResult> {
    for (const [, g] of this.groups) {
      g.members.delete(params.participant);
      g.epoch++;
      return { wmp: params.wmp, epoch: g.epoch };
    }
    throw new WMPError(ErrorCode.MLSError, "No group found");
  }

  async groupUpdate(_params: GroupUpdateParams): Promise<void> {
    // Noop: no key rotation.
  }

  async messageFetch(params: MessageFetchParams): Promise<MessageFetchResult> {
    return { wmp: params.wmp, messages: [], has_more: false };
  }
}

/**
 * NoopMLSProvider implements MLSProvider for TLS-only sessions.
 * Messages pass through unencrypted, relying on transport-level TLS.
 */
export class NoopMLSProvider implements MLSProvider {
  private groups = new Map<string, { epoch: number }>();

  async generateKeyPackage(cipherSuite: number): Promise<KeyPackage> {
    return {
      id: "noop-kp-1",
      cipher_suite: cipherSuite,
      key_package: "",
      expires: "2099-12-31T23:59:59Z",
    };
  }

  async createGroup(_cs: number, participants: string[]): Promise<{ groupInfo: string; welcomes: Record<string, string> }> {
    const welcomes: Record<string, string> = {};
    for (const p of participants) welcomes[p] = "";
    return { groupInfo: "", welcomes };
  }

  async processWelcome(_welcome: string): Promise<{ groupId: string; epoch: number }> {
    return { groupId: "noop-group", epoch: 0 };
  }

  async addMember(groupId: string, _kp: string): Promise<{ commit: string; welcome: string }> {
    const g = this.groups.get(groupId) ?? { epoch: 0 };
    g.epoch++;
    this.groups.set(groupId, g);
    return { commit: "", welcome: "" };
  }

  async removeMember(groupId: string, _p: string): Promise<{ commit: string }> {
    const g = this.groups.get(groupId) ?? { epoch: 0 };
    g.epoch++;
    this.groups.set(groupId, g);
    return { commit: "" };
  }

  async processCommit(groupId: string, _commit: string): Promise<{ epoch: number }> {
    const g = this.groups.get(groupId) ?? { epoch: 0 };
    g.epoch++;
    this.groups.set(groupId, g);
    return { epoch: g.epoch };
  }

  async selfUpdate(groupId: string): Promise<{ commit: string }> {
    const g = this.groups.get(groupId) ?? { epoch: 0 };
    g.epoch++;
    this.groups.set(groupId, g);
    return { commit: "" };
  }

  async encrypt(_groupId: string, plaintext: Uint8Array): Promise<{ ciphertext: string; epoch: number }> {
    return { ciphertext: new TextDecoder().decode(plaintext), epoch: 0 };
  }

  async decrypt(_groupId: string, ciphertext: string): Promise<{ plaintext: Uint8Array; epoch: number }> {
    return { plaintext: new TextEncoder().encode(ciphertext), epoch: 0 };
  }
}
