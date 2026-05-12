import { describe, it, expect } from "vitest";
import {
  MLSMethod,
  CipherSuiteX25519AES128GCM,
  CipherSuiteP256AES128GCM,
  CredentialType,
  MLSProfile,
  mlsMethods,
} from "../src/mls.js";
import type {
  GroupCreateParams,
  GroupJoinParams,
  GroupAddParams,
  GroupRemoveParams,
  GroupUpdateParams,
  MessageFetchParams,
  GroupCreateResult,
  GroupJoinResult,
  GroupAddResult,
  GroupRemoveResult,
  MessageFetchResult,
  MLSHandler,
} from "../src/mls.js";
import { ErrorCode } from "../src/types.js";

describe("MLS method constants", () => {
  it("defines all 6 MLS methods", () => {
    const methods = mlsMethods();
    expect(methods).toHaveLength(6);
    expect(methods).toContain("wmp.mls.group.create");
    expect(methods).toContain("wmp.mls.group.join");
    expect(methods).toContain("wmp.mls.group.add");
    expect(methods).toContain("wmp.mls.group.remove");
    expect(methods).toContain("wmp.mls.group.update");
    expect(methods).toContain("wmp.message.fetch");
  });

  it("has correct cipher suite values", () => {
    expect(CipherSuiteX25519AES128GCM).toBe(0x0001);
    expect(CipherSuiteP256AES128GCM).toBe(0x0002);
  });

  it("has correct credential types", () => {
    expect(CredentialType.Basic).toBe("basic");
    expect(CredentialType.X509).toBe("x509");
  });
});

// Test handler that tracks calls
class TestMLSHandler implements MLSHandler {
  lastMethod = "";

  async groupCreate(params: GroupCreateParams): Promise<GroupCreateResult> {
    this.lastMethod = MLSMethod.GroupCreate;
    return { wmp: params.wmp, group_id: params.group_id, epoch: 0 };
  }

  async groupJoin(params: GroupJoinParams): Promise<GroupJoinResult> {
    this.lastMethod = MLSMethod.GroupJoin;
    return { wmp: params.wmp, group_id: "grp-1", epoch: 0 };
  }

  async groupAdd(params: GroupAddParams): Promise<GroupAddResult> {
    this.lastMethod = MLSMethod.GroupAdd;
    return { wmp: params.wmp, epoch: 1 };
  }

  async groupRemove(params: GroupRemoveParams): Promise<GroupRemoveResult> {
    this.lastMethod = MLSMethod.GroupRemove;
    return { wmp: params.wmp, epoch: 2 };
  }

  async groupUpdate(params: GroupUpdateParams): Promise<void> {
    this.lastMethod = MLSMethod.GroupUpdate;
  }

  async messageFetch(params: MessageFetchParams): Promise<MessageFetchResult> {
    this.lastMethod = MLSMethod.MessageFetch;
    return { wmp: params.wmp, messages: [], has_more: false };
  }
}

describe("MLSProfile dispatch", () => {
  const handler = new TestMLSHandler();
  const profile = new MLSProfile(handler);

  const wmp = { version: "0.1", session_id: "ses-1" };

  it("dispatches GroupCreate", async () => {
    const result = await profile.handleMethod(MLSMethod.GroupCreate, {
      wmp,
      group_id: "grp-1",
      cipher_suite: CipherSuiteX25519AES128GCM,
      group_info: "Z3Jw",
      welcomes: { alice: "d2VsY29tZQ" },
    });
    expect(handler.lastMethod).toBe(MLSMethod.GroupCreate);
    expect(result).toHaveProperty("group_id", "grp-1");
  });

  it("dispatches GroupJoin", async () => {
    const result = await profile.handleMethod(MLSMethod.GroupJoin, {
      wmp,
      welcome_processed: true,
    });
    expect(handler.lastMethod).toBe(MLSMethod.GroupJoin);
    expect(result).toHaveProperty("epoch", 0);
  });

  it("dispatches GroupAdd", async () => {
    const result = await profile.handleMethod(MLSMethod.GroupAdd, {
      wmp,
      participant: "did:web:dave.example.com",
      commit: "Y29tbWl0",
      welcome: "d2VsY29tZQ",
    });
    expect(handler.lastMethod).toBe(MLSMethod.GroupAdd);
    expect(result).toHaveProperty("epoch", 1);
  });

  it("dispatches GroupRemove", async () => {
    const result = await profile.handleMethod(MLSMethod.GroupRemove, {
      wmp,
      participant: "did:web:carol.example.com",
      commit: "Y29tbWl0",
    });
    expect(handler.lastMethod).toBe(MLSMethod.GroupRemove);
    expect(result).toHaveProperty("epoch", 2);
  });

  it("dispatches GroupUpdate (notification)", async () => {
    const result = await profile.handleMethod(MLSMethod.GroupUpdate, {
      wmp,
      commit: "Y29tbWl0",
    });
    expect(handler.lastMethod).toBe(MLSMethod.GroupUpdate);
    expect(result).toBeUndefined();
  });

  it("dispatches MessageFetch", async () => {
    const result = await profile.handleMethod(MLSMethod.MessageFetch, {
      wmp,
      since_epoch: 2,
      sessions: ["ses-1"],
    });
    expect(handler.lastMethod).toBe(MLSMethod.MessageFetch);
    expect(result).toHaveProperty("has_more", false);
  });

  it("rejects unknown MLS method", async () => {
    await expect(
      profile.handleMethod("wmp.mls.unknown", { wmp }),
    ).rejects.toMatchObject({ code: ErrorCode.MethodNotFound });
  });
});

describe("GroupCreateParams serialization", () => {
  it("round-trips through JSON", () => {
    const params: GroupCreateParams = {
      wmp: { version: "0.1", session_id: "ses-abc" },
      group_id: "Z3JvdXAtMQ",
      cipher_suite: CipherSuiteX25519AES128GCM,
      accepted_credential_types: ["x509", "basic"],
      accepted_identity_schemes: ["did", "x509", "uri"],
      group_info: "Z3JvdXBpbmZv",
      welcomes: {
        "did:web:bob.example.com": "d2VsY29tZS1ib2I",
        "did:web:carol.example.com": "d2VsY29tZS1jYXJvbA",
      },
    };

    const json = JSON.stringify(params);
    const decoded = JSON.parse(json) as GroupCreateParams;

    expect(decoded.cipher_suite).toBe(CipherSuiteX25519AES128GCM);
    expect(Object.keys(decoded.welcomes)).toHaveLength(2);
    expect(decoded.accepted_credential_types).toHaveLength(2);
  });
});

describe("EncryptedEnvelope", () => {
  it("carries encrypted metadata correctly", () => {
    const env = {
      wmp: {
        version: "0.1",
        session_id: "ses-abc",
        encrypted: true,
        epoch: 3,
        sender: "did:web:alice.example.com",
      },
      ciphertext: "Y2lwaGVydGV4dC1kYXRh",
    };

    const json = JSON.stringify(env);
    const decoded = JSON.parse(json);

    expect(decoded.wmp.encrypted).toBe(true);
    expect(decoded.wmp.epoch).toBe(3);
    expect(decoded.ciphertext).toBe("Y2lwaGVydGV4dC1kYXRh");
  });
});
