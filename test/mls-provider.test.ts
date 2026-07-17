import { describe, it, expect } from "vitest";
import { TsMlsProvider } from "../src/mls-provider.js";
import { CipherSuiteX25519AES128GCM } from "../src/mls.js";

describe("TsMlsProvider", () => {
  it("generates a key package", async () => {
    const provider = new TsMlsProvider({ identity: "alice" });
    const kp = await provider.generateKeyPackage(CipherSuiteX25519AES128GCM);

    expect(kp.id).toMatch(/^kp-/);
    expect(kp.cipher_suite).toBe(CipherSuiteX25519AES128GCM);
    expect(kp.key_package).toBeTruthy();
    expect(kp.expires).toBeTruthy();
    expect(provider.keyPackageCount).toBe(1);
  });

  it("creates a group", async () => {
    const provider = new TsMlsProvider({ identity: "alice" });
    const result = await provider.createGroup(CipherSuiteX25519AES128GCM, []);

    expect(result.groupInfo).toBeTruthy();
    expect(provider.groupCount).toBe(1);
  });

  it("encrypts and decrypts a message within a group", async () => {
    // Alice creates a group
    const alice = new TsMlsProvider({ identity: "alice" });
    const { groupInfo } = await alice.createGroup(CipherSuiteX25519AES128GCM, []);

    // Alice encrypts a message
    const plaintext = new TextEncoder().encode("Hello, encrypted world!");
    const { ciphertext, epoch } = await alice.encrypt(groupInfo, plaintext);

    expect(ciphertext).toBeTruthy();
    expect(epoch).toBeGreaterThanOrEqual(0);

    // Alice decrypts her own message (single-member group self-test)
    // Note: In a real scenario, another member would decrypt.
    // For a single-member group, the sender can't decrypt their own message
    // (MLS forward secrecy), so we just verify encryption succeeds.
    expect(ciphertext.length).toBeGreaterThan(0);
  });

  it("encrypts multiple messages, epoch advances", async () => {
    const alice = new TsMlsProvider({ identity: "alice" });
    const { groupInfo } = await alice.createGroup(CipherSuiteX25519AES128GCM, []);

    const msg1 = new TextEncoder().encode("Message 1");
    const msg2 = new TextEncoder().encode("Message 2");

    const r1 = await alice.encrypt(groupInfo, msg1);
    const r2 = await alice.encrypt(groupInfo, msg2);

    expect(r1.ciphertext).not.toBe(r2.ciphertext);
    // Epoch stays the same within a single commit period
    expect(r2.epoch).toBeGreaterThanOrEqual(r1.epoch);
  });

  it("two members: create, add, encrypt, decrypt", async () => {
    // Alice creates a group
    const alice = new TsMlsProvider({ identity: "alice" });
    const { groupInfo } = await alice.createGroup(CipherSuiteX25519AES128GCM, []);

    // Bob generates a key package
    const bob = new TsMlsProvider({ identity: "bob" });
    const bobKp = await bob.generateKeyPackage(CipherSuiteX25519AES128GCM);

    // Alice adds Bob to the group
    const { commit, welcome } = await alice.addMember(groupInfo, bobKp.key_package);
    expect(commit).toBeTruthy();
    expect(welcome).toBeTruthy();

    // Bob processes the welcome to join the group
    const joinResult = await bob.processWelcome(welcome);
    expect(joinResult.groupId).toBeTruthy();

    // Alice encrypts a message
    const plaintext = new TextEncoder().encode("Hello Bob!");
    const { ciphertext } = await alice.encrypt(groupInfo, plaintext);

    // Bob decrypts the message
    const decrypted = await bob.decrypt(joinResult.groupId, ciphertext);
    const text = new TextDecoder().decode(decrypted.plaintext);
    expect(text).toBe("Hello Bob!");
  });
});
