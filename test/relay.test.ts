import { describe, it, expect, vi, beforeEach } from "vitest";
import { Relay } from "../src/relay.js";
import { Method, ErrorCode } from "../src/types.js";

describe("Relay registration", () => {
  let relay: Relay;

  beforeEach(() => {
    relay = new Relay({ registrationTTL: 60_000 });
  });

  it("registers a participant", async () => {
    const result = (await relay.handleMethod(Method.RelayRegister, {
      wmp: { version: "0.1", sender: "x509:san:dns:alice.example.com" },
    })) as { registered: boolean; ttl: number };

    expect(result.registered).toBe(true);
    expect(result.ttl).toBe(60);
    expect(relay.isRegistered("x509:san:dns:alice.example.com")).toBe(true);
  });

  it("rejects missing sender", async () => {
    await expect(
      relay.handleMethod(Method.RelayRegister, {
        wmp: { version: "0.1" },
      }),
    ).rejects.toMatchObject({ code: ErrorCode.InvalidParams });
  });

  it("rejects unknown method", async () => {
    await expect(
      relay.handleMethod("wmp.relay.unknown", {}),
    ).rejects.toMatchObject({ code: ErrorCode.MethodNotFound });
  });

  it("returns correct methods list", () => {
    expect(relay.methods()).toEqual(["wmp.relay.register"]);
  });

  it("unregisters a participant", async () => {
    await relay.handleMethod(Method.RelayRegister, {
      wmp: { version: "0.1", sender: "x509:san:dns:alice.example.com" },
    });
    relay.unregister("x509:san:dns:alice.example.com");
    expect(relay.isRegistered("x509:san:dns:alice.example.com")).toBe(false);
  });
});

describe("Relay message queue", () => {
  let relay: Relay;

  beforeEach(() => {
    relay = new Relay({
      maxQueueSize: 3,
      messageTTL: 60_000,
    });
  });

  it("enqueues and drains messages", () => {
    relay.enqueue("x509:san:dns:alice.example.com", { body: "hello" });
    relay.enqueue("x509:san:dns:alice.example.com", { body: "world" });

    expect(relay.queueLength("x509:san:dns:alice.example.com")).toBe(2);

    const messages = relay.drain("x509:san:dns:alice.example.com");
    expect(messages).toHaveLength(2);
    expect(messages[0].data).toEqual({ body: "hello" });
    expect(relay.queueLength("x509:san:dns:alice.example.com")).toBe(0);
  });

  it("rejects when queue is full", () => {
    relay.enqueue("x509:san:dns:bob.example.com", { n: 1 });
    relay.enqueue("x509:san:dns:bob.example.com", { n: 2 });
    relay.enqueue("x509:san:dns:bob.example.com", { n: 3 });

    expect(() => relay.enqueue("x509:san:dns:bob.example.com", { n: 4 })).toThrow();
  });

  it("returns empty array for unknown participant", () => {
    const messages = relay.drain("x509:san:dns:nobody.example.com");
    expect(messages).toEqual([]);
  });

  it("reports zero queue length for unknown participant", () => {
    expect(relay.queueLength("x509:san:dns:nobody.example.com")).toBe(0);
  });
});

describe("Relay expiry", () => {
  it("expires registrations", async () => {
    const relay = new Relay({ registrationTTL: 1 }); // 1ms TTL

    await relay.handleMethod(Method.RelayRegister, {
      wmp: { version: "0.1", sender: "x509:san:dns:alice.example.com" },
    });

    // Wait for expiry
    await new Promise((r) => setTimeout(r, 10));

    expect(relay.isRegistered("x509:san:dns:alice.example.com")).toBe(false);
  });

  it("purges expired messages", () => {
    const relay = new Relay({ messageTTL: 1 }); // 1ms TTL

    relay.enqueue("x509:san:dns:alice.example.com", { body: "test" });

    // Wait for expiry then purge
    const start = Date.now();
    while (Date.now() - start < 5) {
      /* spin */
    }

    relay.purgeExpired();
    expect(relay.queueLength("x509:san:dns:alice.example.com")).toBe(0);
  });

  it("purges expired registrations", async () => {
    const relay = new Relay({ registrationTTL: 1 }); // 1ms TTL

    await relay.handleMethod(Method.RelayRegister, {
      wmp: { version: "0.1", sender: "x509:san:dns:alice.example.com" },
    });

    await new Promise((r) => setTimeout(r, 10));
    relay.purgeExpired();

    expect(relay.isRegistered("x509:san:dns:alice.example.com")).toBe(false);
  });
});
