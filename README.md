# @sirosfoundation/wmp-js

[![CI](https://github.com/sirosfoundation/wmp-js/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/wmp-js/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/wmp-js/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/wmp-js)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](LICENSE)

TypeScript implementation of the Wallet Messaging Protocol (WMP) — a JSON-RPC 2.0 protocol for bidirectional communication between wallet frontends and backend services.

## Features

- **JSON-RPC 2.0** request/response and notification handling
- **Bidirectional peer** with concurrent request tracking and timeout support
- **Pluggable transports** — WebSocket and HTTP+SSE included
- **Profiles** for structured flows (OpenID4VCI, OpenID4VP, signing), MLS and evidence
- **Per-request proof** for HTTPS sessions (WMP Core §4.4.8)
- ESM-only

## Install

```bash
npm install @sirosfoundation/wmp-js
```

## Quick Start

```typescript
import { Peer, HttpSseTransport } from "@sirosfoundation/wmp-js";

// POST endpoint and event-stream endpoint, then options.
const transport = new HttpSseTransport(
  "https://wallet-backend.example.com/wmp",
  "https://wallet-backend.example.com/wmp/events",
  { authorization: "Bearer <token>" },
);

const peer = new Peer(transport, {
  handler: {
    onFlowProgress: (params) => console.log("progress:", params),
    onMessageDeliver: (params) => console.log("message:", params),
  },
});

// Create a session. The peer binds the session id to the transport.
const session = await peer.createSession({
  sender: "did:web:me.example.com",
  security: { mode: "tls" },
  ttl: 3600,
});

// Open the event stream for the session: server-initiated messages arrive on it.
transport.connectSSE();

// Start a flow.
const flow = await peer.startFlow("oid4vci", "flow-1", { credential_offer_uri: "..." });

// Any other method.
const caps = await peer.call("wmp.capability.list", {
  wmp: { version: "0.1", session_id: session.wmp.session_id },
});
```

The order matters: `createSession()` first, `connectSSE()` after it. Binding a session to a transport whose stream was never opened opens nothing, and such a session sends but receives no events. Once the stream is open, a later session (a new create or a resume) reopens it automatically.

### Node.js

Node has no global `EventSource` (it is behind `--experimental-eventsource`), so pass one to the transport. The [`eventsource`](https://www.npmjs.com/package/eventsource) package accepts the `fetch` function the transport uses to send the Authorization header and the per-request proof on the stream:

```typescript
import { EventSource } from "eventsource";

const transport = new HttpSseTransport(rpcUrl, eventsUrl, { EventSource });
```

A browser's native `EventSource` sends no Authorization header; a deployment that authenticates the stream by header needs the same polyfill there.

## API

### Transport

```typescript
interface Transport {
  send(msg: Message): Promise<void>;
  close(): void;
  on(event: "message" | "error" | "close" | "open" | "gap", listener): void;
  off(event, listener): void;
}
```

Built-in transports:
- `WebSocketTransport(url, opts?)` — full-duplex WebSocket
- `HttpSseTransport(rpcUrl, eventsUrl, opts?)` — HTTP POST for requests, SSE for server-initiated messages. `connectSSE()` opens the stream; `setAuthorization()` replaces the Authorization value.
- `StdioTransport`, `UnixSocketTransport` — from `@sirosfoundation/wmp-js/node`

#### Per-request proof

For a deployment that terminates TLS without forwarding the client certificate, `HttpSseTransport` sends the per-request proof of WMP Core §4.4.8 on every request that names a session:

```typescript
const signer = webCryptoProofSigner(privateKey);
const transport = new HttpSseTransport(rpcUrl, eventsUrl, {
  requestProof: (req) => createRequestProof({ signer, x5c: chain, ...req }),
});
```

`verifyRequestProof` checks a proof on the receiving side.

### Peer

Bidirectional JSON-RPC 2.0 peer over any `Transport`.

```typescript
const peer = new Peer(transport, { handler, callTimeout: 30_000 });

// Session lifecycle
await peer.createSession({ sender, participants, capabilities, security, auth, ttl });
await peer.resumeSession();
await peer.closeSession();

// Send a request and wait for the response
const result = await peer.call("method.name", params);

// Send a notification (no response expected)
await peer.notify("method.name", params);

// Flows and resolution
await peer.startFlow(flowType, flowId, params);
await peer.flowAction(flowId, action, params);
await peer.resolve("vctm", "https://credentials.example.com/identity");
```

Incoming calls go to the `handler` option (`onSessionCreate`, `onMessageDeliver`, `onFlowStart`, `onFlowProgress`, `onFlowAction`, `onFlowComplete`, `onFlowError`, `onResolve`, ...); a method without a handler is answered "method not found".

### Profiles

A profile adds flow types, methods or resolve types to a peer:

```typescript
import { OpenID4xProfile } from "@sirosfoundation/wmp-js";

peer.use(new OpenID4xProfile(config));
```

## Development

```bash
npm install
npm test          # run tests
npm run test:watch # watch mode
npm run build     # compile TypeScript
npm run lint      # type-check
```

## License

[BSD-2-Clause](LICENSE) — Copyright (c) 2026, SIROS Foundation
