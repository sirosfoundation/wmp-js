# @sirosfoundation/wmp-js

[![CI](https://github.com/sirosfoundation/wmp-js/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/wmp-js/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](LICENSE)

TypeScript implementation of the Wallet Messaging Protocol (WMP) — a JSON-RPC 2.0 protocol for bidirectional communication between wallet frontends and backend services.

## Features

- **JSON-RPC 2.0** request/response and notification handling
- **Bidirectional peer** with concurrent request tracking and timeout support
- **Pluggable transports** — WebSocket and HTTP+SSE included
- **Flow profile** for orchestrating multi-step wallet flows (issuance, presentation, etc.)
- **Zero runtime dependencies**, ESM-only
- **Fully tested** — 38 tests

## Install

```bash
npm install @sirosfoundation/wmp-js
```

## Quick Start

```typescript
import { Peer, HttpSseTransport } from "@sirosfoundation/wmp-js";

const transport = new HttpSseTransport({
  rpcUrl: "https://wallet-backend.example.com/wmp/rpc",
  eventsUrl: "https://wallet-backend.example.com/wmp/events",
});

const peer = new Peer(transport, {
  // Handle incoming notifications
  onNotification: (method, params) => {
    console.log("notification:", method, params);
  },
});

await peer.connect();

// Create a session
const session = await peer.request("wmp.session.create", {
  wmp: { version: "0.1", session_id: "" },
  auth: { token: "bearer-token" },
});

// Start a flow
const flow = await peer.request("wmp.flow.start", {
  wmp: { version: "0.1", session_id: session.session_id },
  flow_type: "issuance",
  flow_id: "flow-1",
});
```

## API

### Transport

```typescript
interface Transport {
  send(data: string): Promise<void>;
  onMessage(handler: (data: string) => void): void;
  connect(): Promise<void>;
  close(): void;
}
```

Built-in transports:
- `WebSocketTransport` — full-duplex WebSocket
- `HttpSseTransport` — HTTP POST for requests, SSE for server notifications

### Peer

Bidirectional JSON-RPC 2.0 peer over any `Transport`.

```typescript
const peer = new Peer(transport, options);

// Send request and wait for response
const result = await peer.request("method.name", params);

// Send notification (no response expected)
peer.notify("method.name", params);
```

### Flow Profile

Higher-level abstraction for wallet flows.

```typescript
import { Registry } from "@sirosfoundation/wmp-js";

const registry = new Registry();

registry.register("issuance", {
  onStart: async (ctx, params) => { /* ... */ },
  onProgress: async (ctx, params) => { /* ... */ },
  onComplete: async (ctx, params) => { /* ... */ },
});
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
