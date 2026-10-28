/**
 * Peer — the core WMP client/server dispatcher.
 * Mirrors go-wmp/pkg/wmp/peer.go.
 *
 * Handles incoming messages by dispatching to handlers/profiles,
 * and provides methods to send outgoing requests and notifications.
 */

import {
  type Message,
  type Request,
  type Response,
  type RPCError,
  isRequest,
  isResponse,
  isNotification,
  createRequest,
  createNotification,
  createResponse,
  createErrorResponse,
  WMPError,
} from "./jsonrpc.js";
import { type Transport } from "./transport.js";
import {
  type Profile,
  type PeerContext,
  type FlowHandler,
  Registry,
} from "./profile.js";
import { type ValidationError } from "./schema.js";
import { CompletionResultError, dcqlQueryIds, validateCompletionResult, validateMatchResult } from "./completion.js";
import { unsupportedError } from "./errors.js";
import { SUPPORTED_VERSIONS, negotiateVersion, parseVersion, versionRejection } from "./version.js";
import {
  type Metadata,
  type SessionCreateParams,
  type SessionCreateResult,
  type SessionResumeParams,
  type SessionResumeResult,
  type SessionCloseParams,
  type SessionAuthenticateParams,
  type SessionAuthenticateResult,
  type MessageDeliverParams,
  type MessageAckParams,
  type MessagePollParams,
  type MessagePollResult,
  type MessageStatusParams,
  type CapabilityUpdateParams,
  type CapabilityUpdateResult,
  type CapabilityListParams,
  type CapabilityListResult,
  type FlowStartParams,
  type FlowStartResult,
  type FlowProgressParams,
  type FlowActionParams,
  type FlowActionResult,
  type FlowCompleteParams,
  type FlowErrorParams,
  type FlowCancelParams,
  type FlowCancelResult,
  type ResolveParams,
  type ResolveResult,
  type Capabilities,
  type SecurityMode,
  ErrorCode,
  Method,
  VERSION,
} from "./types.js";

// ---------------------------------------------------------------------------
// Handler — application-level callback interface
// ---------------------------------------------------------------------------

/**
 * Handler processes incoming WMP method calls.
 * All methods are optional — unimplemented methods return "method not found".
 */
export interface Handler {
  // Session lifecycle
  onSessionCreate?(params: SessionCreateParams): Promise<SessionCreateResult>;
  onSessionResume?(params: SessionResumeParams): Promise<SessionResumeResult>;
  onSessionClose?(params: SessionCloseParams): void;
  onSessionAuthenticate?(params: SessionAuthenticateParams): Promise<SessionAuthenticateResult>;

  // Message delivery
  onMessageDeliver?(params: MessageDeliverParams): void;
  onMessageAck?(params: MessageAckParams): void;
  onMessagePoll?(params: MessagePollParams): Promise<MessagePollResult>;
  onMessageStatus?(params: MessageStatusParams): void;

  // Capability negotiation
  onCapabilityUpdate?(params: CapabilityUpdateParams): Promise<CapabilityUpdateResult>;
  onCapabilityList?(params: CapabilityListParams): Promise<CapabilityListResult>;

  // Structured flows
  onFlowStart?(params: FlowStartParams): Promise<FlowStartResult>;
  onFlowProgress?(params: FlowProgressParams): void;
  onFlowAction?(params: FlowActionParams): Promise<FlowActionResult>;
  onFlowComplete?(params: FlowCompleteParams): void;
  onFlowError?(params: FlowErrorParams): void;
  onFlowCancel?(params: FlowCancelParams): Promise<FlowCancelResult>;

  // Metadata resolution
  onResolve?(params: ResolveParams): Promise<ResolveResult>;
}

// ---------------------------------------------------------------------------
// Pending request tracking
// ---------------------------------------------------------------------------

interface PendingRequest {
  resolve: (result: unknown) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

// ---------------------------------------------------------------------------
// Peer options
// ---------------------------------------------------------------------------

export interface PeerOptions {
  /** Default timeout for RPC calls in ms. Default: 30000 */
  callTimeout?: number;
  /** Handler for incoming method calls. */
  handler?: Handler;
  /** Optional validator for incoming request parameters. */
  validator?: {
    validateMethod(method: string, params: unknown): ValidationError[] | null;
  };
  /** Optional authorization hook called before dispatching incoming requests/notifications. */
  authorize?: (
    method: string,
    params: unknown,
  ) => boolean | Promise<boolean>;
  /**
   * Refuse an incoming wmp.flow.complete whose result breaks the OpenID4x
   * completion rules (see validateCompletionResult). The completion is not
   * delivered; the flow is ended with a synthesized wmp.flow.error
   * (-32602, no member of the result echoed) to the profile or handler that
   * owns it. Default: true.
   */
  validateCompletions?: boolean;
  /**
   * Protocol versions this peer speaks. As a client it offers the highest and
   * accepts a selected version that is in this list and not above the offered
   * one (Core 2.2.2); as a responder it negotiates incoming session.create and
   * session.resume against it. Default: ["0.1"].
   */
  supportedVersions?: string[];
  /**
   * Called when the session cannot be continued after an event gap (the
   * transport saw 410 and the automatic wmp.session.resume failed or had no
   * resumption token). The application creates a new session
   * (Transport Section 4.3.4).
   */
  onSessionLost?: (error: Error) => void;
  /** Called for every refused completion, with the violation (never a member value). */
  onRefusedCompletion?: (flowId: string, error: CompletionResultError) => void;
}

// ---------------------------------------------------------------------------
// Peer
// ---------------------------------------------------------------------------

export class Peer implements PeerContext {
  private transport: Transport;
  private handler: Handler;
  private registry = new Registry();
  private pending = new Map<string | number, PendingRequest>();
  private callTimeout: number;
  private sessionId?: string;
  private negotiatedVersion?: string;
  private resumptionToken?: string;
  private closed = false;
  private validator?: PeerOptions["validator"];
  private authorize?: PeerOptions["authorize"];
  private validateCompletions: boolean;
  private onRefusedCompletion?: PeerOptions["onRefusedCompletion"];
  private onSessionLost?: PeerOptions["onSessionLost"];
  private supportedVersions: string[];
  /**
   * Capabilities negotiated for a session, bound to that session's ID; undefined
   * until known or after the session ends (gating then fails closed).
   */
  private negotiated?: { sessionId?: string; capabilities: Capabilities };

  constructor(transport: Transport, opts?: PeerOptions) {
    this.transport = transport;
    this.handler = opts?.handler ?? {};
    this.callTimeout = opts?.callTimeout ?? 30_000;
    this.validator = opts?.validator;
    this.authorize = opts?.authorize;
    this.validateCompletions = opts?.validateCompletions ?? true;
    this.onRefusedCompletion = opts?.onRefusedCompletion;
    this.onSessionLost = opts?.onSessionLost;
    this.supportedVersions = [...(opts?.supportedVersions ?? SUPPORTED_VERSIONS)];

    // Wire up transport events.
    this.transport.on("message", (msg: Message) => this.dispatch(msg));
    this.transport.on("error", (err: Error) => this.onTransportError(err));
    this.transport.on("close", () => this.onTransportClose());
    this.transport.on("gap", () => this.onTransportGap());
  }

  /** Register a profile. Call before starting to receive messages. */
  use(profile: Profile): void {
    this.registry.register(profile);
    profile.init(this);
  }

  /**
   * Incremented whenever the session this peer holds state for is replaced or
   * ends. A response or handler result that was requested under an earlier
   * value belongs to a session that is gone and must not touch the current one.
   */
  private lifecycle = 0;

  /** A new session: what it granted replaces what the previous one did (nothing if it omits them). */
  private beginSession(sessionId: string | undefined, capabilities: Capabilities | undefined): void {
    this.lifecycle++;
    this.negotiated = { sessionId, capabilities: capabilities ?? {} };
    this.terminalSeen.clear(); // flow state of the old session does not carry over
  }

  private endSession(): void {
    this.lifecycle++;
    this.negotiated = undefined;
    this.terminalSeen.clear();
  }

  /**
   * A resume of `sessionId`. Capabilities the result lists replace the cache; an
   * omitted set is kept only for the SAME session, otherwise the cache becomes
   * empty (the other session's grant must not carry over).
   */
  private resumeNegotiated(sessionId: string | undefined, capabilities: Capabilities | undefined): void {
    if (capabilities === undefined && this.negotiated && this.negotiated.sessionId === sessionId) return;
    this.lifecycle++;
    this.negotiated = { sessionId, capabilities: capabilities ?? {} };
  }

  /**
   * A capability update/list result replaces the cached set, but only of an
   * existing session that is still the one it was requested under: `gen` and
   * `sessionId` are what was current when the request went out (or the handler
   * was entered), so a late result cannot recreate a closed session's grant or
   * overwrite a newer session's.
   */
  private refreshNegotiated(gen: number, sessionId: string | undefined, capabilities: unknown): void {
    if (typeof capabilities !== "object" || capabilities === null || Array.isArray(capabilities)) return;
    const n = this.negotiated;
    if (!n || this.lifecycle !== gen) return;
    if (sessionId !== undefined && n.sessionId !== undefined && sessionId !== n.sessionId) return;
    n.capabilities = capabilities as Capabilities;
  }

  /** Whether `capability` was negotiated for the session the request names (fail closed). */
  private hasNegotiated(capability: string, requestSession: unknown): boolean {
    const n = this.negotiated;
    if (!n) return false;
    if (typeof requestSession === "string" && n.sessionId !== undefined && requestSession !== n.sessionId) return false;
    return Object.prototype.hasOwnProperty.call(n.capabilities, capability);
  }

  /** The highest supported version (what a client offers). */
  private offeredVersion(): string {
    let best: string = VERSION;
    let bestKey = -1;
    for (const v of this.supportedVersions) {
      const p = parseVersion(v);
      if (!p) continue;
      const key = p.major * 1_000_000 + p.minor;
      if (key > bestKey) {
        bestKey = key;
        best = v;
      }
    }
    return best;
  }

  /** The negotiated session ID (set after session.create). */
  get session(): string | undefined {
    return this.sessionId;
  }

  // -------------------------------------------------------------------------
  // PeerContext implementation (for profiles)
  // -------------------------------------------------------------------------

  private afterResponse_ = new Map<string, (() => void)[]>();

  /** PeerContext: queue `fn` to run once the response to the current flow.start for `flowId` was sent. */
  afterResponse(flowId: string, fn: () => void): void {
    const q = this.afterResponse_.get(flowId) ?? [];
    q.push(fn);
    this.afterResponse_.set(flowId, q);
  }

  private runAfterResponse(flowId: string): void {
    const q = this.afterResponse_.get(flowId);
    this.afterResponse_.delete(flowId);
    for (const fn of q ?? []) {
      try {
        fn();
      } catch {
        /* a queued continuation must not break the dispatcher */
      }
    }
  }

  async notify(method: string, params: unknown): Promise<void> {
    const msg = createNotification(method, params);
    await this.transport.send(msg);
  }

  async call<T = unknown>(method: string, params: unknown): Promise<T> {
    const req = createRequest(method, params);
    const id = req.id!;
    // Every outgoing flow.start goes through here (the convenience method and
    // profiles alike), so the flow's validation context is always recorded.
    const rollback = method === Method.FlowStart ? this.beginFlow(flowIdOf(params), flowTypeOf(params), (params as { params?: unknown }).params) : noop;

    const capturedGen = this.lifecycle;
    const capturedSession = this.negotiated?.sessionId;

    return new Promise<T>((resolve, reject) => {
      const fail = (err: unknown): void => {
        rollback(); // the start did not succeed: it must not leave a context behind
        reject(err);
      };
      const timer = setTimeout(() => {
        this.pending.delete(id);
        fail(new WMPError(ErrorCode.InternalError, `Call to ${method} timed out`));
      }, this.callTimeout);

      this.pending.set(id, {
        resolve: ((v: unknown) => {
          if (method === Method.CapabilityUpdate || method === Method.CapabilityList) {
            // Only the session (and lifecycle) that existed when the request went out may be refreshed.
            this.refreshNegotiated(capturedGen, capturedSession, (v as { capabilities?: unknown } | undefined)?.capabilities);
          }
          (resolve as (v: unknown) => void)(v);
        }),
        reject: fail,
        timer,
      });

      this.transport.send(req).catch((err) => {
        this.pending.delete(id);
        clearTimeout(timer);
        fail(err);
      });
    });
  }

  // -------------------------------------------------------------------------
  // Session convenience methods
  // -------------------------------------------------------------------------

  /** Initiate a WMP session. */
  async createSession(opts: {
    participants?: string[];
    capabilities?: Capabilities;
    security?: SecurityMode;
    auth?: { type: string; token?: string; [key: string]: unknown };
    sender?: string;
    ttl?: number;
    invitationNonce?: string;
  }): Promise<SessionCreateResult> {
    const offered = this.offeredVersion();
    const wmp: Metadata = { version: offered, sender: opts.sender };
    const params: SessionCreateParams = {
      wmp,
      participants: opts.participants,
      capabilities_offered: opts.capabilities,
      security: opts.security ?? { mode: "tls" },
      ttl: opts.ttl,
      auth: opts.auth,
      invitation_nonce: opts.invitationNonce,
    };
    const result = await this.call<SessionCreateResult>(
      Method.SessionCreate,
      params,
    );
    if (!result.wmp?.session_id || typeof result.wmp.session_id !== "string") {
      throw new WMPError(
        ErrorCode.SessionNotFound,
        "session.create response missing session_id",
      );
    }
    // Core 2.2.2: the responder selects the highest version it supports that
    // is not above the offered one. Accept that, never a version this peer does
    // not speak or one above the offer.
    const selected = result.wmp.version;
    if (!selected || !(this.supportedVersions.includes(selected) && negotiateVersion(offered, [selected]) === selected)) {
      throw new WMPError(
        ErrorCode.VersionNotSupported,
        `negotiated version ${selected} is not supported`,
        { supported_versions: this.supportedVersions },
      );
    }
    this.sessionId = result.wmp.session_id;
    this.bindSessionToTransport(result.wmp.session_id);
    this.negotiatedVersion = selected;
    this.beginSession(result.wmp.session_id, result.capabilities);
    if (result.resumption_token) {
      this.resumptionToken = result.resumption_token;
    }
    return result;
  }

  /** Resume a previously established WMP session using a resumption token. */
  async resumeSession(opts?: {
    lastReceivedId?: string;
  }): Promise<SessionResumeResult> {
    if (!this.sessionId || !this.resumptionToken) {
      throw new Error("no session or resumption token to resume");
    }
    const params = {
      wmp: { version: this.negotiatedVersion ?? VERSION } as Metadata,
      session_id: this.sessionId,
      resumption_token: this.resumptionToken,
      // In the HTTP binding this is the last event ID (Transport Section 4.5).
      last_received_id:
        opts?.lastReceivedId ?? (this.transport as { lastEventId?: string }).lastEventId,
    };
    const result = await this.call<SessionResumeResult>(
      Method.SessionResume,
      params,
    );
    // Validate before mutating any session state: a resume that selects a
    // version this peer does not speak, or one above what it offered, is a lost
    // session (the caller creates a new one), not a silent switch.
    const selected = result.wmp?.version;
    const offered = params.wmp.version;
    if (!selected || !(this.supportedVersions.includes(selected) && negotiateVersion(offered, [selected]) === selected)) {
      throw new WMPError(
        ErrorCode.VersionNotSupported,
        `negotiated version ${selected} is not supported`,
        { supported_versions: this.supportedVersions },
      );
    }
    if (result.wmp?.session_id) {
      this.sessionId = result.wmp.session_id;
      this.bindSessionToTransport(result.wmp.session_id);
    }
    this.negotiatedVersion = selected;
    if (result.resumption_token) {
      this.resumptionToken = result.resumption_token;
    }
    this.resumeNegotiated(this.sessionId, result.capabilities);
    return result;
  }

  /** The current resumption token (set after session.create or session.resume). */
  get token(): string | undefined {
    return this.resumptionToken;
  }

  /**
   * Bind a session ID to the underlying transport. For HttpSseTransport,
   * this sets the Wmp-Session-Id header and session_id query parameter.
   */
  private bindSessionToTransport(sessionId: string): void {
    // Duck-type check for HttpSseTransport's setSessionId method.
    const t = this.transport as { setSessionId?: (id: string) => void };
    if (typeof t.setSessionId === "function") {
      t.setSessionId(sessionId);
    }
  }

  /** Close the current session. */
  async closeSession(reason = "complete"): Promise<void> {
    if (!this.sessionId) return;
    await this.notify(Method.SessionClose, {
      wmp: { version: this.negotiatedVersion ?? VERSION, session_id: this.sessionId },
      reason,
    });
    this.sessionId = undefined;
    this.endSession();
  }

  // -------------------------------------------------------------------------
  // Flow convenience methods
  // -------------------------------------------------------------------------

  /** Start a flow. */
  async startFlow(
    flowType: string,
    flowId: string,
    params?: unknown,
    timeout?: number,
  ): Promise<FlowStartResult> {
    return this.call<FlowStartResult>(Method.FlowStart, {
      wmp: this.wmpMeta(),
      flow_type: flowType,
      flow_id: flowId,
      params,
      timeout,
    });
  }

  /** Send a flow progress notification. */
  async flowProgress(
    flowId: string,
    step: string,
    payload?: unknown,
  ): Promise<void> {
    await this.notify(Method.FlowProgress, {
      wmp: this.wmpMeta(),
      flow_id: flowId,
      step,
      payload,
    });
  }

  /** Send a flow action request and wait for result. */
  async flowAction(
    flowId: string,
    action: string,
    params?: unknown,
  ): Promise<FlowActionResult> {
    return this.call<FlowActionResult>(Method.FlowAction, {
      wmp: this.wmpMeta(),
      flow_id: flowId,
      action,
      params,
    });
  }

  /** Notify flow completion. */
  async flowComplete(flowId: string, result?: unknown): Promise<void> {
    await this.notify(Method.FlowComplete, {
      wmp: this.wmpMeta(),
      flow_id: flowId,
      result,
    });
  }

  /** Notify flow error. */
  async flowError(
    flowId: string,
    code: number,
    message: string,
    data?: unknown,
  ): Promise<void> {
    await this.notify(Method.FlowError, {
      wmp: this.wmpMeta(),
      flow_id: flowId,
      code,
      message,
      data,
    });
  }

  /** Cancel a flow. */
  async flowCancel(
    flowId: string,
    reason?: string,
  ): Promise<FlowCancelResult> {
    return this.call<FlowCancelResult>(Method.FlowCancel, {
      wmp: this.wmpMeta(),
      flow_id: flowId,
      reason,
    });
  }

  // -------------------------------------------------------------------------
  // Resolve convenience method
  // -------------------------------------------------------------------------

  async resolve(type: string, uri: string, options?: unknown): Promise<ResolveResult> {
    return this.call<ResolveResult>(Method.Resolve, {
      wmp: this.wmpMeta(),
      type,
      uri,
      options,
    });
  }

  // -------------------------------------------------------------------------
  // Close
  // -------------------------------------------------------------------------

  close(): void {
    this.closed = true;
    // Reject all pending calls.
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Peer closed"));
      this.pending.delete(id);
    }
    this.transport.close();
  }

  // -------------------------------------------------------------------------
  // Internal dispatch
  // -------------------------------------------------------------------------

  private dispatch(msg: Message): void {
    if (isResponse(msg)) {
      this.handleResponse(msg as Response);
    } else if (isRequest(msg)) {
      this.handleRequest(msg as Request);
    }
  }

  private handleResponse(resp: Response): void {
    if (resp.id == null) return;
    const pending = this.pending.get(resp.id);
    if (!pending) return;

    this.pending.delete(resp.id);
    clearTimeout(pending.timer);

    if (resp.error) {
      pending.reject(
        new WMPError(resp.error.code, resp.error.message, resp.error.data),
      );
    } else {
      pending.resolve(resp.result);
    }
  }

  private handleRequest(req: Request): void {
    const dispatch = async () => {
      if (this.authorize) {
        const allowed = await this.authorize(req.method, req.params);
        if (!allowed) {
          throw new WMPError(
            ErrorCode.NotAuthorized,
            `Not authorized to call ${req.method}`,
          );
        }
      }
      return this.dispatchMethod(req.method, req.params);
    };

    if (isNotification(req)) {
      // wmp.flow.start is a request: its response is what lets a profile queue
      // work for after it (afterResponse). In notification form no response can
      // ever be sent, so it is dropped instead of dispatched.
      if (req.method === Method.FlowStart) return;
      dispatch().catch(() => {
        /* notifications get no error response */
      });
    } else {
      const startedFlow = req.method === Method.FlowStart ? flowIdOf(req.params) : undefined;
      const flowKey = typeof startedFlow === "string" ? startedFlow : undefined;
      dispatch()
        .then(async (result) => {
          const resp = createResponse(req.id!, result);
          await this.transport.send(resp);
          // Only now may anything the handler queued for after the response go out.
          if (flowKey !== undefined) this.runAfterResponse(flowKey);
        })
        .catch((err) => {
          if (flowKey !== undefined) this.afterResponse_.delete(flowKey);
          const rpcErr = toRPCError(err);
          const resp = createErrorResponse(req.id!, rpcErr);
          return this.transport.send(resp);
        });
    }
  }

  private async dispatchMethod(
    method: string,
    params: unknown,
  ): Promise<unknown> {
    // A repeat of a terminal notification already processed (a resume re-sends
    // them with fresh event IDs). Only checked here: a flow is marked terminal
    // once its notification passed validation (below), not before.
    if ((method === Method.FlowComplete || method === Method.FlowError) && isFlowIdEnvelope(params) && this.terminalSeen.has(params.flow_id)) {
      return undefined;
    }

    // A completion that breaks the result rules is refused before the generic
    // validator runs: a notification the validator rejected would be dropped
    // silently and the receiving handler would never learn that the flow failed.
    // Authorization (handleRequest) and the envelope shape are still checked.
    if (method === Method.FlowComplete && this.validateCompletions && isFlowCompleteEnvelope(params)) {
      const refusal = this.completionRefusal(params);
      if (refusal) {
        this.refuseCompletion(params, refusal);
        return undefined;
      }
    }

    if (this.validator) {
      const errors = this.validator.validateMethod(method, params);
      if (errors) {
        const detail = errors.map((e) => `${e.path}: ${e.message}`).join("; ");
        throw new WMPError(
          ErrorCode.InvalidParams,
          `Invalid params for ${method}: ${detail}`,
        );
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- JSON-RPC params are untyped
    const p = params as any;

    switch (method) {
      // Session
      case Method.SessionCreate:
        if (this.handler.onSessionCreate) {
          // Core 2.2.2: the highest supported version not above the offer, or
          // -32602 (malformed) / -31013 with supported_versions.
          const selected = negotiateVersion(p?.wmp?.version, this.supportedVersions);
          if (selected === undefined) throw versionRejection(p?.wmp?.version, this.supportedVersions);
          const result = await this.handler.onSessionCreate(p);
          if (result) {
            // The negotiated version is the one that goes on the wire, whatever the handler wrote.
            result.wmp = { ...result.wmp, version: selected };
            this.negotiatedVersion = selected;
            // The session this peer now serves: its identity, and what it granted
            // (nothing if the result omits capabilities).
            if (typeof result.wmp.session_id === "string") this.sessionId = result.wmp.session_id;
            this.beginSession(result.wmp.session_id, result.capabilities);
          }
          return result;
        }
        break;

      case Method.SessionResume:
        if (this.handler.onSessionResume) {
          const selected = negotiateVersion(p?.wmp?.version, this.supportedVersions);
          if (selected === undefined) throw versionRejection(p?.wmp?.version, this.supportedVersions);
          const result = await this.handler.onSessionResume(p);
          if (result) {
            result.wmp = { ...result.wmp, version: selected };
            this.negotiatedVersion = selected;
            const resumedId = typeof result.wmp.session_id === "string" ? result.wmp.session_id : typeof p?.session_id === "string" ? p.session_id : undefined;
            if (resumedId !== undefined && result.resumed !== false) this.sessionId = resumedId;
            this.resumeNegotiated(resumedId, result.capabilities);
          }
          return result;
        }
        break;

      case Method.SessionClose: {
        // Only the close of THIS session ends its state: a delayed close for an
        // earlier session must not strip the grant of the one that replaced it.
        const closing = p?.wmp?.session_id;
        if (closing === undefined || closing === this.sessionId || closing === this.negotiated?.sessionId) {
          if (closing === undefined || closing === this.sessionId) this.sessionId = undefined;
          this.endSession();
        }
        if (this.handler.onSessionClose) {
          this.handler.onSessionClose(p);
        }
        return undefined;
      }

      case Method.SessionAuthenticate:
        if (this.handler.onSessionAuthenticate) {
          return this.handler.onSessionAuthenticate(p);
        }
        break;

      // Messages
      case Method.MessageDeliver:
        if (this.handler.onMessageDeliver) {
          this.handler.onMessageDeliver(p);
        }
        return undefined;

      case Method.MessageAck:
        if (this.handler.onMessageAck) {
          this.handler.onMessageAck(p);
        }
        return undefined;

      case Method.MessagePoll:
        if (this.handler.onMessagePoll) {
          return this.handler.onMessagePoll(p);
        }
        break;

      case Method.MessageStatus:
        if (this.handler.onMessageStatus) {
          this.handler.onMessageStatus(p);
        }
        return undefined;

      // Capabilities
      case Method.CapabilityUpdate:
        if (this.handler.onCapabilityUpdate) {
          const gen = this.lifecycle;
          const result = await this.handler.onCapabilityUpdate(p);
          // The update changed what the session grants: later flow starts are gated by it.
          this.refreshNegotiated(gen, p?.wmp?.session_id, result?.capabilities);
          return result;
        }
        break;

      case Method.CapabilityList:
        if (this.handler.onCapabilityList) {
          const gen = this.lifecycle;
          const result = await this.handler.onCapabilityList(p);
          this.refreshNegotiated(gen, p?.wmp?.session_id, result?.capabilities);
          return result;
        }
        break;

      // Flows — delegate to profile FlowHandlers first, then handler.
      case Method.FlowStart: {
        const fh = this.registry.getFlowHandler(p?.flow_type);
        if (fh) {
          // Core 10.3: a flow type whose capability was not negotiated is
          // refused with -31005 before the profile sees it, and before anything
          // is recorded for the flow. Fails closed: with no negotiated
          // capabilities known, nothing counts as negotiated.
          const need = fh.requiredCapability?.(p.flow_type);
          if (need && !this.hasNegotiated(need, p.wmp?.session_id)) {
            throw unsupportedError(p.flow_type, { capability: need });
          }
        } else if (!this.handler.onFlowStart) {
          // Nobody here implements this flow type.
          throw unsupportedError(p?.flow_type);
        }
        // Rejects a duplicate active flow_id and records the flow's validation
        // context; a start that fails leaves nothing (and no existing flow's
        // context) changed.
        const rollback = this.beginFlow(p?.flow_id, p?.flow_type, p?.params);
        try {
          if (fh) return await fh.startFlow(p);
          return await this.handler.onFlowStart!(p);
        } catch (err) {
          rollback();
          // A handler that does not implement this flow type: unsupported
          // capability (Core 3.8.1), not an unknown method.
          if (!fh && err instanceof WMPError && err.code === ErrorCode.MethodNotFound) throw unsupportedError(p.flow_type);
          throw err;
        }
      }

      case Method.FlowProgress: {
        const fh = this.flowHandlerForId(p.flow_id);
        if (fh) { fh.handleProgress(p); return undefined; }
        if (this.handler.onFlowProgress) {
          this.handler.onFlowProgress(p);
          return undefined;
        }
        return undefined;
      }

      case Method.FlowAction: {
        const fh = this.flowHandlerForId(p.flow_id);
        if (fh) return fh.handleAction(p);
        if (this.handler.onFlowAction) return this.handler.onFlowAction(p);
        break;
      }

      case Method.FlowComplete: {
        this.endFlow(p?.flow_id);
        const fh = this.flowHandlerForId(p.flow_id);
        if (fh) { fh.handleComplete(p); return undefined; }
        if (this.handler.onFlowComplete) {
          this.handler.onFlowComplete(p);
          return undefined;
        }
        return undefined;
      }

      case Method.FlowError: {
        this.endFlow(p?.flow_id);
        const fh = this.flowHandlerForId(p.flow_id);
        if (fh) { fh.handleError(p); return undefined; }
        if (this.handler.onFlowError) {
          this.handler.onFlowError(p);
          return undefined;
        }
        return undefined;
      }

      case Method.FlowCancel:
        if (this.handler.onFlowCancel) {
          // A cancellation already processed (a resume re-sends it with a fresh
          // event ID) is acknowledged again without invoking the handler.
          if (typeof p?.flow_id === "string" && this.terminalSeen.has(p.flow_id)) {
            return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
          }
          const result = await this.handler.onFlowCancel(p);
          this.endFlow(p?.flow_id);
          return result;
        }
        break;

      // Resolve — delegate to profile ResolveHandlers.
      case Method.Resolve: {
        const rh = this.registry.getResolveHandler(p.type);
        if (rh) return rh.handleResolve(p);
        if (this.handler.onResolve) return this.handler.onResolve(p);
        break;
      }

      // Custom method — delegate to profile MethodHandlers.
      default: {
        const mh = this.registry.getMethodHandler(method);
        if (mh) return mh.handleMethod(method, params);
        break;
      }
    }

    throw new WMPError(ErrorCode.MethodNotFound, `Method not found: ${method}`);
  }

  /**
   * The validation context of every ACTIVE flow (started, not yet ended), by
   * flow_id: its type and, for match, the ids of the verifier's query. Never
   * evicted to make room: a new start is refused at capacity instead of
   * weakening an existing flow's checks.
   */
  private recordedFlows = new Map<string, { type: string; queryIds?: string[] }>();

  /**
   * Records a starting flow and returns the function that undoes it. Refuses
   * (-32602) a flow_id that is already active, so a second start cannot replace
   * the context of the first, and (-31007) a start at capacity.
   */
  private beginFlow(flowId: unknown, flowType: unknown, params: unknown): () => void {
    if (typeof flowId !== "string" || typeof flowType !== "string") return noop;
    if (this.recordedFlows.has(flowId)) {
      throw new WMPError(ErrorCode.InvalidParams, "Invalid params", { reason: "flow_id is already active" });
    }
    if (this.recordedFlows.size >= MAX_ACTIVE_FLOWS) {
      throw new WMPError(ErrorCode.RateLimited, "Too many active flows");
    }
    // A new flow under a reused ID is not a repeat of the old one's terminal
    // notification. If the start fails the marker comes back: the old flow's
    // terminal must not be delivered twice because a reuse attempt was refused.
    const hadTerminal = this.terminalSeen.delete(flowId);
    const q = flowType === "match" && typeof params === "object" && params !== null ? (params as { dcql_query?: unknown }).dcql_query : undefined;
    const rec = { type: flowType, queryIds: q === undefined ? undefined : dcqlQueryIds(q) };
    this.recordedFlows.set(flowId, rec);
    return () => {
      if (this.recordedFlows.get(flowId) === rec) this.recordedFlows.delete(flowId);
      if (hadTerminal) this.terminalSeen.add(flowId);
    };
  }

  /**
   * The violation of a completion's result, if any. The check is selected by the
   * flow type recorded when the flow started, never by members of the result
   * (openid4x 3.3.3): a match flow's result is the closed set, and a match
   * completion without a result is refused too.
   */
  private completionRefusal(p: FlowCompleteParams): CompletionResultError | undefined {
    const rec = this.recordedFlows.get(p.flow_id);
    try {
      if (rec?.type === "match") validateMatchResult(p.result, rec.queryIds);
      else if (p.result !== undefined) validateCompletionResult(p.result);
    } catch (err) {
      if (err instanceof CompletionResultError) return err;
      throw err;
    }
    return undefined;
  }

  /**
   * A non-conforming completion is not delivered. The flow ends as failed: a
   * synthesized wmp.flow.error, carrying neither the result nor the violation
   * text, goes to whoever would have received the completion or the error.
   */
  private refuseCompletion(p: FlowCompleteParams, err: CompletionResultError): void {
    this.recordedFlows.delete(p.flow_id);
    this.markTerminal(p.flow_id); // the synthesized error ends the flow
    this.onRefusedCompletion?.(p.flow_id, err);
    const synthesized: FlowErrorParams = {
      wmp: p.wmp,
      flow_id: p.flow_id,
      code: ErrorCode.InvalidParams,
      message: "Non-conforming flow result",
    };
    const fh = this.flowHandlerForId(p.flow_id);
    if (fh) fh.handleError(synthesized);
    else this.handler.onFlowError?.(synthesized);
  }

  /**
   * Flows whose terminal notification (complete / error) this peer already
   * processed. A resume re-sends terminal notifications with fresh event IDs, so
   * transport-level dedupe cannot recognise them; "a client that already
   * processed the terminal notification of a flow ignores the repeat"
   * (Transport 4.3.4). Per session: cleared when the session changes or ends,
   * and for a flow ID when a new flow starts under it. Never evicted: dropping a
   * marker would let a later resume deliver that flow's callbacks again; the set
   * lives as long as the session.
   */
  private terminalSeen = new Set<string>();

  private markTerminal(flowId: string): void {
    this.terminalSeen.add(flowId);
  }

  /** A flow ended (complete, error or cancel): drop its validation context and remember its terminal. */
  private endFlow(flowId: unknown): void {
    if (typeof flowId !== "string") return;
    this.recordedFlows.delete(flowId);
    this.markTerminal(flowId);
  }

  // Track flow_id → flow_type mapping for routing to the right FlowHandler.
  private activeFlows = new Map<string, string>();

  /** Look up the FlowHandler for an active flow by flow_id. */
  private flowHandlerForId(flowId: string): FlowHandler | undefined {
    const flowType = this.activeFlows.get(flowId);
    if (!flowType) return undefined;
    return this.registry.getFlowHandler(flowType);
  }

  /** Track a flow as active (called when flow.start succeeds). */
  trackFlow(flowId: string, flowType: string): void {
    this.activeFlows.set(flowId, flowType);
  }

  /** Untrack a flow (called on flow.complete / flow.error / flow.cancel). */
  untrackFlow(flowId: string): void {
    this.activeFlows.delete(flowId);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private wmpMeta(): Metadata {
    return {
      version: this.negotiatedVersion ?? VERSION,
      session_id: this.sessionId,
      timestamp: new Date().toISOString(),
    };
  }

  private onTransportError(_err: Error): void {
    // Could emit events here for reconnection logic.
  }

  /**
   * The transport lost events (410): resume the session, which re-sends the
   * latest progress of active flows and the terminal notification of ended
   * flows on the already open stream. Without a resumption token, or if the
   * resume fails, the session is lost.
   */
  private onTransportGap(): void {
    if (!this.sessionId || !this.resumptionToken) {
      this.onSessionLost?.(new Error("event gap and no resumption token to resume with"));
      return;
    }
    this.resumeSession().catch((err: unknown) => {
      this.onSessionLost?.(err instanceof Error ? err : new Error(String(err)));
    });
  }

  private onTransportClose(): void {
    if (!this.closed) {
      // Transport closed unexpectedly — reject all pending.
      for (const [id, pending] of this.pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error("Transport closed"));
        this.pending.delete(id);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

function isFlowIdEnvelope(params: unknown): params is { flow_id: string } {
  return typeof params === "object" && params !== null && typeof (params as { flow_id?: unknown }).flow_id === "string";
}

/** The shape a wmp.flow.complete must have before the early result check applies: flow_id and the wmp metadata object with its version. */
function isFlowCompleteEnvelope(params: unknown): params is FlowCompleteParams {
  if (typeof params !== "object" || params === null) return false;
  const p = params as { flow_id?: unknown; wmp?: unknown };
  if (typeof p.flow_id !== "string") return false;
  const w = p.wmp as { version?: unknown } | null | undefined;
  return typeof w === "object" && w !== null && typeof w.version === "string";
}

function flowIdOf(params: unknown): unknown {
  return typeof params === "object" && params !== null ? (params as { flow_id?: unknown }).flow_id : undefined;
}

function flowTypeOf(params: unknown): unknown {
  return typeof params === "object" && params !== null ? (params as { flow_type?: unknown }).flow_type : undefined;
}

const noop = (): void => {};

/** Most flows a peer holds validation context for at once; a new start beyond it is refused. */
const MAX_ACTIVE_FLOWS = 4096;

function toRPCError(err: unknown): RPCError {
  if (err instanceof WMPError) {
    return { code: err.code, message: err.rpcMessage, data: err.data };
  }
  // Sanitize unexpected internal errors to avoid leaking implementation details.
  if (typeof console !== "undefined" && console.error) {
    console.error("Peer handler internal error:", err);
  }
  return {
    code: ErrorCode.InternalError,
    message: "Internal error",
  };
}
