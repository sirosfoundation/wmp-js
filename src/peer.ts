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

  /**
   * Operations that must not overlap, one chain per kind: outgoing capability
   * operations, incoming capability handlers, incoming session create/resume.
   * They finish in the order they started, so the last to finish is also the
   * latest word and an older snapshot can never replace a newer one. (Outgoing
   * and incoming are separate chains: each side waits on the other's answer, and
   * one shared chain could deadlock two peers calling each other.)
   */
  private chains: Record<"out" | "in" | "session", Promise<void>> = {
    out: Promise.resolve(),
    in: Promise.resolve(),
    session: Promise.resolve(),
  };

  private async serialized<T>(kind: "out" | "in" | "session", fn: () => Promise<T>): Promise<T> {
    const previous = this.chains[kind];
    let release!: () => void;
    this.chains[kind] = new Promise<void>((r) => (release = r));
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

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
    // A copy: the grant must not change when the caller's (or handler's) object does.
    this.negotiated = { sessionId, capabilities: { ...capabilities } };
    this.resetFlows(); // flow state of the old session does not carry over
  }

  private endSession(): void {
    this.lifecycle++;
    this.negotiated = undefined;
    this.resetFlows();
  }

  /**
   * A resume of `sessionId`. The SAME session keeps its identity: capabilities
   * the result lists replace its grant, an omitted set leaves it, and neither the
   * lifecycle nor the flow state changes. Another session is a replacement: its
   * grant is what the result lists (nothing if omitted), the lifecycle moves on
   * and the old session's flow state is dropped.
   */
  private resumeNegotiated(sessionId: string | undefined, capabilities: Capabilities | undefined): void {
    const n = this.negotiated;
    if (n && n.sessionId === sessionId) {
      if (capabilities !== undefined) n.capabilities = { ...capabilities };
      return;
    }
    this.lifecycle++;
    this.negotiated = { sessionId, capabilities: { ...capabilities } };
    this.resetFlows();
  }

  /**
   * A capability update/list result replaces the cached set, but only of an
   * existing session that is still the one it was requested under: `gen` and
   * `sessionId` are what was current when the operation started, so a late result
   * cannot recreate a closed session's grant or overwrite a newer session's.
   * Operations of one kind never overlap (see `chains`), so results arrive in
   * the order they were requested.
   */
  private refreshNegotiated(gen: number, sessionId: string | undefined, capabilities: unknown): void {
    if (typeof capabilities !== "object" || capabilities === null || Array.isArray(capabilities)) return;
    const n = this.negotiated;
    if (!n || this.lifecycle !== gen) return;
    if (sessionId !== undefined && n.sessionId !== undefined && sessionId !== n.sessionId) return;
    n.capabilities = { ...(capabilities as Capabilities) };
  }

  /** Whether `capability` was negotiated for the session the request names (fail closed). */
  private hasNegotiated(capability: string, requestSession: unknown): boolean {
    const n = this.negotiated;
    // A grant that is not bound to a session identity admits nothing (fail closed).
    if (!n || n.sessionId === undefined) return false;
    if (typeof requestSession === "string" && requestSession !== n.sessionId) return false;
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

  /**
   * The queue of the flow.start request whose handler is being invoked, set only
   * for the synchronous part of that invocation. Continuations registered with
   * {@link afterResponse} belong to that request alone, so a start that fails
   * (for example a duplicate) can only discard its own.
   */
  private afterTarget?: AfterResponse;

  /**
   * PeerContext: queue `fn` to run once the response to the flow.start being
   * handled was sent. Called outside that handler invocation there is no
   * response to wait for, and `fn` runs on a zero-delay timer instead.
   */
  afterResponse(fn: () => void): void {
    if (this.afterTarget) this.afterTarget.fns.push(fn);
    else setTimeout(fn, 0);
  }

  async notify(method: string, params: unknown): Promise<void> {
    const msg = createNotification(method, params);
    await this.transport.send(msg);
    // This peer ended the flow (complete or error, sent by the convenience
    // methods and by profiles alike): its validation context is no longer needed.
    if (method === Method.FlowComplete || method === Method.FlowError) this.releaseFlow(flowIdOf(params));
  }

  /** PeerContext: the generation token of an active flow (see {@link PeerContext.flowGeneration}). */
  flowGeneration(flowId: string): object | undefined {
    return this.recordedFlows.get(flowId);
  }

  /**
   * PeerContext: send a flow notification on behalf of one flow generation. A
   * generation that is no longer the flow's (the flow ended, was cancelled, and
   * the id may have been started again) sends nothing and never touches the
   * current flow's record.
   */
  async notifyFlow(generation: object | undefined, method: string, params: unknown): Promise<void> {
    const id = flowIdOf(params);
    if (typeof id === "string" && this.recordedFlows.get(id) !== generation) {
      throw new Error("flow is no longer active");
    }
    await this.transport.send(createNotification(method, params));
    // Retire the flow only if it is still the generation that sent this.
    if (typeof id === "string" && this.recordedFlows.get(id) === generation) this.recordedFlows.delete(id);
  }

  /** Drops the validation context of a flow that ended; the flow_id is free to start again. */
  private releaseFlow(flowId: unknown): void {
    if (typeof flowId === "string") this.recordedFlows.delete(flowId);
  }

  async call<T = unknown>(method: string, params: unknown): Promise<T> {
    // Capability operations go one at a time: the grant is whatever the last one
    // said, never an older snapshot that happened to arrive later.
    if (method === Method.CapabilityUpdate || method === Method.CapabilityList) {
      return this.serialized("out", () => this.callNow<T>(method, params));
    }
    return this.callNow<T>(method, params);
  }

  private callNow<T>(method: string, params: unknown): Promise<T> {
    const req = createRequest(method, params);
    const id = req.id!;
    // Every outgoing flow.start goes through here (the convenience method and
    // profiles alike), so the flow's validation context is always recorded.
    const rollback = method === Method.FlowStart ? this.beginFlow(flowIdOf(params), flowTypeOf(params), (params as { params?: unknown }).params) : noop;

    // What a capability result is checked against when it comes back: the
    // lifecycle and the session the REQUEST names (else the current one).
    const capturedGen = this.lifecycle;
    const named = (params as { wmp?: { session_id?: unknown } } | undefined)?.wmp?.session_id;
    const capturedSession = typeof named === "string" ? named : this.negotiated?.sessionId;

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
          // A cancelled flow has ended: release its context (shared by the convenience method and profiles).
          if (method === Method.FlowCancel) this.releaseFlow(flowIdOf(params));
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

  /**
   * Resume a previously established WMP session using a resumption token.
   * Resumes run one at a time (explicit calls and gap recovery alike): the token
   * is single use, so a second resume must wait for the first to store the
   * rotated one and then present that.
   */
  async resumeSession(opts?: {
    lastReceivedId?: string;
  }): Promise<SessionResumeResult> {
    const previous = this.resumeChain;
    let release!: () => void;
    this.resumeChain = new Promise<void>((r) => (release = r));
    await previous;
    try {
      return await this.resumeNow(opts);
    } finally {
      release();
    }
  }

  private resumeChain: Promise<void> = Promise.resolve();

  private async resumeNow(opts?: { lastReceivedId?: string }): Promise<SessionResumeResult> {
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
    const gen = this.lifecycle;
    const result = await this.call<SessionResumeResult>(
      Method.SessionResume,
      params,
    );
    // The session this resume was for may have been closed or replaced while it
    // was in flight: its result must not bring that session back.
    if (this.lifecycle !== gen) throw new StaleSessionError();
    // An unsuccessful resume changes nothing; the caller creates a new session.
    if (result.resumed !== true) {
      throw new WMPError(ErrorCode.SessionExpired, "Session could not be resumed");
    }
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
      // (Flow state: resumeNegotiated below keeps it for the same session and drops it for another.)
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
    const gen = this.lifecycle;
    await this.notify(Method.SessionClose, {
      wmp: { version: this.negotiatedVersion ?? VERSION, session_id: this.sessionId },
      reason,
    });
    // A replacement session may have been established while the close was being
    // sent: only the session that was closed has its state cleared.
    if (this.lifecycle !== gen) return;
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
    // What the handler queued for after this request's response, and how to undo
    // the flow it started if that response cannot be delivered.
    const after: AfterResponse = { fns: [] };
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
      return this.dispatchMethod(req.method, req.params, after);
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
      dispatch()
        .then(async (result) => {
          const resp = createResponse(req.id!, result);
          await this.transport.send(resp);
          // Only now may anything the handler queued for after the response go out.
          for (const fn of after.fns.splice(0)) {
            try {
              fn();
            } catch {
              /* a queued continuation must not break the dispatcher */
            }
          }
        })
        .catch((err) => {
          after.fns.length = 0; // this request's continuations only: they never run
          after.undo?.(); // the start was acknowledged by nobody: it must not leave a flow behind
          const rpcErr = toRPCError(err);
          const resp = createErrorResponse(req.id!, rpcErr);
          return this.transport.send(resp);
        });
    }
  }

  private async dispatchMethod(
    method: string,
    params: unknown,
    after?: AfterResponse,
  ): Promise<unknown> {
    // A repeat of a terminal message already processed (or refused): ignored.
    // Only checked here; a flow is marked once its message passed validation.
    if ((method === Method.FlowComplete || method === Method.FlowError) && isFlowIdEnvelope(params) && this.terminalSeen.has(params.flow_id)) {
      return undefined;
    }

    // A completion that breaks the result rules is refused before the generic
    // validator runs: a notification the validator rejected would be dropped
    // silently and the receiving handler would never learn that the flow failed.
    // Authorization (handleRequest) and the envelope shape are still checked.
    if (method === Method.FlowComplete && this.validateCompletions) {
      if (isFlowCompleteEnvelope(params)) {
        const refusal = this.completionRefusal(params);
        if (refusal) {
          this.refuseCompletion(params, refusal);
          return undefined;
        }
      } else if (!this.validator) {
        // Not even the basic envelope, and no schema validator to judge it: it
        // is not delivered (a result nobody checked must not reach the handler).
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
          // Session establishment is serialized: a slow handler cannot finish
          // after a later create/resume and overwrite what that one installed.
          return this.serialized("session", async () => {
            const result = await this.handler.onSessionCreate!(p);
            if (result) {
              // The negotiated version is the one that goes on the wire, whatever the handler wrote.
              result.wmp = { ...result.wmp, version: selected };
              this.negotiatedVersion = selected;
              // The session this peer now serves: its identity, routing and what it
              // granted (nothing if the result omits capabilities). A new session
              // has no resumption token of ours: the old session's must not linger.
              if (typeof result.wmp.session_id === "string") {
                this.sessionId = result.wmp.session_id;
                this.bindSessionToTransport(result.wmp.session_id);
              }
              this.resumptionToken = undefined;
              this.beginSession(result.wmp.session_id, result.capabilities);
            }
            return result;
          });
        }
        break;

      case Method.SessionResume:
        if (this.handler.onSessionResume) {
          const selected = negotiateVersion(p?.wmp?.version, this.supportedVersions);
          if (selected === undefined) throw versionRejection(p?.wmp?.version, this.supportedVersions);
          return this.serialized("session", async () => {
            const gen = this.lifecycle;
            const result = await this.handler.onSessionResume!(p);
            if (result) {
              result.wmp = { ...result.wmp, version: selected };
              // Only a successful resume that is still current installs session state.
              if (result.resumed === true && this.lifecycle === gen) {
                this.negotiatedVersion = selected;
                const resumedId = typeof result.wmp.session_id === "string" ? result.wmp.session_id : typeof p?.session_id === "string" ? p.session_id : undefined;
                if (resumedId !== undefined) {
                  if (resumedId !== this.sessionId) this.resumptionToken = undefined; // another session: not its token
                  this.sessionId = resumedId;
                  this.bindSessionToTransport(resumedId);
                }
                this.resumeNegotiated(resumedId, result.capabilities);
              }
            }
            return result;
          });
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
          // One at a time: the grant is what the last handler said.
          return this.serialized("in", async () => {
            const gen = this.lifecycle;
            const result = await this.handler.onCapabilityUpdate!(p);
            // The update changed what the session grants: later flow starts are gated by it.
            this.refreshNegotiated(gen, p?.wmp?.session_id, result?.capabilities);
            return result;
          });
        }
        break;

      case Method.CapabilityList:
        if (this.handler.onCapabilityList) {
          return this.serialized("in", async () => {
            const gen = this.lifecycle;
            const result = await this.handler.onCapabilityList!(p);
            this.refreshNegotiated(gen, p?.wmp?.session_id, result?.capabilities);
            return result;
          });
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
        // If the response to this start cannot be delivered, handleRequest undoes it too.
        if (after) after.undo = rollback;
        try {
          // The handler may queue continuations for after the response; they go
          // to THIS request's queue (the window is the synchronous invocation).
          this.afterTarget = after;
          let started: Promise<unknown>;
          try {
            started = fh ? fh.startFlow(p) : this.handler.onFlowStart!(p);
          } finally {
            this.afterTarget = undefined;
          }
          return await started;
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
          const flowId: unknown = p?.flow_id;
          if (typeof flowId === "string") {
            // A cancellation already processed (a resume re-sends it with a fresh
            // event ID) is acknowledged again without invoking the handler. Only a
            // CANCELLED flow: one that ended by complete/error reaches the handler.
            if (this.terminalSeen.get(flowId) === "cancelled") {
              return { wmp: p.wmp, flow_id: flowId, status: "cancelled" };
            }
            // The flow generation this cancellation is for: the session epoch and the
            // flow's record (if any).
            const gen = this.flowEpoch;
            const rec = this.recordedFlows.get(flowId);
            // A repeat for the same generation that arrives while the first is
            // still being processed shares its outcome. A replacement flow under
            // the same id is a different generation and gets its own run.
            const pending = this.cancelling.get(flowId);
            if (pending && pending.gen === gen && pending.rec === rec) return pending.run;
            const entry: { gen: number; rec: object | undefined; run: Promise<unknown> } = { gen, rec, run: undefined as unknown as Promise<unknown> };
            entry.run = (async () => {
              // Yield first: the entry is installed before the handler can throw
              // (even synchronously), so its cleanup always sees it.
              await Promise.resolve();
              try {
                const result = await this.handler.onFlowCancel!(p);
                // Finalize only the generation that was cancelled: if that flow
                // ended and another started under the id meanwhile, leave it alone.
                if (this.flowEpoch === gen && this.recordedFlows.get(flowId) === rec) this.endFlow(flowId, "cancelled");
                return result;
              } finally {
                if (this.cancelling.get(flowId) === entry) this.cancelling.delete(flowId); // a failure leaves a retry possible
              }
            })();
            this.cancelling.set(flowId, entry);
            return entry.run;
          }
          return this.handler.onFlowCancel(p);
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
   * Flows that ended (complete, error, a refused completion or a cancel), by
   * flow_id. A finished or refused flow is not an unknown one: a further terminal
   * message for it is ignored instead of being judged by the general rules, and
   * it holds no active-flow slot. Never evicted (it lives as long as the session)
   * and cleared when the session ends or changes.
   */
  private terminalSeen = new Map<string, "ended" | "cancelled">();

  private markTerminal(flowId: string, kind: "ended" | "cancelled" = "ended"): void {
    this.terminalSeen.set(flowId, kind);
  }

  /**
   * A flow ended: drop its validation context and, if this peer knew the flow
   * (it was started here or by the remote peer and not yet ended), remember how
   * it ended. A terminal message for a flow this peer never saw start is
   * delivered as before but not remembered, so a remote peer cannot grow the
   * history with fresh ids.
   */
  private endFlow(flowId: unknown, kind: "ended" | "cancelled" = "ended"): void {
    if (typeof flowId !== "string") return;
    const known = this.recordedFlows.delete(flowId);
    // A flow already in the history may be re-marked (a cancel of an ended flow
    // upgrades its kind) without growing it.
    if (known || this.terminalSeen.has(flowId)) this.markTerminal(flowId, kind);
  }

  /** A new or ended session: the old session's flow state does not carry over. */
  private resetFlows(): void {
    this.flowEpoch++;
    this.recordedFlows.clear();
    this.terminalSeen.clear();
    this.cancelling.clear(); // pending cancellations belong to the old session
  }

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
    // The history of finished flows is bounded too, and it is never evicted (a
    // dropped marker would weaken validation): at saturation new flows are
    // refused until the session is renewed.
    if (this.terminalSeen.size >= MAX_TERMINAL_HISTORY && !this.terminalSeen.has(flowId)) {
      throw new WMPError(ErrorCode.RateLimited, "Too many finished flows in this session");
    }
    // A new flow under a reused ID is not a repeat of the old one's terminal
    // message. If the start fails the marker comes back (below).
    const hadTerminal = this.terminalSeen.get(flowId);
    this.terminalSeen.delete(flowId);
    const q = flowType === "match" && typeof params === "object" && params !== null ? (params as { dcql_query?: unknown }).dcql_query : undefined;
    const rec = { type: flowType, queryIds: q === undefined ? undefined : dcqlQueryIds(q) };
    this.recordedFlows.set(flowId, rec);
    return () => {
      // Only while this start's own record is still the flow's: if the
      // replacement already ended, or another flow took the id, the marker is theirs.
      if (this.recordedFlows.get(flowId) === rec) {
        this.recordedFlows.delete(flowId);
        if (hadTerminal !== undefined) this.terminalSeen.set(flowId, hadTerminal);
      }
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
    this.endFlow(p.flow_id); // the synthesized error ends the flow
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
   * Cancellations being processed, by flow_id, with the flow generation they
   * belong to: a repeat for the SAME generation arriving meanwhile shares the
   * outcome; a replacement flow under the same id never does.
   */
  private cancelling = new Map<string, { gen: number; rec: object | undefined; run: Promise<unknown> }>();

  /** Incremented whenever the flow state is reset (session closed or replaced). */
  private flowEpoch = 0;

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
    // Recoveries run one at a time: a second resume sent before the first one's
    // response arrived would present the token the first already rotated. A gap
    // that arrives while one is queued adds nothing (the queued one covers it).
    if (this.recoveryQueued) return;
    this.recoveryQueued = true;
    this.recovery = this.recovery.then(async () => {
      this.recoveryQueued = false;
      if (!this.sessionId || !this.resumptionToken) {
        this.onSessionLost?.(new Error("event gap and no resumption token to resume with"));
        return;
      }
      try {
        await this.resumeSession();
      } catch (err: unknown) {
        // The session was closed or replaced meanwhile: nothing was lost.
        if (err instanceof StaleSessionError) return;
        this.onSessionLost?.(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  private recovery: Promise<void> = Promise.resolve();
  private recoveryQueued = false;

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

/** Per request: continuations to run after its response was sent, and the undo for the flow it started. */
interface AfterResponse {
  fns: (() => void)[];
  undo?: () => void;
}

/** A resume result that arrived after its session was closed or replaced. */
class StaleSessionError extends Error {
  constructor() {
    super("session changed while resuming");
    this.name = "StaleSessionError";
  }
}

function flowTypeOf(params: unknown): unknown {
  return typeof params === "object" && params !== null ? (params as { flow_type?: unknown }).flow_type : undefined;
}

const noop = (): void => {};

/** Most flows a peer holds validation context for at once; a new start beyond it is refused. */
const MAX_ACTIVE_FLOWS = 4096;

/** Most finished flows remembered per session; at that point new starts are refused until the session is renewed. */
const MAX_TERMINAL_HISTORY = 65536;

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
