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

  constructor(transport: Transport, opts?: PeerOptions) {
    this.transport = transport;
    this.handler = opts?.handler ?? {};
    this.callTimeout = opts?.callTimeout ?? 30_000;
    this.validator = opts?.validator;
    this.authorize = opts?.authorize;
    this.validateCompletions = opts?.validateCompletions ?? true;
    this.onRefusedCompletion = opts?.onRefusedCompletion;
    this.onSessionLost = opts?.onSessionLost;

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

  /** The negotiated session ID (set after session.create). */
  get session(): string | undefined {
    return this.sessionId;
  }

  // -------------------------------------------------------------------------
  // PeerContext implementation (for profiles)
  // -------------------------------------------------------------------------

  async notify(method: string, params: unknown): Promise<void> {
    const msg = createNotification(method, params);
    await this.transport.send(msg);
    // This peer ended the flow (complete or error, sent by the convenience
    // methods and by profiles alike): its validation context is no longer needed.
    if (method === Method.FlowComplete || method === Method.FlowError) this.releaseFlow(flowIdOf(params));
  }

  /** Drops the validation context of a flow that ended; the flow_id is free to start again. */
  private releaseFlow(flowId: unknown): void {
    if (typeof flowId !== "string") return;
    this.recordedFlows.delete(flowId);
    this.releaseGen(flowId);
  }

  /**
   * Reclaims a flow id's generation once nothing needs it: the flow is not active
   * and no cancellation for it is pending (a pending one compares against it).
   * Without this every finished flow would leave an entry behind for the whole
   * session. A missing entry reads as generation 0.
   */
  private releaseGen(flowId: string): void {
    if (!this.recordedFlows.has(flowId) && (this.cancelCount.get(flowId) ?? 0) === 0) this.flowGen.delete(flowId);
  }

  async call<T = unknown>(method: string, params: unknown): Promise<T> {
    const req = createRequest(method, params);
    const id = req.id!;
    // Every outgoing flow.start goes through here (the convenience method and
    // profiles alike), so the flow's validation context is always recorded.
    const rollback = method === Method.FlowStart ? this.beginFlow(flowIdOf(params), flowTypeOf(params), (params as { params?: unknown }).params) : noop;

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
    const wmp: Metadata = { version: VERSION, sender: opts.sender };
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
    if (result.wmp.version && result.wmp.version !== VERSION) {
      throw new WMPError(
        ErrorCode.VersionNotSupported,
        `negotiated version ${result.wmp.version} is not supported`,
      );
    }
    this.sessionId = result.wmp.session_id;
    this.resetFlows(); // a new session: the old one's flow state does not carry over
    this.bindSessionToTransport(result.wmp.session_id);
    this.negotiatedVersion = result.wmp.version ?? VERSION;
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
    // The session (flow epoch) this resume is requested for is noted NOW, before
    // it waits its turn: if that session is closed or replaced while it queues, it
    // is dropped instead of resuming the session that replaced it.
    return this.resumeSerialized(opts, this.flowEpoch);
  }

  /**
   * `forEpoch`: recovery work that is only valid for the session it was queued
   * for; if that session was closed or replaced (or the peer closed) while it
   * waited its turn, it is dropped (StaleSessionError) instead of resuming the
   * session that replaced it.
   */
  private async resumeSerialized(opts: { lastReceivedId?: string } | undefined, forEpoch: number): Promise<SessionResumeResult> {
    const previous = this.resumeChain;
    let release!: () => void;
    this.resumeChain = new Promise<void>((r) => (release = r));
    await previous;
    try {
      if (this.closed || this.flowEpoch !== forEpoch) throw new StaleSessionError();
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
    const epoch = this.flowEpoch;
    const result = await this.call<SessionResumeResult>(
      Method.SessionResume,
      params,
    );
    // The session this resume was for may have been closed or replaced while it
    // was in flight: its result must not overwrite the session that replaced it.
    if (this.flowEpoch !== epoch) throw new StaleSessionError();
    // An unsuccessful resume changes nothing; the caller creates a new session.
    if (result.resumed !== true) {
      throw new WMPError(ErrorCode.SessionExpired, "Session could not be resumed");
    }
    if (result.wmp?.session_id) {
      // Resuming the same session keeps its flow state; another session does not.
      if (result.wmp.session_id !== this.sessionId) this.resetFlows();
      this.sessionId = result.wmp.session_id;
      this.bindSessionToTransport(result.wmp.session_id);
    }
    if (result.wmp?.version) {
      this.negotiatedVersion = result.wmp.version;
    }
    if (result.resumption_token) {
      this.resumptionToken = result.resumption_token;
    }
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
      wmp: { version: VERSION, session_id: this.sessionId },
      reason,
    });
    this.sessionId = undefined;
    this.resetFlows();
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
      dispatch().catch(() => {
        /* notifications get no error response */
      });
    } else {
      dispatch()
        .then((result) => {
          const resp = createResponse(req.id!, result);
          return this.transport.send(resp);
        })
        .catch((err) => {
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
          const result = await this.handler.onSessionCreate(p);
          if (result) {
            // The session this peer now serves: remember its identity (a responder-only
            // peer has no other way to know it), and drop the previous session's flow state.
            const id = result.wmp?.session_id;
            if (typeof id === "string" && id !== "") this.sessionId = id;
            this.resetFlows();
          }
          return result;
        }
        break;

      case Method.SessionResume:
        if (this.handler.onSessionResume) {
          const result = await this.handler.onSessionResume(p);
          if (result?.resumed === true) {
            const resumed = typeof result.wmp?.session_id === "string" && result.wmp.session_id !== "" ? result.wmp.session_id : typeof p?.session_id === "string" ? p.session_id : undefined;
            // Resuming a different session than the one held drops the old flow
            // state; the same one keeps it. The resumed session is the one held from now on.
            if (resumed !== undefined) {
              if (resumed !== this.sessionId) this.resetFlows();
              this.sessionId = resumed;
            }
          }
          return result;
        }
        break;

      case Method.SessionClose:
        // The close of this session (or one that names none) ends it: its flow
        // state goes and the peer no longer reports (or addresses) it.
        if (p?.wmp?.session_id === undefined || p.wmp.session_id === this.sessionId) {
          this.sessionId = undefined;
          this.resetFlows();
        }
        if (this.handler.onSessionClose) {
          this.handler.onSessionClose(p);
        }
        return undefined;

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
          return this.handler.onCapabilityUpdate(p);
        }
        break;

      case Method.CapabilityList:
        if (this.handler.onCapabilityList) {
          return this.handler.onCapabilityList(p);
        }
        break;

      // Flows — delegate to profile FlowHandlers first, then handler.
      case Method.FlowStart: {
        // Rejects a duplicate active flow_id and records the flow's validation
        // context; a start that fails leaves nothing (and no existing flow's
        // context) changed.
        const rollback = this.beginFlow(p?.flow_id, p?.flow_type, p?.params);
        try {
          const fh = this.registry.getFlowHandler(p.flow_type);
          if (fh) return await fh.startFlow(p);
          if (this.handler.onFlowStart) return await this.handler.onFlowStart(p);
        } catch (err) {
          rollback();
          throw err;
        }
        rollback();
        break;
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
            // The flow this cancellation is for: the session epoch and the flow's
            // generation (stable across the flow's completion, changed by a new flow
            // under the same id or by a session reset).
            const epoch = this.flowEpoch;
            const gen = this.flowGen.get(flowId) ?? 0;
            // A repeat for the same flow that arrives while the first is still being
            // processed shares its outcome, even if the flow completed meanwhile. A
            // replacement flow under the same id is a different generation.
            const pending = this.cancelling.get(flowId);
            if (pending && pending.epoch === epoch && pending.gen === gen) return pending.run;
            const entry: { epoch: number; gen: number; run: Promise<unknown> } = { epoch, gen, run: undefined as unknown as Promise<unknown> };
            this.cancelCount.set(flowId, (this.cancelCount.get(flowId) ?? 0) + 1);
            entry.run = (async () => {
              // Yield first: the entry is installed before the handler can throw
              // (even synchronously), so its cleanup always sees it.
              await Promise.resolve();
              try {
                const result = await this.handler.onFlowCancel!(p);
                // Finalize only the flow that was cancelled: if another started under
                // the id (or the session was reset) meanwhile, leave it alone.
                if (this.flowEpoch === epoch && (this.flowGen.get(flowId) ?? 0) === gen) this.endFlow(flowId, "cancelled");
                return result;
              } finally {
                if (this.cancelling.get(flowId) === entry) this.cancelling.delete(flowId); // a failure leaves a retry possible
                const left = (this.cancelCount.get(flowId) ?? 1) - 1;
                if (left <= 0) this.cancelCount.delete(flowId);
                else this.cancelCount.set(flowId, left);
                this.releaseGen(flowId);
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
    this.releaseGen(flowId);
    // A flow already in the history may be re-marked (a cancel of an ended flow
    // upgrades its kind) without growing it.
    if (known || this.terminalSeen.has(flowId)) this.markTerminal(flowId, kind);
  }

  /** A new or ended session: the old session's flow state does not carry over. */
  private resetFlows(): void {
    this.flowEpoch++;
    this.recordedFlows.clear();
    this.terminalSeen.clear();
    this.flowGen.clear();
    this.cancelling.clear(); // pending cancellations belong to the old session
    this.cancelCount.clear();
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
    const previousGen = this.flowGen.get(flowId);
    const myGen = ++this.genCounter;
    this.flowGen.set(flowId, myGen); // a new flow under this id (tentative until the start succeeds)
    return () => {
      // Only while this start's own record is still the flow's: if the
      // replacement already ended, or another flow took the id, the marker is theirs.
      if (this.recordedFlows.get(flowId) === rec) {
        this.recordedFlows.delete(flowId);
        if (hadTerminal !== undefined) this.terminalSeen.set(flowId, hadTerminal);
        // The start failed: the flow generation it allocated goes with it, so work
        // tied to the flow that was there before (a pending cancellation) still matches.
        if (this.flowGen.get(flowId) === myGen) {
          if (previousGen === undefined) this.flowGen.delete(flowId);
          else this.flowGen.set(flowId, previousGen);
        }
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
  private cancelling = new Map<string, { epoch: number; gen: number; run: Promise<unknown> }>();

  /** Cancellations still running per flow id, of ANY generation: a generation entry is kept while one is. */
  private cancelCount = new Map<string, number>();

  /** Incremented whenever the flow state is reset (session closed or replaced). */
  private flowEpoch = 0;

  /**
   * A per-flow-id generation that survives the flow's completion: it changes only
   * when a new flow starts under the id (and with every reset), so work tied to
   * "this flow" can tell a replacement from the same flow having ended.
   */
  private flowGen = new Map<string, number>();
  /** Source of unique generation numbers (a rolled-back start never reuses one). */
  private genCounter = 0;

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
    // The session this gap belongs to: recovery work for a session that was closed
    // or replaced meanwhile is discarded, never applied to the one that replaced it.
    const epoch = this.flowEpoch;
    if (this.recoveryQueuedEpoch === epoch) return; // coalesce only with a queued recovery of THIS session
    this.recoveryQueuedEpoch = epoch;
    this.recovery = this.recovery.then(async () => {
      // A stale task must not clear the marker of a newer session's queued recovery.
      if (this.recoveryQueuedEpoch === epoch) this.recoveryQueuedEpoch = undefined;
      if (this.closed || this.flowEpoch !== epoch) return;
      if (!this.sessionId || !this.resumptionToken) {
        this.sessionLost(new Error("event gap and no resumption token to resume with"));
        return;
      }
      try {
        await this.resumeSerialized(undefined, epoch);
      } catch (err: unknown) {
        // The session changed (or the peer closed) while resuming: nothing was lost.
        if (err instanceof StaleSessionError || this.closed || this.flowEpoch !== epoch) return;
        this.sessionLost(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  /**
   * The session cannot be continued: the transport's binding to it is dropped
   * BEFORE the application is told, so the "create a new session" fallback the
   * callback is for does not send the dead session's id.
   */
  private sessionLost(err: Error): void {
    const t = this.transport as { clearSession?: () => void };
    if (typeof t.clearSession === "function") t.clearSession();
    this.onSessionLost?.(err);
  }

  private recovery: Promise<void> = Promise.resolve();
  private recoveryQueuedEpoch: number | undefined;

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

/** A resume result (or recovery) that belongs to a session that was closed or replaced meanwhile. */
class StaleSessionError extends Error {
  constructor() {
    super("session changed while resuming");
    this.name = "StaleSessionError";
  }
}

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

/** Most finished flows remembered per session; at that point new starts are refused until the session is renewed. */
const MAX_TERMINAL_HISTORY = 65536;

function toRPCError(err: unknown): RPCError {
  if (err instanceof WMPError) {
    return { code: err.code, message: err.message, data: err.data };
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
