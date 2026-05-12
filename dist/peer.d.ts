/**
 * Peer — the core WMP client/server dispatcher.
 * Mirrors go-wmp/pkg/wmp/peer.go.
 *
 * Handles incoming messages by dispatching to handlers/profiles,
 * and provides methods to send outgoing requests and notifications.
 */
import { type Transport } from "./transport.js";
import { type Profile, type PeerContext } from "./profile.js";
import { type SessionCreateParams, type SessionCreateResult, type SessionCloseParams, type FlowStartParams, type FlowStartResult, type FlowProgressParams, type FlowActionParams, type FlowActionResult, type FlowCompleteParams, type FlowErrorParams, type FlowCancelParams, type FlowCancelResult, type ResolveParams, type ResolveResult, type Capabilities, type SecurityMode } from "./types.js";
/**
 * Handler processes incoming WMP method calls.
 * All methods are optional — unimplemented methods return "method not found".
 */
export interface Handler {
    onSessionCreate?(params: SessionCreateParams): Promise<SessionCreateResult>;
    onSessionClose?(params: SessionCloseParams): void;
    onFlowStart?(params: FlowStartParams): Promise<FlowStartResult>;
    onFlowProgress?(params: FlowProgressParams): void;
    onFlowAction?(params: FlowActionParams): Promise<FlowActionResult>;
    onFlowComplete?(params: FlowCompleteParams): void;
    onFlowError?(params: FlowErrorParams): void;
    onFlowCancel?(params: FlowCancelParams): Promise<FlowCancelResult>;
    onResolve?(params: ResolveParams): Promise<ResolveResult>;
}
export interface PeerOptions {
    /** Default timeout for RPC calls in ms. Default: 30000 */
    callTimeout?: number;
    /** Handler for incoming method calls. */
    handler?: Handler;
}
export declare class Peer implements PeerContext {
    private transport;
    private handler;
    private registry;
    private pending;
    private callTimeout;
    private sessionId?;
    private closed;
    constructor(transport: Transport, opts?: PeerOptions);
    /** Register a profile. Call before starting to receive messages. */
    use(profile: Profile): void;
    /** The negotiated session ID (set after session.create). */
    get session(): string | undefined;
    notify(method: string, params: unknown): Promise<void>;
    call<T = unknown>(method: string, params: unknown): Promise<T>;
    /** Initiate a WMP session. */
    createSession(opts: {
        participants?: string[];
        capabilities?: Capabilities;
        security?: SecurityMode;
        auth?: {
            type: string;
            token?: string;
            [key: string]: unknown;
        };
        sender?: string;
        ttl?: number;
    }): Promise<SessionCreateResult>;
    /**
     * Bind a session ID to the underlying transport. For HttpSseTransport,
     * this sets the Wmp-Session-Id header and session_id query parameter.
     */
    private bindSessionToTransport;
    /** Close the current session. */
    closeSession(reason?: string): Promise<void>;
    /** Start a flow. */
    startFlow(flowType: string, flowId: string, params?: unknown, timeout?: number): Promise<FlowStartResult>;
    /** Send a flow progress notification. */
    flowProgress(flowId: string, step: string, payload?: unknown): Promise<void>;
    /** Send a flow action request and wait for result. */
    flowAction(flowId: string, action: string, params?: unknown): Promise<FlowActionResult>;
    /** Notify flow completion. */
    flowComplete(flowId: string, result?: unknown): Promise<void>;
    /** Notify flow error. */
    flowError(flowId: string, code: number, message: string, data?: unknown): Promise<void>;
    /** Cancel a flow. */
    flowCancel(flowId: string, reason?: string): Promise<FlowCancelResult>;
    resolve(type: string, uri: string, options?: unknown): Promise<ResolveResult>;
    close(): void;
    private dispatch;
    private handleResponse;
    private handleRequest;
    private dispatchMethod;
    private activeFlows;
    /** Look up the FlowHandler for an active flow by flow_id. */
    private flowHandlerForId;
    /** Track a flow as active (called when flow.start succeeds). */
    trackFlow(flowId: string, flowType: string): void;
    /** Untrack a flow (called on flow.complete / flow.error / flow.cancel). */
    untrackFlow(flowId: string): void;
    private wmpMeta;
    private onTransportError;
    private onTransportClose;
}
