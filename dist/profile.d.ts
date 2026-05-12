/**
 * Profile system — mirrors go-wmp/pkg/wmp/profile.go.
 *
 * Profiles are pluggable extensions that define flow handlers,
 * custom method handlers, and resolve handlers.
 */
import type { FlowStartParams, FlowStartResult, FlowActionParams, FlowActionResult, FlowProgressParams, FlowCompleteParams, FlowErrorParams, ResolveParams, ResolveResult } from "./types.js";
export interface PeerContext {
    /** Send a JSON-RPC notification (no response expected). */
    notify(method: string, params: unknown): Promise<void>;
    /** Send a JSON-RPC request and wait for the response. */
    call<T = unknown>(method: string, params: unknown): Promise<T>;
}
export interface Profile {
    /** Profile identifier (e.g., "openid4x", "evidence"). */
    readonly name: string;
    /** Capability names this profile provides. */
    capabilities(): string[];
    /** Called when the profile is registered with a Peer. */
    init(ctx: PeerContext): void;
}
export interface FlowHandler {
    /** Flow type identifiers this handler manages. */
    flowTypes(): string[];
    startFlow(params: FlowStartParams): Promise<FlowStartResult>;
    handleAction(params: FlowActionParams): Promise<FlowActionResult>;
    handleProgress(params: FlowProgressParams): void;
    handleComplete(params: FlowCompleteParams): void;
    handleError(params: FlowErrorParams): void;
}
export interface MethodHandler {
    /** Method names this handler supports. */
    methods(): string[];
    handleMethod(method: string, params: unknown): Promise<unknown>;
}
export interface ResolveHandler {
    /** Resolve type identifiers this handler supports. */
    resolveTypes(): string[];
    handleResolve(params: ResolveParams): Promise<ResolveResult>;
}
export declare class Registry {
    private profiles;
    private flowHandlers;
    private methodHandlers;
    private resolveHandlers;
    register(profile: Profile): void;
    getFlowHandler(flowType: string): FlowHandler | undefined;
    getMethodHandler(method: string): MethodHandler | undefined;
    getResolveHandler(resolveType: string): ResolveHandler | undefined;
    allCapabilities(): string[];
}
