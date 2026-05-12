/**
 * Profile system — mirrors go-wmp/pkg/wmp/profile.go.
 *
 * Profiles are pluggable extensions that define flow handlers,
 * custom method handlers, and resolve handlers.
 */

import type {
  FlowStartParams,
  FlowStartResult,
  FlowActionParams,
  FlowActionResult,
  FlowProgressParams,
  FlowCompleteParams,
  FlowErrorParams,
  ResolveParams,
  ResolveResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// PeerContext — passed to profiles during init
// ---------------------------------------------------------------------------

export interface PeerContext {
  /** Send a JSON-RPC notification (no response expected). */
  notify(method: string, params: unknown): Promise<void>;

  /** Send a JSON-RPC request and wait for the response. */
  call<T = unknown>(method: string, params: unknown): Promise<T>;
}

// ---------------------------------------------------------------------------
// Profile interface
// ---------------------------------------------------------------------------

export interface Profile {
  /** Profile identifier (e.g., "openid4x", "evidence"). */
  readonly name: string;

  /** Capability names this profile provides. */
  capabilities(): string[];

  /** Called when the profile is registered with a Peer. */
  init(ctx: PeerContext): void;
}

// ---------------------------------------------------------------------------
// FlowHandler — handles profile-specific flow types
// ---------------------------------------------------------------------------

export interface FlowHandler {
  /** Flow type identifiers this handler manages. */
  flowTypes(): string[];

  startFlow(params: FlowStartParams): Promise<FlowStartResult>;
  handleAction(params: FlowActionParams): Promise<FlowActionResult>;
  handleProgress(params: FlowProgressParams): void;
  handleComplete(params: FlowCompleteParams): void;
  handleError(params: FlowErrorParams): void;
}

// ---------------------------------------------------------------------------
// MethodHandler — handles custom JSON-RPC methods
// ---------------------------------------------------------------------------

export interface MethodHandler {
  /** Method names this handler supports. */
  methods(): string[];

  handleMethod(method: string, params: unknown): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// ResolveHandler — handles profile-specific resolve types
// ---------------------------------------------------------------------------

export interface ResolveHandler {
  /** Resolve type identifiers this handler supports. */
  resolveTypes(): string[];

  handleResolve(params: ResolveParams): Promise<ResolveResult>;
}

// ---------------------------------------------------------------------------
// Registry — internal profile/handler registry
// ---------------------------------------------------------------------------

export class Registry {
  private profiles: Profile[] = [];
  private flowHandlers = new Map<string, FlowHandler>();
  private methodHandlers = new Map<string, MethodHandler>();
  private resolveHandlers = new Map<string, ResolveHandler>();

  register(profile: Profile): void {
    // Register sub-interfaces.
    if (isFlowHandler(profile)) {
      for (const ft of profile.flowTypes()) {
        if (this.flowHandlers.has(ft)) {
          throw new Error(
            `Flow type "${ft}" already registered by another profile`,
          );
        }
        this.flowHandlers.set(ft, profile);
      }
    }

    if (isMethodHandler(profile)) {
      for (const m of profile.methods()) {
        if (this.methodHandlers.has(m)) {
          throw new Error(
            `Method "${m}" already registered by another profile`,
          );
        }
        this.methodHandlers.set(m, profile);
      }
    }

    if (isResolveHandler(profile)) {
      for (const rt of profile.resolveTypes()) {
        if (this.resolveHandlers.has(rt)) {
          throw new Error(
            `Resolve type "${rt}" already registered by another profile`,
          );
        }
        this.resolveHandlers.set(rt, profile);
      }
    }

    this.profiles.push(profile);
  }

  getFlowHandler(flowType: string): FlowHandler | undefined {
    return this.flowHandlers.get(flowType);
  }

  getMethodHandler(method: string): MethodHandler | undefined {
    return this.methodHandlers.get(method);
  }

  getResolveHandler(resolveType: string): ResolveHandler | undefined {
    return this.resolveHandlers.get(resolveType);
  }

  allCapabilities(): string[] {
    return this.profiles.flatMap((p) => p.capabilities());
  }
}

// Type guards for profile sub-interfaces.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isFlowHandler(p: Profile): p is Profile & FlowHandler {
  return (
    "flowTypes" in p &&
    typeof (p as any).flowTypes === "function" &&
    "startFlow" in p
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isMethodHandler(p: Profile): p is Profile & MethodHandler {
  return (
    "methods" in p &&
    typeof (p as any).methods === "function" &&
    "handleMethod" in p
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isResolveHandler(p: Profile): p is Profile & ResolveHandler {
  return (
    "resolveTypes" in p &&
    typeof (p as any).resolveTypes === "function" &&
    "handleResolve" in p
  );
}
