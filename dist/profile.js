/**
 * Profile system — mirrors go-wmp/pkg/wmp/profile.go.
 *
 * Profiles are pluggable extensions that define flow handlers,
 * custom method handlers, and resolve handlers.
 */
// ---------------------------------------------------------------------------
// Registry — internal profile/handler registry
// ---------------------------------------------------------------------------
export class Registry {
    profiles = [];
    flowHandlers = new Map();
    methodHandlers = new Map();
    resolveHandlers = new Map();
    register(profile) {
        // Register sub-interfaces.
        if (isFlowHandler(profile)) {
            for (const ft of profile.flowTypes()) {
                if (this.flowHandlers.has(ft)) {
                    throw new Error(`Flow type "${ft}" already registered by another profile`);
                }
                this.flowHandlers.set(ft, profile);
            }
        }
        if (isMethodHandler(profile)) {
            for (const m of profile.methods()) {
                if (this.methodHandlers.has(m)) {
                    throw new Error(`Method "${m}" already registered by another profile`);
                }
                this.methodHandlers.set(m, profile);
            }
        }
        if (isResolveHandler(profile)) {
            for (const rt of profile.resolveTypes()) {
                if (this.resolveHandlers.has(rt)) {
                    throw new Error(`Resolve type "${rt}" already registered by another profile`);
                }
                this.resolveHandlers.set(rt, profile);
            }
        }
        this.profiles.push(profile);
    }
    getFlowHandler(flowType) {
        return this.flowHandlers.get(flowType);
    }
    getMethodHandler(method) {
        return this.methodHandlers.get(method);
    }
    getResolveHandler(resolveType) {
        return this.resolveHandlers.get(resolveType);
    }
    allCapabilities() {
        return this.profiles.flatMap((p) => p.capabilities());
    }
}
// Type guards for profile sub-interfaces.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isFlowHandler(p) {
    return ("flowTypes" in p &&
        typeof p.flowTypes === "function" &&
        "startFlow" in p);
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isMethodHandler(p) {
    return ("methods" in p &&
        typeof p.methods === "function" &&
        "handleMethod" in p);
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function isResolveHandler(p) {
    return ("resolveTypes" in p &&
        typeof p.resolveTypes === "function" &&
        "handleResolve" in p);
}
