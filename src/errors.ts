import { WMPError } from "./jsonrpc.js";
import { ErrorCode } from "./types.js";

/**
 * The -31005 (Capability not supported) error whose data is
 * {"unsupported": item} plus the additive members in `extra` (Core 3.8.1);
 * mirrors go-wmp NewUnsupportedError. A key "unsupported" in extra is ignored.
 */
export function unsupportedError(unsupported: string, extra?: Record<string, unknown>): WMPError {
  return new WMPError(ErrorCode.CapabilityNotSupported, "Capability not supported", { ...extra, unsupported });
}
