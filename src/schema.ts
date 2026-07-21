/**
 * WMP JSON Schema validation.
 *
 * Validates WMP messages against the JSON Schema 2020-12 definitions
 * from the WMP specification. Schemas are loaded from the wmp/schema
 * directory at build time (via file paths) or at runtime (via URLs).
 *
 * Usage:
 *   import { createValidator } from '@sirosfoundation/wmp-js/schema';
 *   const validator = await createValidator(schemaDir);
 *   const errors = validator.validateMethod('wmp.session.create', message);
 */

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

// Method → request schema file mapping.
const METHOD_SCHEMAS: Record<string, string> = {
  "wmp.session.create": "methods/session-create-request.json",
  "wmp.session.close": "methods/session-close.json",
  "wmp.flow.start": "methods/flow-start.json",
  "wmp.flow.progress": "methods/flow-progress.json",
  "wmp.flow.action": "methods/flow-action.json",
  "wmp.flow.complete": "methods/flow-complete.json",
  "wmp.flow.error": "methods/flow-error.json",
  "wmp.resolve": "methods/resolve-request.json",
  "wmp.message.deliver": "methods/message-deliver.json",
  "wmp.message.ack": "methods/message-ack.json",
  "wmp.capability.update": "methods/capability-update-request.json",
};

// Method → response schema file mapping.
const RESPONSE_SCHEMAS: Record<string, string> = {
  "wmp.session.create": "methods/session-create-response.json",
  "wmp.resolve": "methods/resolve-response.json",
  "wmp.capability.list": "methods/capability-list-response.json",
};

export interface ValidationError {
  path: string;
  message: string;
}

export interface Validator {
  /** Validate a request message for the given method. Returns null if valid. */
  validateMethod(method: string, message: unknown): ValidationError[] | null;

  /** Validate a response for the given method. Returns null if valid. */
  validateResponse(method: string, message: unknown): ValidationError[] | null;

  /** Validate a WMP metadata object. Returns null if valid. */
  validateMetadata(metadata: unknown): ValidationError[] | null;

  /** List methods that have request schemas. */
  methodSchemas(): string[];
}

/**
 * Create a schema validator by loading schemas from the filesystem.
 *
 * @param schemaDir Path to the wmp/schema directory containing the JSON Schema files.
 * @param strict When true, unknown methods/responses are reported as validation errors.
 */
export function createValidator(schemaDir: string, strict = false): Validator {
  const ajv = new Ajv2020({
    strict: false,
    allErrors: true,
  });
  addFormats(ajv);

  const absDir = resolve(schemaDir);

  // Load top-level schemas.
  const topFiles = readdirSync(absDir).filter((f: string) => f.endsWith(".json"));
  for (const file of topFiles) {
    const content = JSON.parse(readFileSync(join(absDir, file), "utf-8"));
    const id = content.$id || file;
    try {
      ajv.addSchema(content, id);
      if (id !== file) ajv.addSchema(content, file);
    } catch {
      // Schema may already be added.
    }
  }

  // Load method schemas.
  const methodDir = join(absDir, "methods");
  if (existsSync(methodDir)) {
    const methodFiles = readdirSync(methodDir).filter((f: string) => f.endsWith(".json"));
    for (const file of methodFiles) {
      const content = JSON.parse(readFileSync(join(methodDir, file), "utf-8"));
      const id = content.$id || `methods/${file}`;
      try {
        ajv.addSchema(content, id);
        if (id !== `methods/${file}`) ajv.addSchema(content, `methods/${file}`);
      } catch {
        // Schema may already be added.
      }
    }
  }

  function validate(schemaId: string, data: unknown): ValidationError[] | null {
    const valid = ajv.validate(schemaId, data);
    if (valid) return null;

    return (ajv.errors ?? []).map((e) => ({
      path: e.instancePath || "/",
      message: e.message ?? "unknown error",
    }));
  }

  return {
    validateMethod(method: string, message: unknown): ValidationError[] | null {
      const schema = METHOD_SCHEMAS[method];
      if (!schema) {
        return strict
          ? [{ path: "/", message: `No schema defined for method ${method}` }]
          : null;
      }
      return validate(schema, message);
    },

    validateResponse(method: string, message: unknown): ValidationError[] | null {
      const schema = RESPONSE_SCHEMAS[method];
      if (!schema) {
        return strict
          ? [{ path: "/", message: `No response schema defined for method ${method}` }]
          : null;
      }
      return validate(schema, message);
    },

    validateMetadata(metadata: unknown): ValidationError[] | null {
      return validate("wmp-metadata.json", metadata);
    },

    methodSchemas(): string[] {
      return Object.keys(METHOD_SCHEMAS);
    },
  };
}
