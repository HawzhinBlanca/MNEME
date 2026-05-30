import type { APIRequestContext } from "@playwright/test";

/**
 * Placeholder for future UI auth (operator key / capability token in session).
 * MCP and CLI use offline capabilities (blueprint §12); wire here when a web UI exists.
 */
export type MnemeAuthFixture = {
  capabilityToken?: string;
  operatorPubkeyHex?: string;
};

export async function applyAuthHeaders(
  _request: APIRequestContext,
  _auth: MnemeAuthFixture,
): Promise<void> {
  // No-op until MNEME_UI exposes HTTP with cap-based auth.
}
