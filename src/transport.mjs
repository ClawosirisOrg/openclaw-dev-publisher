/**
 * Inert publication boundary. This prototype intentionally has no credential
 * minting, git transport, GitHub API client or persistent credential storage.
 * See README.md for the required per-publish adapter contract and lifecycle.
 */
export async function publishSignedCommit() {
  throw new Error('unsupported: credentialed publication is not implemented');
}
