/**
 * PUBLIC-SAFE, DISABLED Gateway-to-worker handoff fixture. Not a plugin,
 * launcher, authenticated base issuer, private-pipe implementation, or permit.
 * Every injected dependency is TEST-ONLY, not authority. There is no production
 * entrypoint, process spawn, credential, environment or logging path here.
 */
import { admitCandidate } from './context-contract.mjs';
import { createClaimFrameIssuer } from './claim-frame.mjs';

const SHA = /^[0-9a-f]{40}$/;
const PART = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;

/** Fixed target and zero-argument fake adapters must be supplied by the test host,
 * never by a tool request. Shape checks do not authenticate any of them.
 * A fixture instance is one-use, including failed attempts.
 */
export function createDisabledHandoffFixture(fixture = {}) {
  if (!fixture || typeof fixture !== 'object' || Array.isArray(fixture)) {
    throw new Error('test_handoff_dependencies_unavailable');
  }
  const { repository, ref, lookupFixedBaseForTest, openPrivatePipeForTest } = fixture;
  const parts = typeof repository === 'string' ? repository.split('/') : [];
  if (parts.length !== 2 || !parts.every(part => PART.test(part) && part !== '.' && part !== '..') ||
      ref !== 'refs/heads/main' || typeof lookupFixedBaseForTest !== 'function' ||
      typeof openPrivatePipeForTest !== 'function') {
    throw new Error('test_handoff_dependencies_unavailable');
  }
  // Retain primitive pins, not a mutable config object. No request can retarget them.
  const fixedRepository = repository;
  const fixedRef = ref;
  let used = false;
  return Object.freeze({
    async run(context, request) {
      if (used) throw new Error('handoff_replay_denied');
      used = true;
      const { candidate, assertCurrent } = admitCandidate(context, request);
      assertCurrent();
      let base;
      try { base = await lookupFixedBaseForTest(); }
      catch { assertCurrent(); throw new Error('trusted_base_unavailable'); }
      assertCurrent(); // keep the original live closure across the lookup await
      if (typeof base !== 'string' || !SHA.test(base) || base === candidate.sha) {
        throw new Error('trusted_base_unavailable');
      }
      let pipe;
      try {
        assertCurrent();
        try { pipe = await openPrivatePipeForTest(); }
        catch { assertCurrent(); throw new Error('private_pipe_unavailable'); }
        assertCurrent(); // changed model, revoked sandbox or abort: no pipe write
        if (!pipe || typeof pipe.destroy !== 'function') {
          throw new Error('private_pipe_unavailable');
        }
        const issuer = createClaimFrameIssuer({
          trustedHost: { repository: fixedRepository, ref: fixedRef, base,
            candidate, assertCurrent },
          privatePipe: pipe,
        });
        await issuer.emit(); // issuer checks live closure synchronously at write
        assertCurrent(); // a later abort cannot yield a receipt
        throw new Error('publication_disabled');
      } finally {
        // Owned pipe is never returned, even on issuer/setup/write failure.
        // Fake opener owns cleanup if it rejects without returning a pipe.
        // Fixture cleanup cannot replace the stable terminal denial or leak
        // adapter details. A production launcher must prove cleanup separately.
        try {
          if (pipe && typeof pipe.destroy === 'function') {
            void Promise.resolve(pipe.destroy()).catch(() => {});
          }
        } catch { /* no publication receipt exists, even if cleanup fails */ }
      }
    },
  });
}
