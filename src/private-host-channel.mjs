/** Disabled Gateway-only claim socket seam. Not a plugin, publisher, or
 * authenticated production route. Constructor pins must be Gateway-owned;
 * the injected base lookup is explicitly test-only and unauthenticated.
 */
import { lstat } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { dirname, isAbsolute, parse, resolve } from 'node:path';
import { admitCandidate } from './context-contract.mjs';
import { createClaimFrameIssuer } from './claim-frame.mjs';

const SHA = /^[0-9a-f]{40}$/;
const PART = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const DENIAL = Buffer.from('publication_disabled');
const MAX_RESPONSE_BYTES = 64;
const unavailable = () => new Error('private_socket_unavailable');

// Check every ancestor without following symlinks. Only a root-owned sticky
// ancestor may be writable by others (e.g. /tmp); immediate parent must be
// private and owned by this process. Recheck identity after connect. Node's
// path-based connect cannot fully eliminate filesystem TOCTOU or attest peer.
async function inspectSocket(path, assertCurrent) {
  const parent = dirname(path);
  const paths = [];
  for (let p = parent; ; p = dirname(p)) {
    paths.push(p);
    if (p === dirname(p)) break;
  }
  paths.reverse();
  paths.push(path);
  let socket;
  for (const p of paths) {
    assertCurrent();
    const st = await lstat(p);
    assertCurrent();
    if (st.isSymbolicLink()) throw unavailable();
    if (p === path) {
      if (!st.isSocket() || st.uid !== process.getuid() || (st.mode & 0o077)) throw unavailable();
      socket = st;
    } else {
      if (!st.isDirectory() || ((st.mode & 0o022) &&
          !(p !== parent && st.uid === 0 && (st.mode & 0o1000)))) throw unavailable();
      if (p === parent && (st.uid !== process.getuid() || (st.mode & 0o077))) throw unavailable();
    }
  }
  return socket;
}

/** All config comes from the trusted constructing host, never tool input.
 * Shape checks here do not authenticate that host or its test base lookup.
 */
export function createPrivateHostChannel(config = {}) {
  const { repository, ref, socketPath, lookupFixedBaseForTest, deadlineMs = 2000 } = config;
  const parts = typeof repository === 'string' ? repository.split('/') : [];
  if (parts.length !== 2 || !parts.every(p => PART.test(p) && p !== '.' && p !== '..') ||
      ref !== 'refs/heads/main' || typeof socketPath !== 'string' ||
      !isAbsolute(socketPath) || resolve(socketPath) !== socketPath ||
      socketPath === parse(socketPath).root || socketPath.includes('\0') ||
      typeof lookupFixedBaseForTest !== 'function' ||
      !Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 10000 ||
      typeof process.getuid !== 'function') throw new Error('private_host_config_unavailable');
  const fixedRepository = repository, fixedRef = ref, fixedPath = socketPath;
  let used = false;
  return Object.freeze({
    async run(context, request, { signal } = {}) {
      if (used) throw new Error('handoff_replay_denied');
      used = true;
      const { candidate, assertCurrent } = admitCandidate(context, request);
      if (signal !== undefined && (typeof signal?.addEventListener !== 'function' ||
          typeof signal?.removeEventListener !== 'function' ||
          typeof signal?.aborted !== 'boolean')) throw new Error('claim_cancelled');
      let socket, timer, onAbort, interrupt;
      const stopped = new Promise((_, reject) => { interrupt = reject; });
      void stopped.catch(() => {});
      const guard = () => {
        assertCurrent();
        if (signal?.aborted) throw new Error('claim_cancelled');
      };
      const wait = async promise => {
        let value;
        try { value = await Promise.race([promise, stopped]); }
        catch (error) { guard(); throw error; }
        guard();
        return value;
      };
      try {
        guard();
        timer = setTimeout(() => { interrupt(new Error('claim_deadline_exceeded')); socket?.destroy(); }, deadlineMs);
        onAbort = () => { interrupt(new Error('claim_cancelled')); socket?.destroy(); };
        signal?.addEventListener('abort', onAbort, { once: true });
        guard();
        let base;
        try { base = await wait(Promise.resolve().then(() => lookupFixedBaseForTest())); }
        catch (error) {
          guard();
          if (error.message === 'claim_deadline_exceeded' || error.message === 'claim_cancelled') throw error;
          throw new Error('trusted_base_unavailable');
        }
        if (typeof base !== 'string' || !SHA.test(base) || base === candidate.sha) throw new Error('trusted_base_unavailable');
        let original;
        try { original = await wait(inspectSocket(fixedPath, guard)); }
        catch (error) {
          guard();
          if (error.message === 'claim_deadline_exceeded' || error.message === 'claim_cancelled') throw error;
          throw unavailable();
        }
        guard();
        try { socket = createConnection({ path: fixedPath }); }
        catch { throw unavailable(); }
        let connectResolve, connectReject, responseResolve, responseReject;
        let connected = false, received = Buffer.alloc(0);
        const connection = new Promise((resolve, reject) => { connectResolve = resolve; connectReject = reject; });
        const response = new Promise((resolve, reject) => { responseResolve = resolve; responseReject = reject; });
        void connection.catch(() => {});
        void response.catch(() => {});
        socket.on('connect', () => { connected = true; connectResolve(); });
        socket.on('data', chunk => {
          if (received.length + chunk.length > MAX_RESPONSE_BYTES) {
            responseReject(new Error('claim_response_invalid'));
            socket.destroy();
          } else received = Buffer.concat([received, chunk]);
        });
        socket.on('end', () => {
          if (received.equals(DENIAL)) responseResolve();
          else responseReject(new Error('claim_response_invalid'));
        });
        socket.on('error', () => { connectReject(unavailable()); responseReject(unavailable()); });
        socket.on('close', () => {
          if (!connected) connectReject(unavailable());
          responseReject(new Error('claim_socket_closed'));
        });
        await wait(connection);
        let rechecked;
        try { rechecked = await wait(inspectSocket(fixedPath, guard)); }
        catch (error) {
          guard();
          if (error.message === 'claim_deadline_exceeded' || error.message === 'claim_cancelled') throw error;
          throw unavailable();
        }
        if (original.dev !== rechecked.dev || original.ino !== rechecked.ino) throw unavailable();
        guard();
        const issuer = createClaimFrameIssuer({
          trustedHost: { repository: fixedRepository, ref: fixedRef, base,
            candidate, assertCurrent: guard }, privatePipe: socket,
        });
        await wait(issuer.emit()); // issuer guards synchronously before its single write
        guard();
        socket.end(); // one canonical frame, then EOF
        await wait(response);
        throw new Error('publication_disabled'); // denial is never a permit
      } finally {
        clearTimeout(timer);
        if (onAbort) signal?.removeEventListener('abort', onAbort);
        socket?.destroy();
      }
    },
  });
}
