/** PUBLIC-SAFE framing only. Not a worker claim or authority for a final write.
 * Caller must be a trusted Gateway host retaining the live assertion closure
 * from context-contract.mjs and own the private pipe. Never supply this object
 * or its dependencies from a tool request, argv, environment, or stdout.
 */
import { randomBytes } from 'node:crypto';

export const MAX_CLAIM_FRAME_BODY_BYTES = 1024;
const KEYS = ['version', 'transactionId', 'repository', 'ref', 'base', 'sha',
  'branch', 'model', 'thinking', 'thinkingSource', 'claimId'];
const SHA = /^[0-9a-f]{40}$/;
const BRANCH = /^dev-syn\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._/+:-]{0,127}$/;
const REPO_PART = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const BASE_REF = 'refs/heads/main';
const CLAIM_ID = /^[0-9a-f]{32}$/;
const THINKING = new Set(['off', 'minimal', 'low', 'medium', 'high', 'xhigh']);

function ownData(input, keys) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(input)) ||
      Reflect.ownKeys(input).length !== keys.length ||
      !keys.every(key => {
        const property = Object.getOwnPropertyDescriptor(input, key);
        return property && Object.hasOwn(property, 'value') && property.enumerable;
      })) throw new Error('claim_frame_invalid');
  return Object.fromEntries(keys.map(key => [key, Object.getOwnPropertyDescriptor(input, key).value]));
}

function checkedBody(input) {
  const body = ownData(input, KEYS);
  const parts = typeof body.repository === 'string' ? body.repository.split('/') : [];
  if (body.version !== 1 || typeof body.transactionId !== 'string' ||
      !/^[0-9a-f]{32}$/.test(body.transactionId) || parts.length !== 2 ||
      !parts.every(part => REPO_PART.test(part) && part !== '.' && part !== '..') ||
      body.ref !== BASE_REF ||
      typeof body.base !== 'string' || !SHA.test(body.base) ||
      typeof body.sha !== 'string' || !SHA.test(body.sha) || body.sha === body.base ||
      typeof body.branch !== 'string' || !BRANCH.test(body.branch) ||
      typeof body.model !== 'string' || !MODEL.test(body.model) ||
      typeof body.thinking !== 'string' || !THINKING.has(body.thinking) ||
      body.thinkingSource !== 'agent_attested' ||
      typeof body.claimId !== 'string' || !CLAIM_ID.test(body.claimId) ||
      body.claimId !== body.transactionId) {
    throw new Error('claim_frame_invalid');
  }
  return Object.freeze(Object.fromEntries(KEYS.map(key => [key, body[key]])));
}

function encodeBody(body) {
  const bytes = Buffer.from(JSON.stringify(checkedBody(body)), 'utf8');
  if (bytes.length > MAX_CLAIM_FRAME_BODY_BYTES) throw new Error('claim_frame_oversized');
  const frame = Buffer.alloc(4 + bytes.length);
  frame.writeUInt32BE(bytes.length, 0);
  bytes.copy(frame, 4);
  return frame;
}

/** Decoder for offline verification; decoding does not confer replay protection. */
export function decodeClaimFrame(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < 4) throw new Error('claim_frame_truncated');
  const length = frame.readUInt32BE(0);
  if (length === 0 || length > MAX_CLAIM_FRAME_BODY_BYTES) throw new Error('claim_frame_oversized');
  if (frame.length !== 4 + length) throw new Error('claim_frame_truncated');
  let body;
  try {
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(frame.subarray(4)));
  } catch {
    throw new Error('claim_frame_invalid');
  }
  const checked = checkedBody(body);
  if (!encodeBody(checked).equals(frame)) throw new Error('claim_frame_noncanonical');
  return checked;
}

function writeOnce(pipe, frame, assertCurrent) {
  return new Promise((resolve, reject) => {
    let finished = false;
    let callbackDone = false;
    let drained = false;
    function cleanup() {
      pipe.off('error', onError);
      pipe.off('close', onClose);
      pipe.off('drain', onDrain);
    }
    function finish(error) {
      if (finished) return;
      finished = true;
      cleanup();
      if (error) reject(error);
      else resolve();
    }
    function maybeFinish() { if (callbackDone && drained) finish(); }
    function onError() { finish(new Error('claim_pipe_error')); }
    function onClose() { finish(new Error('claim_pipe_closed')); }
    function onDrain() { drained = true; maybeFinish(); }
    pipe.on('error', onError);
    pipe.on('close', onClose);
    pipe.on('drain', onDrain);
    try {
      if (pipe.destroyed || pipe.writableEnded || pipe.writable === false) {
        finish(new Error('claim_pipe_closed'));
        return;
      }
      // No await or other operation intervenes between the live assertion
      // and the write to the private pipe.
      let current;
      try { current = assertCurrent(); }
      catch { finish(new Error('stale_invocation')); return; }
      if (current === false) { finish(new Error('stale_invocation')); return; }
      const accepted = pipe.write(frame, (error, bytesWritten) => {
        if (error) return finish(new Error('claim_pipe_error'));
        // Node Writable callbacks normally omit a count. An adapter reporting
        // partial completion is rejected, not retried (which could duplicate).
        if (bytesWritten !== undefined && bytesWritten !== frame.length) {
          return finish(new Error('claim_pipe_short_write'));
        }
        callbackDone = true;
        maybeFinish();
      });
      if (accepted !== true && accepted !== false) finish(new Error('claim_pipe_error'));
      else if (accepted) { drained = true; maybeFinish(); }
    } catch {
      finish(new Error('claim_pipe_error'));
    }
  });
}

/** One-use issuer: no toolCallId/request value can choose the CSPRNG ID.
 * trustedHost provides repository/ref/base, admitted candidate,
 * and the live admitCandidate().assertCurrent closure. The guard is checked directly
 * before the synchronous pipe write; no await intervenes. This API assumes
 * the caller is the trusted host; JS shape checks cannot authenticate it.
 */
export function createClaimFrameIssuer({ trustedHost, privatePipe } = {}) {
  if (!trustedHost || typeof trustedHost.assertCurrent !== 'function' ||
      !trustedHost.candidate || trustedHost.candidate.model_source !== 'gateway_active_model' ||
      trustedHost.candidate.thinking_source !== 'agent_attested' ||
      !privatePipe || typeof privatePipe.write !== 'function' ||
      typeof privatePipe.on !== 'function' || typeof privatePipe.off !== 'function') {
    throw new Error('trusted_claim_host_unavailable');
  }
  const { candidate } = trustedHost;
  const assertCurrent = trustedHost.assertCurrent; // retain admission closure including model recheck
  const transactionId = randomBytes(16).toString('hex');
  const common = {
    version: 1, transactionId,
    repository: trustedHost.repository, ref: trustedHost.ref, base: trustedHost.base,
    sha: candidate.sha, branch: candidate.branch, model: candidate.model,
    thinking: candidate.thinking, thinkingSource: candidate.thinking_source,
    claimId: transactionId,
  };
  checkedBody(common);
  const frame = encodeBody(common);
  let used = false;
  return Object.freeze({
    async emit() {
      if (used) throw new Error('claim_frame_already_emitted');
      used = true;
      await writeOnce(privatePipe, frame, assertCurrent);
    },
  });
}
