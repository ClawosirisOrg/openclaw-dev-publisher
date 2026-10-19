/**
 * An invocation-scoped readiness gate, not a signing implementation.
 * No container runtime, socket protocol or credential is bundled here.
 */
export class ReadinessError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ReadinessError';
    this.code = code;
  }
}

function nonempty(value) {
  return typeof value === 'string' && value.length > 0 && value.trim() === value;
}

/**
 * Adapters:
 *   containers.get(id, { signal }) -> { id, name, imageDigest, running }
 *   sockets.probe(path, { containerId, signal }) ->
 *     { path, containerId, signerFingerprint, ready }
 * Both adapters must use an independent, trusted source of identity; a socket
 * filesystem existence check alone does not establish its peer's identity.
 */
export function createReadinessPolicy(config, adapters, runtime = {}) {
  if (!config || !nonempty(config.containerId) || !nonempty(config.containerName) ||
      !nonempty(config.imageDigest) || !nonempty(config.socketPath) ||
      !nonempty(config.signerFingerprint) ||
      !Array.isArray(config.knownContainerIds) ||
      !config.knownContainerIds.every(nonempty) ||
      !Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0 || config.timeoutMs > 10_000) {
    throw new TypeError('invalid readiness configuration');
  }
  if (!adapters || typeof adapters.containers?.get !== 'function' ||
      typeof adapters.sockets?.probe !== 'function') {
    throw new TypeError('missing readiness adapters');
  }
  const expected = Object.freeze({
    containerId: config.containerId,
    containerName: config.containerName,
    imageDigest: config.imageDigest,
    socketPath: config.socketPath,
    signerFingerprint: config.signerFingerprint,
    knownContainerIds: Object.freeze([...config.knownContainerIds]),
    timeoutMs: config.timeoutMs,
  });
  const now = runtime.now ?? (() => performance.now());
  const schedule = runtime.setTimeout ?? setTimeout;
  const cancel = runtime.clearTimeout ?? clearTimeout;
  if (typeof now !== 'function' || typeof schedule !== 'function' || typeof cancel !== 'function') {
    throw new TypeError('invalid clock');
  }

  /** Checks and consumes readiness inside this call; no reusable permit escapes. */
  async function withReadySigner(operation, { signal } = {}) {
    if (typeof operation !== 'function') throw new TypeError('operation must be a function');
    if (signal !== undefined && !(signal instanceof AbortSignal)) {
      throw new TypeError('signal must be an AbortSignal');
    }
    if (signal?.aborted) throw new ReadinessError('aborted');
    // Fail before doing any IO if configuration doesn't identify a known peer.
    if (!expected.knownContainerIds.includes(expected.containerId)) {
      throw new ReadinessError('unknown_container');
    }
    const start = now();
    if (!Number.isFinite(start)) throw new ReadinessError('invalid_clock');
    const deadline = start + expected.timeoutMs;
    const controller = new AbortController();
    let active = true;
    let timer;
    let onAbort;
    const fail = new Promise((_, reject) => {
      timer = schedule(() => {
        controller.abort();
        reject(new ReadinessError('deadline_exceeded'));
      }, expected.timeoutMs);
      if (signal) {
        onAbort = () => {
          controller.abort();
          reject(new ReadinessError('aborted'));
        };
        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) onAbort();
      }
    });
    function assertCurrent() {
      if (!active || controller.signal.aborted) throw new ReadinessError('inactive_invocation');
      const current = now();
      if (!Number.isFinite(current) || current >= deadline) {
        controller.abort();
        throw new ReadinessError('deadline_exceeded');
      }
    }
    const work = async () => {
      assertCurrent();
      const peer = await adapters.containers.get(expected.containerId, { signal: controller.signal });
      assertCurrent();
      if (!peer || peer.id !== expected.containerId || peer.name !== expected.containerName ||
          peer.imageDigest !== expected.imageDigest || peer.running !== true) {
        throw new ReadinessError('container_identity_mismatch');
      }
      const socket = await adapters.sockets.probe(expected.socketPath, {
        containerId: expected.containerId, signal: controller.signal,
      });
      assertCurrent();
      if (!socket || socket.ready !== true || socket.path !== expected.socketPath ||
          socket.signerFingerprint !== expected.signerFingerprint ||
          socket.containerId !== expected.containerId) {
        throw new ReadinessError('socket_identity_mismatch');
      }
      // The callback must check assertCurrent immediately before any side effect.
      const result = await operation({ signal: controller.signal, assertCurrent });
      assertCurrent();
      return result;
    };
    try {
      return await Promise.race([work(), fail]);
    } finally {
      active = false;
      controller.abort();
      cancel(timer);
      if (signal && onAbort) signal.removeEventListener('abort', onAbort);
    }
  }
  return Object.freeze({ withReadySigner });
}
