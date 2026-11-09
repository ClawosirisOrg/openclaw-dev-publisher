/** Trusted Gateway construction only. No plugin installation or I/O on import.
 * Host code/config must be an immutable reviewed install, not an agent checkout.
 * The child receives admitted primitive labels through anonymous pipes; neither
 * a token, socket, key, process handle nor a reusable permit reaches the agent.
 */
import childProcess from 'node:child_process';
import { createHash } from 'node:crypto';
import { isAbsolute, normalize } from 'node:path';
import { admitCandidate } from './context-contract.mjs';

const phases = ['base', 'capture', 'reverify', 'mint', 'deliver', 'handoff', 'create'];
const failure = () => new Error('publication_failed_or_uncertain_inspect_no_retry');
const absolute = value => typeof value === 'string' && isAbsolute(value) &&
  normalize(value) === value && value !== '/' && !/[\0\r\n]/.test(value);
const ownKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === keys.sort().join(',');

export function createProductionPublisher(config) {
  if (!Object.isFrozen(config) || !ownKeys(config,
      ['pythonPath', 'brokerRoot', 'configPath', 'deploymentId']) ||
      !absolute(config.pythonPath) || !absolute(config.brokerRoot) || !absolute(config.configPath) ||
      typeof config.deploymentId !== 'string' || !/^[a-z0-9-]{1,64}$/.test(config.deploymentId)) {
    throw new Error('trusted_production_config_unavailable');
  }
  const { pythonPath, brokerRoot, configPath, deploymentId } = config;
  return Object.freeze({
    async run(context, toolCallId, request, { signal } = {}) {
      // Thinking is temporarily agent-attested by explicit owner decision.
      // Model identity is still exclusively the retained Gateway observation.
      const { candidate, assertCurrent } = admitCandidate(context, request);
      const inspect = ['inspect-mint', 'inspect-deliver'];
      const operation = candidate.operation ?? 'create';
      const expectedPhases = ['issue', 'pr'].includes(operation)
        ? [...inspect, 'api-mint', 'api-deliver', 'api-write']
        : operation === 'reconcile' ? inspect
          : operation === 'update' ? [...phases.slice(0, 3), ...inspect, ...phases.slice(3), ...inspect] : phases;
      if (typeof toolCallId !== 'string' || !/^[!-~]{1,512}$/.test(toolCallId)) {
        throw new Error('trusted_tool_call_id_unavailable');
      }
      // Correlation only. The host derives a separate durable repository/branch
      // publication key; different call IDs cannot bypass its tombstone.
      const attempt = createHash('sha256').update(deploymentId + '\0' + toolCallId).digest('hex').slice(0, 32);
      const guard = () => {
        assertCurrent();
        if (signal?.aborted) throw failure();
      };
      guard();
      return new Promise((resolve, reject) => {
        let child, pending = '', total = 0, phase = 0, result;
        let failed = false, timer, killTimer;
        const stop = () => {
          if (failed) return;
          failed = true;
          child?.stdin.destroy();
          child?.kill('SIGTERM'); // child finally revokes and removes its own workers
          killTimer = setTimeout(() => child?.kill('SIGKILL'), 45000);
          killTimer.unref();
        };
        const send = message => {
          guard(); // synchronous check immediately before the only pipe write
          if (!child.stdin.writable || child.stdin.destroyed) throw failure();
          child.stdin.write(JSON.stringify(message) + '\n');
        };
        const onAbort = () => stop();
        try {
          child = childProcess.spawn(pythonPath,
            ['-B', '-m', 'broker.host.production', configPath], {
              cwd: brokerRoot, env: { PATH: '/usr/bin:/bin', HOME: '/nonexistent',
                LANG: 'C', PYTHONDONTWRITEBYTECODE: '1' },
              stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true,
            });
          timer = setTimeout(stop, 610000);
          child.on('error', stop);
          child.stdin.on('error', stop);
          child.stdout.on('error', stop);
          child.stdout.on('data', chunk => {
            if (failed) return;
            try {
              total += chunk.length;
              if (total > 131072) throw failure();
              pending += chunk.toString('utf8');
              if (pending.length > 65536) throw failure();
              for (;;) {
                const index = pending.indexOf('\n');
                if (index < 0) break;
                const line = pending.slice(0, index);
                pending = pending.slice(index + 1);
                if (line.length > 65536 || result) throw failure();
                const message = JSON.parse(line);
                if (ownKeys(message, ['guard', 'nonce']) &&
                    message.guard === expectedPhases[phase] && /^[0-9a-f]{32}$/.test(message.nonce)) {
                  phase++;
                  send({ allow: message.guard, nonce: message.nonce });
                } else if (ownKeys(message, ['result']) && phase === expectedPhases.length) {
                  const r = message.result;
                  if (['issue', 'pr', 'reconcile'].includes(operation)) {
                    if (!ownKeys(r, ['number', 'url', 'head', 'readback_checked']) ||
                        !Number.isSafeInteger(r.number) || r.number < 1 ||
                        r.head !== candidate.sha || r.readback_checked !== true ||
                        typeof r.url !== 'string' ||
                        !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/(issues|pull)\/[1-9][0-9]*$/.test(r.url) ||
                        !r.url.endsWith('/' + r.number)) throw failure();
                  } else if (!ownKeys(r, ['sha', 'branch', 'base', 'acknowledged', 'readback_checked',
                      'main_at_readback', 'stale']) || r.sha !== candidate.sha ||
                      r.branch !== candidate.branch || !/^[0-9a-f]{40}$/.test(r.base) ||
                      !/^[0-9a-f]{40}$/.test(r.main_at_readback) ||
                      r.acknowledged !== true || r.readback_checked !== true ||
                      typeof r.stale !== 'boolean' || r.stale !== (r.main_at_readback !== r.base)) {
                    throw failure();
                  }
                  result = Object.freeze({ ...r });
                  child.stdin.end();
                } else throw failure();
              }
            } catch { stop(); }
          });
          child.on('close', code => {
            clearTimeout(timer);
            clearTimeout(killTimer);
            signal?.removeEventListener('abort', onAbort);
            try {
              guard();
              if (failed || code !== 0 || !result || pending !== '') throw failure();
              resolve(result);
            } catch { reject(failure()); }
          });
          signal?.addEventListener('abort', onAbort, { once: true });
          send({ attempt, sha: candidate.sha, branch: candidate.branch,
            model: candidate.model, thinking: candidate.thinking,
            ...(candidate.operation ? { operation: candidate.operation } : {}),
            ...(candidate.expectedOldSha ? { expectedOldSha: candidate.expectedOldSha } : {}),
            ...(['issue', 'pr'].includes(operation) ? { title: candidate.title, body: candidate.body } : {}) });
        } catch {
          if (child) stop();
          else reject(failure());
        }
      });
    },
  });
}
