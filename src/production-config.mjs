/** Package-owned production construction. Only a protected path reference is
 * accepted from Gateway plugin config; neither executable code nor secrets are
 * loaded from an agent request/checkout. No filesystem IO occurs on import.
 */
import { constants, openSync, closeSync, fstatSync, lstatSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const unavailable = () => new Error('trusted_production_config_unavailable');
const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
const within = (path, parent) => path === parent || path.startsWith(parent + sep);

export function loadProductionDeployment(configPath, packageRoot = root) {
  let fd;
  try {
    if (typeof configPath !== 'string' || !isAbsolute(configPath) ||
        resolve(configPath) !== configPath || /[\0\r\n]/.test(configPath) ||
        within(configPath, packageRoot)) throw unavailable();
    const parent = dirname(configPath), ancestors = [];
    for (let p = parent; ; p = dirname(p)) {
      ancestors.unshift(p);
      if (p === dirname(p)) break;
    }
    const uid = process.getuid();
    for (const p of ancestors) {
      const st = lstatSync(p);
      if (!st.isDirectory() || st.isSymbolicLink() || ![0, uid].includes(st.uid) ||
          ((st.mode & 0o022) && !(p !== parent && st.uid === 0 && (st.mode & 0o1000)))) {
        throw unavailable();
      }
    }
    fd = openSync(configPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile() || st.uid !== uid || st.nlink !== 1 || (st.mode & 0o077) ||
        st.size < 1 || st.size > 16384) throw unavailable();
    const bytes = readFileSync(fd);
    if (bytes.length !== st.size) throw unavailable();
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!data || typeof data !== 'object' || Array.isArray(data) ||
        typeof data.source_host !== 'string' || within(configPath, resolve(data.source_host)) ||
        typeof data.python_path !== 'string' || !isAbsolute(data.python_path) ||
        resolve(data.python_path) !== data.python_path || /[\0\r\n]/.test(data.python_path) ||
        typeof data.deployment_id !== 'string' || !/^[a-z0-9-]{1,64}$/.test(data.deployment_id)) {
      throw unavailable();
    }
    return Object.freeze({ pythonPath: data.python_path, brokerRoot: packageRoot,
      configPath, deploymentId: data.deployment_id });
  } catch { throw unavailable(); }
  finally { if (fd !== undefined) closeSync(fd); }
}
