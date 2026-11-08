import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, symlinkSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import plugin from '../src/plugin.mjs';
import { loadProductionDeployment } from '../src/production-config.mjs';

const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'publisher-package-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'deployment.json');
  writeFileSync(path, JSON.stringify({ python_path: '/usr/bin/python3',
    deployment_id: 'fixture-publisher', source_host: '/fixture/repository' }), { mode: 0o600 });
  return { dir, path };
}
function registration(entry, config) {
  const registrations = [];
  entry.register({ pluginConfig: config, registerTool(descriptor, options) {
    registrations.push({ descriptor, options });
  } });
  assert.equal(registrations.length, 1);
  return registrations[0];
}
const context = { agentId: 'dev-syn', sandboxed: true,
  activeModel: { modelRef: 'fixture/model' }, assertInvocationCurrent() {} };

test('package default stays disabled; production mode uses protected config reference', async t => {
  const f = fixture(t);
  const disabled = registration(plugin, undefined).descriptor.create(context);
  await assert.rejects(disabled.execute('fixture-call', { commitSha: 'a'.repeat(40),
    branch: 'dev-syn/fixture', thinking: 'off' }), /publication_disabled/);
  const prod = registration(plugin, { mode: 'production', productionConfigPath: f.path });
  assert.equal(prod.descriptor.contextVersion, 2);
  assert.equal(prod.options.optional, true);
  const tool = prod.descriptor.create(context);
  assert.match(tool.description, /Publish one verified signed commit/);
  // Agent-supplied model cannot become a broker input, even with mode enabled.
  await assert.rejects(tool.execute('fixture-model', { commitSha: 'a'.repeat(40),
    branch: 'dev-syn/fixture', thinking: 'off', model: 'claimed/model' }), /candidate_request_invalid/);
  const loaded = loadProductionDeployment(f.path);
  assert.equal(loaded.brokerRoot, root);
  assert.equal(loaded.pythonPath, '/usr/bin/python3');
  assert(Object.isFrozen(loaded));
});

test('unsafe config references fail before registration or process launch', t => {
  const f = fixture(t);
  for (const config of [{ mode: 'production' }, { mode: 'unknown' },
      { mode: 'production', productionConfigPath: f.path, model: 'claimed/model' }]) {
    assert.throws(() => registration(plugin, config), /config_invalid/);
  }
  chmodSync(f.path, 0o644);
  assert.throws(() => loadProductionDeployment(f.path), /config_unavailable/);
  chmodSync(f.path, 0o600);
  symlinkSync(f.path, join(f.dir, 'linked.json'));
  assert.throws(() => loadProductionDeployment(join(f.dir, 'linked.json')), /config_unavailable/);
  writeFileSync(f.path, JSON.stringify({ python_path: '/usr/bin/python3', deployment_id: 'fixture', source_host: f.dir }));
  assert.throws(() => loadProductionDeployment(f.path), /config_unavailable/);
});

test('real offline npm archive ships complete Python closure and loadable operational entry', async t => {
  const f = fixture(t);
  const env = { PATH: process.env.PATH, HOME: f.dir, LC_ALL: 'C',
    npm_config_offline: 'true', npm_config_cache: join(f.dir, 'npm-cache'),
    PYTHONDONTWRITEBYTECODE: '1' };
  const raw = execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', f.dir],
    { cwd: root, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 });
  const packedResponse = JSON.parse(raw);
  const packed = Array.isArray(packedResponse) ? packedResponse[0] : Object.values(packedResponse)[0];
  const files = packed.files.map(f => f.path);
  const expected = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).files.filter(f => f.startsWith('broker/'));
  assert.deepEqual(files.filter(f => f.startsWith('broker/')).sort(), expected.sort());
  assert(files.includes('src/production-config.mjs'));
  assert(files.includes('src/production-plugin.mjs'));
  assert.equal(readFileSync(join(root, 'broker/transport/askpass.py'), 'utf8').split('\n')[0],
    '#!/usr/local/bin/python3');
  assert(!files.some(f => /(?:^|\/)(?:tests?|__pycache__|private-config)(?:\/|$)|\.(?:pem|key|pub|sock|pyc|token)$/.test(f)));
  const extracted = join(f.dir, 'extracted'); mkdirSync(extracted);
  execFileSync('tar', ['-xf', join(f.dir, packed.filename), '-C', extracted], { env, timeout: 5000 });
  const installed = join(extracted, 'package');
  execFileSync('/usr/bin/python3', ['-B', '-c',
    'import broker.host.production, broker.host.production_runtime, broker.issuer.write_lease, broker.worker.production, broker.transport.production'],
    { cwd: installed, env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 });
  const host = spawnSync('/usr/bin/python3', ['-B', '-m', 'broker.host.production'],
    { cwd: installed, env, encoding: 'utf8', timeout: 5000 });
  assert.equal(host.status, 1);
  assert.equal(host.stderr, '');
  assert.deepEqual(JSON.parse(host.stdout), { error: 'publication_failed_or_uncertain_inspect_no_retry' });
  const loaded = (await import(pathToFileURL(join(installed, 'src/plugin.mjs')).href)).default;
  const active = registration(loaded, { mode: 'production', productionConfigPath: f.path });
  assert.equal(active.descriptor.create(context).name, 'request_signed_publication');
  const configModule = await import(pathToFileURL(join(installed, 'src/production-config.mjs')).href);
  assert.equal(configModule.loadProductionDeployment(f.path).brokerRoot, installed);
  const manifest = JSON.parse(readFileSync(join(installed, 'openclaw.plugin.json'), 'utf8'));
  assert.equal(manifest.configSchema.properties.mode.default, 'disabled');
  assert(manifest.configSchema.properties.productionConfigPath);
});
