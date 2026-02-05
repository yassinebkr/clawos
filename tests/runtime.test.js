/**
 * Tests for ClawOS Layer 3: Runtime Security
 */
const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { writeFileSync, mkdirSync, existsSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const {
  selectIsolationLevel,
  createSandboxConfig,
  isBubblewrapAvailable,
  effectiveLevel,
  BehavioralMonitor,
  DEFAULT_RULES,
  spawn,
  sendInput,
  killProcess,
  waitForProcess,
  execute,
  getProcess,
  listProcesses,
  cleanup,
  cleanupAll,
} = require('../dist/runtime/index.js');

const { createTag, userSource, toolSource, externalSource } = require('../dist/tagging/index.js');

// ─── Test Manifests ──────────────────────────────────────────

const weatherManifest = {
  version: '1.0',
  id: 'skill:weather',
  name: 'Weather',
  description: 'Get weather data',
  capabilities: [
    { capability: 'net:https', reason: 'Fetch weather', required: true },
  ],
  minInputTrust: 'untrusted',
  outputTrust: 'tool',
  limits: { timeoutMs: 5000, maxHttpRequests: 3 },
  allowedDomains: ['wttr.in'],
};

const dangerousManifest = {
  version: '1.0',
  id: 'skill:dangerous',
  name: 'Dangerous',
  description: 'Needs exec',
  capabilities: [
    { capability: 'proc:exec', reason: 'Run commands', required: true },
    { capability: 'env:secrets', reason: 'Read keys', required: true },
  ],
  minInputTrust: 'user',
  outputTrust: 'tool',
};

const builtinManifest = {
  version: '1.0',
  id: 'builtin:time',
  name: 'Time',
  description: 'Get current time',
  capabilities: [
    { capability: 'sys:time', reason: 'Read time', required: true },
  ],
  minInputTrust: 'untrusted',
  outputTrust: 'system',
};

const mcpManifest = {
  version: '1.0',
  id: 'mcp:external-server',
  name: 'MCP Server',
  description: 'External MCP server',
  capabilities: [
    { capability: 'net:https', reason: 'Communicate', required: true },
  ],
  minInputTrust: 'tool',
  outputTrust: 'untrusted',
};

// ─── Isolation Level Selection ───────────────────────────────

describe('isolation level selection', () => {
  it('selects Level 0 for system-trust builtin', () => {
    const tag = createTag({ kind: 'system', id: 'openclaw' }, 'system');
    assert.equal(selectIsolationLevel(builtinManifest, tag), 0);
  });

  it('selects Level 1 for standard skill with user input', () => {
    const tag = createTag(userSource('+33xxx'), 'user');
    assert.equal(selectIsolationLevel(weatherManifest, tag), 1);
  });

  it('selects Level 2 for untrusted input', () => {
    const tag = createTag(externalSource('web'), 'untrusted');
    assert.equal(selectIsolationLevel(weatherManifest, tag), 2);
  });

  it('selects Level 2 for high-risk capabilities', () => {
    const tag = createTag(userSource('+33xxx'), 'user');
    assert.equal(selectIsolationLevel(dangerousManifest, tag), 2);
  });

  it('selects Level 2 for MCP servers always', () => {
    const tag = createTag(toolSource('agent'), 'tool');
    assert.equal(selectIsolationLevel(mcpManifest, tag), 2);
  });

  it('respects policy override for isolation level', () => {
    const tag = createTag(userSource('+33xxx'), 'user');
    const policy = {
      skills: { 'skill:weather': { isolationLevel: 2 } },
    };
    assert.equal(selectIsolationLevel(weatherManifest, tag, policy), 2);
  });
});

// ─── Sandbox Configuration ───────────────────────────────────

describe('sandbox configuration', () => {
  it('creates Level 0 config with no path restrictions', () => {
    const config = createSandboxConfig(builtinManifest, 0);
    assert.equal(config.level, 0);
    assert.equal(config.allowedPaths.length, 0);
    assert.equal(config.env.CLAWOS_ISOLATION_LEVEL, '0');
  });

  it('creates Level 1 config with system + workspace paths', () => {
    const config = createSandboxConfig(weatherManifest, 1, '/home/user/workspace');
    assert.equal(config.level, 1);
    assert.ok(config.allowedPaths.length > 0);
    assert.ok(config.allowedPaths.some((p) => p.path === '/home/user/workspace'));
    assert.ok(config.allowedPaths.some((p) => p.path.includes('/usr/lib')));
  });

  it('creates Level 2 config with minimal paths', () => {
    const config = createSandboxConfig(weatherManifest, 2);
    assert.equal(config.level, 2);
    // Level 2 should have very few paths
    const writeable = config.allowedPaths.filter((p) => p.mode === 'readwrite');
    assert.equal(writeable.length, 1); // Only temp dir
  });

  it('applies resource limits from manifest', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    assert.equal(config.resourceLimits.timeoutMs, 5000);
    assert.equal(config.resourceLimits.maxHttpRequests, 3);
  });

  it('sets safe environment variables', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    assert.equal(config.env.CLAWOS_SKILL_ID, 'skill:weather');
    assert.ok(config.env.CLAWOS_RUN_ID);
    assert.equal(config.env.NODE_ENV, 'production');
    // HOME should be redirected to temp
    assert.equal(config.env.HOME, config.tempDir);
  });

  it('includes allowed domains from manifest', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    assert.deepEqual(config.allowedDomains, ['wttr.in']);
  });
});

// ─── Bubblewrap Detection ────────────────────────────────────

describe('bubblewrap detection', () => {
  it('returns boolean for bwrap availability', () => {
    const available = isBubblewrapAvailable();
    assert.equal(typeof available, 'boolean');
  });

  it('falls back Level 2 to Level 1 when bwrap unavailable', () => {
    // This test is platform-dependent
    const effective = effectiveLevel(2);
    assert.ok(effective === 1 || effective === 2);
  });

  it('keeps Level 0 and Level 1 unchanged', () => {
    assert.equal(effectiveLevel(0), 0);
    assert.equal(effectiveLevel(1), 1);
  });
});

// ─── Behavioral Monitor ─────────────────────────────────────

describe('behavioral monitor', () => {
  it('tracks peak memory', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    const monitor = new BehavioralMonitor(config);

    monitor.recordMetric('memory', 50);
    monitor.recordMetric('memory', 100);
    monitor.recordMetric('memory', 75);

    const metrics = monitor.getMetrics();
    assert.equal(metrics.peakMemoryMb, 100);
  });

  it('accumulates network requests', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    const monitor = new BehavioralMonitor(config);

    monitor.recordMetric('networkRequest', 1);
    monitor.recordMetric('networkRequest', 1);

    const metrics = monitor.getMetrics();
    assert.equal(metrics.networkRequests, 2);
  });

  it('accumulates output bytes', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    const monitor = new BehavioralMonitor(config);

    monitor.recordMetric('output', 500);
    monitor.recordMetric('output', 300);

    const metrics = monitor.getMetrics();
    assert.equal(metrics.outputBytes, 800);
  });

  it('triggers kill on memory limit exceeded', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    config.resourceLimits.maxMemoryMb = 100;

    let killReason = '';
    const monitor = new BehavioralMonitor(config, undefined, (reason) => {
      killReason = reason;
    });

    monitor.recordMetric('memory', 150);

    assert.ok(monitor.isKilled());
    assert.ok(killReason.includes('exceeded'));
    assert.ok(monitor.getIncidents().some((i) => i.severity === 'critical'));
  });

  it('triggers kill on output limit exceeded', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    config.resourceLimits.maxOutputBytes = 1000;

    let killed = false;
    const monitor = new BehavioralMonitor(config, undefined, () => { killed = true; });

    monitor.recordMetric('output', 600);
    assert.ok(!killed);

    monitor.recordMetric('output', 600); // Total: 1200 > 1000
    assert.ok(killed);
  });

  it('records manual incidents', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    const monitor = new BehavioralMonitor(config);

    monitor.recordIncident('warning', 'test', 'Something suspicious');
    const incidents = monitor.getIncidents();

    assert.equal(incidents.length, 1);
    assert.equal(incidents[0].severity, 'warning');
    assert.equal(incidents[0].type, 'test');
    assert.equal(incidents[0].message, 'Something suspicious');
  });

  it('detects timeout', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    config.resourceLimits.timeoutMs = 100;

    const monitor = new BehavioralMonitor(config);

    assert.ok(!monitor.checkTimeout());

    // Fake the start time to simulate timeout
    monitor.startTime = Date.now() - 200;

    assert.ok(monitor.checkTimeout());
  });

  it('finalizes metrics with duration', () => {
    const config = createSandboxConfig(weatherManifest, 1);
    const monitor = new BehavioralMonitor(config);

    monitor.recordMetric('memory', 50);
    monitor.recordMetric('output', 100);

    const metrics = monitor.finalize();
    assert.ok(metrics.durationMs >= 0);
    assert.equal(metrics.peakMemoryMb, 50);
    assert.equal(metrics.outputBytes, 100);
  });

  it('has sensible default rules', () => {
    assert.ok(DEFAULT_RULES.length >= 4);
    assert.ok(DEFAULT_RULES.some((r) => r.id === 'timeout'));
    assert.ok(DEFAULT_RULES.some((r) => r.id === 'memory-limit'));
    assert.ok(DEFAULT_RULES.some((r) => r.id === 'output-limit'));
  });
});

// ─── Sandbox Process Management ──────────────────────────────

describe('sandbox process management', () => {
  it('spawns Level 0 process inline', () => {
    const config = createSandboxConfig(builtinManifest, 0);
    const ctx = {
      skillId: 'builtin:time',
      grantedCapabilities: new Set(['sys:time']),
      limits: config.resourceLimits,
      usage: { startTime: Date.now(), httpRequestCount: 0, bytesRead: 0, bytesWritten: 0, outputBytes: 0 },
      inputTrust: 'system',
    };

    const proc = spawn('/dev/null', config, ctx);
    assert.equal(proc.status, 'running');
    assert.equal(proc.skillId, 'builtin:time');
    assert.ok(proc.pid > 0); // Should be current process PID
    assert.ok(proc.runId);

    cleanup(proc.runId);
  });

  it('executes Level 0 skill inline', async () => {
    // Create a simple skill module
    const skillDir = join(tmpdir(), `clawos-test-skill-${Date.now()}`);
    mkdirSync(skillDir, { recursive: true });
    const skillPath = join(skillDir, 'skill.js');
    writeFileSync(skillPath, 'module.exports.run = (input) => `echo: ${input}`;');

    const config = createSandboxConfig(builtinManifest, 0);
    const ctx = {
      skillId: 'builtin:time',
      grantedCapabilities: new Set(['sys:time']),
      limits: config.resourceLimits,
      usage: { startTime: Date.now(), httpRequestCount: 0, bytesRead: 0, bytesWritten: 0, outputBytes: 0 },
      inputTrust: 'system',
    };

    const result = await execute(skillPath, 'hello', config, ctx);
    assert.ok(result.success);
    assert.equal(result.output, 'echo: hello');
    assert.equal(result.status, 'completed');
    assert.ok(result.metrics.durationMs >= 0);

    // Cleanup
    rmSync(skillDir, { recursive: true, force: true });
  });

  it('handles inline execution errors', async () => {
    const skillDir = join(tmpdir(), `clawos-test-err-${Date.now()}`);
    mkdirSync(skillDir, { recursive: true });
    const skillPath = join(skillDir, 'skill.js');
    writeFileSync(skillPath, 'module.exports.run = () => { throw new Error("boom"); };');

    const config = createSandboxConfig(builtinManifest, 0);
    const ctx = {
      skillId: 'builtin:time',
      grantedCapabilities: new Set(['sys:time']),
      limits: config.resourceLimits,
      usage: { startTime: Date.now(), httpRequestCount: 0, bytesRead: 0, bytesWritten: 0, outputBytes: 0 },
      inputTrust: 'system',
    };

    const result = await execute(skillPath, 'hello', config, ctx);
    assert.ok(!result.success);
    assert.equal(result.status, 'error');
    assert.ok(result.error.includes('boom'));

    rmSync(skillDir, { recursive: true, force: true });
  });

  it('spawns Level 1 process as child', async () => {
    const skillDir = join(tmpdir(), `clawos-test-child-${Date.now()}`);
    mkdirSync(skillDir, { recursive: true });
    const skillPath = join(skillDir, 'skill.js');
    writeFileSync(skillPath, `
      process.on('message', (msg) => {
        if (msg.type === 'input') {
          process.send({ type: 'output', data: 'processed: ' + msg.data });
          process.exit(0);
        }
      });
    `);

    const config = createSandboxConfig(weatherManifest, 1);
    config.cwd = skillDir; // Override cwd to exist
    const ctx = {
      skillId: 'skill:weather',
      grantedCapabilities: new Set(['net:https']),
      limits: config.resourceLimits,
      usage: { startTime: Date.now(), httpRequestCount: 0, bytesRead: 0, bytesWritten: 0, outputBytes: 0 },
      inputTrust: 'user',
    };

    const result = await execute(skillPath, 'test input', config, ctx);
    assert.ok(result.success, `Expected success but got: ${result.error}`);
    assert.equal(result.status, 'completed');

    rmSync(skillDir, { recursive: true, force: true });
  });

  it('kills timed-out Level 1 process', async () => {
    const skillDir = join(tmpdir(), `clawos-test-timeout-${Date.now()}`);
    mkdirSync(skillDir, { recursive: true });
    const skillPath = join(skillDir, 'skill.js');
    // This skill never responds — simulates hang
    writeFileSync(skillPath, `
      process.on('message', () => {});
      setInterval(() => {}, 1000);
    `);

    const manifest = { ...weatherManifest, limits: { timeoutMs: 1000 } };
    const config = createSandboxConfig(manifest, 1);
    config.cwd = skillDir;
    const ctx = {
      skillId: 'skill:weather',
      grantedCapabilities: new Set(['net:https']),
      limits: config.resourceLimits,
      usage: { startTime: Date.now(), httpRequestCount: 0, bytesRead: 0, bytesWritten: 0, outputBytes: 0 },
      inputTrust: 'user',
    };

    const result = await execute(skillPath, 'test', config, ctx);
    assert.ok(!result.success);
    assert.ok(result.status === 'timeout' || result.status === 'killed');

    rmSync(skillDir, { recursive: true, force: true });
  });

  it('lists active processes', () => {
    const procs = listProcesses();
    assert.ok(Array.isArray(procs));
  });

  it('cleans up completed processes', () => {
    const cleaned = cleanupAll();
    assert.ok(typeof cleaned === 'number');
  });
});
