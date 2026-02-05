/**
 * Tests for ClawOS Layer 2: Capability Control
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  validateManifest,
  parseManifest,
  registerManifest,
  getManifest,
  clearManifestCache,
  listRegisteredSkills,
  checkPermission,
  createContext,
  enforce,
  hasTimedOut,
  remainingTime,
  CAPABILITY_MIN_TRUST,
  CAPABILITY_RISK,
} = require('../dist/capabilities/index.js');

const { createTag, userSource, toolSource, externalSource } = require('../dist/tagging/index.js');

// ─── Test Manifests ──────────────────────────────────────────

const weatherManifest = {
  version: '1.0',
  id: 'skill:weather',
  name: 'Weather',
  description: 'Get current weather and forecasts',
  capabilities: [
    { capability: 'net:https', reason: 'Fetches weather data from wttr.in', required: true },
  ],
  minInputTrust: 'untrusted',
  outputTrust: 'tool',
  limits: { timeoutMs: 10000, maxHttpRequests: 3 },
  allowedDomains: ['wttr.in'],
};

const fileManagerManifest = {
  version: '1.0',
  id: 'skill:file-manager',
  name: 'File Manager',
  description: 'Read, write, and organize files',
  capabilities: [
    { capability: 'fs:read', reason: 'Reads files', required: true },
    { capability: 'fs:write', reason: 'Writes files', required: true },
    { capability: 'fs:delete', reason: 'Deletes files', required: false },
  ],
  minInputTrust: 'user',
  outputTrust: 'tool',
  limits: { maxFileSizeBytes: 10485760 },
  allowedPaths: ['/home/*/workspace/**'],
};

const dangerousManifest = {
  version: '1.0',
  id: 'skill:dangerous',
  name: 'Dangerous Tool',
  description: 'Needs everything',
  capabilities: [
    { capability: 'proc:exec', reason: 'Runs commands', required: true },
    { capability: 'env:secrets', reason: 'Reads API keys', required: true },
    { capability: 'net:https', reason: 'Makes requests', required: true },
  ],
  minInputTrust: 'user',
  outputTrust: 'tool',
};

// ─── Manifest Validation ─────────────────────────────────────

describe('manifest validation', () => {
  it('validates a correct manifest', () => {
    const result = validateManifest(weatherManifest);
    assert.ok(result.valid);
    assert.equal(result.errors.length, 0);
  });

  it('rejects non-object input', () => {
    const result = validateManifest('not an object');
    assert.ok(!result.valid);
    assert.ok(result.errors[0].includes('must be an object'));
  });

  it('rejects missing required fields', () => {
    const result = validateManifest({ version: '1.0' });
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes('id')));
    assert.ok(result.errors.some((e) => e.includes('name')));
  });

  it('rejects unsupported version', () => {
    const result = validateManifest({ ...weatherManifest, version: '2.0' });
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes('version')));
  });

  it('rejects invalid trust levels', () => {
    const result = validateManifest({ ...weatherManifest, minInputTrust: 'admin' });
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes('minInputTrust')));
  });

  it('rejects invalid capabilities format', () => {
    const result = validateManifest({
      ...weatherManifest,
      capabilities: [{ capability: '', reason: 'test', required: true }],
    });
    assert.ok(!result.valid);
  });

  it('warns on non-standard capability format', () => {
    const result = validateManifest({
      ...weatherManifest,
      capabilities: [{ capability: 'nocolon', reason: 'test', required: true }],
    });
    assert.ok(result.valid); // Valid but with warning
    assert.ok(result.warnings.some((w) => w.includes('domain:action')));
  });

  it('rejects negative limits', () => {
    const result = validateManifest({
      ...weatherManifest,
      limits: { timeoutMs: -1 },
    });
    assert.ok(!result.valid);
  });
});

describe('manifest parsing', () => {
  it('parses valid JSON manifest', () => {
    const manifest = parseManifest(JSON.stringify(weatherManifest));
    assert.equal(manifest.id, 'skill:weather');
    assert.equal(manifest.capabilities.length, 1);
  });

  it('throws on invalid manifest', () => {
    assert.throws(() => {
      parseManifest('{"version":"2.0"}');
    }, /Invalid manifest/);
  });
});

describe('manifest cache', () => {
  it('registers and retrieves manifests', () => {
    clearManifestCache();
    registerManifest(weatherManifest);
    const retrieved = getManifest('skill:weather');
    assert.equal(retrieved.id, 'skill:weather');
  });

  it('lists registered skills', () => {
    clearManifestCache();
    registerManifest(weatherManifest);
    registerManifest(fileManagerManifest);
    const skills = listRegisteredSkills();
    assert.ok(skills.includes('skill:weather'));
    assert.ok(skills.includes('skill:file-manager'));
  });

  it('returns undefined for unknown skill', () => {
    clearManifestCache();
    assert.equal(getManifest('nonexistent'), undefined);
  });
});

// ─── Permission Checking ─────────────────────────────────────

describe('permission checking', () => {
  it('allows skill with matching trust + capabilities', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const result = checkPermission(weatherManifest, inputTag);
    assert.ok(result.allowed);
    assert.ok(result.granted.includes('net:https'));
    assert.equal(result.denied.length, 0);
  });

  it('allows weather skill even with untrusted input (low minInputTrust)', () => {
    const inputTag = createTag(externalSource('web'), 'untrusted');
    // Weather manifest has minInputTrust: 'untrusted'
    // But net:https requires 'tool' trust — so it should be denied
    const result = checkPermission(weatherManifest, inputTag);
    assert.ok(!result.allowed);
    assert.ok(result.denied.includes('net:https'));
  });

  it('denies when input trust below manifest minimum', () => {
    const inputTag = createTag(externalSource('web'), 'untrusted');
    // File manager requires user trust
    const result = checkPermission(fileManagerManifest, inputTag);
    assert.ok(!result.allowed);
    assert.ok(result.reasons.some((r) => r.includes('below manifest minimum')));
  });

  it('denies fs:write with tool-level input', () => {
    const inputTag = createTag(toolSource('api'), 'tool');
    // File manager requires user trust for minInputTrust
    const result = checkPermission(fileManagerManifest, inputTag);
    assert.ok(!result.allowed);
  });

  it('grants fs:read + fs:write with user input', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const result = checkPermission(fileManagerManifest, inputTag);
    assert.ok(result.allowed);
    assert.ok(result.granted.includes('fs:read'));
    assert.ok(result.granted.includes('fs:write'));
  });

  it('respects global deny list', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const policy = { globalDeny: ['proc:exec'] };
    const result = checkPermission(dangerousManifest, inputTag, policy);
    assert.ok(!result.allowed); // proc:exec is required and denied
    assert.ok(result.denied.includes('proc:exec'));
  });

  it('respects per-skill deny', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const policy = {
      skills: {
        'skill:dangerous': { deny: ['env:secrets'] },
      },
    };
    const result = checkPermission(dangerousManifest, inputTag, policy);
    assert.ok(!result.allowed);
    assert.ok(result.denied.includes('env:secrets'));
  });

  it('blocks skill when blocked=true', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const policy = {
      skills: {
        'skill:weather': { blocked: true },
      },
    };
    const result = checkPermission(weatherManifest, inputTag, policy);
    assert.ok(!result.allowed);
    assert.ok(result.reasons.some((r) => r.includes('blocked')));
  });

  it('respects global allow list', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const policy = { globalAllow: ['proc:exec', 'env:secrets', 'net:https'] };
    const result = checkPermission(dangerousManifest, inputTag, policy);
    assert.ok(result.allowed);
    assert.equal(result.granted.length, 3);
  });

  it('requires approval when policy says so', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const policy = { requireApproval: true, autoApproveBelow: 'low' };
    const result = checkPermission(dangerousManifest, inputTag, policy);
    assert.ok(!result.allowed);
    assert.ok(result.requiresApproval.length > 0);
  });

  it('auto-approves low-risk capabilities', () => {
    const simpleManifest = {
      ...weatherManifest,
      id: 'skill:simple',
      capabilities: [
        { capability: 'sys:time', reason: 'Needs time', required: true },
        { capability: 'sys:info', reason: 'Needs info', required: true },
      ],
    };
    const inputTag = createTag(userSource('+33xxx'), 'user');
    const policy = { requireApproval: true, autoApproveBelow: 'low' };
    const result = checkPermission(simpleManifest, inputTag, policy);
    assert.ok(result.allowed);
    assert.ok(result.granted.includes('sys:time'));
    assert.ok(result.granted.includes('sys:info'));
  });

  it('handles optional denied capabilities without blocking', () => {
    const inputTag = createTag(userSource('+33xxx'), 'user');
    // fs:delete is optional in fileManagerManifest
    const policy = {
      skills: {
        'skill:file-manager': { deny: ['fs:delete'] },
      },
    };
    const result = checkPermission(fileManagerManifest, inputTag, policy);
    assert.ok(result.allowed); // Still allowed — fs:delete is optional
    assert.ok(result.denied.includes('fs:delete'));
    assert.ok(result.granted.includes('fs:read'));
    assert.ok(result.granted.includes('fs:write'));
  });
});

// ─── Execution Context ───────────────────────────────────────

describe('execution context', () => {
  it('creates context with correct defaults', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user');
    assert.ok(ctx.grantedCapabilities.has('net:https'));
    assert.equal(ctx.skillId, 'skill:weather');
    assert.equal(ctx.inputTrust, 'user');
    assert.equal(ctx.limits.timeoutMs, 10000); // From manifest
    assert.equal(ctx.limits.maxHttpRequests, 3); // From manifest
    assert.ok(ctx.limits.maxMemoryMb > 0); // Default
    assert.equal(ctx.usage.httpRequestCount, 0);
  });

  it('applies limit overrides', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user', { timeoutMs: 5000 });
    assert.equal(ctx.limits.timeoutMs, 5000);
  });
});

// ─── Runtime Enforcement ─────────────────────────────────────

describe('enforcement', () => {
  it('allows granted capability', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user');
    const result = enforce(ctx, 'net:https', { domain: 'wttr.in' });
    assert.ok(result.allowed);
  });

  it('denies ungranted capability', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user');
    const result = enforce(ctx, 'fs:write');
    assert.ok(!result.allowed);
    assert.ok(result.reason.includes('not granted'));
  });

  it('enforces domain restrictions', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user');

    const ok = enforce(ctx, 'net:https', { domain: 'wttr.in' });
    assert.ok(ok.allowed);

    const denied = enforce(ctx, 'net:https', { domain: 'evil.com' });
    assert.ok(!denied.allowed);
    assert.ok(denied.reason.includes('not in allowed list'));
  });

  it('enforces HTTP request count', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user');

    // 3 requests allowed
    assert.ok(enforce(ctx, 'net:https', { domain: 'wttr.in' }).allowed);
    assert.ok(enforce(ctx, 'net:https', { domain: 'wttr.in' }).allowed);
    assert.ok(enforce(ctx, 'net:https', { domain: 'wttr.in' }).allowed);

    // 4th should be denied
    const fourth = enforce(ctx, 'net:https', { domain: 'wttr.in' });
    assert.ok(!fourth.allowed);
    assert.ok(fourth.reason.includes('request limit'));
  });

  it('enforces path restrictions', () => {
    const ctx = createContext(fileManagerManifest, ['fs:read', 'fs:write'], 'user');

    const ok = enforce(ctx, 'fs:read', { path: '/home/nonbios/workspace/file.txt' });
    assert.ok(ok.allowed);

    const denied = enforce(ctx, 'fs:read', { path: '/etc/passwd' });
    assert.ok(!denied.allowed);
    assert.ok(denied.reason.includes('not in allowed list'));
  });

  it('enforces file size limits', () => {
    const ctx = createContext(fileManagerManifest, ['fs:write'], 'user');

    const ok = enforce(ctx, 'fs:write', { bytes: 1000 });
    assert.ok(ok.allowed);

    const denied = enforce(ctx, 'fs:write', { bytes: 20000000 }); // 20MB > 10MB limit
    assert.ok(!denied.allowed);
    assert.ok(denied.reason.includes('exceeds limit'));
  });

  it('tracks resource usage', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user');
    enforce(ctx, 'net:https', { domain: 'wttr.in' });
    enforce(ctx, 'net:https', { domain: 'wttr.in' });
    assert.equal(ctx.usage.httpRequestCount, 2);
  });

  it('detects timeout', () => {
    const ctx = createContext(weatherManifest, ['net:https'], 'user');
    assert.ok(!hasTimedOut(ctx));
    assert.ok(remainingTime(ctx) > 0);

    // Simulate timeout
    ctx.usage.startTime = Date.now() - 20000; // 20s ago, limit is 10s
    assert.ok(hasTimedOut(ctx));
    assert.equal(remainingTime(ctx), 0);
  });
});

// ─── Capability Constants ────────────────────────────────────

describe('capability constants', () => {
  it('has trust minimums for all capabilities', () => {
    const caps = Object.keys(CAPABILITY_MIN_TRUST);
    assert.ok(caps.length > 15);
    assert.equal(CAPABILITY_MIN_TRUST['fs:write'], 'user');
    assert.equal(CAPABILITY_MIN_TRUST['sys:time'], 'untrusted');
    assert.equal(CAPABILITY_MIN_TRUST['proc:exec'], 'user');
  });

  it('has risk levels for all capabilities', () => {
    const caps = Object.keys(CAPABILITY_RISK);
    assert.ok(caps.length > 15);
    assert.equal(CAPABILITY_RISK['sys:time'], 'low');
    assert.equal(CAPABILITY_RISK['proc:exec'], 'high');
    assert.equal(CAPABILITY_RISK['net:https'], 'medium');
  });
});
