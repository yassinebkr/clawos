/**
 * ClawOS Layer 3: Sandbox Execution
 *
 * Spawns skill code in isolated processes with resource limits.
 * Supports three isolation levels:
 * - Level 0: inline (no isolation)
 * - Level 1: child process with resource limits
 * - Level 2: bubblewrap sandbox (Linux only, falls back to L1)
 */

import { fork, type ChildProcess } from 'node:child_process';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import type { SandboxConfig, SandboxResult, SandboxedProcess, ProcessStatus } from './types';
import type { ExecutionContext } from '../capabilities/types';
import { BehavioralMonitor } from './monitor';
import { randomBytes } from 'node:crypto';

// ─── Sandbox Process Manager ─────────────────────────────────

const activeProcesses = new Map<string, ManagedProcess>();

interface ManagedProcess {
  process: SandboxedProcess;
  child?: ChildProcess;
  monitor: BehavioralMonitor;
  resolve?: (result: SandboxResult) => void;
  outputChunks: string[];
}

/**
 * Spawn a skill in a sandboxed process.
 *
 * For Level 1: uses Node.js fork() with resource limits
 * For Level 2: would use bubblewrap (bwrap) — currently falls back to Level 1
 * For Level 0: returns a handle for inline execution
 */
export function spawn(
  skillPath: string,
  config: SandboxConfig,
  context: ExecutionContext,
): SandboxedProcess {
  const runId = randomBytes(8).toString('hex');

  // Ensure temp directory exists with restricted permissions
  if (config.tempDir && !existsSync(config.tempDir)) {
    mkdirSync(config.tempDir, { recursive: true, mode: 0o700 });
  }

  const monitor = new BehavioralMonitor(config, undefined, (reason) => {
    killProcess(runId, reason);
  });

  const handle: SandboxedProcess = {
    pid: 0,
    runId,
    skillId: context.skillId,
    config,
    status: 'pending',
    startTime: Date.now(),
    incidents: [],
    metrics: monitor.getMetrics(),
  };

  if (config.level === 0) {
    // Level 0: no process spawning, execution is inline
    // WARNING: Level 0 has NO isolation — skill code runs in main process
    console.warn(`[ClawOS L3] Level 0 execution for "${context.skillId}" — NO ISOLATION (only use for trusted first-party skills)`);
    handle.status = 'running';
    handle.pid = process.pid;
  } else {
    // Level 1 & 2: spawn child process
    try {
      const child = forkSkill(skillPath, config);
      handle.pid = child.pid || 0;
      handle.status = 'running';

      const managed: ManagedProcess = {
        process: handle,
        child,
        monitor,
        outputChunks: [],
      };

      // Set up event handlers
      setupChildHandlers(managed, config);

      activeProcesses.set(runId, managed);
    } catch (err) {
      handle.status = 'error';
      monitor.recordIncident('critical', 'spawn-error', `Failed to spawn: ${err}`);
    }
  }

  // Store handle for monitoring
  if (!activeProcesses.has(runId)) {
    activeProcesses.set(runId, {
      process: handle,
      monitor,
      outputChunks: [],
    });
  }

  return handle;
}

/**
 * Send input data to a sandboxed process.
 */
export function sendInput(runId: string, data: string): boolean {
  const managed = activeProcesses.get(runId);
  if (!managed || !managed.child || managed.process.status !== 'running') {
    return false;
  }

  managed.child.send({ type: 'input', data });
  return true;
}

/**
 * Kill a sandboxed process.
 */
export function killProcess(runId: string, reason: string): boolean {
  const managed = activeProcesses.get(runId);
  if (!managed) return false;

  if (managed.child && managed.process.status === 'running') {
    managed.monitor.recordIncident('critical', 'killed', reason);
    managed.process.status = 'killed';

    try {
      managed.child.kill('SIGKILL');
    } catch {
      // Process may already be dead
    }
  }

  return true;
}

/**
 * Wait for a sandboxed process to complete.
 */
export function waitForProcess(runId: string, timeoutMs?: number): Promise<SandboxResult> {
  return new Promise((resolve) => {
    const managed = activeProcesses.get(runId);
    if (!managed) {
      resolve({
        success: false,
        error: 'Process not found',
        status: 'error',
        metrics: emptyMetrics(),
        incidents: [],
      });
      return;
    }

    // Already finished
    if (['completed', 'killed', 'error', 'timeout'].includes(managed.process.status)) {
      resolve(buildResult(managed));
      return;
    }

    // Set up timeout
    const timeout = timeoutMs || managed.process.config.resourceLimits.timeoutMs || 30000;
    const timer = setTimeout(() => {
      managed.process.status = 'timeout';
      managed.monitor.recordIncident('critical', 'timeout', `Execution timed out after ${timeout}ms`);
      killProcess(runId, 'timeout');
      resolve(buildResult(managed));
    }, timeout);

    // Wait for completion
    managed.resolve = (result) => {
      clearTimeout(timer);
      resolve(result);
    };
  });
}

/**
 * Execute a skill and return result (convenience wrapper).
 */
export async function execute(
  skillPath: string,
  input: string,
  config: SandboxConfig,
  context: ExecutionContext,
): Promise<SandboxResult> {
  const proc = spawn(skillPath, config, context);

  if (config.level === 0) {
    // Level 0: inline execution
    return executeInline(skillPath, input, proc.runId);
  }

  sendInput(proc.runId, input);
  return waitForProcess(proc.runId);
}

/**
 * Get info about an active process.
 */
export function getProcess(runId: string): SandboxedProcess | undefined {
  return activeProcesses.get(runId)?.process;
}

/**
 * List all active sandboxed processes.
 */
export function listProcesses(): SandboxedProcess[] {
  return Array.from(activeProcesses.values()).map((m) => m.process);
}

/**
 * Clean up a completed process (remove temp files, free resources).
 */
export function cleanup(runId: string): void {
  const managed = activeProcesses.get(runId);
  if (!managed) return;

  // Clean up temp directory
  const tempDir = managed.process.config.tempDir;
  if (tempDir && existsSync(tempDir)) {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  }

  activeProcesses.delete(runId);
}

/**
 * Clean up all completed processes.
 */
export function cleanupAll(): number {
  let cleaned = 0;
  for (const [runId, managed] of activeProcesses) {
    if (['completed', 'killed', 'error', 'timeout'].includes(managed.process.status)) {
      cleanup(runId);
      cleaned++;
    }
  }
  return cleaned;
}

// ─── Internal Helpers ────────────────────────────────────────

function forkSkill(skillPath: string, config: SandboxConfig): ChildProcess {
  const execArgv: string[] = [];

  // Set memory limit via V8 flag
  if (config.resourceLimits.maxMemoryMb) {
    execArgv.push(`--max-old-space-size=${config.resourceLimits.maxMemoryMb}`);
  }

  return fork(skillPath, [], {
    env: config.env,
    cwd: config.cwd,
    execArgv,
    stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
    serialization: 'json',
  });
}

function setupChildHandlers(managed: ManagedProcess, config: SandboxConfig): void {
  const child = managed.child!;

  // Capture stdout
  child.stdout?.on('data', (data: Buffer) => {
    const chunk = data.toString();
    managed.outputChunks.push(chunk);
    managed.monitor.recordMetric('output', Buffer.byteLength(chunk));
  });

  // Capture stderr (log as incidents)
  child.stderr?.on('data', (data: Buffer) => {
    const msg = data.toString().trim();
    if (msg) {
      managed.monitor.recordIncident('warning', 'stderr', msg);
    }
  });

  // Handle messages from child (for structured output)
  child.on('message', (msg: any) => {
    if (msg?.type === 'output') {
      managed.outputChunks.push(String(msg.data));
      managed.monitor.recordMetric('output', Buffer.byteLength(String(msg.data)));
    } else if (msg?.type === 'metric') {
      managed.monitor.recordMetric(msg.metric, msg.value);
    }
  });

  // Handle exit
  child.on('exit', (code, signal) => {
    if (managed.process.status === 'running') {
      managed.process.status = code === 0 ? 'completed' : 'error';
    }

    managed.process.metrics = managed.monitor.finalize();
    managed.process.incidents = managed.monitor.getIncidents();

    if (managed.resolve) {
      managed.resolve(buildResult(managed));
    }
  });

  // Handle error
  child.on('error', (err) => {
    managed.monitor.recordIncident('critical', 'process-error', err.message);
    managed.process.status = 'error';

    if (managed.resolve) {
      managed.resolve(buildResult(managed));
    }
  });

  // Periodic timeout check
  const interval = setInterval(() => {
    if (managed.monitor.checkTimeout()) {
      killProcess(managed.process.runId, 'timeout');
      clearInterval(interval);
    }
    if (['completed', 'killed', 'error', 'timeout'].includes(managed.process.status)) {
      clearInterval(interval);
    }
  }, 1000);
}

async function executeInline(
  skillPath: string,
  input: string,
  runId: string,
): Promise<SandboxResult> {
  const managed = activeProcesses.get(runId);
  if (!managed) {
    return {
      success: false,
      error: 'Process not found',
      status: 'error',
      metrics: emptyMetrics(),
      incidents: [],
    };
  }

  const startTime = Date.now();

  try {
    // Dynamic import the skill module
    const skill = require(skillPath);
    const fn = skill.default || skill.run || skill.execute;

    if (typeof fn !== 'function') {
      throw new Error('Skill module must export default, run, or execute function');
    }

    const output = await fn(input);
    managed.process.status = 'completed';

    return {
      success: true,
      output: typeof output === 'string' ? output : JSON.stringify(output),
      status: 'completed',
      metrics: {
        ...emptyMetrics(),
        durationMs: Date.now() - startTime,
        outputBytes: Buffer.byteLength(String(output)),
      },
      incidents: managed.monitor.getIncidents(),
    };
  } catch (err: any) {
    managed.process.status = 'error';

    return {
      success: false,
      error: err.message || String(err),
      status: 'error',
      metrics: {
        ...emptyMetrics(),
        durationMs: Date.now() - startTime,
      },
      incidents: managed.monitor.getIncidents(),
    };
  }
}

function buildResult(managed: ManagedProcess): SandboxResult {
  const metrics = managed.monitor.finalize();
  const output = managed.outputChunks.join('');

  return {
    success: managed.process.status === 'completed',
    output: output || undefined,
    error: managed.process.status === 'error' ? 'Process exited with error' :
           managed.process.status === 'killed' ? 'Process was killed' :
           managed.process.status === 'timeout' ? 'Process timed out' :
           undefined,
    exitCode: managed.process.status === 'completed' ? 0 : 1,
    status: managed.process.status,
    metrics,
    incidents: managed.monitor.getIncidents(),
  };
}

function emptyMetrics() {
  return {
    durationMs: 0,
    peakMemoryMb: 0,
    cpuTimeMs: 0,
    networkRequests: 0,
    bytesRead: 0,
    bytesWritten: 0,
    outputBytes: 0,
  };
}
