/**
 * ClawOS Layer 3: Runtime Security
 *
 * Process isolation, behavioral monitoring, and resource enforcement.
 */

export type {
  IsolationLevel,
  PathRule,
  SandboxConfig,
  ExecutionMetrics,
  IncidentSeverity,
  SecurityIncident,
  ProcessStatus,
  SandboxResult,
  AnomalyAction,
  AnomalyRule,
  SandboxedProcess,
} from './types';

export {
  selectIsolationLevel,
  createSandboxConfig,
  isBubblewrapAvailable,
  effectiveLevel,
} from './isolation';

export {
  BehavioralMonitor,
  DEFAULT_RULES,
} from './monitor';

export {
  spawn,
  sendInput,
  killProcess,
  waitForProcess,
  execute,
  getProcess,
  listProcesses,
  cleanup,
  cleanupAll,
} from './sandbox';
