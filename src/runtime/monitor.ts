/**
 * ClawOS Layer 3: Behavioral Monitor
 *
 * Watches sandboxed processes for anomalies and enforces
 * behavioral bounds. Tracks metrics, logs incidents, and
 * can throttle or kill misbehaving processes.
 */

import type {
  AnomalyRule,
  AnomalyAction,
  SecurityIncident,
  IncidentSeverity,
  ExecutionMetrics,
  SandboxConfig,
} from './types';

// ─── Default Anomaly Rules ───────────────────────────────────

export const DEFAULT_RULES: AnomalyRule[] = [
  {
    id: 'timeout',
    metric: 'duration',
    threshold: 0,  // Dynamic — uses config.resourceLimits.timeoutMs
    windowMs: 0,
    action: 'kill',
    description: 'Execution exceeded time limit',
  },
  {
    id: 'memory-limit',
    metric: 'memory',
    threshold: 0,  // Dynamic — uses config.resourceLimits.maxMemoryMb
    windowMs: 0,
    action: 'kill',
    description: 'Memory usage exceeded limit',
  },
  {
    id: 'output-limit',
    metric: 'output',
    threshold: 0,  // Dynamic — uses config.resourceLimits.maxOutputBytes
    windowMs: 0,
    action: 'kill',
    description: 'Output size exceeded limit',
  },
  {
    id: 'cpu-spike',
    metric: 'cpu',
    threshold: 95,  // percent
    windowMs: 5000,
    action: 'throttle',
    description: 'Sustained high CPU usage',
  },
  {
    id: 'rapid-file-access',
    metric: 'fileOpsPerSec',
    threshold: 100,
    windowMs: 1000,
    action: 'alert',
    description: 'Unusually rapid file operations',
  },
];

// ─── Behavioral Monitor ──────────────────────────────────────

export class BehavioralMonitor {
  private rules: AnomalyRule[];
  private incidents: SecurityIncident[] = [];
  private config: SandboxConfig;
  private startTime: number;
  private killed = false;
  private onKill?: (reason: string) => void;

  // Metric accumulators
  private metrics: ExecutionMetrics = {
    durationMs: 0,
    peakMemoryMb: 0,
    cpuTimeMs: 0,
    networkRequests: 0,
    bytesRead: 0,
    bytesWritten: 0,
    outputBytes: 0,
  };

  constructor(
    config: SandboxConfig,
    rules?: AnomalyRule[],
    onKill?: (reason: string) => void,
  ) {
    this.config = config;
    this.rules = rules || DEFAULT_RULES;
    this.startTime = Date.now();
    this.onKill = onKill;
  }

  /**
   * Record a metric update. Called periodically or on events.
   */
  recordMetric(metric: string, value: number): void {
    if (this.killed) return;

    switch (metric) {
      case 'memory':
        if (value > this.metrics.peakMemoryMb) {
          this.metrics.peakMemoryMb = value;
        }
        break;
      case 'cpu':
        this.metrics.cpuTimeMs = value;
        break;
      case 'networkRequest':
        this.metrics.networkRequests += value;
        break;
      case 'bytesRead':
        this.metrics.bytesRead += value;
        break;
      case 'bytesWritten':
        this.metrics.bytesWritten += value;
        break;
      case 'output':
        this.metrics.outputBytes += value;
        break;
    }

    // Check rules
    this.evaluate(metric, value);
  }

  /**
   * Check current state against all anomaly rules.
   */
  private evaluate(updatedMetric: string, value: number): void {
    const elapsed = Date.now() - this.startTime;

    for (const rule of this.rules) {
      let triggered = false;
      let effectiveThreshold = rule.threshold;

      switch (rule.id) {
        case 'timeout':
          effectiveThreshold = this.config.resourceLimits.timeoutMs || 30000;
          triggered = elapsed > effectiveThreshold;
          break;

        case 'memory-limit':
          effectiveThreshold = this.config.resourceLimits.maxMemoryMb || 256;
          triggered = updatedMetric === 'memory' && value > effectiveThreshold;
          break;

        case 'output-limit':
          effectiveThreshold = this.config.resourceLimits.maxOutputBytes || 1048576;
          triggered = this.metrics.outputBytes > effectiveThreshold;
          break;

        default:
          // Generic threshold check
          if (rule.metric === updatedMetric) {
            triggered = value > rule.threshold;
          }
          break;
      }

      if (triggered) {
        this.handleAnomaly(rule, value, effectiveThreshold);
      }
    }
  }

  /**
   * Handle a triggered anomaly rule.
   */
  private handleAnomaly(rule: AnomalyRule, value: number, threshold: number): void {
    const incident: SecurityIncident = {
      timestamp: Date.now(),
      severity: actionToSeverity(rule.action),
      type: rule.id,
      message: `${rule.description}: ${value} exceeded threshold ${threshold}`,
      details: {
        metric: rule.metric,
        value,
        threshold,
        action: rule.action,
      },
    };

    this.incidents.push(incident);

    if (rule.action === 'kill' && !this.killed) {
      this.killed = true;
      if (this.onKill) {
        this.onKill(incident.message);
      }
    }
  }

  /**
   * Manually check for timeout. Call this periodically.
   */
  checkTimeout(): boolean {
    const elapsed = Date.now() - this.startTime;
    const limit = this.config.resourceLimits.timeoutMs || 30000;

    if (elapsed > limit && !this.killed) {
      this.recordMetric('duration', elapsed);
      return true;
    }
    return false;
  }

  /**
   * Record a security incident manually.
   */
  recordIncident(
    severity: IncidentSeverity,
    type: string,
    message: string,
    details?: Record<string, unknown>,
  ): void {
    this.incidents.push({
      timestamp: Date.now(),
      severity,
      type,
      message,
      details,
    });
  }

  /**
   * Get all recorded incidents.
   */
  getIncidents(): SecurityIncident[] {
    return [...this.incidents];
  }

  /**
   * Get current metrics snapshot.
   */
  getMetrics(): ExecutionMetrics {
    return {
      ...this.metrics,
      durationMs: Date.now() - this.startTime,
    };
  }

  /**
   * Has the process been flagged for killing?
   */
  isKilled(): boolean {
    return this.killed;
  }

  /**
   * Finalize metrics (call when process ends).
   */
  finalize(): ExecutionMetrics {
    this.metrics.durationMs = Date.now() - this.startTime;
    return { ...this.metrics };
  }
}

// ─── Helpers ─────────────────────────────────────────────────

function actionToSeverity(action: AnomalyAction): IncidentSeverity {
  switch (action) {
    case 'log': return 'info';
    case 'throttle': return 'warning';
    case 'alert': return 'warning';
    case 'kill': return 'critical';
  }
}
