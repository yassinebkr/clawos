/**
 * Layer 3: Runtime Security — Behavioral Monitor Tests
 */

import { describe, it, expect, beforeEach } from "vitest";
import { BehavioralMonitor, DEFAULT_RULES } from "../../src/runtime/monitor";
import type { SandboxConfig, AnomalyRule } from "../../src/runtime/types";

function createConfig(overrides?: Partial<SandboxConfig["resourceLimits"]>): SandboxConfig {
  return {
    level: 1,
    allowedPaths: [],
    allowedDomains: [],
    resourceLimits: {
      timeoutMs: 5000,
      maxMemoryMb: 128,
      maxOutputBytes: 1048576,
      maxHttpRequests: 10,
      maxFileSizeBytes: 10485760,
      ...overrides,
    },
    tempDir: "/tmp/test",
    env: {},
    cwd: "/tmp/test",
  };
}

describe("BehavioralMonitor", () => {
  let monitor: BehavioralMonitor;

  beforeEach(() => {
    monitor = new BehavioralMonitor(createConfig());
  });

  describe("recordMetric", () => {
    it("tracks peak memory", () => {
      monitor.recordMetric("memory", 50);
      monitor.recordMetric("memory", 100);
      monitor.recordMetric("memory", 75);
      const metrics = monitor.getMetrics();
      expect(metrics.peakMemoryMb).toBe(100);
    });

    it("accumulates network requests", () => {
      monitor.recordMetric("networkRequest", 1);
      monitor.recordMetric("networkRequest", 1);
      expect(monitor.getMetrics().networkRequests).toBe(2);
    });

    it("accumulates bytes read", () => {
      monitor.recordMetric("bytesRead", 100);
      monitor.recordMetric("bytesRead", 200);
      expect(monitor.getMetrics().bytesRead).toBe(300);
    });

    it("accumulates bytes written", () => {
      monitor.recordMetric("bytesWritten", 500);
      expect(monitor.getMetrics().bytesWritten).toBe(500);
    });

    it("accumulates output bytes", () => {
      monitor.recordMetric("output", 1000);
      monitor.recordMetric("output", 2000);
      expect(monitor.getMetrics().outputBytes).toBe(3000);
    });
  });

  describe("anomaly detection", () => {
    it("triggers memory limit kill", () => {
      let killReason = "";
      const mon = new BehavioralMonitor(createConfig({ maxMemoryMb: 100 }), undefined, (reason) => {
        killReason = reason;
      });

      mon.recordMetric("memory", 150);
      expect(mon.isKilled()).toBe(true);
      expect(killReason).toContain("150");
    });

    it("triggers output limit kill", () => {
      let killed = false;
      const mon = new BehavioralMonitor(
        createConfig({ maxOutputBytes: 100 }),
        undefined,
        () => { killed = true; }
      );

      mon.recordMetric("output", 200);
      expect(killed).toBe(true);
    });

    it("does not fire below thresholds", () => {
      let killed = false;
      const mon = new BehavioralMonitor(createConfig(), undefined, () => { killed = true; });

      mon.recordMetric("memory", 50);
      mon.recordMetric("output", 100);
      expect(killed).toBe(false);
    });

    it("records incidents on anomaly", () => {
      const mon = new BehavioralMonitor(createConfig({ maxMemoryMb: 50 }));
      mon.recordMetric("memory", 100);

      const incidents = mon.getIncidents();
      expect(incidents.length).toBeGreaterThan(0);
      expect(incidents[0].severity).toBe("critical");
      expect(incidents[0].type).toBe("memory-limit");
    });
  });

  describe("manual incident recording", () => {
    it("records custom incidents", () => {
      monitor.recordIncident("warning", "suspicious-behavior", "Unusual pattern detected");
      const incidents = monitor.getIncidents();
      expect(incidents).toHaveLength(1);
      expect(incidents[0].severity).toBe("warning");
      expect(incidents[0].type).toBe("suspicious-behavior");
    });

    it("includes details in incident", () => {
      monitor.recordIncident("info", "test", "Test", { key: "value" });
      const incidents = monitor.getIncidents();
      expect(incidents[0].details).toEqual({ key: "value" });
    });
  });

  describe("checkTimeout", () => {
    it("returns false when within limit", () => {
      expect(monitor.checkTimeout()).toBe(false);
    });

    it("returns true after timeout exceeded", async () => {
      const mon = new BehavioralMonitor(createConfig({ timeoutMs: 1 }));
      await new Promise((r) => setTimeout(r, 10));
      expect(mon.checkTimeout()).toBe(true);
    });
  });

  describe("finalize", () => {
    it("returns final metrics with duration", () => {
      const metrics = monitor.finalize();
      expect(metrics.durationMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe("killed state", () => {
    it("stops recording after kill", () => {
      let killed = false;
      const mon = new BehavioralMonitor(
        createConfig({ maxMemoryMb: 50 }),
        undefined,
        () => { killed = true; }
      );

      mon.recordMetric("memory", 100); // Triggers kill
      expect(mon.isKilled()).toBe(true);

      // Further metrics should be ignored
      mon.recordMetric("memory", 200);
      expect(mon.getMetrics().peakMemoryMb).toBe(100);
    });
  });
});

describe("DEFAULT_RULES", () => {
  it("includes timeout rule", () => {
    expect(DEFAULT_RULES.some((r) => r.id === "timeout")).toBe(true);
  });

  it("includes memory-limit rule", () => {
    expect(DEFAULT_RULES.some((r) => r.id === "memory-limit")).toBe(true);
  });

  it("includes output-limit rule", () => {
    expect(DEFAULT_RULES.some((r) => r.id === "output-limit")).toBe(true);
  });

  it("includes cpu-spike rule", () => {
    expect(DEFAULT_RULES.some((r) => r.id === "cpu-spike")).toBe(true);
  });

  it("timeout and memory rules use kill action", () => {
    const killRules = DEFAULT_RULES.filter((r) => r.action === "kill");
    expect(killRules.length).toBeGreaterThanOrEqual(2);
  });
});
