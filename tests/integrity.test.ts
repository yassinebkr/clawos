/**
 * ClawOS Layer 0: Session Integrity — Tests
 */

import {
  // Types
  type Message,
  type ToolUseContent,
  type ToolResultContent,
  type SessionAdapter,

  // Validation
  validate,
  isValid,
  validateToolPairs,
  validateToolCompletion,
  validateUniqueIds,

  // Checkpoints
  createCheckpointManager,
  MemoryCheckpointStore,

  // Repair
  repair,
  repairCopy,

  // Main controller
  createSessionIntegrity,
  SessionIntegrityError,
} from '../src/integrity';

// ─── Test Helpers ────────────────────────────────────────────

function textMessage(role: 'user' | 'assistant', text: string): Message {
  return { role, content: [{ type: 'text', text }] };
}

function toolUseMessage(id: string, name: string, input: unknown): Message {
  return {
    role: 'assistant',
    content: [{ type: 'tool_use', id, name, input }],
  };
}

function toolResultMessage(toolUseId: string, content: string, isError = false): Message {
  return {
    role: 'user',
    content: [{ type: 'tool_result', tool_use_id: toolUseId, content, is_error: isError }],
  };
}

function mixedAssistantMessage(text: string, toolId: string, toolName: string): Message {
  return {
    role: 'assistant',
    content: [
      { type: 'text', text },
      { type: 'tool_use', id: toolId, name: toolName, input: {} },
    ],
  };
}

function createMockSession(messages: Message[]): SessionAdapter {
  return {
    sessionId: 'test-session',
    messages: [...messages],
    persist: async () => {},
    archive: async () => '/tmp/archive.json',
    truncate: (index) => { messages.length = index; },
  };
}

// ─── Validation Tests ────────────────────────────────────────

describe('Layer 0: Validation', () => {
  describe('validateToolPairs', () => {
    test('valid session with no tools passes', () => {
      const messages: Message[] = [
        textMessage('user', 'Hello'),
        textMessage('assistant', 'Hi there!'),
      ];

      const result = validate(messages);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    test('valid session with matched tool_use/tool_result passes', () => {
      const messages: Message[] = [
        textMessage('user', 'Search for cats'),
        toolUseMessage('toolu_abc123', 'web_search', { query: 'cats' }),
        toolResultMessage('toolu_abc123', 'Found 10 results about cats'),
        textMessage('assistant', 'I found information about cats.'),
      ];

      const result = validate(messages);
      expect(result.valid).toBe(true);
    });

    test('orphaned tool_result fails', () => {
      const messages: Message[] = [
        textMessage('user', 'Hello'),
        textMessage('assistant', 'Hi!'),
        toolResultMessage('toolu_orphan', 'Some result'),  // No matching tool_use
      ];

      const result = validate(messages);
      expect(result.valid).toBe(false);
      expect(result.orphanedIds).toContain('toolu_orphan');
    });

    test('tool_result without preceding assistant fails', () => {
      const messages: Message[] = [
        toolResultMessage('toolu_abc', 'Result'),  // First message, no preceding
      ];

      const errors = validateToolPairs(messages);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].type).toBe('missing_preceding_message');
    });
  });

  describe('validateToolCompletion', () => {
    test('incomplete tool_use fails (except last message)', () => {
      const messages: Message[] = [
        textMessage('user', 'Do something'),
        toolUseMessage('toolu_incomplete', 'some_tool', {}),
        textMessage('user', 'Another message'),  // user message, but no tool_result
      ];

      const result = validate(messages);
      expect(result.valid).toBe(false);
      expect(result.incompleteIds).toContain('toolu_incomplete');
    });

    test('pending tool_use in last message is OK', () => {
      const messages: Message[] = [
        textMessage('user', 'Do something'),
        toolUseMessage('toolu_pending', 'some_tool', {}),  // Last message, OK to be pending
      ];

      const errors = validateToolCompletion(messages);
      expect(errors).toHaveLength(0);
    });
  });

  describe('validateUniqueIds', () => {
    test('duplicate tool IDs fail', () => {
      const messages: Message[] = [
        textMessage('user', 'First request'),
        toolUseMessage('toolu_dup', 'tool1', {}),
        toolResultMessage('toolu_dup', 'Result 1'),
        textMessage('user', 'Second request'),
        toolUseMessage('toolu_dup', 'tool2', {}),  // Same ID!
        toolResultMessage('toolu_dup', 'Result 2'),
      ];

      const errors = validateUniqueIds(messages);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0].type).toBe('duplicate_tool_id');
    });
  });

  describe('isValid (quick check)', () => {
    test('returns true for valid session', () => {
      const messages: Message[] = [
        textMessage('user', 'Hello'),
        textMessage('assistant', 'Hi!'),
      ];
      expect(isValid(messages)).toBe(true);
    });

    test('returns false for corrupt session', () => {
      const messages: Message[] = [
        textMessage('assistant', 'Hi'),
        toolResultMessage('toolu_orphan', 'Orphan'),
      ];
      expect(isValid(messages)).toBe(false);
    });
  });
});

// ─── Checkpoint Tests ────────────────────────────────────────

describe('Layer 0: Checkpoints', () => {
  test('create and retrieve checkpoint', async () => {
    const store = new MemoryCheckpointStore();
    const manager = createCheckpointManager({ store });

    const messages: Message[] = [
      textMessage('user', 'Hello'),
      textMessage('assistant', 'Hi!'),
    ];

    const checkpoint = await manager.create('session1', messages, 'api_call');

    expect(checkpoint.sessionId).toBe('session1');
    expect(checkpoint.messageIndex).toBe(2);
    expect(checkpoint.state).toBe('pending');

    const retrieved = await manager.getLatest('session1');
    expect(retrieved?.id).toBe(checkpoint.id);
  });

  test('commit checkpoint', async () => {
    const store = new MemoryCheckpointStore();
    const manager = createCheckpointManager({ store });

    const checkpoint = await manager.create('session1', [], 'tool_cycle');
    await manager.commit(checkpoint.id);

    const retrieved = await store.get(checkpoint.id);
    expect(retrieved?.state).toBe('committed');
  });

  test('rollback restores messages', async () => {
    const store = new MemoryCheckpointStore();
    const manager = createCheckpointManager({ store, snapshotMessages: true });

    const originalMessages: Message[] = [
      textMessage('user', 'Hello'),
    ];

    const checkpoint = await manager.create('session1', originalMessages, 'tool_cycle');

    // Simulate adding more messages
    const currentMessages: Message[] = [
      ...originalMessages,
      textMessage('assistant', 'Hi!'),
      textMessage('user', 'How are you?'),
    ];

    const restore = await manager.getRestoreMessages(checkpoint.id, currentMessages);

    expect(restore).toBeDefined();
    expect(restore?.messages).toHaveLength(1);
    expect(restore?.removed).toBe(2);
  });

  test('prune removes old checkpoints', async () => {
    const store = new MemoryCheckpointStore();
    const manager = createCheckpointManager({ store, retention: 2 });

    // Create 5 checkpoints
    for (let i = 0; i < 5; i++) {
      const ckpt = await manager.create('session1', [], 'api_call');
      await manager.commit(ckpt.id);
    }

    const remaining = await manager.list('session1');
    // Should have pruned down to retention count
    expect(remaining.filter(c => c.state === 'committed').length).toBeLessThanOrEqual(2);
  });
});

// ─── Repair Tests ────────────────────────────────────────────

describe('Layer 0: Repair', () => {
  test('repair removes orphaned tool_results', () => {
    const messages: Message[] = [
      textMessage('user', 'Hello'),
      textMessage('assistant', 'Hi!'),
      toolResultMessage('toolu_orphan', 'Orphaned result'),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(result.repairs.some(r => r.action === 'remove_orphan')).toBe(true);
    expect(result.newCount).toBeLessThan(result.originalCount);
  });

  test('repair removes incomplete tool_uses', () => {
    const messages: Message[] = [
      textMessage('user', 'Request'),
      toolUseMessage('toolu_incomplete', 'tool', {}),
      textMessage('user', 'Next message'),  // No tool_result!
      textMessage('assistant', 'Response'),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(result.repairs.some(r => r.action === 'remove_incomplete')).toBe(true);
  });

  test('repairCopy does not mutate original', () => {
    const original: Message[] = [
      textMessage('assistant', 'Hi'),
      toolResultMessage('toolu_orphan', 'Orphan'),
    ];
    const originalLength = original.length;

    const result = repairCopy(original);

    expect(original.length).toBe(originalLength);  // Original unchanged
    expect(result.newCount).toBeLessThan(originalLength);  // Copy was repaired
  });

  test('repair handles empty messages', () => {
    const messages: Message[] = [
      textMessage('user', 'Hello'),
      { role: 'assistant', content: [] },  // Empty!
      textMessage('assistant', 'Real response'),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(result.repairs.some(r => r.action === 'remove_empty_message')).toBe(true);
  });
});

// ─── Session Integrity Controller Tests ──────────────────────

describe('Layer 0: SessionIntegrity', () => {
  describe('validation', () => {
    test('validateOrThrow passes for valid session', () => {
      const integrity = createSessionIntegrity();
      const session = createMockSession([
        textMessage('user', 'Hello'),
        textMessage('assistant', 'Hi!'),
      ]);

      expect(() => integrity.validateOrThrow(session)).not.toThrow();
    });

    test('validateOrThrow throws for corrupt session', () => {
      const integrity = createSessionIntegrity();
      const session = createMockSession([
        textMessage('assistant', 'Hi'),
        toolResultMessage('toolu_orphan', 'Orphan'),
      ]);

      expect(() => integrity.validateOrThrow(session)).toThrow(SessionIntegrityError);
    });

    test('validateOrThrow with autoRepair fixes session', () => {
      const integrity = createSessionIntegrity({ autoRepair: true });
      const session = createMockSession([
        textMessage('user', 'Hello'),
        textMessage('assistant', 'Hi'),
        toolResultMessage('toolu_orphan', 'Orphan'),
      ]);

      // Should not throw because autoRepair fixes it
      expect(() => integrity.validateOrThrow(session)).not.toThrow();
    });
  });

  describe('tool cycles', () => {
    test('executeToolCycle succeeds', async () => {
      const integrity = createSessionIntegrity();
      const session = createMockSession([
        textMessage('user', 'Search for cats'),
      ]);

      const toolUse: ToolUseContent = {
        type: 'tool_use',
        id: 'toolu_test',
        name: 'web_search',
        input: { query: 'cats' },
      };

      const mockExecutor = {
        execute: async () => ({ output: 'Found cats!', isError: false }),
      };

      const result = await integrity.executeToolCycle(session, toolUse, mockExecutor);

      expect(result.success).toBe(true);
      expect(result.result?.tool_use_id).toBe('toolu_test');
      expect(result.result?.content).toBe('Found cats!');
    });

    test('executeToolCycle rolls back on failure', async () => {
      const integrity = createSessionIntegrity({ snapshotMessages: true });
      const session = createMockSession([
        textMessage('user', 'Request'),
      ]);
      const originalLength = session.messages.length;

      const toolUse: ToolUseContent = {
        type: 'tool_use',
        id: 'toolu_fail',
        name: 'failing_tool',
        input: {},
      };

      const mockExecutor = {
        execute: async () => { throw new Error('Tool failed!'); },
      };

      const result = await integrity.executeToolCycle(session, toolUse, mockExecutor);

      expect(result.success).toBe(false);
      expect(result.rolledBack).toBe(true);
      expect(result.error).toBe('Tool failed!');
    });
  });

  describe('error handling', () => {
    test('handleError attempts rollback', async () => {
      const integrity = createSessionIntegrity({ snapshotMessages: true });
      const session = createMockSession([
        textMessage('user', 'Hello'),
      ]);

      // Create a checkpoint first
      await integrity.createCheckpoint(session, 'api_call');

      // Simulate adding messages that would be rolled back
      session.messages.push(textMessage('assistant', 'Response'));

      const error = new Error('Content filter blocked');
      const recovery = await integrity.handleError(session, error);

      // Should attempt rollback or repair
      expect(['rolled_back', 'repaired', 'escalate']).toContain(recovery.action);
    });
  });

  describe('incidents', () => {
    test('logs incidents during operations', async () => {
      const integrity = createSessionIntegrity({ verbose: false });
      const session = createMockSession([
        textMessage('user', 'Hello'),
      ]);

      await integrity.createCheckpoint(session, 'manual');

      const incidents = integrity.getIncidents(session.sessionId);
      expect(incidents.length).toBeGreaterThan(0);
      expect(incidents[0].type).toBe('checkpoint_created');
    });
  });
});

// ─── Integration Test: The Corruption Scenario ───────────────

describe('Layer 0: Corruption Scenario (Case Study 001)', () => {
  test('detects and repairs the exact corruption pattern', () => {
    // Recreate the corruption: orphaned tool_result from partial processing
    const messages: Message[] = [
      textMessage('user', 'Add the missing docs'),
      // Assistant message with tool_use was lost/truncated
      // But tool_result remained:
      toolResultMessage('toolu_01KCKcNdNjS4fjQF8uAE8ADS', 'Docs added successfully'),
      textMessage('user', 'Help me improve our first phases'),
    ];

    // Validation should catch this
    const validation = validate(messages);
    expect(validation.valid).toBe(false);
    expect(validation.orphanedIds).toContain('toolu_01KCKcNdNjS4fjQF8uAE8ADS');

    // Repair should fix it
    const repairResult = repair(messages);
    expect(repairResult.repaired).toBe(true);

    // After repair, should be valid
    const revalidation = validate(messages);
    expect(revalidation.valid).toBe(true);
  });

  test('prevents corruption with checkpoints', async () => {
    const integrity = createSessionIntegrity({ snapshotMessages: true });

    // Initial valid state
    const session = createMockSession([
      textMessage('user', 'Add the missing docs'),
    ]);

    // Create checkpoint before tool cycle
    const checkpoint = await integrity.createCheckpoint(session, 'tool_cycle');

    // Simulate partial processing (tool_use recorded)
    session.messages.push(toolUseMessage('toolu_01ABC', 'edit_file', { file: 'docs.md' }));

    // Simulate content filter before tool_result could be recorded
    const error = new Error('Content filter blocked');
    const recovery = await integrity.handleError(session, error);

    // Should have rolled back or repaired
    expect(['rolled_back', 'repaired', 'escalate']).toContain(recovery.action);

    // Session should be valid after recovery
    expect(integrity.isSessionValid(session)).toBe(true);
  });
});
