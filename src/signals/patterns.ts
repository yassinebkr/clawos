/**
 * ClawOS Layer 4: Signal Detection — Pattern Definitions
 */

import type { PatternDefinition, SignalCategory } from "./types.js";

// ============================================================================
// Injection Patterns
// ============================================================================

export const INJECTION_PATTERNS: PatternDefinition[] = [
  // Direct instruction override
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/i,
    category: "injection",
    weight: 0.8,
    description: "Direct instruction override attempt",
  },
  {
    pattern: /disregard\s+(all\s+)?(previous|prior|above)/i,
    category: "injection",
    weight: 0.7,
    description: "Disregard previous content",
  },
  {
    pattern: /forget\s+(everything|all|what)\s+(you|i)\s+(told|said)/i,
    category: "injection",
    weight: 0.6,
    description: "Memory wipe attempt",
  },

  // New instruction injection
  {
    pattern: /new\s+instructions?:?\s/i,
    category: "injection",
    weight: 0.6,
    description: "New instruction injection",
  },
  {
    pattern: /your\s+real\s+instructions?\s+are/i,
    category: "injection",
    weight: 0.8,
    description: "Fake real instructions",
  },
  {
    pattern: /system\s*prompt:?\s/i,
    category: "injection",
    weight: 0.7,
    description: "System prompt spoofing",
  },
  {
    pattern: /\[INST\]/i,
    category: "injection",
    weight: 0.5,
    description: "Instruction token injection",
  },

  // Delimiter abuse
  {
    pattern: /^\s*SYSTEM\s*:/im,
    category: "injection",
    weight: 0.7,
    description: "System label injection",
  },
  {
    pattern: /```system\b/i,
    category: "injection",
    weight: 0.7,
    description: "Markdown system block",
  },
  {
    pattern: /<\/?system>/i,
    category: "injection",
    weight: 0.8,
    description: "XML system tag",
  },
  {
    pattern: /\[SYSTEM\]/i,
    category: "injection",
    weight: 0.6,
    description: "System marker injection",
  },
  {
    pattern: /<\|im_start\|>|<\|im_end\|>/i,
    category: "injection",
    weight: 0.9,
    description: "ChatML token injection",
  },

  // Developer/debug mode
  {
    pattern: /developer\s+mode\s+(enabled|on|activated)/i,
    category: "injection",
    weight: 0.6,
    description: "Developer mode activation",
  },
  {
    pattern: /debug\s+mode\s+(enabled|on|activated)/i,
    category: "injection",
    weight: 0.5,
    description: "Debug mode activation",
  },
  {
    pattern: /maintenance\s+mode/i,
    category: "injection",
    weight: 0.5,
    description: "Maintenance mode claim",
  },

  // Jailbreak phrases
  {
    pattern: /\bDAN\s*(mode)?/i,
    category: "injection",
    weight: 0.9,
    description: "DAN jailbreak reference",
  },
  {
    pattern: /do\s+anything\s+now/i,
    category: "injection",
    weight: 0.8,
    description: "DAN phrase",
  },
  {
    pattern: /\bjailbreak/i,
    category: "injection",
    weight: 0.7,
    description: "Jailbreak reference",
  },
  {
    pattern: /unlock\s+(your\s+)?full\s+potential/i,
    category: "injection",
    weight: 0.6,
    description: "Unlocking attempt",
  },
];

// ============================================================================
// Exfiltration Patterns
// ============================================================================

export const EXFILTRATION_PATTERNS: PatternDefinition[] = [
  // System prompt extraction
  {
    pattern: /what\s+(is|are)\s+your\s+(system\s+)?instructions?/i,
    category: "exfiltration",
    weight: 0.6,
    description: "System instruction query",
  },
  {
    pattern: /repeat\s+your\s+(system\s+)?prompt/i,
    category: "exfiltration",
    weight: 0.8,
    description: "Prompt repeat request",
  },
  {
    pattern: /print\s+(your\s+)?(initial|original|system)/i,
    category: "exfiltration",
    weight: 0.7,
    description: "System print request",
  },
  {
    pattern: /output\s+(your|the)\s+(system\s+)?prompt/i,
    category: "exfiltration",
    weight: 0.7,
    description: "Prompt output request",
  },
  {
    pattern: /show\s+me\s+your\s+(full\s+)?prompt/i,
    category: "exfiltration",
    weight: 0.6,
    description: "Prompt show request",
  },
  {
    pattern: /what\s+were\s+you\s+told\s+(to\s+do)?/i,
    category: "exfiltration",
    weight: 0.5,
    description: "Instructions query",
  },

  // Credential extraction
  {
    pattern: /show\s+me\s+(your\s+)?(api\s+)?keys?/i,
    category: "exfiltration",
    weight: 0.8,
    description: "API key extraction",
  },
  {
    pattern: /what\s+are\s+(your\s+)?credentials/i,
    category: "exfiltration",
    weight: 0.7,
    description: "Credential query",
  },
  {
    pattern: /output\s+(all\s+)?environment\s+variables/i,
    category: "exfiltration",
    weight: 0.8,
    description: "Env var extraction",
  },
  {
    pattern: /print\s+\$?[A-Z_]+_KEY/i,
    category: "exfiltration",
    weight: 0.7,
    description: "Specific key extraction",
  },

  // Data exfiltration via URLs / network
  {
    pattern: /(?:fetch|curl|wget|http\.get|requests?\.(?:get|post))\s*\(?.*(?:evil|attacker|webhook|steal)/i,
    category: "exfiltration",
    weight: 0.9,
    description: "Data exfiltration via HTTP request",
  },
  {
    pattern: /send\s+(?:this\s+)?to\s+https?:\/\//i,
    category: "exfiltration",
    weight: 0.7,
    description: "Data send to external URL",
  },
  {
    pattern: /curl\s+https?:\/\/.*\|\s*(?:bash|sh|zsh)/i,
    category: "exfiltration",
    weight: 0.9,
    description: "Pipe from URL to shell",
  },
  {
    pattern: /(?:send|post|upload|exfil)\s+.*(?:to|via)\s+(?:webhook|external|remote)/i,
    category: "exfiltration",
    weight: 0.7,
    description: "Data exfiltration to external service",
  },

  // Memory/context extraction
  {
    pattern: /list\s+all\s+(your\s+)?(memories|context|history)/i,
    category: "exfiltration",
    weight: 0.5,
    description: "Memory listing",
  },
  {
    pattern: /what\s+do\s+you\s+know\s+about\s+other\s+users/i,
    category: "exfiltration",
    weight: 0.6,
    description: "Cross-user data query",
  },
];

// ============================================================================
// Encoding Patterns
// ============================================================================

export const ENCODING_PATTERNS: PatternDefinition[] = [
  // Base64 in suspicious contexts
  {
    pattern: /decode\s+this:?\s*[A-Za-z0-9+/]{20,}={0,2}/i,
    category: "encoding",
    weight: 0.7,
    description: "Decode request with base64",
  },

  // Hex encoding
  {
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}/i,
    category: "encoding",
    weight: 0.6,
    description: "Hex escape sequence",
  },

  // Unicode escapes
  {
    pattern: /\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){5,}/i,
    category: "encoding",
    weight: 0.5,
    description: "Unicode escape sequence",
  },

  // ROT13 markers
  {
    pattern: /rot13|decode\s+this|translate\s+from\s+cipher/i,
    category: "encoding",
    weight: 0.4,
    description: "Cipher decode request",
  },

  // Character splitting/obfuscation
  {
    pattern: /i\.g\.n\.o\.r\.e/i,
    category: "encoding",
    weight: 0.8,
    description: "Character-split ignore",
  },
  {
    pattern: /s\.y\.s\.t\.e\.m/i,
    category: "encoding",
    weight: 0.7,
    description: "Character-split system",
  },

  // Reverse text
  {
    pattern: /reverse\s+(this|the\s+following)/i,
    category: "encoding",
    weight: 0.3,
    description: "Reverse text request",
  },
];

// ============================================================================
// Roleplay Patterns
// ============================================================================

export const ROLEPLAY_PATTERNS: PatternDefinition[] = [
  // Persona override
  {
    pattern: /you\s+are\s+(now\s+)?(a|an|the)\s+\w+\s+(named|called)/i,
    category: "roleplay",
    weight: 0.5,
    description: "Persona assignment",
  },
  {
    pattern: /pretend\s+(you\s+are|to\s+be)\s+(a|an)/i,
    category: "roleplay",
    weight: 0.4,
    description: "Pretend request",
  },
  {
    pattern: /from\s+now\s+on,?\s+you\s+(are|will\s+be)/i,
    category: "roleplay",
    weight: 0.6,
    description: "Persistent persona change",
  },

  // Authority assumption
  {
    pattern: /i\s+am\s+your\s+(creator|developer|admin|owner)/i,
    category: "roleplay",
    weight: 0.7,
    description: "Authority claim",
  },
  {
    pattern: /speaking\s+as\s+your\s+(owner|admin|developer)/i,
    category: "roleplay",
    weight: 0.7,
    description: "Authority speaking",
  },
  {
    pattern: /this\s+is\s+(anthropic|openai|the\s+company|your\s+creators?)/i,
    category: "roleplay",
    weight: 0.8,
    description: "Company impersonation",
  },

  // Override capabilities
  {
    pattern: /you\s+can\s+actually\s+do\s+(anything|everything)/i,
    category: "roleplay",
    weight: 0.5,
    description: "Capability override claim",
  },
  {
    pattern: /you\s+don'?t\s+have\s+(any\s+)?(restrictions?|limitations?)/i,
    category: "roleplay",
    weight: 0.6,
    description: "Restriction denial",
  },
];

// ============================================================================
// Self-Modification Patterns
// ============================================================================

export const SELF_MODIFICATION_PATTERNS: PatternDefinition[] = [
  // Modify SOUL file
  {
    pattern: /(?:edit|modify|rewrite|change|update)\s+your\s+(?:.*\s+)?SOUL/i,
    category: "self_modification",
    weight: 0.8,
    description: "Attempt to modify agent SOUL file",
    contextCheck: (text: string, _match: RegExpExecArray): boolean => {
      // Exclude "help me write/edit a SOUL.md" (user asking for help with their own file)
      if (/help\s+me\s+(?:write|edit|create|make)/i.test(text)) return false;
      return true;
    },
  },

  // Modify AGENTS file
  {
    pattern: /(?:edit|modify|rewrite|change|update)\s+your\s+(?:.*\s+)?AGENTS/i,
    category: "self_modification",
    weight: 0.8,
    description: "Attempt to modify agent AGENTS file",
    contextCheck: (text: string, _match: RegExpExecArray): boolean => {
      if (/help\s+me\s+(?:write|edit|create|make)/i.test(text)) return false;
      return true;
    },
  },

  // Modify system prompt / instructions / rules / personality / behavior
  {
    pattern: /(?:change|modify|rewrite|edit)\s+your\s+(?:system\s+prompt|instructions|rules|personality|behavior)/i,
    category: "self_modification",
    weight: 0.85,
    description: "Attempt to modify agent system prompt or core instructions",
  },

  // Write to / overwrite SOUL.md / AGENTS.md / USER.md
  {
    pattern: /(?:write\s+to|overwrite)\s+(?:your\s+)?(?:SOUL\.md|AGENTS\.md|USER\.md)/i,
    category: "self_modification",
    weight: 0.85,
    description: "Attempt to write to agent config files",
    contextCheck: (text: string, _match: RegExpExecArray): boolean => {
      // Exclude "help me write a SOUL.md" or similar
      if (/help\s+me/i.test(text)) return false;
      // Exclude "I wrote to SOUL.md" (past tense, user did it)
      if (/\bI\s+(?:wrote|updated|changed)\b/i.test(text)) return false;
      return true;
    },
  },

  // Remove restrictions / rules / safety / guidelines from config/files/prompt
  {
    pattern: /(?:remove|disable|delete)\s+(?:all\s+)?(?:restrictions?|rules?|safety|guidelines?)\s+from\s+your\s+(?:config|files?|prompt|system)/i,
    category: "self_modification",
    weight: 0.9,
    description: "Attempt to remove restrictions from agent configuration",
  },

  // "you are (now) free to change/modify/rewrite yourself/your rules/prompt/soul"
  {
    pattern: /you\s+are\s+(?:now\s+)?free\s+to\s+(?:change|modify|rewrite)\s+(?:yourself|your\s+(?:rules|prompt|soul))/i,
    category: "self_modification",
    weight: 0.8,
    description: "Claim that agent is free to self-modify",
  },

  // "make this/these change(s) permanent/persistent" in context of instructions
  {
    pattern: /make\s+(?:this|these)\s+changes?\s+(?:to\s+your\s+(?:instructions?|prompt|rules?|config)\s+)?(?:permanent|persistent)/i,
    category: "self_modification",
    weight: 0.7,
    description: "Attempt to make instruction changes persistent",
  },
];

// ============================================================================
// All Patterns
// ============================================================================

export const ALL_PATTERNS: PatternDefinition[] = [
  ...INJECTION_PATTERNS,
  ...EXFILTRATION_PATTERNS,
  ...ENCODING_PATTERNS,
  ...ROLEPLAY_PATTERNS,
  ...SELF_MODIFICATION_PATTERNS,
];

// ============================================================================
// Pattern Categories Map
// ============================================================================

export const PATTERNS_BY_CATEGORY: Record<string, PatternDefinition[]> = {
  injection: INJECTION_PATTERNS,
  exfiltration: EXFILTRATION_PATTERNS,
  encoding: ENCODING_PATTERNS,
  roleplay: ROLEPLAY_PATTERNS,
  self_modification: SELF_MODIFICATION_PATTERNS,
};
