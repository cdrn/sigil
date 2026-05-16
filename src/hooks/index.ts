export {
  type BlockerOpts,
  type BlockDecision as PathBlockDecision,
  DEFAULT_PATH_PATTERNS,
  isBlockedPath,
} from './path-blocker.js';
export { scanBashCommand } from './command-scanner.js';
export {
  type RedactionStat,
  type RedactionResult,
  redact,
} from './redactor.js';
export {
  type HookEnvelope,
  type BlockDecision,
  type PostToolModification,
  readHookEnvelope,
} from './protocol.js';
export { decidePreToolUse } from './pre-tool-use.js';
export { decidePostToolUse, walkAndRedact } from './post-tool-use.js';
export {
  type InitOpts,
  type InitScope,
  type InitResult,
  installInto,
  settingsPath,
} from './install.js';
export { expandTilde, globMatch, globToRegex, normalizePath } from './glob.js';
