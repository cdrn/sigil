export {
  type AuditDecision,
  type AuditEntry,
  type StoredAuditEntry,
  type ChainHead,
  ZERO_HASH,
  HASH_HEX_LEN,
  AuditChainError,
  AuditWriter,
  canonicalJSON,
  hashEntry,
  sealEntry,
  serializeEntry,
  parseLine,
  verifyChain,
  readHead,
  type AuditWriterOpts,
} from './log.js';
export { type AcquireLockOptions, AuditLockError, acquireLockSync } from '../fs/lock.js';
