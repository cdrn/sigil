export {
  type AcquireLockOptions,
  AuditLockError,
  FileLockError,
  acquireLockSync,
  lockPathFor,
  releaseWithRetry,
  withFileLock,
  writeAllSync,
} from './lock.js';
