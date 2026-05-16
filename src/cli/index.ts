export { type SigilPaths, resolvePaths } from './paths.js';
export { ArgsError, parseSubcommand } from './args.js';
export {
  type PortalAddOpts,
  type PortalInfo,
  type PortalRemoveResult,
  portalAdd,
  portalListFromDisk,
  portalRemove,
} from './portal.js';
export { type StatusReport, status } from './status.js';
export { type RunCliOpts, type CliExit, runCli } from './main.js';
