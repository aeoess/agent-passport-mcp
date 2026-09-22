// Nullifier stores for the v0.1 capability-token reference implementation.
// The sink consults one of these on every M3 redemption to prevent token
// replay: a preimage may be consumed exactly once.
//
// InMemoryNullifierSet is process-local and does not survive a restart or
// span multiple processes. It exists for tests and as a building block; it
// must never be the silent default for a real redemption path, because the
// hosted bridge spawns a fresh subprocess per session and every process
// would start with an empty set.
//
// FileNullifierStore is durable and safe across concurrent processes: it
// consumes a token via an exclusive file create (`wx`), which is atomic at
// the filesystem level, so two processes racing to consume the same
// preimage can never both succeed. Only the preimage's SHA-256 hash is
// ever written to disk. The directory is created 0700 and markers 0600 —
// this state is security-sensitive (each marker names a consumed token's
// hash) and must not be readable or writable by other local users.
//
// In hosted mode (MCP_REMOTE === '1') the store never creates its
// directory and requires it to already exist with a provisioning sentinel
// file (HOSTED_NULLIFIER_SENTINEL). This catches a hosted deployment
// pointing APS_NULLIFIER_DIR at a path whose persistent volume isn't
// actually mounted: without this check, the store would silently create
// an ephemeral directory that looks durable until the next restart, when
// replay protection resets.

import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { join } from "node:path";
import { sha256Hex } from "./canonical.js";

// Provisioning sentinel required in hosted mode (see FileNullifierStore
// below). Written by whatever process provisions the persistent volume,
// never by this store itself.
export const HOSTED_NULLIFIER_SENTINEL = ".aps-nullifier-store";

export interface NullifierStore {
  isConsumed(preimage: string): boolean;
  consume(preimage: string): void;
  /**
   * Best-effort undo of a consume() that is not going to produce a valid
   * result (e.g. the signing step after it threw). Not part of the replay
   * guarantee — only used to avoid permanently burning a token on a
   * transient failure unrelated to redemption itself.
   */
  release?(preimage: string): void;
  size(): number;
  clear(): void;
}

export class NullifierReplayError extends Error {
  constructor(preimage: string) {
    super(`nullifier replay: token preimage ${preimage.slice(0, 12)}... already consumed`);
    this.name = "NullifierReplayError";
  }
}

export class InMemoryNullifierSet implements NullifierStore {
  private readonly seen = new Set<string>();

  isConsumed(preimage: string): boolean {
    return this.seen.has(preimage);
  }

  consume(preimage: string): void {
    if (this.seen.has(preimage)) {
      throw new NullifierReplayError(preimage);
    }
    this.seen.add(preimage);
  }

  release(preimage: string): void {
    this.seen.delete(preimage);
  }

  size(): number {
    return this.seen.size;
  }

  clear(): void {
    this.seen.clear();
  }
}

const NULLIFIER_FILENAME = /^[0-9a-f]{64}$/;

export interface FileNullifierStoreOptions {
  /**
   * Hosted mode: MCP_REMOTE === '1' on the hosted bridge. The store never
   * creates `dir` — it must already exist on a provisioned, persistent
   * volume and contain the HOSTED_NULLIFIER_SENTINEL file written when that
   * volume was provisioned. This exists because a hosted service pointing
   * APS_NULLIFIER_DIR at an unmounted path would otherwise get a silently
   * auto-created, container-ephemeral directory: replay protection would
   * appear to work until the next restart, when the directory (and every
   * marker in it) is gone. Local stdio mode does not set this.
   */
  hosted?: boolean;
}

/**
 * Durable, cross-process nullifier store. One file per consumed preimage,
 * named by its SHA-256 hex digest, under `dir`. Consuming is a single
 * `open(path, 'wx')` call: it either creates the file (first consumption)
 * or fails with EEXIST (replay), with no separate check-then-act window
 * for concurrent processes to race through.
 *
 * If `dir` cannot be used, construction does not throw (so an unrelated
 * server with 150+ other tools does not fail to start over one
 * misconfigured directory); instead every operation on this store throws,
 * so the one redemption path that depends on it fails closed with a clear
 * error naming which check failed.
 */
export class FileNullifierStore implements NullifierStore {
  private readonly dir: string | undefined;
  private readonly initError: Error | null;

  constructor(dir: string | undefined, options: FileNullifierStoreOptions = {}) {
    this.dir = dir;
    this.initError = options.hosted
      ? FileNullifierStore.tryInitHosted(dir)
      : FileNullifierStore.tryInitLocal(dir);
  }

  // Directory and marker files are owner-only (0700 / 0600): a nullifier
  // marker's existence is itself sensitive (it names a consumed capability
  // token preimage's hash), and a group/world-writable directory would let
  // another local user delete markers to reopen replay.
  private static readonly DIR_MODE = 0o700;
  private static readonly MARKER_MODE = 0o600;

  private static checkDirPermissions(dir: string, stat: Stats): Error | null {
    const groupOrWorldWritable = (stat.mode & 0o022) !== 0;
    if (groupOrWorldWritable) {
      return new Error(
        `nullifier store: directory "${dir}" is group- or world-writable (mode ${(stat.mode & 0o777).toString(8)}). ` +
          `Refusing to use it: anyone else with access could delete replay markers and reopen replay. ` +
          `chmod it to 0700 (owner read/write/execute only) and retry.`,
      );
    }
    return null;
  }

  private static tryInitLocal(dir: string | undefined): Error | null {
    if (!dir) {
      return new Error(`nullifier store: no directory configured.`);
    }
    try {
      mkdirSync(dir, { recursive: true, mode: FileNullifierStore.DIR_MODE });
      // mkdirSync is a silent no-op if dir already exists, even if its mode
      // is looser than DIR_MODE (e.g. created before this hardening, or
      // changed since), so check the actual mode explicitly rather than
      // trusting mkdirSync alone.
      const stat = statSync(dir);
      const permError = FileNullifierStore.checkDirPermissions(dir, stat);
      if (permError) return permError;
      // Also probe writability explicitly: an owner-only-but-read-only
      // directory (e.g. 0500) passes the permission check above but still
      // can't hold markers.
      const probe = join(dir, `.write-probe-${process.pid}-${Date.now()}`);
      closeSync(openSync(probe, "w", FileNullifierStore.MARKER_MODE));
      unlinkSync(probe);
      return null;
    } catch (e) {
      return new Error(
        `nullifier store: directory "${dir}" is not usable (${(e as Error).message}). ` +
          `Set APS_NULLIFIER_DIR to a writable directory. Redemption fails closed rather than falling back to an in-memory store.`,
      );
    }
  }

  private static tryInitHosted(dir: string | undefined): Error | null {
    if (!dir) {
      return new Error(
        `nullifier store (hosted mode): APS_NULLIFIER_DIR must be set explicitly when MCP_REMOTE=1. ` +
          `Point it at a directory on a persistent, provisioned volume — hosted mode never picks a default ` +
          `and never creates the directory, to avoid silently falling back to container-ephemeral storage.`,
      );
    }
    if (!existsSync(dir)) {
      return new Error(
        `nullifier store (hosted mode): directory "${dir}" does not exist. ` +
          `Hosted mode never creates it — provision the persistent volume and directory (mode 0700) before ` +
          `starting the server, and write the "${HOSTED_NULLIFIER_SENTINEL}" sentinel into it.`,
      );
    }
    let stat: Stats;
    try {
      stat = statSync(dir);
    } catch (e) {
      return new Error(`nullifier store (hosted mode): cannot stat directory "${dir}": ${(e as Error).message}`);
    }
    if (!stat.isDirectory()) {
      return new Error(`nullifier store (hosted mode): "${dir}" exists but is not a directory.`);
    }
    const permError = FileNullifierStore.checkDirPermissions(dir, stat);
    if (permError) return permError;
    if (!existsSync(join(dir, HOSTED_NULLIFIER_SENTINEL))) {
      return new Error(
        `nullifier store (hosted mode): directory "${dir}" is missing the provisioning sentinel ` +
          `"${HOSTED_NULLIFIER_SENTINEL}". This means the volume was not provisioned as expected (or is not ` +
          `actually mounted here) — refusing to use it as the nullifier store, since that would silently start ` +
          `an ephemeral store that reopens replay on the next restart.`,
      );
    }
    return null;
  }

  private ensureReady(): void {
    if (this.initError) throw this.initError;
  }

  private pathFor(preimage: string): string {
    // this.dir is defined whenever initError is null (both tryInitLocal and
    // tryInitHosted fail closed on an undefined dir), and ensureReady() is
    // called by every caller of pathFor() before it is reached.
    return join(this.dir as string, sha256Hex(preimage));
  }

  private fsyncDir(): void {
    try {
      const dfd = openSync(this.dir as string, "r");
      try {
        fsyncSync(dfd);
      } finally {
        closeSync(dfd);
      }
    } catch {
      // Directory fsync isn't available on every platform. Best-effort only:
      // the per-file fsync in consume() is what actually matters for
      // durability of the marker itself.
    }
  }

  isConsumed(preimage: string): boolean {
    this.ensureReady();
    return existsSync(this.pathFor(preimage));
  }

  consume(preimage: string): void {
    this.ensureReady();
    const path = this.pathFor(preimage);
    let fd: number;
    try {
      // Markers are never pruned by this store, and none should be added
      // without care: a marker deleted before a token's signed `expires_at`
      // has passed reopens replay for that token. Any future pruning must
      // keep every marker at least as long as the maximum validity window
      // of a capability token.
      fd = openSync(path, "wx", FileNullifierStore.MARKER_MODE);
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      if (err.code === "EEXIST") {
        throw new NullifierReplayError(preimage);
      }
      throw new Error(`nullifier store: cannot consume token: ${err.message}`);
    }
    try {
      // Only a timestamp is written — never the preimage itself.
      writeSync(fd, new Date().toISOString());
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    this.fsyncDir();
  }

  release(preimage: string): void {
    try {
      unlinkSync(this.pathFor(preimage));
    } catch {
      // Already gone, or never existed — nothing to roll back.
    }
  }

  size(): number {
    this.ensureReady();
    return this.listMarkers().length;
  }

  clear(): void {
    this.ensureReady();
    for (const name of this.listMarkers()) {
      unlinkSync(join(this.dir as string, name));
    }
  }

  private listMarkers(): string[] {
    return readdirSync(this.dir as string).filter((name) => NULLIFIER_FILENAME.test(name));
  }
}
