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
// ever written to disk.

import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { sha256Hex } from "./canonical.js";

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

/**
 * Durable, cross-process nullifier store. One file per consumed preimage,
 * named by its SHA-256 hex digest, under `dir`. Consuming is a single
 * `open(path, 'wx')` call: it either creates the file (first consumption)
 * or fails with EEXIST (replay), with no separate check-then-act window
 * for concurrent processes to race through.
 *
 * If `dir` cannot be created or is not writable, construction does not
 * throw (so an unrelated server with 150+ other tools does not fail to
 * start over one misconfigured directory); instead every operation on this
 * store throws, so the one redemption path that depends on it fails closed
 * with a clear error.
 */
export class FileNullifierStore implements NullifierStore {
  private readonly dir: string;
  private readonly initError: Error | null;

  constructor(dir: string) {
    this.dir = dir;
    this.initError = FileNullifierStore.tryInit(dir);
  }

  private static tryInit(dir: string): Error | null {
    try {
      mkdirSync(dir, { recursive: true });
      // mkdirSync is a silent no-op if dir already exists, even if it is no
      // longer writable (e.g. permissions changed since it was created), so
      // probe writability explicitly rather than trusting mkdirSync alone.
      const probe = join(dir, `.write-probe-${process.pid}-${Date.now()}`);
      closeSync(openSync(probe, "w"));
      unlinkSync(probe);
      return null;
    } catch (e) {
      return new Error(
        `nullifier store: directory "${dir}" is not usable (${(e as Error).message}). ` +
          `Set APS_NULLIFIER_DIR to a writable directory. Redemption fails closed rather than falling back to an in-memory store.`,
      );
    }
  }

  private ensureReady(): void {
    if (this.initError) throw this.initError;
  }

  private pathFor(preimage: string): string {
    return join(this.dir, sha256Hex(preimage));
  }

  private fsyncDir(): void {
    try {
      const dfd = openSync(this.dir, "r");
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
      fd = openSync(path, "wx");
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
      unlinkSync(join(this.dir, name));
    }
  }

  private listMarkers(): string[] {
    return readdirSync(this.dir).filter((name) => NULLIFIER_FILENAME.test(name));
  }
}
