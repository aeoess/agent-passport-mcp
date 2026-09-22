// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// FileNullifierStore is the durable, cross-process replacement for the
// in-memory nullifier set on the capability-token redemption path
// (aps_capability_sign_effect in src/index.ts). These tests exercise the
// properties an in-memory Set cannot provide: survival across process
// restarts, and a single winner when multiple processes race to redeem
// the same token.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  chmodSync,
  closeSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  FileNullifierStore,
  HOSTED_NULLIFIER_SENTINEL,
  NullifierReplayError,
} from "../capabilityToken/nullifierSet.js";
import { sha256Hex } from "../capabilityToken/canonical.js";

// Absolute file:// URL to the compiled module, for child processes spawned
// via `node --input-type=module -e`, which have no relative-import context
// of their own.
const NULLIFIER_MODULE_URL = new URL("../capabilityToken/nullifierSet.js", import.meta.url).href;

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "aps-nullifier-"));
}

// Runs `store.consume(preimage)` against `dir` in a brand-new node process.
// Returns the exit code (0 = consumed, 1 = threw — replay or otherwise) and
// stderr (for asserting on the replay message).
function consumeInChildProcess(dir: string, preimage: string): { status: number | null; stderr: string } {
  const script = `
    const { FileNullifierStore } = await import(${JSON.stringify(NULLIFIER_MODULE_URL)});
    const store = new FileNullifierStore(${JSON.stringify(dir)});
    try {
      store.consume(${JSON.stringify(preimage)});
      process.exit(0);
    } catch (e) {
      process.stderr.write(String(e && e.message));
      process.exit(1);
    }
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf-8",
  });
  return { status: result.status, stderr: result.stderr };
}

test("consume() rejects a second attempt on the same preimage with NullifierReplayError", () => {
  const dir = freshDir();
  try {
    const store = new FileNullifierStore(dir);
    const preimage = "preimage-unit-test-001";
    assert.equal(store.isConsumed(preimage), false);
    store.consume(preimage);
    assert.equal(store.isConsumed(preimage), true);
    assert.throws(() => store.consume(preimage), NullifierReplayError);
    assert.equal(store.size(), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release() un-burns a token so a later consume() succeeds", () => {
  const dir = freshDir();
  try {
    const store = new FileNullifierStore(dir);
    const preimage = "preimage-unit-test-release";
    store.consume(preimage);
    store.release(preimage);
    assert.equal(store.isConsumed(preimage), false);
    store.consume(preimage); // does not throw
    assert.equal(store.size(), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("clear() removes every consumed marker in the directory", () => {
  const dir = freshDir();
  try {
    const store = new FileNullifierStore(dir);
    store.consume("a");
    store.consume("b");
    assert.equal(store.size(), 2);
    store.clear();
    assert.equal(store.size(), 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the preimage itself never appears on disk — only its SHA-256 hash as a filename", () => {
  const dir = freshDir();
  try {
    const store = new FileNullifierStore(dir);
    const preimage = "super-secret-token-preimage-do-not-persist";
    store.consume(preimage);

    const entries = readdirSync(dir);
    assert.equal(entries.length, 1);
    const [filename] = entries;

    // Filename is the hash, not the preimage, and matches sha256Hex exactly.
    assert.equal(filename, sha256Hex(preimage));
    assert.notEqual(filename, preimage);
    assert.doesNotMatch(filename, /secret|preimage/);

    // File contents (a timestamp) never contain the preimage either.
    const contents = readFileSync(join(dir, filename), "utf-8");
    assert.doesNotMatch(contents, /secret|preimage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an unwritable directory fails closed on redemption instead of falling back to memory", () => {
  const parent = freshDir();
  const dir = join(parent, "locked");
  try {
    // Directory exists but is read-only: mkdirSync(recursive) succeeds
    // (no-op), so the writability probe in the constructor is what must
    // catch this.
    mkdirSync(dir);
    chmodSync(dir, 0o500); // r-x------: cannot create files inside
    const store = new FileNullifierStore(dir);
    assert.throws(() => store.consume("whatever"), /not usable|not writable|EACCES|permission/i);
    assert.throws(() => store.isConsumed("whatever"), /not usable|not writable|EACCES|permission/i);
  } finally {
    chmodSync(dir, 0o700);
    rmSync(parent, { recursive: true, force: true });
  }
});

test("a freshly created directory and marker are owner-only (0700 / 0600)", () => {
  const parent = freshDir();
  const dir = join(parent, "nested", "nullifiers");
  try {
    const store = new FileNullifierStore(dir);
    assert.equal(statSync(dir).mode & 0o777, 0o700);

    store.consume("mode-check-preimage");
    const [filename] = readdirSync(dir);
    assert.equal(statSync(join(dir, filename)).mode & 0o777, 0o600);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("refuses an existing directory that is group- or world-writable", () => {
  const parent = freshDir();
  const dir = join(parent, "shared");
  try {
    mkdirSync(dir);
    chmodSync(dir, 0o777); // chmod bypasses umask, unlike mkdirSync's mode option
    const store = new FileNullifierStore(dir);
    assert.throws(() => store.consume("whatever"), /group- or world-writable/i);
    assert.throws(() => store.isConsumed("whatever"), /group- or world-writable/i);
  } finally {
    chmodSync(dir, 0o700);
    rmSync(parent, { recursive: true, force: true });
  }
});

test("hosted mode refuses a missing APS_NULLIFIER_DIR", () => {
  const store = new FileNullifierStore(undefined, { hosted: true });
  assert.throws(() => store.consume("whatever"), /APS_NULLIFIER_DIR must be set explicitly/i);
  assert.throws(() => store.isConsumed("whatever"), /APS_NULLIFIER_DIR must be set explicitly/i);
});

test("hosted mode refuses a directory that does not exist", () => {
  const parent = freshDir();
  const dir = join(parent, "never-provisioned");
  try {
    const store = new FileNullifierStore(dir, { hosted: true });
    assert.throws(() => store.consume("whatever"), /does not exist/i);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("hosted mode refuses an existing directory missing the provisioning sentinel", () => {
  const dir = freshDir();
  try {
    // Directory exists (as it would if only the volume were mounted) but
    // was never actually provisioned with the sentinel file.
    const store = new FileNullifierStore(dir, { hosted: true });
    assert.throws(() => store.consume("whatever"), new RegExp(HOSTED_NULLIFIER_SENTINEL));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hosted mode works with a pre-created directory plus sentinel, and never creates the directory itself", () => {
  const parent = freshDir();
  const dir = join(parent, "provisioned");
  try {
    mkdirSync(dir, { mode: 0o700 });
    closeSync(openSync(join(dir, HOSTED_NULLIFIER_SENTINEL), "w", 0o600));

    const store = new FileNullifierStore(dir, { hosted: true });
    const preimage = "hosted-preimage-001";
    assert.equal(store.isConsumed(preimage), false);
    store.consume(preimage);
    assert.equal(store.isConsumed(preimage), true);
    assert.throws(() => store.consume(preimage), NullifierReplayError);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("hosted mode refuses a directory that is actually a symlink", () => {
  const parent = freshDir();
  const realDir = join(parent, "real");
  const linkDir = join(parent, "link");
  try {
    mkdirSync(realDir, { mode: 0o700 });
    closeSync(openSync(join(realDir, HOSTED_NULLIFIER_SENTINEL), "w", 0o600));
    symlinkSync(realDir, linkDir);

    const store = new FileNullifierStore(linkDir, { hosted: true });
    assert.throws(() => store.consume("whatever"), /symbolic link/i);
    assert.throws(() => store.isConsumed("whatever"), /symbolic link/i);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("hosted mode refuses a sentinel that is a directory", () => {
  const dir = freshDir();
  try {
    mkdirSync(join(dir, HOSTED_NULLIFIER_SENTINEL));
    const store = new FileNullifierStore(dir, { hosted: true });
    assert.throws(() => store.consume("whatever"), /not a regular file|is a directory/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hosted mode refuses a sentinel that is a symlink", () => {
  const parent = freshDir();
  const dir = join(parent, "provisioned");
  try {
    mkdirSync(dir, { mode: 0o700 });
    const realSentinel = join(parent, "real-sentinel");
    closeSync(openSync(realSentinel, "w", 0o600));
    symlinkSync(realSentinel, join(dir, HOSTED_NULLIFIER_SENTINEL));

    const store = new FileNullifierStore(dir, { hosted: true });
    assert.throws(() => store.consume("whatever"), /not a regular file|symbolic link/i);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("hosted mode: replay across two independently spawned processes is rejected", () => {
  const dir = freshDir();
  try {
    closeSync(openSync(join(dir, HOSTED_NULLIFIER_SENTINEL), "w", 0o600));
    const preimage = "hosted-cross-process-preimage-001";

    const script = (p: string) => `
      const { FileNullifierStore } = await import(${JSON.stringify(NULLIFIER_MODULE_URL)});
      const store = new FileNullifierStore(${JSON.stringify(dir)}, { hosted: true });
      try {
        store.consume(${JSON.stringify(p)});
        process.exit(0);
      } catch (e) {
        process.stderr.write(String(e && e.message));
        process.exit(1);
      }
    `;

    const first = spawnSync(process.execPath, ["--input-type=module", "-e", script(preimage)], {
      encoding: "utf-8",
    });
    assert.equal(first.status, 0, `first redemption should succeed: ${first.stderr}`);

    const second = spawnSync(process.execPath, ["--input-type=module", "-e", script(preimage)], {
      encoding: "utf-8",
    });
    assert.equal(second.status, 1, "second redemption over the same directory must be rejected");
    assert.match(second.stderr, /nullifier replay/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("replay across two independently spawned processes is rejected", () => {
  const dir = freshDir();
  try {
    const preimage = "cross-process-preimage-001";
    const first = consumeInChildProcess(dir, preimage);
    assert.equal(first.status, 0, `first redemption should succeed: ${first.stderr}`);

    const second = consumeInChildProcess(dir, preimage);
    assert.equal(second.status, 1, "second redemption over the same directory must be rejected");
    assert.match(second.stderr, /nullifier replay/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("replay is rejected after the first process has fully exited (restart)", () => {
  const dir = freshDir();
  try {
    const preimage = "restart-preimage-001";

    // spawnSync blocks until the child has fully terminated — there is no
    // process holding this preimage in memory by the time this line
    // returns, which is exactly the "server restarted" scenario.
    const first = consumeInChildProcess(dir, preimage);
    assert.equal(first.status, 0, `pre-restart redemption should succeed: ${first.stderr}`);

    const second = consumeInChildProcess(dir, preimage);
    assert.equal(second.status, 1, "redemption after restart must still be rejected as replay");
    assert.match(second.stderr, /nullifier replay/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("concurrent redemption from several processes: exactly one succeeds", async () => {
  const dir = freshDir();
  try {
    const preimage = "concurrent-preimage-001";
    const N = 8;
    const script = `
      const { FileNullifierStore } = await import(${JSON.stringify(NULLIFIER_MODULE_URL)});
      const store = new FileNullifierStore(${JSON.stringify(dir)});
      try {
        store.consume(${JSON.stringify(preimage)});
        process.exit(0);
      } catch (e) {
        process.exit(1);
      }
    `;

    const runs = Array.from({ length: N }, () => new Promise<number | null>((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script]);
      child.on("close", (code) => resolve(code));
    }));

    const codes = await Promise.all(runs);
    const successes = codes.filter((c) => c === 0).length;
    const rejections = codes.filter((c) => c === 1).length;

    assert.equal(successes, 1, `expected exactly one winner, got exit codes: ${codes}`);
    assert.equal(rejections, N - 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
