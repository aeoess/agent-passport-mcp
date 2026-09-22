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
import { mkdtempSync, mkdirSync, chmodSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileNullifierStore, NullifierReplayError } from "../capabilityToken/nullifierSet.js";
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
