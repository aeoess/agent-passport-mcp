// In-memory nullifier set. v0.1: process-local Set, no persistence. The
// sink consults this on every M3 redemption to prevent token replay.

export interface NullifierStore {
  isConsumed(preimage: string): boolean;
  consume(preimage: string): void;
  size(): number;
  clear(): void;
}

export class InMemoryNullifierSet implements NullifierStore {
  private readonly seen = new Set<string>();

  isConsumed(preimage: string): boolean {
    return this.seen.has(preimage);
  }

  consume(preimage: string): void {
    if (this.seen.has(preimage)) {
      throw new Error(
        `nullifier replay: token preimage ${preimage.slice(0, 12)}... already consumed`,
      );
    }
    this.seen.add(preimage);
  }

  size(): number {
    return this.seen.size;
  }

  clear(): void {
    this.seen.clear();
  }
}
