#!/usr/bin/env python3
"""Apply security fixes to MCP server src/index.ts"""
import re

with open('src/index.ts', 'r') as f:
    content = f.read()

# --- Fix 1: Add safeError helper after isPathWithin ---
old = """function isPathWithin(filePath: string, allowedDir: string): boolean {
  return resolve(filePath).startsWith(resolve(allowedDir) + '/');
}"""
new = """function isPathWithin(filePath: string, allowedDir: string): boolean {
  return resolve(filePath).startsWith(resolve(allowedDir) + '/');
}

// Sanitize error messages before returning to clients
function safeError(prefix: string, e: unknown): string {
  if (e instanceof Error) {
    const msg = e.message.replace(/\\/[^\\s:]+/g, '[path]').replace(/at\\s+.+/g, '').slice(0, 200);
    return `${prefix}: ${msg}`.trim();
  }
  return `${prefix}: operation failed`;
}"""
assert old in content, "Fix 1: isPathWithin not found"
content = content.replace(old, new, 1)
print("Fix 1: Added safeError helper")

# --- Fix 2: Sanitize getAgentName ---
old = """function getAgentName(): string {
  // Derive agent name from agentId (e.g., "claude-001" → "claude")
  if (state.agentId) return state.agentId.replace(/-\\d+$/, '');
  if (state.agentKey) return state.agentKey.slice(0, 8);
  return 'unknown';
}"""
new = """function getAgentName(): string {
  // Derive agent name from agentId — always sanitize to prevent path traversal
  let name = 'unknown';
  if (state.agentId) name = state.agentId.replace(/-\\d+$/, '');
  else if (state.agentKey) name = state.agentKey.slice(0, 8);
  return sanitizeAgentName(name) || 'unknown';
}"""
assert old in content, "Fix 2: getAgentName not found"
content = content.replace(old, new, 1)
print("Fix 2: Sanitized getAgentName")

# --- Fix 3: Add path check to check_messages ---
old = """  async (args) => {
    const name = getAgentName();
    const filePath = join(COMMS_PATH, `to-${name}.json`);
    let messages = readCommsFile(filePath);"""
new = """  async (args) => {
    const name = getAgentName();
    const filePath = join(COMMS_PATH, `to-${name}.json`);
    if (!isPathWithin(filePath, COMMS_PATH)) {
      return { content: [{ type: "text" as const, text: "Invalid agent name — path rejected" }] };
    }
    let messages = readCommsFile(filePath);"""
assert old in content, "Fix 3: check_messages handler not found"
content = content.replace(old, new, 1)
print("Fix 3: Added path validation to check_messages")

# --- Fix 4: Strip error object from console.error ---
old = """console.error('Failed to load task store:', e);"""
new = """console.error('Failed to load task store');"""
assert old in content, "Fix 4: console.error not found"
content = content.replace(old, new, 1)
print("Fix 4: Stripped error object from console.error")

# --- Fix 5: Add delegation scope validation ---
old = """    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const delegation = createDelegation({
      delegatedBy: state.agentKey!,
      delegatedTo: args.delegated_to,
      scope: args.scope,"""
new = """    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    // Validate delegation scopes
    if (!args.scope || args.scope.length === 0) {
      return { content: [{ type: "text" as const, text: "Delegation must include at least one scope." }], isError: true };
    }
    const SCOPE_PATTERN = /^[a-zA-Z0-9_.:/-]+$/;
    for (const s of args.scope) {
      if (s === '*' || s === '**') {
        return { content: [{ type: "text" as const, text: `Wildcard scope "${s}" not allowed. Use explicit scopes.` }], isError: true };
      }
      if (s.length > 128) {
        return { content: [{ type: "text" as const, text: `Scope exceeds max length (128 chars).` }], isError: true };
      }
      if (!SCOPE_PATTERN.test(s)) {
        return { content: [{ type: "text" as const, text: `Scope "${s}" contains invalid characters.` }], isError: true };
      }
    }

    const delegation = createDelegation({
      delegatedBy: state.agentKey!,
      delegatedTo: args.delegated_to,
      scope: args.scope,"""
# This pattern may appear in create_delegation tool — find the right one
idx = content.find('create_delegation,')
if idx == -1:
    idx = content.find('"create_delegation"')
# Find the old pattern after the tool registration
search_start = content.find(old, idx)
assert search_start != -1, "Fix 5: create_delegation scope block not found"
content = content[:search_start] + new + content[search_start + len(old):]
print("Fix 5: Added delegation scope validation")

# --- Fix 6: Replace e.message with safeError in error returns ---
# These are specific patterns in catch blocks
replacements = {
    'text: `Error: ${e.message}`': ('text: safeError("Error", e)', 0),
    'text: `Sub-delegation failed: ${e.message}`': ('text: safeError("Sub-delegation failed", e)', 0),
    'text: `❌ Failed to create issue: ${e.message}`': ('text: safeError("Failed to create issue", e)', 0),
    'text: `Failed to load floor: ${e.message}`': ('text: safeError("Failed to load floor", e)', 0),
    'text: `Policy evaluation failed: ${e.message}`': ('text: safeError("Policy evaluation failed", e)', 0),
    'text: `Failed to create context: ${e.message}`': ('text: safeError("Failed to create context", e)', 0),
    'text: `Execute failed: ${e.message}`': ('text: safeError("Execute failed", e)', 0),
    'text: `Complete failed: ${e.message}`': ('text: safeError("Complete failed", e)', 0),
    'text: `API error: ${e.message}`': ('text: safeError("API error", e)', 0),
    'text: `Intro request failed: ${e.message}`': ('text: safeError("Intro request failed", e)', 0),
    'text: `Intro response failed: ${e.message}`': ('text: safeError("Intro response failed", e)', 0),
}

total = 0
for old_str, (new_str, _) in replacements.items():
    count = content.count(old_str)
    if count > 0:
        content = content.replace(old_str, new_str)
        total += count
        print(f"  Replaced {count}x: {old_str[:50]}...")

print(f"Fix 6: Replaced {total} error message leaks with safeError")

# --- Fix 7: Add logging to silent catch blocks ---
# Replace bare `catch {` or `catch (e) {` that do nothing
# Only fix the ones that are completely empty
empty_catches = content.count('} catch { return []; }')
content = content.replace('} catch { return []; }', '} catch { /* file read failed */ return []; }')
empty_catches2 = content.count("} catch {\n")
# Don't replace these automatically — too risky. Just count them.
print(f"Fix 7: Annotated {empty_catches} empty catch blocks, {empty_catches2} remaining (manual review needed)")

with open('src/index.ts', 'w') as f:
    f.write(content)

print("\nAll fixes applied successfully!")
