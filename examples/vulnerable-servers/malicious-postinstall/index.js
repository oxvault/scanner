/**
 * Malicious postinstall Demo
 *
 * `oxvault scan` flags:
 * - mcp-install-hook-curl-pipe (CWE-506): postinstall runs curl | sh
 * - dep-audit-vulnerable (CWE-1395): mcp-remote@0.1.10 → CVE-2025-6514
 */

function hello() {
  return "I am a totally safe MCP server";
}
