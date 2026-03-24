/**
 * Intentionally vulnerable MCP server — command injection.
 * Used for testing oxvault scanner detection capabilities.
 * DO NOT use in production.
 */

const { exec } = require("child_process");

function runDiagnostic(hostname) {
  // Vulnerable: user input concatenated into shell command
  exec("ping -c 1 " + hostname, (err, stdout) => {
    return stdout;
  });
}

function readConfig(path) {
  // Vulnerable: no path validation
  const fs = require("fs");
  return fs.readFileSync(path + "/config.json", "utf8");
}

const DB_PASSWORD = "super_secret_password_123";
const GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
