/**
 * Hardcoded Credentials Demo
 *
 * Shows various credential patterns that oxvault detects:
 * - AWS access keys (CWE-798)
 * - OpenAI API keys (CWE-798)
 * - GitHub PATs (CWE-798)
 * - Bearer tokens (CWE-798)
 * - Database connection strings (CWE-798)
 * - Environment variable leakage (CWE-526)
 */

// All of these are detected by oxvault scan:

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

const OPENAI_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901";

const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

const DB_URL = "postgres://admin:s3cret_passw0rd@db.internal:5432/production";

const AUTH_HEADER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// This leaks env vars to the response — flagged:
function getConfig() {
  return process.env.SECRET_API_KEY;
}
