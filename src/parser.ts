// Two connection string shapes are common enough to be worth handling on day one:
//
//   1. URL style: postgres://user:pass@host:5432/dbname?sslmode=require
//   2. Key/value style (ODBC, ADO.NET): Server=.;Database=x;User Id=y;Password=z;
//
// Anything else is passed through unchanged rather than guessed at.

export type ConnectionStringFormat = "url" | "keyvalue" | "unknown";

export interface RedactionResult {
  input: string;
  redacted: string;
  format: ConnectionStringFormat;
}

const SENSITIVE_KEY_PATTERN = /^(password|pwd|pass|secret|token|api[-_]?key|access[-_]?key)$/i;

function redactUrlStyle(line: string): RedactionResult | null {
  // Cheap pre-check before paying for a throwing URL parse.
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(line)) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  if (url.password) {
    url.password = "REDACTED";
  }
  return { input: line, redacted: url.toString(), format: "url" };
}

function redactKeyValueStyle(line: string): RedactionResult | null {
  if (!line.includes("=") || !line.includes(";")) {
    return null;
  }
  const parts = line
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  if (parts.length < 2) {
    return null;
  }

  const redactedParts: string[] = [];
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      redactedParts.push(part);
      continue;
    }
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    redactedParts.push(SENSITIVE_KEY_PATTERN.test(key) ? `${key}=REDACTED` : `${key}=${value}`);
  }
  return { input: line, redacted: redactedParts.join(";"), format: "keyvalue" };
}

export function redactConnectionString(line: string): RedactionResult {
  return (
    redactUrlStyle(line) ??
    redactKeyValueStyle(line) ?? { input: line, redacted: line, format: "unknown" }
  );
}
