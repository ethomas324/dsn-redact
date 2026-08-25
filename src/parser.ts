// Two connection string shapes are common enough to be worth handling on day one:
//
//   1. URL style: postgres://user:pass@host:5432/dbname?sslmode=require
//   2. Key/value style (ODBC, ADO.NET): Server=.;Database=x;User Id=y;Password=z;
//
// Anything else is passed through unchanged rather than guessed at.

export type ConnectionStringFormat = "url" | "keyvalue" | "unknown";

// Never includes the password/secret itself, only the shape around it --
// these are meant to be safe to dump as JSON right alongside the redacted
// string.
export interface UrlComponents {
  scheme: string;
  username: string;
  host: string;
  port: string;
  database: string;
  params: Record<string, string>;
}

export interface KeyValueComponents {
  pairs: Record<string, string>;
}

export interface RedactionResult {
  input: string;
  redacted: string;
  format: ConnectionStringFormat;
  components?: UrlComponents | KeyValueComponents;
}

// Covers both key/value DSN fields and URL query-string parameters. Kept
// narrow on purpose -- e.g. "sslkey" (a file path, not a secret value)
// should not match just because it ends in "key".
const SENSITIVE_KEY_PATTERN =
  /^(password|pwd|pass|secret|token|access[-_]?token|refresh[-_]?token|auth[-_]?token|id[-_]?token|api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|client[-_]?secret|credential)$/i;

function parseQueryString(search: string): Record<string, string> {
  const params: Record<string, string> = {};
  const trimmed = search.startsWith("?") ? search.slice(1) : search;
  if (trimmed.length === 0) {
    return params;
  }
  for (const pair of trimmed.split("&")) {
    if (pair.length === 0) {
      continue;
    }
    const eq = pair.indexOf("=");
    const rawKey = eq === -1 ? pair : pair.slice(0, eq);
    const rawValue = eq === -1 ? "" : pair.slice(eq + 1);
    const key = decodeURIComponent(rawKey.replace(/\+/g, " "));
    const value = decodeURIComponent(rawValue.replace(/\+/g, " "));
    params[key] = value;
  }
  return params;
}

function redactParams(params: Record<string, string>): Record<string, string> {
  const redacted: Record<string, string> = {};
  for (const key of Object.keys(params)) {
    redacted[key] = SENSITIVE_KEY_PATTERN.test(key) ? "REDACTED" : params[key];
  }
  return redacted;
}

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
  const username = url.username;
  if (url.password) {
    url.password = "REDACTED";
  }
  const params = redactParams(parseQueryString(url.search));
  if (Object.keys(params).length > 0) {
    // Query strings often carry credentials too (?password=..., ?token=...),
    // so the redacted params need to make it back into the URL itself, not
    // just the components breakdown.
    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      search.set(key, value);
    }
    url.search = search.toString();
  }
  const components: UrlComponents = {
    scheme: url.protocol.replace(/:$/, ""),
    username,
    host: url.hostname,
    port: url.port,
    database: url.pathname.replace(/^\//, ""),
    params,
  };
  return { input: line, redacted: url.toString(), format: "url", components };
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
  const pairs: Record<string, string> = {};
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      redactedParts.push(part);
      continue;
    }
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    const redactedValue = SENSITIVE_KEY_PATTERN.test(key) ? "REDACTED" : value;
    redactedParts.push(`${key}=${redactedValue}`);
    pairs[key] = redactedValue;
  }
  return {
    input: line,
    redacted: redactedParts.join(";"),
    format: "keyvalue",
    components: { pairs },
  };
}

export function redactConnectionString(line: string): RedactionResult {
  return (
    redactUrlStyle(line) ??
    redactKeyValueStyle(line) ?? { input: line, redacted: line, format: "unknown" }
  );
}
