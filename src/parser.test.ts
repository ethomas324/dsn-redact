import { test } from "node:test";
import assert from "node:assert/strict";
import { redactConnectionString, checkRequiredFields } from "./parser";

// URL style

test("redacts a postgres password and leaves the rest intact", () => {
  const result = redactConnectionString("postgres://admin:hunter2@db.internal:5432/orders");
  assert.equal(result.format, "url");
  assert.equal(result.redacted, "postgres://admin:REDACTED@db.internal:5432/orders");
  assert.equal(result.input, "postgres://admin:hunter2@db.internal:5432/orders");
});

test("url with no password is left untouched", () => {
  const result = redactConnectionString("postgres://admin@db.internal:5432/orders");
  assert.equal(result.redacted, "postgres://admin@db.internal:5432/orders");
});

test("redacts sensitive query-string params and keeps others as-is", () => {
  const result = redactConnectionString(
    "mysql://root:hunter2@localhost:3306/app?sslmode=require&token=abc123",
  );
  assert.equal(
    result.redacted,
    "mysql://root:REDACTED@localhost:3306/app?sslmode=require&token=REDACTED",
  );
});

test("url components never carry the password", () => {
  const result = redactConnectionString("redis://user:hunter2@cache.internal:6379/0");
  assert.equal(result.format, "url");
  const components = result.components as import("./parser").UrlComponents;
  assert.equal(components.scheme, "redis");
  assert.equal(components.username, "user");
  assert.equal(components.host, "cache.internal");
  assert.equal(components.port, "6379");
  assert.equal(components.database, "0");
  assert.equal(JSON.stringify(result).includes("hunter2"), false);
});

test("url query params keep non-sensitive keys and values verbatim", () => {
  const result = redactConnectionString("postgres://admin:hunter2@db.internal/orders?sslmode=require");
  const components = result.components as import("./parser").UrlComponents;
  assert.deepEqual(components.params, { sslmode: "require" });
});

// Key/value style

test("redacts Password in a key/value DSN", () => {
  const result = redactConnectionString("Server=myserver;Database=mydb;User Id=admin;Password=hunter2;");
  assert.equal(result.format, "keyvalue");
  assert.equal(result.redacted, "Server=myserver;Database=mydb;User Id=admin;Password=REDACTED;");
});

test("key/value pairs component never carries the secret value", () => {
  const result = redactConnectionString("Server=myserver;Uid=admin;Pwd=hunter2");
  const components = result.components as import("./parser").KeyValueComponents;
  assert.equal(components.pairs.Pwd, "REDACTED");
  assert.equal(components.pairs.Server, "myserver");
});

test("key/value matching is case-insensitive and ignores separators", () => {
  const result = redactConnectionString("Host=db;API-KEY=hunter2;client_secret=hunter3");
  assert.equal(result.redacted, "Host=db;API-KEY=REDACTED;client_secret=REDACTED");
});

test("sslkey is not treated as sensitive just because it ends in key", () => {
  const result = redactConnectionString("Server=db;sslkey=/etc/ssl/client.key");
  assert.equal(result.redacted, "Server=db;sslkey=/etc/ssl/client.key");
});

test("a single key=value pair with no semicolon separator is not treated as keyvalue", () => {
  const result = redactConnectionString("password=hunter2");
  assert.equal(result.format, "unknown");
});

// Fallback

test("strings that match neither shape pass through unchanged", () => {
  const result = redactConnectionString("just a plain note, not a connection string");
  assert.equal(result.format, "unknown");
  assert.equal(result.redacted, "just a plain note, not a connection string");
  assert.equal(result.components, undefined);
});

// --check

test("check passes a postgres url with host and database present", () => {
  const result = redactConnectionString("postgres://admin:hunter2@db.internal:5432/orders");
  const check = checkRequiredFields(result);
  assert.equal(check.driver, "postgres");
  assert.equal(check.known, true);
  assert.deepEqual(check.missing, []);
  assert.equal(check.ok, true);
});

test("check flags a postgres url missing a database", () => {
  const result = redactConnectionString("postgres://admin:hunter2@db.internal:5432/");
  const check = checkRequiredFields(result);
  assert.equal(check.ok, false);
  assert.deepEqual(check.missing, ["database"]);
});

test("check flags a mysql url missing a host", () => {
  const result = redactConnectionString("mysql://admin:hunter2@/orders");
  const check = checkRequiredFields(result);
  assert.equal(check.ok, false);
  assert.ok(check.missing.includes("host"));
});

test("check is a no-op for schemes with no known requirements", () => {
  const result = redactConnectionString("customdriver://admin:hunter2@host/thing");
  const check = checkRequiredFields(result);
  assert.equal(check.known, false);
  assert.equal(check.ok, true);
  assert.deepEqual(check.missing, []);
});

test("check passes a keyvalue dsn with server and database aliases", () => {
  const result = redactConnectionString("Server=myserver;Database=mydb;User Id=admin;Password=hunter2;");
  const check = checkRequiredFields(result);
  assert.equal(check.known, true);
  assert.equal(check.ok, true);
});

test("check flags a keyvalue dsn missing database, using Driver as the label", () => {
  const result = redactConnectionString("Driver={PostgreSQL};Server=myserver;Uid=admin;Pwd=hunter2");
  const check = checkRequiredFields(result);
  assert.equal(check.driver, "PostgreSQL");
  assert.equal(check.ok, false);
  assert.deepEqual(check.missing, ["database"]);
});

test("check recognizes Data Source and Initial Catalog as host/database aliases", () => {
  const result = redactConnectionString("Data Source=myserver;Initial Catalog=mydb;User Id=admin;Password=hunter2;");
  const check = checkRequiredFields(result);
  assert.equal(check.ok, true);
});
