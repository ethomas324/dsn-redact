# dsn-redact

Connection strings end up in the wrong places constantly: pasted into a bug
report, dropped into a Slack thread while debugging a flaky staging box,
copied into a log line "just for now." Most of them carry a plaintext
password right in the string, and that password gets copied along with
everything else because nobody wants to hand-edit the string before pasting
it.

`dsn-redact` takes connection strings in and prints them back out with the
password (or anything that looks like one) replaced, keeping the host, port,
database name, and driver intact so the string is still useful for debugging.

## Usage

Pipe a string in on stdin:

```
$ echo "postgres://admin:hunter2@db.internal:5432/orders" | dsn-redact
postgres://admin:REDACTED@db.internal:5432/orders
```

Key/value style DSNs (ODBC, ADO.NET) work the same way:

```
$ echo "Server=myserver;Database=mydb;User Id=admin;Password=hunter2;" | dsn-redact
Server=myserver;Database=mydb;User Id=admin;Password=REDACTED;
```

Or point it at one or more files, one connection string per line:

```
$ dsn-redact strings.txt other-strings.txt
```

Mix files and stdin by passing `-` alongside file arguments. With no
arguments at all, it reads stdin. Blank lines and lines starting with `#` are
skipped, so you can keep a running file of strings with comments in it.

Pass `--json` to get one JSON object per line instead of the plain redacted
string. Each object carries the original input, the redacted string, the
detected format, and a `components` breakdown with the password itself left
out entirely, so it's safe to pipe into another tool without re-deriving the
redaction:

```
$ echo "postgres://admin:hunter2@db.internal:5432/orders?sslmode=require" | dsn-redact --json
{"input":"postgres://admin:hunter2@db.internal:5432/orders?sslmode=require","redacted":"postgres://admin:REDACTED@db.internal:5432/orders?sslmode=require","format":"url","components":{"scheme":"postgres","username":"admin","host":"db.internal","port":"5432","database":"orders","params":{"sslmode":"require"}}}
```

Strings that don't match either recognized shape come back with
`"format":"unknown"` and no `components` key, since there's nothing to
parse them into.

## What it recognizes

- URL-style DSNs with a `scheme://` prefix: `postgres://`, `mysql://`,
  `mongodb://`, `redis://`, `amqp://`, and anything else shaped like a URL.
  The userinfo password component is redacted, and so is any query-string
  parameter with a sensitive-looking key (`?password=...`, `?token=...`,
  and so on -- same key list as below).
- Key/value DSNs separated by `;`, the ODBC/ADO.NET convention
  (`Key=Value;Key=Value;...`). Any key matching `password`, `pwd`, `pass`,
  `secret`, `token`, `access-token`, `refresh-token`, `auth-token`,
  `id-token`, `api-key`, `access-key`, `secret-key`, `private-key`,
  `client-secret`, or `credential` (case-insensitive, `-`/`_` interchangeable)
  is redacted.
- Anything that doesn't match either shape is printed back unchanged, rather
  than guessed at.

## Building

No dependencies are installed by default. `npm install` pulls in TypeScript
as a dev dependency, then:

```
npm run build
node dist/index.js < strings.txt
```

Run the tests with `npm test` (compiles with `tsc`, then runs the compiled
specs with Node's built-in test runner -- no test framework dependency).

## Status

Redacts and, with `--json`, parses into component fields. It doesn't yet
validate that required fields are present per driver. See the issues for
what's next.
