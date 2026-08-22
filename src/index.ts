#!/usr/bin/env node
import { readFileSync } from "fs";
import { redactConnectionString } from "./parser";

function readStdin(): string {
  // Synchronous stdin read via fd 0. No streams/readline needed for a tool
  // that just wants everything piped in before it starts working.
  return readFileSync(0, "utf-8");
}

function main(): void {
  const args = process.argv.slice(2);
  const fileArgs = args.filter((arg) => arg !== "-");
  const readStdinToo = args.length === 0 || args.includes("-");

  const chunks: string[] = [];
  if (readStdinToo) {
    chunks.push(readStdin());
  }
  for (const file of fileArgs) {
    chunks.push(readFileSync(file, "utf-8"));
  }

  const lines = chunks
    .join("\n")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));

  if (lines.length === 0) {
    process.stderr.write("dsn-redact: no connection strings given (pass files, or pipe to stdin)\n");
    process.exit(1);
  }

  for (const line of lines) {
    process.stdout.write(redactConnectionString(line).redacted + "\n");
  }
}

main();
