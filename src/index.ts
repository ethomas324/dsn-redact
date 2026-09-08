#!/usr/bin/env node
import { readFileSync } from "fs";
import { redactConnectionString, checkRequiredFields } from "./parser";

function readStdin(): string {
  // Synchronous stdin read via fd 0. No streams/readline needed for a tool
  // that just wants everything piped in before it starts working.
  return readFileSync(0, "utf-8");
}

function main(): void {
  const rawArgs = process.argv.slice(2);
  const jsonOutput = rawArgs.includes("--json");
  const checkFields = rawArgs.includes("--check");
  const args = rawArgs.filter((arg) => arg !== "--json" && arg !== "--check");
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

  let hasCheckFailure = false;
  lines.forEach((line, index) => {
    const result = redactConnectionString(line);
    if (checkFields) {
      const check = checkRequiredFields(result);
      if (!check.ok) {
        hasCheckFailure = true;
        process.stderr.write(
          `dsn-redact: line ${index + 1} (${check.driver}): missing required field(s): ${check.missing.join(", ")}\n`,
        );
      }
      process.stdout.write((jsonOutput ? JSON.stringify({ ...result, check }) : result.redacted) + "\n");
    } else {
      process.stdout.write((jsonOutput ? JSON.stringify(result) : result.redacted) + "\n");
    }
  });

  if (checkFields && hasCheckFailure) {
    process.exitCode = 1;
  }
}

main();
