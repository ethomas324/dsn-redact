// Hand-rolled ambient declarations for the small slice of Node's runtime this
// tool touches. Avoids pulling in @types/node just to type process.argv and
// readFileSync -- keeps the dependency tree at zero.

declare module "fs" {
  export function readFileSync(path: string | number, encoding: string): string;
}

declare const process: {
  argv: string[];
  exit(code?: number): never;
  stdout: { write(chunk: string): void };
  stderr: { write(chunk: string): void };
};

// Node exposes the WHATWG URL parser as a global, same shape as in browsers.
// Only declaring the members this project actually reads or writes.
declare class URL {
  constructor(input: string, base?: string);
  protocol: string;
  username: string;
  password: string;
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  toString(): string;
}
