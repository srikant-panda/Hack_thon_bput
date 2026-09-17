/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_ANON_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare module 'node:test' {
  export function describe(name: string, fn: () => void | Promise<void>): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
  export function test(name: string, fn: () => void | Promise<void>): void;
  export function beforeEach(fn: () => void | Promise<void>): void;
  export function afterEach(fn: () => void | Promise<void>): void;
}

declare module 'node:assert' {
  interface Assert {
    (value: unknown, message?: string | Error): void;
    ok(value: unknown, message?: string | Error): void;
    strictEqual<T>(actual: unknown, expected: T, message?: string | Error): void;
    deepStrictEqual<T>(actual: unknown, expected: T, message?: string | Error): void;
  }
  const assert: Assert;
  export default assert;
}
