/* tslint:disable */
/* eslint-disable */

/**
 * Verify a STARK proof from a structured input.
 *
 * Accepts a JS object matching `{ version: number, bytes: Uint8Array }`.
 * Returns `{ ok: boolean, error?: string, version?: number }`.
 */
export function verify(input: any): any;

/**
 * Verify a STARK proof from a JSON string.
 *
 * The JSON must be a serialized proof in the SDK format (the same format
 * produced by `hc-cli prove --output proof.json`).
 *
 * Returns `{ ok: boolean, error?: string, version?: number }`.
 */
export function verify_json(json: string): any;

/**
 * Returns the library version string.
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly verify: (a: any) => any;
  readonly verify_json: (a: number, b: number) => any;
  readonly version: () => [number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
