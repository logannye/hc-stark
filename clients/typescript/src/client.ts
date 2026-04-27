/**
 * TypeScript HTTP client for the TinyZKP proving API.
 *
 * Works in Node 18+, Bun, Deno, and modern browsers (anywhere `fetch` exists).
 *
 * @example
 * ```typescript
 * import { TinyZKP } from "tinyzkp";
 *
 * const client = new TinyZKP("https://api.tinyzkp.com", { apiKey: "tzk_..." });
 *
 * const jobId = await client.proveTemplate("range_proof", {
 *   min: 0, max: 100, witness_steps: [42, 44],
 * });
 *
 * const proof = await client.waitForProof(jobId);
 * const result = await client.verify(proof);
 * console.log(result.ok); // true
 * ```
 */

// ---- Types ----

/**
 * Serialized proof payload returned by the prover.
 *
 * Implemented as a class (not just an interface) so it is available at
 * runtime — `import { ProofBytes } from "tinyzkp"` gives you a real value
 * you can `new` or pass around. Object literals matching `{ version, bytes }`
 * are still accepted everywhere a `ProofBytes` is expected, via TypeScript
 * structural typing.
 */
export class ProofBytes {
  constructor(
    public readonly version: number,
    public readonly bytes: number[],
  ) {}

  /** Build a ProofBytes from a plain object (e.g., parsed JSON). */
  static from(obj: { version: number; bytes: number[] }): ProofBytes {
    return new ProofBytes(obj.version, obj.bytes);
  }

  /** Serialize back to a plain object for transport. */
  toJSON(): { version: number; bytes: number[] } {
    return { version: this.version, bytes: this.bytes };
  }
}

export interface VerifyResult {
  ok: boolean;
  error?: string;
}

export interface ProveRequest {
  program?: string[];
  workloadId?: string;
  initialAcc: number;
  finalAcc: number;
  blockSize?: number;
  friFinalPolySize?: number;
  queryCount?: number;
  ldeBlowupFactor?: number;
  zkMaskDegree?: number;
}

export interface TemplateProveOptions {
  zk?: boolean;
  blockSize?: number;
  friFinalPolySize?: number;
}

export interface TemplateSummary {
  id: string;
  summary: string;
  tags: string[];
  cost_category: string;
  backend: string;
}

export interface TemplateListResponse {
  count: number;
  templates: TemplateSummary[];
}

interface ProveSubmitResponse {
  job_id: string;
}

export type ProveJobStatus =
  | { status: "pending" }
  | { status: "running" }
  | { status: "succeeded"; proof: ProofBytes }
  | { status: "failed"; error: string };

export interface HcClientOptions {
  /** API key for Bearer authentication. */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 30000). */
  timeoutMs?: number;
}

// ---- Error ----

export class HcClientError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(`HTTP ${statusCode}: ${message}`);
    this.name = "HcClientError";
  }
}

// ---- Client ----

export class HcClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, options?: HcClientOptions) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = options?.apiKey;
    this.timeoutMs = options?.timeoutMs ?? 30_000;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) {
      h["Authorization"] = `Bearer ${this.apiKey}`;
    }
    return h;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const init: RequestInit = {
        method,
        headers: this.headers(),
        signal: controller.signal,
      };
      if (body !== undefined) {
        init.body = JSON.stringify(body);
      }

      const resp = await fetch(url, init);
      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        throw new HcClientError(resp.status, text);
      }
      const contentType = resp.headers.get("content-type") ?? "";
      if (contentType.includes("application/json")) {
        return (await resp.json()) as T;
      }
      return undefined as unknown as T;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Check server health. */
  async healthz(): Promise<boolean> {
    try {
      await this.request("GET", "/healthz");
      return true;
    } catch {
      return false;
    }
  }

  /** List all available proof templates (no auth required). */
  async templates(): Promise<TemplateSummary[]> {
    const resp = await this.request<TemplateListResponse>("GET", "/templates");
    return resp.templates;
  }

  /** Get full template info including parameter schema (no auth required). */
  async template(templateId: string): Promise<unknown> {
    return this.request("GET", `/templates/${encodeURIComponent(templateId)}`);
  }

  /** Verify a proof. Always free; never charges your usage. */
  async verify(proof: ProofBytes, allowLegacyV2 = true): Promise<VerifyResult> {
    return this.request<VerifyResult>("POST", "/verify", {
      proof,
      allow_legacy_v2: allowLegacyV2,
    });
  }

  /** Submit a raw prove job and return the job_id. */
  async prove(req: ProveRequest): Promise<string> {
    const body: Record<string, unknown> = {
      initial_acc: req.initialAcc,
      final_acc: req.finalAcc,
      block_size: req.blockSize ?? 2,
      fri_final_poly_size: req.friFinalPolySize ?? 2,
      query_count: req.queryCount ?? 30,
      lde_blowup_factor: req.ldeBlowupFactor ?? 2,
    };
    if (req.program) body.program = req.program;
    if (req.workloadId) body.workload_id = req.workloadId;
    if (req.zkMaskDegree !== undefined) body.zk_mask_degree = req.zkMaskDegree;

    const resp = await this.request<ProveSubmitResponse>("POST", "/prove", body);
    return resp.job_id;
  }

  /** Submit a prove job using a named template. Returns the job_id. */
  async proveTemplate(
    templateId: string,
    params: Record<string, unknown>,
    options?: TemplateProveOptions,
  ): Promise<string> {
    const body: Record<string, unknown> = { params };
    if (options?.zk !== undefined) body.zk = options.zk;
    if (options?.blockSize !== undefined) body.block_size = options.blockSize;
    if (options?.friFinalPolySize !== undefined) {
      body.fri_final_poly_size = options.friFinalPolySize;
    }

    const resp = await this.request<ProveSubmitResponse>(
      "POST",
      `/prove/template/${encodeURIComponent(templateId)}`,
      body,
    );
    return resp.job_id;
  }

  /** Get the status of a prove job. */
  async proveStatus(jobId: string): Promise<ProveJobStatus> {
    const raw = await this.request<ProveJobStatus>(
      "GET",
      `/prove/${encodeURIComponent(jobId)}`,
    );
    if (raw.status === "succeeded" && raw.proof) {
      return { status: "succeeded", proof: ProofBytes.from(raw.proof) };
    }
    return raw;
  }

  /** Poll a prove job until it completes; return the proof on success. */
  async waitForProof(
    jobId: string,
    options?: { pollIntervalMs?: number; timeoutMs?: number },
  ): Promise<ProofBytes> {
    const pollInterval = options?.pollIntervalMs ?? 1000;
    const timeout = options?.timeoutMs ?? 300_000;
    const deadline = Date.now() + timeout;

    while (Date.now() < deadline) {
      const status = await this.proveStatus(jobId);
      if (status.status === "succeeded") {
        return status.proof;
      }
      if (status.status === "failed") {
        throw new HcClientError(500, status.error);
      }
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }
    throw new Error(`prove job ${jobId} did not complete within ${timeout}ms`);
  }
}

/** Friendly alias matching the marketing name. */
export const TinyZKP = HcClient;
export type TinyZKP = HcClient;
