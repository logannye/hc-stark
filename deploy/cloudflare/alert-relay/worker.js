const MAX_BODY_BYTES = 16 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const INCIDENT = /^[a-z0-9_]{1,80}$/;

function json(status, code) {
  return Response.json({ code }, { status, headers: { "cache-control": "no-store" } });
}

async function tokenMatches(supplied, expected) {
  if (!supplied || !expected || supplied.length !== expected.length) return false;
  const encoder = new TextEncoder();
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(supplied)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

function validPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const allowed = new Set(["text", "release_sha", "incident", "report_sha256"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) return false;
  if (
    typeof value.text !== "string" ||
    value.text.length < 1 ||
    value.text.length > 2000 ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value.text)
  ) return false;
  if (value.release_sha !== undefined && !GIT_SHA.test(value.release_sha)) return false;
  if (value.incident !== undefined && !INCIDENT.test(value.incident)) return false;
  if (value.report_sha256 !== undefined && !SHA256.test(value.report_sha256)) return false;
  return true;
}

function emailText(value) {
  const lines = [value.text, ""];
  if (value.incident) lines.push(`Incident: ${value.incident}`);
  if (value.release_sha) lines.push(`Release: ${value.release_sha}`);
  if (value.report_sha256) lines.push(`Report SHA-256: ${value.report_sha256}`);
  lines.push("", `Received: ${new Date().toISOString()}`);
  return lines.join("\n");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/alert") return json(404, "not_found");
    if (request.method !== "POST") return json(405, "method_not_allowed");
    if (!env.ALERT_RELAY_TOKEN || env.ALERT_RELAY_TOKEN.length < 32) {
      return json(503, "relay_not_configured");
    }
    const authorization = request.headers.get("authorization") || "";
    const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    if (!(await tokenMatches(supplied, env.ALERT_RELAY_TOKEN))) {
      return json(401, "unauthorized");
    }
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return json(415, "unsupported_media_type");
    }
    const declared = Number(request.headers.get("content-length") || "0");
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      return json(413, "payload_too_large");
    }
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > MAX_BODY_BYTES) return json(413, "payload_too_large");
    let value;
    try {
      value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      return json(400, "invalid_json");
    }
    if (!validPayload(value)) return json(422, "invalid_alert");
    try {
      await env.ALERT_EMAIL.send({
        from: env.ALERT_FROM,
        to: env.ALERT_TO,
        subject: "TinyZKP production alert",
        text: emailText(value),
        headers: { "X-TinyZKP-Alert": "production" },
      });
    } catch (error) {
      console.error("alert email delivery failed", error instanceof Error ? error.message : "unknown");
      return json(502, "email_delivery_failed");
    }
    return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  },
};

export { emailText, tokenMatches, validPayload };
