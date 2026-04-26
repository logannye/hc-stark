// Minimal test function to verify Pages Functions bundling.
export async function onRequestPost(context) {
  return new Response(JSON.stringify({
    ok: true,
    message: "test function reached",
    method: context.request.method,
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
export async function onRequestGet(context) {
  return new Response(JSON.stringify({ ok: true, method: "GET" }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
