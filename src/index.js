// Password gate: every request must carry the right username and password.
// The credentials live in Cloudflare as secrets (AUTH_USER and AUTH_PASS),
// never in this file or in GitHub.

const enc = new TextEncoder();

async function digest(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

async function same(a, b) {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  return crypto.subtle.timingSafeEqual(x, y);
}

export default {
  async fetch(request, env) {
    const header = request.headers.get("Authorization") || "";

    if (env.AUTH_USER && env.AUTH_PASS && header.startsWith("Basic ")) {
      let decoded = "";
      try {
        decoded = atob(header.slice(6));
      } catch (e) {}
      const i = decoded.indexOf(":");
      if (i > -1) {
        const userOk = await same(decoded.slice(0, i), env.AUTH_USER);
        const passOk = await same(decoded.slice(i + 1), env.AUTH_PASS);
        if (userOk && passOk) {
          return env.ASSETS.fetch(request);
        }
      }
    }

    return new Response("Login required", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="My dashboard", charset="UTF-8"',
        "Cache-Control": "no-store",
      },
    });
  },
};
