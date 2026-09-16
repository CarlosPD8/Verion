// ADR-0031 decision 2: the browser calls /api/* on this origin and the rewrite
// forwards it to the API, so the API needs no CORS. The destination comes from
// server-side configuration only, never from anything a request carries.
// 127.0.0.1, not localhost: Node resolves `localhost` to ::1 first on this machine, and
// uvicorn binds 127.0.0.1 by default, so a `localhost` default got ECONNREFUSED and every
// proxied call answered 500. Found by rendering the screen; P1 had set this variable explicitly.
const apiBaseUrl = process.env.VERION_API_BASE_URL ?? "http://127.0.0.1:8000";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Without this, `next dev` writes AGENTS.md and a CLAUDE.md into frontend/, and a
  // second CLAUDE.md would be loaded as project instructions beside the repository's.
  agentRules: false,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiBaseUrl}/:path*` }];
  },
};

export default nextConfig;
