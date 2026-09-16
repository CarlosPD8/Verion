// ADR-0031 decision 2: the browser calls /api/* on this origin and the rewrite
// forwards it to the API, so the API needs no CORS. The destination comes from
// server-side configuration only, never from anything a request carries.
const apiBaseUrl = process.env.VERION_API_BASE_URL ?? "http://localhost:8000";

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
