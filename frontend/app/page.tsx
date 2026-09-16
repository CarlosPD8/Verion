"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { login } from "../lib/api";
import { getLastProjectId, setAccessToken, setLastProjectId } from "../lib/session";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // No route lists a user's projects, so the id is typed or carried over in memory.
  const [projectId, setProjectId] = useState(getLastProjectId());
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    const result = await login(email, password);
    setBusy(false);
    if (result.kind === "invalid") {
      setMessage("That email and password don't match an account.");
      return;
    }
    if (result.kind === "error") {
      setMessage("Couldn't reach Verion. Check that the API is running, then sign in again.");
      return;
    }
    setAccessToken(result.token);
    const id = projectId.trim();
    setLastProjectId(id);
    router.push(`/projects/${encodeURIComponent(id)}/risks`);
  }

  return (
    <main className="login">
      <header className="page-header">
        <p className="wordmark">verion</p>
        <p className="tagline">From security findings to security decisions.</p>
      </header>
      <form className="login-form" onSubmit={onSubmit}>
        <label className="field">
          Email
          <input
            className="input"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>
        <label className="field">
          Password
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <label className="field">
          Project id
          <input
            className="input data"
            required
            value={projectId}
            onChange={(event) => setProjectId(event.target.value)}
          />
          <span className="hint">Paste the id of the project whose Risks you want to see.</span>
        </label>
        <button className="button" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {message !== null && (
          <p className="form-error" role="alert">
            {message}
          </p>
        )}
      </form>
    </main>
  );
}
