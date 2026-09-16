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
      setMessage("Email or password is incorrect.");
      return;
    }
    if (result.kind === "error") {
      setMessage("Could not sign in. Try again.");
      return;
    }
    setAccessToken(result.token);
    const id = projectId.trim();
    setLastProjectId(id);
    router.push(`/projects/${encodeURIComponent(id)}/risks`);
  }

  return (
    <main>
      <h1>Verion</h1>
      <form onSubmit={onSubmit}>
        <label>
          Email
          <input
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <label>
          Project id
          <input required value={projectId} onChange={(event) => setProjectId(event.target.value)} />
        </label>
        <button type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
      {message !== null && <p role="alert">{message}</p>}
    </main>
  );
}
