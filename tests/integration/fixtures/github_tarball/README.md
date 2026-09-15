# Captured GitHub repository archive (M5.6 commit 4)

The real response body GitHub's archive download serves for `verion-demo-target`. It is
captured once and committed so that `GitHubAdapter.fetch_source_archive` is tested against
what GitHub actually sends, not against what this project believes it sends.

**No test regenerates this file.** Re-capturing is a deliberate act (see *How to
re-capture*).

## Two kinds of tarball fixture, two jobs

Keep them apart, or the tests become self-referential again: a format assertion checked
against a fixture built from the same assumption proves nothing.

- **This capture is the FORMAT contract.** It is the only fixture that can answer *"can we
  read what GitHub actually sends"*:
  - the full SHA in the pax global header;
  - the abbreviated `owner-repo-sha7` top-level directory;
  - a real `app.py` whose `eval` sink is at line 28.

  Assertions about the archive's shape belong against this file.
- **The synthetic tarballs are the ADVERSARIAL cases and the caps.** They are built in
  `tests/integration/test_github_adapter.py` with `tarfile`:
  - symlink and hardlink members;
  - **sparse members**, which `isreg()` admits and which expand on read past what the archive
    decompressed to;
  - sparse headers malformed enough that `tarfile` raises a bare `ValueError`;
  - a `..` component, a member outside the root, a duplicate member;
  - a missing pax comment, and a directory that disagrees with its SHA;
  - truncated gzip, trailing bytes after the gzip stream;
  - bodies over the compressed and decompressed caps.

  GitHub never serves any of those, so none can come from a capture.

Do not ask one fixture to do the other's job. Do not add a format assertion to a synthetic
tarball: it would only restate how the synthetic tarball was built. Do not try to capture an
adversarial case: there is nothing real to capture.

**`tests/integration/test_derived_group_end_to_end.py` also reads this file**, as the
archive its `MockTransport` serves. That module proves the pipeline (detect, store,
correlate, gate). It does not re-prove the format. That claim stays with the adapter test
alone.

## Provenance

| field | value |
|---|---|
| target | `github.com/CarlosPD8/verion-demo-target` |
| commit | `c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850`, the same commit as `tests/fixtures/scanners/` |
| captured | 2026-09-15, unauthenticated |
| bytes | 5,458 (binary; no line-ending conversion applies) |
| sha256 | `53e5ea3a9b7f0366b5f531f4bd9436ba3f4a2b4988bfa1ccfd590975ddf3a580` |

The exact command, from any directory:

```sh
curl -sSL -H "Accept: application/vnd.github+json" \
  -o verion-demo-target-c68caa7.tar.gz \
  https://api.github.com/repos/CarlosPD8/verion-demo-target/tarball/c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850
```

The API answered `302` with
`location: https://codeload.github.com/CarlosPD8/verion-demo-target/legacy.tar.gz/c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850`,
and `-L` followed it.

### What is inside, read with `tarfile` rather than assumed

- **gzip header:** `mtime` 0, OS byte 3.
- **pax global header:** `{'comment': 'c68caa7aba8db8ae64da6dd2b4e1b8a05ecd1850'}`. This is
  the full SHA, and the adapter reads the commit from here.
- **members, in order:**
  - `CarlosPD8-verion-demo-target-c68caa7` (directory)
  - `.gitignore`, `README.md`, `app.py`, `requirements.txt`
  - `templates` (directory)
  - `templates/index.html`, `templates/result.html`
- Every member has `mtime` 1787590727 and uid 0. There are no symlinks and no hardlinks.
- `app.py`: `@app.route("/")` at line 9, `@app.route("/calculate")` at line 14,
  `result = eval(expr)` at line 28.

### Fetched by SHA, served for `HEAD`

The capture was fetched at the pinned SHA. `fetch_source_archive` asks for `tarball/HEAD`,
and the tests' `MockTransport` answers that request with this file.

The two requests produce the same body only while the demo target's default branch *is*
`c68caa7`. A `HEAD` fetch taken the same day while planning also measured 5,458 bytes, but
its hash was not recorded, so no stronger claim is made.

## Reproducibility, as measured

**Identical on two fetches, 2026-09-15:** same 5,458 bytes, same sha256, `cmp` reports no
difference. The fetches ran at 11:24:00Z and 11:24:04Z.

That covers four seconds and nothing more. It does not show that GitHub serves these bytes
for this SHA next month, and the file claims no more than that. The fixed gzip `mtime` of 0
and the fixed member `mtime` values make stability plausible, but they are not a
measurement of it.

If a re-capture gives different bytes, diff three things before replacing the file:
- the gzip header, the first 10 bytes;
- the pax header;
- the member list.

Record which of the three differed.

## Coupling: a change to the demo target invalidates this file

The capture is pinned to `c68caa7`, exactly as `tests/fixtures/scanners/semgrep_scan.json`
is.
- **If the demo target moves**, re-capture this file together with that corpus, or record
  why it still stands.
- **If `app.py`'s line numbers move**, the end-to-end module's seeded `app.py:28` finding
  stops falling inside the `/calculate` span.

This is the shape **G39** tracks: a fixture tied to a live repository with nothing mechanical
comparing them.

## What this file does NOT change

This is **the first Flask source tree committed to this repository**. It is a **format**
fixture, and it is the same two-route app.

So it does not widen anything ADR-0029 decision 5 bounds. Blueprints, `add_url_rule`,
variable converters, class-based views, stacked decorators and the miss case are each
exactly as tested, or as untested, as before this file existed.

## How to re-capture

1. Run the command above twice, a few seconds apart, and `cmp` the two results.
2. Update the table above: date, bytes, sha256.
3. Update the reproducibility section with what step 1 showed.
4. Re-read the member list with `tarfile`, and update *What is inside* if it changed.
5. If the target's commit changed, update the commit row, the end-to-end module's seeded
   locations, and `tests/fixtures/scanners/`.
