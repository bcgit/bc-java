# Porting `UPSTREAM-*.md` changes from the BC-LTS tree

Root-level `UPSTREAM-<topic>.md` files are porting docs for changes already running in BC-LTS. A
local BC-LTS checkout (`bc-lts-java`, same module layout) sits beside this one, so
`diff <path> ../lts-java/bc-lts-java/<path>` usually gives the exact shape to port. Worked examples:
the ESTService 204/404 drain hardening (`b0d0e07064`) and the JceKTSKeyTransRecipient constraint
port (`915e7f3ffb`).

- **Verify the doc against this tree first.** Parts may already be committed, possibly in a
  different shape (the EST drain landed inline as `b6a05505d7` while the doc described an extracted
  method), and "related" concerns may already be satisfied. When shapes disagree, converge on the
  LTS shape so cross-tree diffs stay clean, then fix the doc.
- **Verification claims in the doc were made in LTS** ("verified with japi-compliance-checker",
  "tests pass"). Re-run here or reword to what was actually done here.
- **LTS code often lacks upstream trimmings**: setter/method javadoc (mirror sibling classes'
  wording), release-note entries, package-info updates. Add them.
- **Tests:** LTS may have a test class to port near-verbatim (`ESTServiceDrainTest`), or none (the
  KTS hardening). Mirror the sibling-family tests in the same battery; when the new test is the
  first coverage of a path, keep the unconstrained/baseline case - it is the compatibility
  assertion.
- **Verify with stash-the-fix** (`build-and-test.md`), using the enforcement-only variant when the
  change is additive API the tests compile against.
- **Release notes** go in the current unreleased block, but check whether a *released* block
  already covers the area: the 1.85 #781 entry described the `Streams.drain` the port replaced, so
  the 1.86 entry was written as a follow-up to what shipped.
- **When done, revise the UPSTREAM doc to the implemented state** (status, actual code shape, real
  test names, how verified). It's a living record.
- **The `UPSTREAM-*.md` file stays out of the commit** - keep it local, unstage it if indexed. The
  commit carries only code, tests and `docs/releasenotes.md`, with the usual single-line message.
