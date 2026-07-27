# Porting `UPSTREAM-*.md` changes from the BC-LTS tree

Root-level `UPSTREAM-<topic>.md` files are porting docs for changes already running in the
downstream BC-LTS tree, aimed at this repo. The LTS checkout lives at
`/home/dgh/bc/git/repositories/lts-java/bc-lts-java` (its module layout mirrors bc-java), so
`diff <path> ../lts-java/bc-lts-java/<path>` usually gives the exact shape to port. Worked
examples: the ESTService 204/404 drain hardening (`b0d0e07064`) and the JceKTSKeyTransRecipient
constraint port (`915e7f3ffb`).

- **Verify the doc against this tree before porting anything.** Parts may already be committed —
  possibly in a different shape than the doc shows (the EST drain landed inline as `b6a05505d7`
  while the doc described an extracted method) — and "related" concerns the doc raises may already
  be satisfied here. When this tree and the doc disagree about shape, prefer converging on the LTS
  shape so future cross-tree diffs stay clean, then fix the doc.
- **Claims of verification in the doc were made in the LTS tree.** A "verified with
  japi-compliance-checker" or "tests pass" statement doesn't transfer; re-run it here or reword the
  claim to what was actually done in this tree.
- **LTS code often lacks upstream trimmings.** Setter/method javadoc (mirror the sibling classes'
  wording), release-note entries, package-info updates — port the code, add the trimmings.
- **Tests:** LTS may carry a test class to port near-verbatim (`ESTServiceDrainTest`), or may have
  shipped the change with no test at all (the KTS hardening). Mirror the sibling-family tests in
  the same battery, and when the new test is the first coverage of an entire path, keep the
  unconstrained/baseline case — it is the compatibility assertion, not filler.
- **Verify with stash-the-fix** (see build-and-test.md), using the enforcement-only variant when
  the change is additive API the tests need to compile against.
- **Release notes** go in the current unreleased block as usual — but check whether a *released*
  block already describes the same area: the 1.85 #781 entry described the `Streams.drain` the
  port replaced, so the 1.86 entry had to be written as a follow-up relative to what actually
  shipped, not as a fresh fix.
- **When done, revise the UPSTREAM doc to the implemented state** (status line, the actual code
  shape, real test names, how it was verified). It's a living record, not a frozen proposal.
- **The `UPSTREAM-*.md` file itself stays out of the commit.** dgh keeps these local in the working
  tree — unstage one if it's in the index — and the commit carries only code, tests and
  `docs/releasenotes.html`, with the usual single-line message (see the commit conventions).
