# Zeerak Trademark Policy

Zeerak is licensed under [Apache-2.0](LICENSE), which grants generous rights
to use, modify, and redistribute the **code**. It does **not** grant rights
to the project's name or branding. Section 6 of the Apache-2.0 license
explicitly excludes trademarks from the grant.

This document spells out what that means in practice for Zeerak.

## What is reserved

The following are reserved marks of the upstream Zeerak project:

- The name **"Zeerak"** (and stylized variants like `zeerak`, `Zeerak.io`, etc.)
- The Zeerak logo and any future visual identity
- The domain `zeerak.*` and the GitHub org `github.com/zeerak`
- The `zeerak`, `zeerak-server`, `zeerak-mcp`, and `zeerak-testkit` binary names

## What you can do without asking

- **Use Zeerak.** Run it, deploy it, embed it, sell services around it.
- **Fork the code.** Modify it, redistribute it, ship your own builds — under
  Apache-2.0, that's your right.
- **Refer to Zeerak by name** in factual, descriptive contexts:
  _"compatible with Zeerak"_, _"based on Zeerak"_, _"a Zeerak plugin"_,
  blog posts, talks, comparisons, tutorials. This is **nominative use** and
  is fine.
- **Distribute unmodified Zeerak** through Linux distros, container registries,
  Homebrew, etc., keeping the name. (Distro packagers: thank you.)

## What requires a different name

If you ship a **modified** version of Zeerak — patched, rebranded, forked,
or repackaged with non-trivial changes — you must:

1. **Rename it.** Pick something that isn't "Zeerak" or a confusable variant.
   Good: `firewalld-ng`, `myorg-fw`, `nftui`. Not good: `Zeerak Pro`, `zeerak-ee`,
   `Zeerak by AcmeCorp`.
2. **Keep attribution.** Include a visible line in your README and `--version`
   output: `Based on Zeerak — https://github.com/zeerak/zeerak`.
3. **Don't imply endorsement.** Don't suggest that the upstream Zeerak project
   endorses, supports, or is otherwise affiliated with your fork.

This is the same pattern used by Caddy, Kubernetes, and most Apache-2.0
projects with a brand worth protecting.

## What is never allowed

- Selling a product or SaaS literally called "Zeerak" that you didn't build.
- Registering domains, GitHub orgs, package names, or trademarks containing
  "Zeerak" in a way that would confuse users about the origin.
- Using the Zeerak logo on a fork's website or binaries.

## Questions

If you're not sure whether a particular use is OK, open an issue on
[github.com/zeerak/zeerak](https://github.com/zeerak/zeerak) and ask.
We'd much rather have a five-minute conversation than a lawyer's letter.

---

This policy may evolve. The current version is always the one in `main`.
