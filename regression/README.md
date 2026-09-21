# Historical remediation regression fixtures

This draft branch adds isolated **recipe regression tests**, not a completed Mantis scan-to-PR service test. The root application is unchanged. GitHub Actions uses an ephemeral runner, a read-only repository token, no persisted checkout credentials, and no application secrets.

Two scenarios generate disposable Maven projects in `regression-output/`:

- Jackson Databind 2.9.8 to 2.13.5 for CVE-2020-36518.
- Spring Boot parent 3.3.3 to 3.3.4, which aligns managed Spring Framework 6.1.12 to 6.1.13 for CVE-2024-38816. No Framework override is introduced.

Both query OSV against the actual resolved target dependency before and after OpenRewrite, run Maven tests, check for actual changes, rerun for idempotence, and preserve existing recipe configuration. Logs, dependency trees, full OSV responses, tests and patch evidence are retained for seven days. Failed requests or missing test reports fail the run.

These are historical versions used to reproduce individual advisories. They may have other vulnerabilities and are **not recommended production upgrade destinations**. Dependency findings are not an exploit demonstration; the Boot fixture checks dependency alignment and context startup, not all CVE exploit preconditions or HTTP behavior. Major Boot/Jakarta migration, Mantis webhook processing, multi-tenant recipe selection, build-failure publication gates, and automatic PR publication remain separate tests.

References:
- https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.13
- https://spring.io/security/cve-2024-38816/
- https://spring.io/blog/2024/09/12/spring-framework-6-1-13-available-now/
- https://docs.openrewrite.org/recipes/maven/upgradeparentversion

Run only in an isolated build environment: `python3 regression/run.py jackson` or `python3 regression/run.py boot-managed`.
