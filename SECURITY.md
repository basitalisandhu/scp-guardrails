# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability") rather than a public issue. Include the version, a minimal spec or policy that reproduces the problem, and what you expected to happen. Replace real account ids and role names with example values.

You will get an acknowledgement within 7 days and a fix or a mitigation plan within 30 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## Scope

scp-guardrails reads spec and policy files and writes only the files you name (the build output directory, `--output`, `--sarif`, `--summary`, `--github-output`). It executes nothing it reads, makes no network calls, never calls AWS and has no dependencies outside the Python standard library.

Issues of interest:

- a spec that makes `build` write a policy that grants access, denies less than the catalogue says, or exempts principals that were not in `protected_roles`;
- a policy with a lockout, a dead statement or a size problem that `lint` reports clean, or reports at a lower severity than [docs/rules.md](docs/rules.md) says it should;
- `diff` reporting two policies as identical when they deny different things;
- input that makes any command write outside the paths it was given, crash, or hang;
- the composite Action interpolating inputs into shell commands, or running anything other than the checked-out linter.

Out of scope: AWS services or global endpoints missing from the AWS region-deny example list (report them as ordinary issues with a link to the AWS documentation), and the behaviour of policies once attached, which only AWS evaluates.
