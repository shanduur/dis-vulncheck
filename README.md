# dis-vulncheck

dis-vulncheck is a wrapper around [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) to ensure we can exclude vulnerabilities where necesssary whilst awaiting updates to govulncheck.

## Dependencies

dis-vulncheck requires govulncheck to be installed to work as it wraps around it.

```sh
  go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Installation

```sh
  go install github.com/ONSdigital/dis-vulncheck@latest
```

## Configuration

dis-vulncheck looks for a configuration file, currently defaulting to searching through:

- .dis-vulncheck.yml
- .dis-vulncheck.yaml
- .disvulncheck.yml
- .disvulncheck.yaml

This can be overriden by using a [config flag](#flags)

This specification for this file is below:

```yml
---
ignore:
  type: array
  items:
    type: object
    properties:
      id:
        description: "The Go vuln database ID of this vulnerability"
        example: "GO-2025-3563"
        type: string
      reason:
        description: "A reason why this vulnerability has been excluded from auditing"
        example: "This doesn't affect our application"
        type: string
      date:
        description: "The date the ignore was added (required). Used with ignore_ttl to expire stale ignores."
        example: "2025-06-01"
        type: string
        format: date
ignore_ttl:
  description: "How long an ignore entry remains valid before it expires. Defaults to 168h (7 days)."
  example: "720h"
  type: string
  format: duration
toolchain:
  description: "An optional toolchain directive to override the default"
  example: "go1.25.0"
  type: string
```

### Ignore TTL

Each ignore entry requires a `date` field indicating when it was added. dis-vulncheck uses `ignore_ttl` (default: 7 days / `168h`) to determine whether an ignore has expired. If the time elapsed since `date` exceeds the TTL, the ignore is **not applied** and the vulnerability is counted as a failure.

This prevents stale ignores from silently suppressing vulnerabilities indefinitely. To renew an ignore, update its `date` to the current date.

Example configuration:

```yml
---
ignore_ttl: 720h  # 30 days
ignore:
  - id: GO-2025-3563
    reason: Tracked in JIRA-1234, fix expected next sprint
    date: 2025-06-01
```

## Running

To run dis-vulncheck:

```sh
  dis-vulncheck
```

### Flags

You can use two different flags against dis-vulncheck:

- `--build-tags` will pass this down to the underlying govulncheck scan
- `--config` can supply a string filepath for your config file
- `--verbose` will add full logging output

## What it checks against

By default, dis-vulncheck will inspect the CI build yml (`/ci/build.yml`) to retrieve the version of Go it will be built with.

e.g.

```yml
image_resource:
  type: docker-image
  source:
    repository: golang
    tag: 1.24.6-bookworm
```

In this case it will extract "1.24.6" and set this as the `GOTOOLCHAIN` when running `govulncheck`. This is to ensure consistency between CI and local environments.

If this is not found it will default to the Go version found in the local environment, or can be overriden through the [config file](#configuration).
