<!--
  SPDX-License-Identifier: Apache-2.0
  SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# cvss

CVSS (Common Vulnerability Scoring System) library for Erlang.

[![EEF Security WG project](https://img.shields.io/badge/EEF-Security-black)](https://github.com/erlef/security-wg)
[![Main Branch](https://github.com/erlef/cvss/actions/workflows/branch_main.yml/badge.svg?branch=main)](https://github.com/erlef/cvss/actions/workflows/branch_main.yml)
[![REUSE status](https://api.reuse.software/badge/github.com/erlef/cvss)](https://api.reuse.software/info/github.com/erlef/cvss)
[![Coverage Status](https://coveralls.io/repos/github/erlef/cvss/badge.svg?branch=main)](https://coveralls.io/github/erlef/cvss?branch=main)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12398/badge)](https://www.bestpractices.dev/projects/12398)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/12398/baseline)](https://www.bestpractices.dev/projects/12398)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/erlef/cvss/badge)](https://scorecard.dev/viewer/?uri=github.com/erlef/cvss)
[![Module Version](https://img.shields.io/hexpm/v/cvss.svg)](https://hex.pm/packages/cvss)
[![Total Download](https://img.shields.io/hexpm/dt/cvss.svg)](https://hex.pm/packages/cvss)
[![License](https://img.shields.io/hexpm/l/cvss.svg)](https://github.com/erlef/cvss/blob/main/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/erlef/cvss.svg)](https://github.com/erlef/cvss/commits/main)

Supports all CVSS versions:

- **CVSS 1.0** — [Specification](https://www.first.org/cvss/v1/guide)
- **CVSS 2.0** — [Specification](https://www.first.org/cvss/v2/guide)
- **CVSS 3.0** — [Specification](https://www.first.org/cvss/v3.0/specification-document)
- **CVSS 3.1** — [Specification](https://www.first.org/cvss/v3.1/specification-document)
- **CVSS 4.0** — [Specification](https://www.first.org/cvss/v4.0/specification-document)

## Setup

**Minimum supported Erlang/OTP version is OTP 26.**

<!-- tabs-open -->

### Erlang

Add `cvss` to your dependencies in `rebar.config`:

```erlang
{deps, [cvss]}.
```

### Elixir

Add `cvss` to your dependencies in `mix.exs`:

```elixir
{:cvss, "~> 0.1"}
```

<!-- tabs-close -->

## Usage

### Version-Agnostic API

Use the `cvss` module when the version is not known ahead of time:

<!-- tabs-open -->

### Erlang

```erlang
%% Parse a vector of any version
{ok, Cvss} = cvss:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).

%% Calculate the overall score
9.8 = cvss:score(Cvss).

%% Get the severity rating (v3.0+)
critical = cvss:rating(Cvss).

%% Compose back to a vector string
<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">> = iolist_to_binary(cvss:compose(Cvss)).

%% Check if a vector is valid
true = cvss:valid(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
```

### Elixir

```elixir
# Parse a vector of any version
{:ok, cvss} = :cvss.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

# Calculate the overall score
9.8 = :cvss.score(cvss)

# Get the severity rating (v3.0+)
:critical = :cvss.rating(cvss)

# Compose back to a vector string
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" =
  :cvss.compose(cvss) |> IO.iodata_to_binary()

# Check if a vector is valid
true = :cvss.valid("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

<!-- tabs-close -->

## Version-Specific Modules

For direct access to version-specific features and detailed score types, use
`:cvss_v1`, `:cvss_v2`, `:cvss_v3`, or `:cvss_v4` directly.

### CVSS 1.0 / 2.0 / 3.x

These versions share the same score types: **Base**, **Temporal**, and
**Environmental**. Each score builds on the previous one.

<!-- tabs-open -->

### Erlang

```erlang
{ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:R">>).

9.8 = cvss_v3:base_score(Cvss).
9.1 = cvss_v3:temporal_score(Cvss).
9.1 = cvss_v3:environmental_score(Cvss).
9.1 = cvss_v3:score(Cvss).  %% Returns the most specific score available
```

### Elixir

```elixir
{:ok, cvss} = :cvss_v3.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:R")

9.8 = :cvss_v3.base_score(cvss)
9.1 = :cvss_v3.temporal_score(cvss)
9.1 = :cvss_v3.environmental_score(cvss)
9.1 = :cvss_v3.score(cvss)  # Returns the most specific score available
```

<!-- tabs-close -->

### CVSS 4.0

CVSS 4.0 uses a unified scoring formula. The score functions control which
metric groups are considered, matching the
[CVSS 4.0 nomenclature](https://www.first.org/cvss/v4.0/specification-document):

| Function                | Nomenclature | Metrics Used                    |
|-------------------------|--------------|---------------------------------|
| `base_score/1`          | CVSS-B       | Base only                       |
| `threat_score/1`        | CVSS-BT      | Base + Threat                   |
| `environmental_score/1` | CVSS-BE      | Base + Environmental            |
| `score/1`               | CVSS-BTE     | Base + Threat + Environmental   |

<!-- tabs-open -->

### Erlang

```erlang
{ok, Cvss} = cvss_v4:parse(
    <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P">>
).

cvss_v4:base_score(Cvss).          %% CVSS-B: ignores threat & environmental
cvss_v4:threat_score(Cvss).        %% CVSS-BT: ignores environmental
cvss_v4:environmental_score(Cvss). %% CVSS-BE: ignores threat
cvss_v4:score(Cvss).               %% CVSS-BTE: uses all present metrics
```

### Elixir

```elixir
{:ok, cvss} = :cvss_v4.parse(
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P"
)

:cvss_v4.base_score(cvss)          # CVSS-B: ignores threat & environmental
:cvss_v4.threat_score(cvss)        # CVSS-BT: ignores environmental
:cvss_v4.environmental_score(cvss) # CVSS-BE: ignores threat
:cvss_v4.score(cvss)               # CVSS-BTE: uses all present metrics
```

<!-- tabs-close -->

## Working with Records in Elixir

The parsed CVSS values are Erlang records. To pattern match or construct them
in Elixir, use `Record.defrecord/2`:

```elixir
import Record

defrecord :cvss_v3, Record.extract(:cvss_v3, from_lib: "cvss/include/cvss_v3.hrl")
defrecord :cvss_v4, Record.extract(:cvss_v4, from_lib: "cvss/include/cvss_v4.hrl")

# Pattern match on parsed results
{:ok, cvss} = :cvss_v3.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
cvss_v3(av: :network, c: confidentiality) = cvss
```

## Severity Ratings

Qualitative severity ratings are defined by the CVSS v3.0, v3.1, and v4.0
specifications. The `cvss:rating/1` function applies these thresholds:

| Rating     | Score Range |
|------------|-------------|
| `none`     | 0.0         |
| `low`      | 0.1 – 3.9  |
| `medium`   | 4.0 – 6.9  |
| `high`     | 7.0 – 8.9  |
| `critical` | 9.0 – 10.0 |

CVSS v1.0 and v2.0 do not define severity ratings in their specifications.
The same thresholds are applied as a convenience but are not spec-mandated for
those versions.