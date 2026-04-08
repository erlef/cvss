<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# Vendored Dependencies

## `cvss_decimal` / `cvss_decimal_conv`

Vendored from [`erlang_decimal`](https://hex.pm/packages/erlang_decimal) v0.6.5
([source](https://github.com/egobrain/decimal)), licensed under MIT.

The `erlang_decimal` package registers the OTP application name `decimal`, which
collides with Elixir's [`decimal`](https://hex.pm/packages/decimal) package. Any
project that depends on both `cvss` and Elixir's `decimal` would get an
application name conflict at boot time. See
[egobrain/decimal#8](https://github.com/egobrain/decimal/issues/8) for details.

By vendoring the code (renamed to `cvss_decimal` / `cvss_decimal_conv`) we
eliminate the separate OTP application and avoid the collision entirely.