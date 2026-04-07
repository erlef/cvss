%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss).
-moduledoc """
Version-agnostic API for CVSS (Common Vulnerability Scoring System).

This module handles all CVSS versions (1.0, 2.0, 3.0, 3.1, and 4.0)
and automatically detects the version when parsing. Use this module when
the CVSS version is not known ahead of time, for example when parsing
vectors from external sources.

If you already know which version you are working with, use the
version-specific module directly instead: `m:cvss_v1`, `m:cvss_v2`,
`m:cvss_v3`, or `m:cvss_v4`.
""".

-export([compose/1, parse/1, rating/1, score/1, valid/1]).

-include("cvss.hrl").

%% Type exports
-export_type([
    cvss/0,
    score/0,
    severity/0,
    parse_error/0,
    validation_error/0,
    cvss_error/0
]).

%%====================================================================
%% Types
%%====================================================================

-type cvss() :: cvss_v1:cvss() | cvss_v2:cvss() | cvss_v3:cvss() | cvss_v4:cvss().
-if(?OTP_RELEASE >= 28).
-doc "A CVSS score value, ranging from 0.0 (no impact) to 10.0 (critical).".
-nominal score() :: number().
-else.
-doc "A CVSS score value, ranging from 0.0 (no impact) to 10.0 (critical).".
-type score() :: number().
-endif.
-type severity() :: none | low | medium | high | critical.

-type parse_error() ::
    {invalid_prefix, Prefix :: binary()}
    | {invalid_metric, Metric :: binary(), Value :: binary()}
    | {missing_required_metric, Metric :: atom()}
    | {duplicate_metric, Metric :: binary()}
    | malformed_vector.

-type validation_error() ::
    {invalid_metric_value, Metric :: atom(), Value :: term()}
    | {missing_required_metric, Metric :: atom()}.

-type cvss_error() :: parse_error() | validation_error().

%%====================================================================
%% Public API
%%====================================================================

-doc """
Parse a CVSS vector string into a record.

Automatically detects the CVSS version from the vector format:
- CVSS 4.0: Starts with `CVSS:4.0/`
- CVSS 3.1: Starts with `CVSS:3.1/`
- CVSS 3.0: Starts with `CVSS:3.0/`
- CVSS 2.0: Starts with `AV:` and uses N/A/L for Access Vector
- CVSS 1.0: Starts with `AV:` and uses R/L for Access Vector

```erlang
> cvss:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>).
{ok, #cvss_v4{av = network, ac = low, at = none, pr = none, ui = none,
              vc = high, vi = high, va = high, sc = high, si = high, sa = high}}

> cvss:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
{ok, #cvss_v3{version = '3.1', av = network, ac = low, pr = none,
              ui = none, s = unchanged, c = high, i = high, a = high}}

> cvss:parse(<<"AV:N/AC:L/Au:N/C:P/I:P/A:C">>).
{ok, #cvss_v2{av = network, ac = low, au = none, c = partial, i = partial, a = complete}}

> cvss:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>).
{ok, #cvss_v1{av = remote, ac = low, au = not_required,
              c = complete, i = complete, a = complete}}

> cvss:parse(<<"CVSS:5.0/AV:N">>).
{error, {invalid_prefix, <<"CVSS:5.0/AV:N">>}}

> cvss:parse(<<"INVALID">>).
{error, malformed_vector}
```
""".
-spec parse(iodata()) -> {ok, cvss()} | {error, parse_error()}.
parse(Vector) when is_list(Vector) ->
    parse(iolist_to_binary(Vector));
parse(<<"CVSS:4.0/", _/binary>> = Vector) ->
    cvss_v4:parse(Vector);
parse(<<"CVSS:3.", _/binary>> = Vector) ->
    cvss_v3:parse(Vector);
parse(<<"CVSS:", Rest/binary>>) ->
    {error, {invalid_prefix, <<"CVSS:", Rest/binary>>}};
parse(Vector) when is_binary(Vector) ->
    %% For v1/v2, we need to detect which one based on the AV metric values
    %% v1 uses: AV:L (local) or AV:R (remote)
    %% v2 uses: AV:L (local), AV:A (adjacent), or AV:N (network)
    Stripped = cvss_common:strip_parens(Vector),
    case detect_v1_or_v2(Stripped) of
        v1 -> cvss_v1:parse(Stripped);
        v2 -> cvss_v2:parse(Stripped);
        unknown -> {error, malformed_vector}
    end.

-doc """
Compose a CVSS record into a vector string.

```erlang
> {ok, Cvss} = cvss:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
> iolist_to_binary(cvss:compose(Cvss)).
<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>
```
""".
-spec compose(cvss()) -> iolist().
compose(#cvss_v1{} = Cvss) ->
    cvss_v1:compose(Cvss);
compose(#cvss_v2{} = Cvss) ->
    cvss_v2:compose(Cvss);
compose(#cvss_v3{} = Cvss) ->
    cvss_v3:compose(Cvss);
compose(#cvss_v4{} = Cvss) ->
    cvss_v4:compose(Cvss).

-doc """
Check whether a CVSS value is valid.

Accepts either a vector string or a parsed record.
Returns true if valid, false otherwise.

```erlang
> cvss:valid(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
true

> cvss:valid(<<"INVALID">>).
false

> cvss:valid(#cvss_v3{version = '3.1', av = network, ac = low, pr = none,
                        ui = none, s = unchanged, c = high, i = high, a = high}).
true
```
""".
-spec valid(iodata() | cvss()) -> boolean().
valid(#cvss_v1{} = Cvss) ->
    cvss_v1:valid(Cvss);
valid(#cvss_v2{} = Cvss) ->
    cvss_v2:valid(Cvss);
valid(#cvss_v3{} = Cvss) ->
    cvss_v3:valid(Cvss);
valid(#cvss_v4{} = Cvss) ->
    cvss_v4:valid(Cvss);
valid(Vector) ->
    case parse(Vector) of
        {ok, Cvss} -> valid(Cvss);
        {error, _} -> false
    end.

-doc """
Calculate the CVSS score.

Accepts either a vector string or a parsed record.
Returns the appropriate score based on which metrics are present:
- Environmental score (if environmental metrics present)
- Temporal score (if temporal metrics present)
- Base score (otherwise)

```erlang
> cvss:score(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
9.8

> cvss:score(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N">>).
0.0

> cvss:score(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H">>).
10.0
```
""".
-spec score(iodata() | cvss()) -> score().
score(#cvss_v1{} = Cvss) ->
    cvss_v1:score(Cvss);
score(#cvss_v2{} = Cvss) ->
    cvss_v2:score(Cvss);
score(#cvss_v3{} = Cvss) ->
    cvss_v3:score(Cvss);
score(#cvss_v4{} = Cvss) ->
    cvss_v4:score(Cvss);
score(Vector) ->
    case parse(Vector) of
        {ok, Cvss} -> score(Cvss);
        {error, _} -> 0.0
    end.

-doc """
Get the severity rating for a CVSS score or vector.

Thresholds are the same for all CVSS versions:
- None: 0.0
- Low: 0.1 - 3.9
- Medium: 4.0 - 6.9
- High: 7.0 - 8.9
- Critical: 9.0 - 10.0

```erlang
> cvss:rating(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
critical

> cvss:rating(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N">>).
none
```
""".
-spec rating(iodata() | cvss()) -> severity().
rating(Vector) when is_list(Vector); is_binary(Vector) ->
    cvss_common:score_to_rating(score(Vector));
rating(Cvss) when is_tuple(Cvss) ->
    cvss_common:score_to_rating(score(Cvss)).

%%====================================================================
%% Internal
%%====================================================================

detect_v1_or_v2(Vector) ->
    %% Look for AV: metric value to determine version
    case binary:match(Vector, <<"AV:">>) of
        {Start, 3} ->
            ValueStart = Start + 3,
            case Vector of
                <<_:ValueStart/binary, "R", _/binary>> ->
                    v1;
                <<_:ValueStart/binary, "N", _/binary>> ->
                    v2;
                <<_:ValueStart/binary, "A", _/binary>> ->
                    v2;
                <<_:ValueStart/binary, "L", _/binary>> ->
                    %% Both v1 and v2 have L (local), need to check other metrics
                    %% v2 has Au: with M/S/N, v1 has Au: with R/NR
                    detect_by_auth(Vector);
                _ ->
                    unknown
            end;
        nomatch ->
            unknown
    end.

detect_by_auth(Vector) ->
    case binary:match(Vector, <<"Au:">>) of
        {Start, 3} ->
            ValueStart = Start + 3,
            case Vector of
                <<_:ValueStart/binary, "NR", _/binary>> -> v1;
                <<_:ValueStart/binary, "R/", _/binary>> -> v1;
                <<_:ValueStart/binary, "R">> -> v1;
                <<_:ValueStart/binary, "M", _/binary>> -> v2;
                <<_:ValueStart/binary, "S", _/binary>> -> v2;
                <<_:ValueStart/binary, "N", _/binary>> -> v2;
                _ -> unknown
            end;
        nomatch ->
            unknown
    end.
