%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

%% Common utilities for CVSS calculations.
-module(cvss_common).
-moduledoc false.

-export([
    round_v1_v2/1,
    roundup/1,
    score_to_rating/1,
    d/1,
    to_float/1,
    dmin/2,
    dmax/2,
    dpow/2,
    parse_metrics/2,
    check_required/2,
    encode_optional/2,
    valid_optional/2,
    strip_parens/1
]).

-include("internal/decimal.hrl").

-doc """
Convert a number to a decimal value.

```erlang
> cvss_common:d(0.85).
{85, -2}
```
""".
-spec d(number() | binary()) -> decimal:decimal().
d(Value) when is_float(Value) ->
    decimal:to_decimal(Value, ?DECIMAL_OPTS);
d(Value) when is_integer(Value) ->
    decimal:to_decimal(Value, ?DECIMAL_OPTS);
d(Value) when is_binary(Value) ->
    decimal:to_decimal(Value, ?DECIMAL_OPTS).

-doc """
Convert a decimal value to a float.
""".
-spec to_float(decimal:decimal()) -> float().
to_float({0, _}) ->
    0.0;
to_float(D) ->
    Bin = decimal:to_binary(D),
    case binary:match(Bin, <<".">>) of
        nomatch ->
            float(binary_to_integer(Bin));
        _ ->
            binary_to_float(Bin)
    end.

-doc """
Round to 1 decimal place using "round half up" (CVSS 1.0/2.0).
Uses decimal arithmetic for precision.

```erlang
> cvss_common:round_v1_v2(cvss_common:d(6.6555)).
{67, -1}

> cvss_common:round_v1_v2(cvss_common:d(3.14)).
{31, -1}

> cvss_common:round_v1_v2(cvss_common:d(3.15)).
{32, -1}
```
""".
-spec round_v1_v2(decimal:decimal()) -> decimal:decimal().
round_v1_v2(Value) ->
    decimal:round(round_half_up, Value, 1).

-doc """
Round up to 1 decimal place (CVSS 3.x).
Uses decimal arithmetic for precision.

```erlang
> cvss_common:roundup(cvss_common:d(4.02)).
{41, -1}

> cvss_common:roundup(cvss_common:d(4.0)).
{40, -1}

> cvss_common:roundup(cvss_common:d(4.001)).
{41, -1}
```
""".
-spec roundup(decimal:decimal()) -> decimal:decimal().
roundup(Value) ->
    %% "Round up" means: if there's any fractional part beyond 1 decimal,
    %% round up to next 0.1. This is ceiling at 1 decimal place.
    Rounded = decimal:round(round_down, Value, 1),
    case decimal:cmp(Value, Rounded, ?DECIMAL_OPTS) of
        0 -> Rounded;
        1 -> decimal:add(Rounded, {1, -1});
        -1 -> Rounded
    end.

-doc "Return the smaller of two decimals.".
-spec dmin(decimal:decimal(), decimal:decimal()) -> decimal:decimal().
dmin(A, B) ->
    case decimal:cmp(A, B, ?DECIMAL_OPTS) of
        1 -> B;
        _ -> A
    end.

-doc "Return the larger of two decimals.".
-spec dmax(decimal:decimal(), decimal:decimal()) -> decimal:decimal().
dmax(A, B) ->
    case decimal:cmp(A, B, ?DECIMAL_OPTS) of
        -1 -> B;
        _ -> A
    end.

-doc """
Convert a CVSS score to a severity rating.
Thresholds are the same for all CVSS versions.

```erlang
> cvss_common:score_to_rating(0.0).
none

> cvss_common:score_to_rating(2.5).
low

> cvss_common:score_to_rating(5.0).
medium

> cvss_common:score_to_rating(7.5).
high

> cvss_common:score_to_rating(9.5).
critical
```
""".
-spec score_to_rating(cvss:score()) -> cvss:severity().
score_to_rating(Score) when Score == 0.0; Score == 0 ->
    none;
score_to_rating(Score) when Score >= 0.1, Score =< 3.9 ->
    low;
score_to_rating(Score) when Score >= 4.0, Score =< 6.9 ->
    medium;
score_to_rating(Score) when Score >= 7.0, Score =< 8.9 ->
    high;
score_to_rating(Score) when Score >= 9.0, Score =< 10.0 ->
    critical.

-doc "Decimal integer power: Base^N for non-negative integer N.".
-spec dpow(decimal:decimal(), non_neg_integer()) -> decimal:decimal().
dpow(_Base, 0) ->
    d(1);
dpow(Base, N) when N > 0 ->
    dpow(Base, N, d(1)).

dpow(_Base, 0, Acc) -> Acc;
dpow(Base, N, Acc) -> dpow(Base, N - 1, decimal:mult(Acc, Base)).

-doc """
Parse a list of `Key:Value` binary pairs into a map using the given parse function.
""".
-spec parse_metrics([binary()], ParseFun) -> {ok, map()} | {error, term()} when
    ParseFun :: fun((binary(), binary()) -> {ok, {atom(), term()}} | {error, term()}).
parse_metrics([], _ParseFun) ->
    {ok, #{}};
parse_metrics(Parts, ParseFun) ->
    parse_metrics(Parts, ParseFun, #{}).

parse_metrics([], _ParseFun, Acc) ->
    {ok, Acc};
parse_metrics([Pair | Rest], ParseFun, Acc) ->
    case binary:split(Pair, <<":">>) of
        [Key, Value] ->
            case ParseFun(Key, Value) of
                {ok, {AtomKey, AtomValue}} ->
                    case maps:is_key(AtomKey, Acc) of
                        true -> {error, {duplicate_metric, Key}};
                        false -> parse_metrics(Rest, ParseFun, Acc#{AtomKey => AtomValue})
                    end;
                {error, _} = Error ->
                    Error
            end;
        _ ->
            {error, malformed_vector}
    end.

-doc """
Check that all required keys are present in the metrics map.
""".
-spec check_required([atom()], map()) -> ok | {error, {missing_required_metric, atom()}}.
check_required([], _Metrics) ->
    ok;
check_required([Key | Rest], Metrics) ->
    case maps:is_key(Key, Metrics) of
        true -> check_required(Rest, Metrics);
        false -> {error, {missing_required_metric, Key}}
    end.

-doc """
Encode optional metrics, skipping any whose value is in `SkipValues`.
""".
-spec encode_optional([{iodata(), term(), fun((term()) -> iodata())}], [term()]) -> iolist().
encode_optional(Metrics, SkipValues) ->
    lists:filtermap(
        fun({Key, Value, Encoder}) ->
            case lists:member(Value, SkipValues) of
                true -> false;
                false -> {true, [<<$/>>, Key, <<":">>, Encoder(Value)]}
            end
        end,
        Metrics
    ).

-doc """
Check whether an optional metric value is valid.
Returns `true` if the value is `undefined` or a member of `ValidValues`.
""".
-spec valid_optional(term(), [term()]) -> boolean().
valid_optional(undefined, _ValidValues) ->
    true;
valid_optional(Value, ValidValues) ->
    lists:member(Value, ValidValues).

-doc """
Strip optional surrounding parentheses from a binary.
""".
-spec strip_parens(binary()) -> binary().
strip_parens(<<"(", Rest/binary>>) ->
    case binary:last(Rest) of
        $) -> binary:part(Rest, 0, byte_size(Rest) - 1);
        _ -> Rest
    end;
strip_parens(Vector) ->
    Vector.
