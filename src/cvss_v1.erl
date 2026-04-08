%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v1).
-moduledoc """
CVSS 1.0 parsing, composition, validation, and scoring.

Use this module when working with CVSS 1.0 vectors directly. If the
version is not known ahead of time, use `m:cvss` instead.

Vector format: `AV:R/AC:L/Au:NR/C:C/I:C/A:C`

See: https://www.first.org/cvss/v1/guide
""".

-export([
    base_score/1, compose/1, environmental_score/1, parse/1, score/1, temporal_score/1, valid/1
]).

-export_type([
    cvss/0,
    av/0,
    ac/0,
    au/0,
    impact/0,
    impact_bias/0,
    exploitability/0,
    remediation_level/0,
    report_confidence/0,
    cdp/0,
    td/0
]).

-include("cvss_v1.hrl").

-type av() :: local | remote.
-type ac() :: high | low.
-type au() :: required | not_required.
-type impact() :: none | partial | complete.
-type impact_bias() :: normal | confidentiality | integrity | availability.
-type exploitability() :: unproven | proof_of_concept | functional | high.
-type remediation_level() :: official_fix | temporary_fix | workaround | unavailable.
-type report_confidence() :: unconfirmed | uncorroborated | confirmed.
-type cdp() :: none | low | medium | high.
-type td() :: none | low | medium | high.

-type cvss() :: #cvss_v1{}.

%%====================================================================
%% API
%%====================================================================

-doc """
Parse a CVSS 1.0 vector string.
Format: AV:R/AC:L/Au:NR/C:C/I:C/A:C

```erlang
> cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>).
{ok, #cvss_v1{av = remote, ac = low, au = not_required,
              c = complete, i = complete, a = complete}}

> cvss_v1:parse(<<"AV:L/AC:H/Au:R/C:P/I:P/A:N">>).
{ok, #cvss_v1{av = local, ac = high, au = required,
              c = partial, i = partial, a = none}}

> cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C">>).
{ok, #cvss_v1{av = remote, ac = low, au = not_required,
              c = complete, i = complete, a = complete,
              e = high, rl = unavailable, rc = confirmed}}

> cvss_v1:parse(<<"AV:X/AC:L/Au:NR/C:C/I:C/A:C">>).
{error, {invalid_metric, <<"AV">>, <<"X">>}}

> cvss_v1:parse(<<"AC:L/Au:NR/C:C/I:C/A:C">>).
{error, {missing_required_metric, av}}
```
""".
-spec parse(binary()) -> {ok, cvss_v1:cvss()} | {error, cvss:parse_error()}.
parse(Vector) when is_binary(Vector) ->
    case cvss_common:parse_metrics(binary:split(Vector, <<"/">>, [global]), fun parse_metric/2) of
        {ok, Metrics} ->
            build_record(Metrics);
        {error, _} = Error ->
            Error
    end.

-doc """
Compose a CVSS 1.0 record into a vector string.

```erlang
> iolist_to_binary(cvss_v1:compose(#cvss_v1{av = remote, ac = low, au = not_required,
                                           c = complete, i = complete, a = complete,
                                           ib = normal})).
<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>

> iolist_to_binary(cvss_v1:compose(#cvss_v1{av = remote, ac = low, au = not_required,
                                           c = complete, i = complete, a = complete,
                                           ib = normal,
                                           e = high, rl = unavailable, rc = confirmed})).
<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C">>
```
""".
-spec compose(cvss_v1:cvss()) -> iolist().
compose(#cvss_v1{} = Cvss) ->
    Base = [
        <<"AV:">>,
        encode_av(Cvss#cvss_v1.av),
        <<"/AC:">>,
        encode_ac(Cvss#cvss_v1.ac),
        <<"/Au:">>,
        encode_au(Cvss#cvss_v1.au),
        <<"/C:">>,
        encode_impact(Cvss#cvss_v1.c),
        <<"/I:">>,
        encode_impact(Cvss#cvss_v1.i),
        <<"/A:">>,
        encode_impact(Cvss#cvss_v1.a)
    ],
    ImpactBias =
        case Cvss#cvss_v1.ib of
            normal -> [];
            _ -> [<<"/IB:">>, encode_impact_bias(Cvss#cvss_v1.ib)]
        end,
    Temporal = cvss_common:encode_optional(
        [
            {<<"E">>, Cvss#cvss_v1.e, fun encode_exploitability/1},
            {<<"RL">>, Cvss#cvss_v1.rl, fun encode_remediation_level/1},
            {<<"RC">>, Cvss#cvss_v1.rc, fun encode_report_confidence/1}
        ],
        [undefined]
    ),
    Environmental = cvss_common:encode_optional(
        [
            {<<"CDP">>, Cvss#cvss_v1.cdp, fun encode_cdp/1},
            {<<"TD">>, Cvss#cvss_v1.td, fun encode_td/1}
        ],
        [undefined]
    ),
    [Base, ImpactBias, Temporal, Environmental].

-doc """
Check whether a CVSS 1.0 value is valid.

Accepts either a vector string or a parsed record.

```erlang
> cvss_v1:valid(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>).
true

> cvss_v1:valid(#cvss_v1{av = remote, ac = low, au = not_required,
                         c = complete, i = complete, a = complete,
                         ib = normal}).
true

> cvss_v1:valid(<<"AV:X/AC:L/Au:NR/C:C/I:C/A:C">>).
false
```
""".
-spec valid(iodata() | cvss_v1:cvss()) -> boolean().
valid(#cvss_v1{av = AV, ac = AC, au = Au, c = C, i = I, a = A, ib = IB} = Cvss) ->
    ValidBase =
        lists:member(AV, [local, remote]) andalso
            lists:member(AC, [high, low]) andalso
            lists:member(Au, [required, not_required]) andalso
            lists:member(C, [none, partial, complete]) andalso
            lists:member(I, [none, partial, complete]) andalso
            lists:member(A, [none, partial, complete]) andalso
            lists:member(IB, [normal, confidentiality, integrity, availability]),
    ValidTemporal =
        cvss_common:valid_optional(Cvss#cvss_v1.e, [unproven, proof_of_concept, functional, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v1.rl, [
                official_fix, temporary_fix, workaround, unavailable
            ]) andalso
            cvss_common:valid_optional(Cvss#cvss_v1.rc, [unconfirmed, uncorroborated, confirmed]),
    ValidEnvironmental =
        cvss_common:valid_optional(Cvss#cvss_v1.cdp, [none, low, medium, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v1.td, [none, low, medium, high]),
    ValidBase andalso ValidTemporal andalso ValidEnvironmental;
valid(Vector) ->
    case parse(iolist_to_binary(Vector)) of
        {ok, Cvss} -> valid(Cvss);
        {error, _} -> false
    end.

-doc """
Calculate the CVSS 1.0 score.
Returns the most relevant score: Environmental > Temporal > Base.

```erlang
> {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>).
> cvss_v1:score(Cvss).
10.0

> {ok, Cvss2} = cvss_v1:parse(<<"AV:L/AC:H/Au:NR/C:C/I:C/A:C">>).
> cvss_v1:score(Cvss2).
5.6

> {ok, Cvss3} = cvss_v1:parse(<<"AV:L/AC:H/Au:R/C:N/I:N/A:N">>).
> cvss_v1:score(Cvss3).
0.0
```
""".
-spec score(cvss_v1:cvss()) -> cvss:score().
score(#cvss_v1{} = Cvss) ->
    BaseScore = calculate_base_score(Cvss),
    TemporalScore = calculate_temporal_score(Cvss, BaseScore),
    cvss_common:to_float(calculate_environmental_score(Cvss, TemporalScore)).

-doc """
Calculate the CVSS 1.0 Base Score.

```erlang
> {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>).
> cvss_v1:base_score(Cvss).
10.0
```
""".
-spec base_score(cvss_v1:cvss()) -> cvss:score().
base_score(#cvss_v1{} = Cvss) ->
    cvss_common:to_float(calculate_base_score(Cvss)).

-doc """
Calculate the CVSS 1.0 Temporal Score. Returns the Base Score if no temporal metrics are present.

```erlang
> {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:U/RL:OF/RC:UC">>).
> cvss_v1:temporal_score(Cvss).
6.7
```
""".
-spec temporal_score(cvss_v1:cvss()) -> cvss:score().
temporal_score(#cvss_v1{} = Cvss) ->
    cvss_common:to_float(calculate_temporal_score(Cvss, calculate_base_score(Cvss))).

-doc """
Calculate the CVSS 1.0 Environmental Score. Returns the Temporal Score if no environmental metrics are present.

```erlang
> {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:L/TD:L">>).
> cvss_v1:environmental_score(Cvss).
2.5
```
""".
-spec environmental_score(cvss_v1:cvss()) -> cvss:score().
environmental_score(#cvss_v1{} = Cvss) ->
    BaseScore = calculate_base_score(Cvss),
    TemporalScore = calculate_temporal_score(Cvss, BaseScore),
    cvss_common:to_float(calculate_environmental_score(Cvss, TemporalScore)).

%%====================================================================
%% Internal - Parsing
%%====================================================================

parse_metric(<<"AV">>, <<"L">>) -> {ok, {av, local}};
parse_metric(<<"AV">>, <<"R">>) -> {ok, {av, remote}};
parse_metric(<<"AC">>, <<"H">>) -> {ok, {ac, high}};
parse_metric(<<"AC">>, <<"L">>) -> {ok, {ac, low}};
parse_metric(<<"Au">>, <<"R">>) -> {ok, {au, required}};
parse_metric(<<"Au">>, <<"NR">>) -> {ok, {au, not_required}};
parse_metric(<<"C">>, V) -> parse_impact(c, V);
parse_metric(<<"I">>, V) -> parse_impact(i, V);
parse_metric(<<"A">>, V) -> parse_impact(a, V);
parse_metric(<<"IB">>, <<"N">>) -> {ok, {ib, normal}};
parse_metric(<<"IB">>, <<"C">>) -> {ok, {ib, confidentiality}};
parse_metric(<<"IB">>, <<"I">>) -> {ok, {ib, integrity}};
parse_metric(<<"IB">>, <<"A">>) -> {ok, {ib, availability}};
parse_metric(<<"E">>, <<"U">>) -> {ok, {e, unproven}};
parse_metric(<<"E">>, <<"POC">>) -> {ok, {e, proof_of_concept}};
parse_metric(<<"E">>, <<"F">>) -> {ok, {e, functional}};
parse_metric(<<"E">>, <<"H">>) -> {ok, {e, high}};
parse_metric(<<"RL">>, <<"OF">>) -> {ok, {rl, official_fix}};
parse_metric(<<"RL">>, <<"TF">>) -> {ok, {rl, temporary_fix}};
parse_metric(<<"RL">>, <<"W">>) -> {ok, {rl, workaround}};
parse_metric(<<"RL">>, <<"U">>) -> {ok, {rl, unavailable}};
parse_metric(<<"RC">>, <<"UC">>) -> {ok, {rc, unconfirmed}};
parse_metric(<<"RC">>, <<"UR">>) -> {ok, {rc, uncorroborated}};
parse_metric(<<"RC">>, <<"C">>) -> {ok, {rc, confirmed}};
parse_metric(<<"CDP">>, <<"N">>) -> {ok, {cdp, none}};
parse_metric(<<"CDP">>, <<"L">>) -> {ok, {cdp, low}};
parse_metric(<<"CDP">>, <<"M">>) -> {ok, {cdp, medium}};
parse_metric(<<"CDP">>, <<"H">>) -> {ok, {cdp, high}};
parse_metric(<<"TD">>, <<"N">>) -> {ok, {td, none}};
parse_metric(<<"TD">>, <<"L">>) -> {ok, {td, low}};
parse_metric(<<"TD">>, <<"M">>) -> {ok, {td, medium}};
parse_metric(<<"TD">>, <<"H">>) -> {ok, {td, high}};
parse_metric(Key, Value) -> {error, {invalid_metric, Key, Value}}.

parse_impact(Field, <<"N">>) -> {ok, {Field, none}};
parse_impact(Field, <<"P">>) -> {ok, {Field, partial}};
parse_impact(Field, <<"C">>) -> {ok, {Field, complete}};
parse_impact(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

build_record(Metrics) ->
    Required = [av, ac, au, c, i, a],
    case cvss_common:check_required(Required, Metrics) of
        ok ->
            {ok, #cvss_v1{
                av = maps:get(av, Metrics),
                ac = maps:get(ac, Metrics),
                au = maps:get(au, Metrics),
                c = maps:get(c, Metrics),
                i = maps:get(i, Metrics),
                a = maps:get(a, Metrics),
                ib = maps:get(ib, Metrics, normal),
                e = maps:get(e, Metrics, undefined),
                rl = maps:get(rl, Metrics, undefined),
                rc = maps:get(rc, Metrics, undefined),
                cdp = maps:get(cdp, Metrics, undefined),
                td = maps:get(td, Metrics, undefined)
            }};
        {error, _} = Error ->
            Error
    end.

%%====================================================================
%% Internal - Encoding
%%====================================================================

encode_av(local) -> <<"L">>;
encode_av(remote) -> <<"R">>.

encode_ac(high) -> <<"H">>;
encode_ac(low) -> <<"L">>.

encode_au(required) -> <<"R">>;
encode_au(not_required) -> <<"NR">>.

encode_impact(none) -> <<"N">>;
encode_impact(partial) -> <<"P">>;
encode_impact(complete) -> <<"C">>.

encode_impact_bias(normal) -> <<"N">>;
encode_impact_bias(confidentiality) -> <<"C">>;
encode_impact_bias(integrity) -> <<"I">>;
encode_impact_bias(availability) -> <<"A">>.

encode_exploitability(unproven) -> <<"U">>;
encode_exploitability(proof_of_concept) -> <<"POC">>;
encode_exploitability(functional) -> <<"F">>;
encode_exploitability(high) -> <<"H">>.

encode_remediation_level(official_fix) -> <<"OF">>;
encode_remediation_level(temporary_fix) -> <<"TF">>;
encode_remediation_level(workaround) -> <<"W">>;
encode_remediation_level(unavailable) -> <<"U">>.

encode_report_confidence(unconfirmed) -> <<"UC">>;
encode_report_confidence(uncorroborated) -> <<"UR">>;
encode_report_confidence(confirmed) -> <<"C">>.

encode_cdp(none) -> <<"N">>;
encode_cdp(low) -> <<"L">>;
encode_cdp(medium) -> <<"M">>;
encode_cdp(high) -> <<"H">>.

encode_td(none) -> <<"N">>;
encode_td(low) -> <<"L">>;
encode_td(medium) -> <<"M">>;
encode_td(high) -> <<"H">>.

%%====================================================================
%% Internal - Scoring
%%====================================================================

-include("internal/decimal.hrl").

%% Coefficients from CVSS 1.0 spec (decimal values)
av_coeff(local) -> ?D(<<"0.7">>);
av_coeff(remote) -> ?D(1).

ac_coeff(high) -> ?D(<<"0.8">>);
ac_coeff(low) -> ?D(1).

au_coeff(required) -> ?D(<<"0.6">>);
au_coeff(not_required) -> ?D(1).

impact_coeff(none) -> ?D(0);
impact_coeff(partial) -> ?D(<<"0.7">>);
impact_coeff(complete) -> ?D(1).

%% Impact bias coefficients
impact_bias(normal) -> {?D(<<"0.333">>), ?D(<<"0.333">>), ?D(<<"0.333">>)};
impact_bias(confidentiality) -> {?D(<<"0.5">>), ?D(<<"0.25">>), ?D(<<"0.25">>)};
impact_bias(integrity) -> {?D(<<"0.25">>), ?D(<<"0.5">>), ?D(<<"0.25">>)};
impact_bias(availability) -> {?D(<<"0.25">>), ?D(<<"0.25">>), ?D(<<"0.5">>)}.

exploitability_coeff(undefined) -> ?D(1);
exploitability_coeff(unproven) -> ?D(<<"0.85">>);
exploitability_coeff(proof_of_concept) -> ?D(<<"0.9">>);
exploitability_coeff(functional) -> ?D(<<"0.95">>);
exploitability_coeff(high) -> ?D(1).

remediation_level_coeff(undefined) -> ?D(1);
remediation_level_coeff(official_fix) -> ?D(<<"0.87">>);
remediation_level_coeff(temporary_fix) -> ?D(<<"0.9">>);
remediation_level_coeff(workaround) -> ?D(<<"0.95">>);
remediation_level_coeff(unavailable) -> ?D(1).

report_confidence_coeff(undefined) -> ?D(1);
report_confidence_coeff(unconfirmed) -> ?D(<<"0.9">>);
report_confidence_coeff(uncorroborated) -> ?D(<<"0.95">>);
report_confidence_coeff(confirmed) -> ?D(1).

cdp_coeff(undefined) -> ?D(0);
cdp_coeff(none) -> ?D(0);
cdp_coeff(low) -> ?D(<<"0.1">>);
cdp_coeff(medium) -> ?D(<<"0.3">>);
cdp_coeff(high) -> ?D(<<"0.5">>).

td_coeff(undefined) -> ?D(1);
td_coeff(none) -> ?D(0);
td_coeff(low) -> ?D(<<"0.25">>);
td_coeff(medium) -> ?D(<<"0.75">>);
td_coeff(high) -> ?D(1).

calculate_base_score(#cvss_v1{av = AV, ac = AC, au = Au, c = C, i = I, a = A, ib = IB}) ->
    {ConfBias, IntegBias, AvailBias} = impact_bias(IB),
    ImpactScore =
        cvss_decimal:add(
            cvss_decimal:add(
                cvss_decimal:mult(impact_coeff(C), ConfBias),
                cvss_decimal:mult(impact_coeff(I), IntegBias)
            ),
            cvss_decimal:mult(impact_coeff(A), AvailBias)
        ),
    Score = cvss_decimal:mult(
        cvss_decimal:mult(
            cvss_decimal:mult(
                cvss_decimal:mult(?D(10), av_coeff(AV)),
                ac_coeff(AC)
            ),
            au_coeff(Au)
        ),
        ImpactScore
    ),
    cvss_common:round_v1_v2(Score).

calculate_temporal_score(#cvss_v1{e = E, rl = RL, rc = RC}, BaseScore) ->
    case {E, RL, RC} of
        {undefined, undefined, undefined} ->
            BaseScore;
        _ ->
            Score = cvss_decimal:mult(
                cvss_decimal:mult(
                    cvss_decimal:mult(BaseScore, exploitability_coeff(E)),
                    remediation_level_coeff(RL)
                ),
                report_confidence_coeff(RC)
            ),
            cvss_common:round_v1_v2(Score)
    end.

calculate_environmental_score(#cvss_v1{cdp = CDP, td = TD}, TemporalScore) ->
    case {CDP, TD} of
        {undefined, undefined} ->
            TemporalScore;
        _ ->
            Score = cvss_decimal:mult(
                cvss_decimal:add(
                    TemporalScore,
                    cvss_decimal:mult(
                        cvss_decimal:sub(?D(10), TemporalScore),
                        cdp_coeff(CDP)
                    )
                ),
                td_coeff(TD)
            ),
            cvss_common:round_v1_v2(Score)
    end.
