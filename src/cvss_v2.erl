%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v2).
-moduledoc """
CVSS 2.0 parsing, composition, validation, and scoring.

Use this module when working with CVSS 2.0 vectors directly. If the
version is not known ahead of time, use `m:cvss` instead.

Vector format: `AV:N/AC:L/Au:N/C:P/I:P/A:C`

See: https://www.first.org/cvss/v2/guide
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
    exploitability/0,
    remediation_level/0,
    report_confidence/0,
    cdp/0,
    td/0,
    requirement/0
]).

-include("cvss_v2.hrl").

-type av() :: local | adjacent_network | network.
-type ac() :: high | medium | low.
-type au() :: multiple | single | none.
-type impact() :: none | partial | complete.
-type exploitability() :: unproven | proof_of_concept | functional | high | not_defined.
-type remediation_level() ::
    official_fix | temporary_fix | workaround | unavailable | not_defined.
-type report_confidence() :: unconfirmed | uncorroborated | confirmed | not_defined.
-type cdp() :: none | low | low_medium | medium_high | high | not_defined.
-type td() :: none | low | medium | high | not_defined.
-type requirement() :: low | medium | high | not_defined.

-type cvss() :: #cvss_v2{}.

%%====================================================================
%% API
%%====================================================================

-doc """
Parse a CVSS 2.0 vector string.
Format: AV:N/AC:L/Au:N/C:P/I:P/A:C (parentheses optional)

```erlang
> cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>).
{ok, #cvss_v2{av = network, ac = low, au = none,
              c = complete, i = complete, a = complete}}

> cvss_v2:parse(<<"(AV:N/AC:L/Au:N/C:P/I:P/A:C)">>).
{ok, #cvss_v2{av = network, ac = low, au = none,
              c = partial, i = partial, a = complete}}

> cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:W/RC:C">>).
{ok, #cvss_v2{av = network, ac = low, au = none,
              c = complete, i = complete, a = complete,
              e = functional, rl = workaround, rc = confirmed}}

> cvss_v2:parse(<<"AV:X/AC:L/Au:N/C:C/I:C/A:C">>).
{error, {invalid_metric, <<"AV">>, <<"X">>}}
```
""".
-spec parse(binary()) -> {ok, cvss_v2:cvss()} | {error, cvss:parse_error()}.
parse(Vector) when is_binary(Vector) ->
    %% Strip optional parentheses
    Stripped = cvss_common:strip_parens(Vector),
    case cvss_common:parse_metrics(binary:split(Stripped, <<"/">>, [global]), fun parse_metric/2) of
        {ok, Metrics} ->
            build_record(Metrics);
        {error, _} = Error ->
            Error
    end.

-doc """
Compose a CVSS 2.0 record into a vector string.

```erlang
> iolist_to_binary(cvss_v2:compose(#cvss_v2{av = network, ac = low, au = none,
                                           c = complete, i = complete, a = complete})).
<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>
```
""".
-spec compose(cvss_v2:cvss()) -> iolist().
compose(#cvss_v2{} = Cvss) ->
    Base = [
        <<"AV:">>,
        encode_av(Cvss#cvss_v2.av),
        <<"/AC:">>,
        encode_ac(Cvss#cvss_v2.ac),
        <<"/Au:">>,
        encode_au(Cvss#cvss_v2.au),
        <<"/C:">>,
        encode_impact(Cvss#cvss_v2.c),
        <<"/I:">>,
        encode_impact(Cvss#cvss_v2.i),
        <<"/A:">>,
        encode_impact(Cvss#cvss_v2.a)
    ],
    Temporal = cvss_common:encode_optional(
        [
            {<<"E">>, Cvss#cvss_v2.e, fun encode_exploitability/1},
            {<<"RL">>, Cvss#cvss_v2.rl, fun encode_remediation_level/1},
            {<<"RC">>, Cvss#cvss_v2.rc, fun encode_report_confidence/1}
        ],
        [undefined]
    ),
    Environmental = cvss_common:encode_optional(
        [
            {<<"CDP">>, Cvss#cvss_v2.cdp, fun encode_cdp/1},
            {<<"TD">>, Cvss#cvss_v2.td, fun encode_td/1},
            {<<"CR">>, Cvss#cvss_v2.cr, fun encode_requirement/1},
            {<<"IR">>, Cvss#cvss_v2.ir, fun encode_requirement/1},
            {<<"AR">>, Cvss#cvss_v2.ar, fun encode_requirement/1}
        ],
        [undefined]
    ),
    [Base, Temporal, Environmental].

-doc """
Check whether a CVSS 2.0 value is valid.

Accepts either a vector string or a parsed record.

```erlang
> cvss_v2:valid(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>).
true

> cvss_v2:valid(#cvss_v2{av = network, ac = low, au = none,
                         c = complete, i = complete, a = complete}).
true

> cvss_v2:valid(<<"AV:X/AC:L/Au:N/C:C/I:C/A:C">>).
false
```
""".
-spec valid(iodata() | cvss_v2:cvss()) -> boolean().
valid(#cvss_v2{av = AV, ac = AC, au = Au, c = C, i = I, a = A} = Cvss) ->
    ValidBase =
        lists:member(AV, [local, adjacent_network, network]) andalso
            lists:member(AC, [high, medium, low]) andalso
            lists:member(Au, [multiple, single, none]) andalso
            lists:member(C, [none, partial, complete]) andalso
            lists:member(I, [none, partial, complete]) andalso
            lists:member(A, [none, partial, complete]),
    ValidTemporal =
        cvss_common:valid_optional(Cvss#cvss_v2.e, [
            unproven, proof_of_concept, functional, high, not_defined
        ]) andalso
            cvss_common:valid_optional(Cvss#cvss_v2.rl, [
                official_fix, temporary_fix, workaround, unavailable, not_defined
            ]) andalso
            cvss_common:valid_optional(Cvss#cvss_v2.rc, [
                unconfirmed, uncorroborated, confirmed, not_defined
            ]),
    ValidEnvironmental =
        cvss_common:valid_optional(Cvss#cvss_v2.cdp, [
            none, low, low_medium, medium_high, high, not_defined
        ]) andalso
            cvss_common:valid_optional(Cvss#cvss_v2.td, [none, low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v2.cr, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v2.ir, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v2.ar, [low, medium, high, not_defined]),
    ValidBase andalso ValidTemporal andalso ValidEnvironmental;
valid(Vector) ->
    case parse(iolist_to_binary(Vector)) of
        {ok, Cvss} -> valid(Cvss);
        {error, _} -> false
    end.

-doc """
Calculate the CVSS 2.0 score.
Returns the most relevant score: Environmental > Temporal > Base.

```erlang
> {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>).
> cvss_v2:score(Cvss).
10.0

> {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:N/I:N/A:N">>).
> cvss_v2:score(Cvss2).
0.0

> {ok, Cvss3} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:N/I:N/A:C">>).
> cvss_v2:score(Cvss3).
7.8
```
""".
-spec score(cvss_v2:cvss()) -> cvss:score().
score(#cvss_v2{} = Cvss) ->
    BaseScore = calculate_base_score(Cvss),
    TemporalScore = calculate_temporal_score(Cvss, BaseScore),
    cvss_common:to_float(calculate_environmental_score(Cvss, TemporalScore)).

-doc """
Calculate the CVSS 2.0 Base Score.

```erlang
> {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>).
> cvss_v2:base_score(Cvss).
10.0
```
""".
-spec base_score(cvss_v2:cvss()) -> cvss:score().
base_score(#cvss_v2{} = Cvss) ->
    cvss_common:to_float(calculate_base_score(Cvss)).

-doc """
Calculate the CVSS 2.0 Temporal Score. Returns the Base Score if no temporal metrics are present.

```erlang
> {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC">>).
> cvss_v2:temporal_score(Cvss).
6.7
```
""".
-spec temporal_score(cvss_v2:cvss()) -> cvss:score().
temporal_score(#cvss_v2{} = Cvss) ->
    cvss_common:to_float(calculate_temporal_score(Cvss, calculate_base_score(Cvss))).

-doc """
Calculate the CVSS 2.0 Environmental Score. Returns the Temporal Score if no environmental metrics are present.

```erlang
> {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:H/AR:H">>).
> cvss_v2:environmental_score(Cvss).
10.0
```
""".
-spec environmental_score(cvss_v2:cvss()) -> cvss:score().
environmental_score(#cvss_v2{} = Cvss) ->
    BaseScore = calculate_base_score(Cvss),
    TemporalScore = calculate_temporal_score(Cvss, BaseScore),
    cvss_common:to_float(calculate_environmental_score(Cvss, TemporalScore)).

%%====================================================================
%% Internal - Parsing
%%====================================================================

parse_metric(<<"AV">>, <<"L">>) -> {ok, {av, local}};
parse_metric(<<"AV">>, <<"A">>) -> {ok, {av, adjacent_network}};
parse_metric(<<"AV">>, <<"N">>) -> {ok, {av, network}};
parse_metric(<<"AC">>, <<"H">>) -> {ok, {ac, high}};
parse_metric(<<"AC">>, <<"M">>) -> {ok, {ac, medium}};
parse_metric(<<"AC">>, <<"L">>) -> {ok, {ac, low}};
parse_metric(<<"Au">>, <<"M">>) -> {ok, {au, multiple}};
parse_metric(<<"Au">>, <<"S">>) -> {ok, {au, single}};
parse_metric(<<"Au">>, <<"N">>) -> {ok, {au, none}};
parse_metric(<<"C">>, V) -> parse_impact(c, V);
parse_metric(<<"I">>, V) -> parse_impact(i, V);
parse_metric(<<"A">>, V) -> parse_impact(a, V);
parse_metric(<<"E">>, <<"U">>) -> {ok, {e, unproven}};
parse_metric(<<"E">>, <<"POC">>) -> {ok, {e, proof_of_concept}};
parse_metric(<<"E">>, <<"F">>) -> {ok, {e, functional}};
parse_metric(<<"E">>, <<"H">>) -> {ok, {e, high}};
parse_metric(<<"E">>, <<"ND">>) -> {ok, {e, not_defined}};
parse_metric(<<"RL">>, <<"OF">>) -> {ok, {rl, official_fix}};
parse_metric(<<"RL">>, <<"TF">>) -> {ok, {rl, temporary_fix}};
parse_metric(<<"RL">>, <<"W">>) -> {ok, {rl, workaround}};
parse_metric(<<"RL">>, <<"U">>) -> {ok, {rl, unavailable}};
parse_metric(<<"RL">>, <<"ND">>) -> {ok, {rl, not_defined}};
parse_metric(<<"RC">>, <<"UC">>) -> {ok, {rc, unconfirmed}};
parse_metric(<<"RC">>, <<"UR">>) -> {ok, {rc, uncorroborated}};
parse_metric(<<"RC">>, <<"C">>) -> {ok, {rc, confirmed}};
parse_metric(<<"RC">>, <<"ND">>) -> {ok, {rc, not_defined}};
parse_metric(<<"CDP">>, <<"N">>) -> {ok, {cdp, none}};
parse_metric(<<"CDP">>, <<"L">>) -> {ok, {cdp, low}};
parse_metric(<<"CDP">>, <<"LM">>) -> {ok, {cdp, low_medium}};
parse_metric(<<"CDP">>, <<"MH">>) -> {ok, {cdp, medium_high}};
parse_metric(<<"CDP">>, <<"H">>) -> {ok, {cdp, high}};
parse_metric(<<"CDP">>, <<"ND">>) -> {ok, {cdp, not_defined}};
parse_metric(<<"TD">>, <<"N">>) -> {ok, {td, none}};
parse_metric(<<"TD">>, <<"L">>) -> {ok, {td, low}};
parse_metric(<<"TD">>, <<"M">>) -> {ok, {td, medium}};
parse_metric(<<"TD">>, <<"H">>) -> {ok, {td, high}};
parse_metric(<<"TD">>, <<"ND">>) -> {ok, {td, not_defined}};
parse_metric(<<"CR">>, V) -> parse_requirement(cr, V);
parse_metric(<<"IR">>, V) -> parse_requirement(ir, V);
parse_metric(<<"AR">>, V) -> parse_requirement(ar, V);
parse_metric(Key, Value) -> {error, {invalid_metric, Key, Value}}.

parse_impact(Field, <<"N">>) -> {ok, {Field, none}};
parse_impact(Field, <<"P">>) -> {ok, {Field, partial}};
parse_impact(Field, <<"C">>) -> {ok, {Field, complete}};
parse_impact(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_requirement(Field, <<"L">>) -> {ok, {Field, low}};
parse_requirement(Field, <<"M">>) -> {ok, {Field, medium}};
parse_requirement(Field, <<"H">>) -> {ok, {Field, high}};
parse_requirement(Field, <<"ND">>) -> {ok, {Field, not_defined}};
parse_requirement(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

build_record(Metrics) ->
    Required = [av, ac, au, c, i, a],
    case cvss_common:check_required(Required, Metrics) of
        ok ->
            {ok, #cvss_v2{
                av = maps:get(av, Metrics),
                ac = maps:get(ac, Metrics),
                au = maps:get(au, Metrics),
                c = maps:get(c, Metrics),
                i = maps:get(i, Metrics),
                a = maps:get(a, Metrics),
                e = maps:get(e, Metrics, undefined),
                rl = maps:get(rl, Metrics, undefined),
                rc = maps:get(rc, Metrics, undefined),
                cdp = maps:get(cdp, Metrics, undefined),
                td = maps:get(td, Metrics, undefined),
                cr = maps:get(cr, Metrics, undefined),
                ir = maps:get(ir, Metrics, undefined),
                ar = maps:get(ar, Metrics, undefined)
            }};
        {error, _} = Error ->
            Error
    end.

%%====================================================================
%% Internal - Encoding
%%====================================================================

encode_av(local) -> <<"L">>;
encode_av(adjacent_network) -> <<"A">>;
encode_av(network) -> <<"N">>.

encode_ac(high) -> <<"H">>;
encode_ac(medium) -> <<"M">>;
encode_ac(low) -> <<"L">>.

encode_au(multiple) -> <<"M">>;
encode_au(single) -> <<"S">>;
encode_au(none) -> <<"N">>.

encode_impact(none) -> <<"N">>;
encode_impact(partial) -> <<"P">>;
encode_impact(complete) -> <<"C">>.

encode_exploitability(unproven) -> <<"U">>;
encode_exploitability(proof_of_concept) -> <<"POC">>;
encode_exploitability(functional) -> <<"F">>;
encode_exploitability(high) -> <<"H">>;
encode_exploitability(not_defined) -> <<"ND">>.

encode_remediation_level(official_fix) -> <<"OF">>;
encode_remediation_level(temporary_fix) -> <<"TF">>;
encode_remediation_level(workaround) -> <<"W">>;
encode_remediation_level(unavailable) -> <<"U">>;
encode_remediation_level(not_defined) -> <<"ND">>.

encode_report_confidence(unconfirmed) -> <<"UC">>;
encode_report_confidence(uncorroborated) -> <<"UR">>;
encode_report_confidence(confirmed) -> <<"C">>;
encode_report_confidence(not_defined) -> <<"ND">>.

encode_cdp(none) -> <<"N">>;
encode_cdp(low) -> <<"L">>;
encode_cdp(low_medium) -> <<"LM">>;
encode_cdp(medium_high) -> <<"MH">>;
encode_cdp(high) -> <<"H">>;
encode_cdp(not_defined) -> <<"ND">>.

encode_td(none) -> <<"N">>;
encode_td(low) -> <<"L">>;
encode_td(medium) -> <<"M">>;
encode_td(high) -> <<"H">>;
encode_td(not_defined) -> <<"ND">>.

encode_requirement(low) -> <<"L">>;
encode_requirement(medium) -> <<"M">>;
encode_requirement(high) -> <<"H">>;
encode_requirement(not_defined) -> <<"ND">>.

%%====================================================================
%% Internal - Scoring
%%====================================================================

-include("internal/decimal.hrl").

%% Coefficients from CVSS 2.0 spec (decimal values)
av_coeff(local) -> ?D(<<"0.395">>);
av_coeff(adjacent_network) -> ?D(<<"0.646">>);
av_coeff(network) -> ?ONE.

ac_coeff(high) -> ?D(<<"0.35">>);
ac_coeff(medium) -> ?D(<<"0.61">>);
ac_coeff(low) -> ?D(<<"0.71">>).

au_coeff(multiple) -> ?D(<<"0.45">>);
au_coeff(single) -> ?D(<<"0.56">>);
au_coeff(none) -> ?D(<<"0.704">>).

impact_coeff(none) -> ?ZERO;
impact_coeff(partial) -> ?D(<<"0.275">>);
impact_coeff(complete) -> ?D(<<"0.660">>).

exploitability_coeff(undefined) -> ?ONE;
exploitability_coeff(unproven) -> ?D(<<"0.85">>);
exploitability_coeff(proof_of_concept) -> ?D(<<"0.9">>);
exploitability_coeff(functional) -> ?D(<<"0.95">>);
exploitability_coeff(high) -> ?ONE;
exploitability_coeff(not_defined) -> ?ONE.

remediation_level_coeff(undefined) -> ?ONE;
remediation_level_coeff(official_fix) -> ?D(<<"0.87">>);
remediation_level_coeff(temporary_fix) -> ?D(<<"0.9">>);
remediation_level_coeff(workaround) -> ?D(<<"0.95">>);
remediation_level_coeff(unavailable) -> ?ONE;
remediation_level_coeff(not_defined) -> ?ONE.

report_confidence_coeff(undefined) -> ?ONE;
report_confidence_coeff(unconfirmed) -> ?D(<<"0.9">>);
report_confidence_coeff(uncorroborated) -> ?D(<<"0.95">>);
report_confidence_coeff(confirmed) -> ?ONE;
report_confidence_coeff(not_defined) -> ?ONE.

cdp_coeff(undefined) -> ?ZERO;
cdp_coeff(none) -> ?ZERO;
cdp_coeff(low) -> ?D(<<"0.1">>);
cdp_coeff(low_medium) -> ?D(<<"0.3">>);
cdp_coeff(medium_high) -> ?D(<<"0.4">>);
cdp_coeff(high) -> ?D(<<"0.5">>);
cdp_coeff(not_defined) -> ?ZERO.

td_coeff(undefined) -> ?ONE;
td_coeff(none) -> ?ZERO;
td_coeff(low) -> ?D(<<"0.25">>);
td_coeff(medium) -> ?D(<<"0.75">>);
td_coeff(high) -> ?ONE;
td_coeff(not_defined) -> ?ONE.

requirement_coeff(undefined) -> ?ONE;
requirement_coeff(low) -> ?D(<<"0.5">>);
requirement_coeff(medium) -> ?ONE;
requirement_coeff(high) -> ?D(<<"1.51">>);
requirement_coeff(not_defined) -> ?ONE.

exploitability_sub_score(AV, AC, Au) ->
    cvss_decimal:mult(
        cvss_decimal:mult(
            cvss_decimal:mult(?D(20), av_coeff(AV)),
            ac_coeff(AC)
        ),
        au_coeff(Au)
    ).

base_score_from_components(Impact, Exploitability) ->
    FImpact =
        case cvss_decimal:is_zero(Impact) of
            true -> ?ZERO;
            false -> ?D(<<"1.176">>)
        end,
    Score = cvss_decimal:mult(
        cvss_decimal:sub(
            cvss_decimal:add(
                cvss_decimal:mult(?D(<<"0.6">>), Impact),
                cvss_decimal:mult(?D(<<"0.4">>), Exploitability)
            ),
            ?D(<<"1.5">>)
        ),
        FImpact
    ),
    cvss_common:round_v1_v2(Score).

calculate_base_score(#cvss_v2{av = AV, ac = AC, au = Au, c = C, i = I, a = A}) ->
    Impact = cvss_decimal:mult(
        ?D(<<"10.41">>),
        cvss_decimal:sub(
            ?ONE,
            cvss_decimal:mult(
                cvss_decimal:mult(
                    cvss_decimal:sub(?ONE, impact_coeff(C)),
                    cvss_decimal:sub(?ONE, impact_coeff(I))
                ),
                cvss_decimal:sub(?ONE, impact_coeff(A))
            )
        )
    ),
    Exploitability = exploitability_sub_score(AV, AC, Au),
    cvss_common:dmax(?ZERO, base_score_from_components(Impact, Exploitability)).

calculate_temporal_score(#cvss_v2{e = E, rl = RL, rc = RC}, BaseScore) ->
    case has_temporal_metrics(E, RL, RC) of
        false ->
            BaseScore;
        true ->
            Score = cvss_decimal:mult(
                cvss_decimal:mult(
                    cvss_decimal:mult(BaseScore, exploitability_coeff(E)),
                    remediation_level_coeff(RL)
                ),
                report_confidence_coeff(RC)
            ),
            cvss_common:dmax(?ZERO, cvss_common:round_v1_v2(Score))
    end.

has_temporal_metrics(undefined, undefined, undefined) -> false;
has_temporal_metrics(_, _, _) -> true.

calculate_environmental_score(
    #cvss_v2{cdp = CDP, td = TD, cr = CR, ir = IR, ar = AR} = Cvss, TemporalScore
) ->
    case has_environmental_metrics(CDP, TD, CR, IR, AR) of
        false ->
            TemporalScore;
        true ->
            %% Calculate adjusted impact
            #cvss_v2{c = C, i = I, a = A} = Cvss,
            AdjustedImpact =
                cvss_common:dmin(
                    ?D(10),
                    cvss_decimal:mult(
                        ?D(<<"10.41">>),
                        cvss_decimal:sub(
                            ?ONE,
                            cvss_decimal:mult(
                                cvss_decimal:mult(
                                    cvss_decimal:sub(
                                        ?ONE,
                                        cvss_decimal:mult(impact_coeff(C), requirement_coeff(CR))
                                    ),
                                    cvss_decimal:sub(
                                        ?ONE,
                                        cvss_decimal:mult(impact_coeff(I), requirement_coeff(IR))
                                    )
                                ),
                                cvss_decimal:sub(
                                    ?ONE, cvss_decimal:mult(impact_coeff(A), requirement_coeff(AR))
                                )
                            )
                        )
                    )
                ),
            %% Recalculate base with adjusted impact
            #cvss_v2{av = AV, ac = AC, au = Au, e = E, rl = RL, rc = RC} = Cvss,
            Exploitability = exploitability_sub_score(AV, AC, Au),
            AdjustedBase = base_score_from_components(AdjustedImpact, Exploitability),
            AdjustedTemporal =
                cvss_common:round_v1_v2(
                    cvss_decimal:mult(
                        cvss_decimal:mult(
                            cvss_decimal:mult(AdjustedBase, exploitability_coeff(E)),
                            remediation_level_coeff(RL)
                        ),
                        report_confidence_coeff(RC)
                    )
                ),
            Score = cvss_decimal:mult(
                cvss_decimal:add(
                    AdjustedTemporal,
                    cvss_decimal:mult(
                        cvss_decimal:sub(?D(10), AdjustedTemporal),
                        cdp_coeff(CDP)
                    )
                ),
                td_coeff(TD)
            ),
            cvss_common:dmax(?ZERO, cvss_common:round_v1_v2(Score))
    end.

has_environmental_metrics(undefined, undefined, undefined, undefined, undefined) -> false;
has_environmental_metrics(_, _, _, _, _) -> true.
