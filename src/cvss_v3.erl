%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v3).
-moduledoc """
CVSS 3.0/3.1 parsing, composition, validation, and scoring.

Use this module when working with CVSS 3.x vectors directly. If the
version is not known ahead of time, use `m:cvss` instead.

Vector format: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

See: https://www.first.org/cvss/v3.1/specification-document
""".

-export([
    base_score/1, compose/1, environmental_score/1, parse/1, score/1, temporal_score/1, valid/1
]).

-export_type([
    cvss/0,
    version/0,
    av/0,
    ac/0,
    pr/0,
    ui/0,
    scope/0,
    cia/0,
    exploit_maturity/0,
    remediation_level/0,
    report_confidence/0,
    requirement/0
]).

-include("cvss_v3.hrl").

-type version() :: '3.0' | '3.1'.
-type av() :: network | adjacent | local | physical.
-type ac() :: low | high.
-type pr() :: none | low | high.
-type ui() :: none | required.
-type scope() :: unchanged | changed.
-type cia() :: none | low | high.
-type exploit_maturity() :: unproven | poc | functional | high | not_defined.
-type remediation_level() ::
    official_fix | temporary_fix | workaround | unavailable | not_defined.
-type report_confidence() :: unknown | reasonable | confirmed | not_defined.
-type requirement() :: low | medium | high | not_defined.

-type cvss() :: #cvss_v3{}.

%%====================================================================
%% API
%%====================================================================

-doc """
Parse a CVSS 3.0/3.1 vector string.
Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

```erlang
> cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
{ok, #cvss_v3{version = '3.1', av = network, ac = low, pr = none,
              ui = none, s = unchanged, c = high, i = high, a = high}}

> cvss_v3:parse(<<"CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L">>).
{ok, #cvss_v3{version = '3.0', av = adjacent, ac = high, pr = low,
              ui = required, s = changed, c = low, i = low, a = low}}

> cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:R">>).
{ok, #cvss_v3{version = '3.1', av = network, ac = low, pr = none,
              ui = none, s = unchanged, c = high, i = high, a = high,
              e = functional, rl = workaround, rc = reasonable}}

> cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L">>).
{error, {missing_required_metric, pr}}

> cvss_v3:parse(<<"not a vector">>).
{error, malformed_vector}
```
""".
-spec parse(binary()) -> {ok, cvss_v3:cvss()} | {error, cvss:parse_error()}.
parse(<<"CVSS:3.0/", Rest/binary>>) ->
    parse_body('3.0', Rest);
parse(<<"CVSS:3.1/", Rest/binary>>) ->
    parse_body('3.1', Rest);
parse(<<"CVSS:", _/binary>> = Vector) ->
    {error, {invalid_prefix, Vector}};
parse(_) ->
    {error, malformed_vector}.

-doc """
Compose a CVSS 3.x record into a vector string.

```erlang
> iolist_to_binary(cvss_v3:compose(#cvss_v3{version = '3.1', av = network, ac = low,
                                           pr = none, ui = none, s = unchanged,
                                           c = high, i = high, a = high})).
<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>
```
""".
-spec compose(cvss_v3:cvss()) -> iolist().
compose(#cvss_v3{version = Version} = Cvss) ->
    Prefix =
        case Version of
            '3.0' -> <<"CVSS:3.0/">>;
            '3.1' -> <<"CVSS:3.1/">>
        end,
    Base = [
        Prefix,
        <<"AV:">>,
        encode_av(Cvss#cvss_v3.av),
        <<"/AC:">>,
        encode_ac(Cvss#cvss_v3.ac),
        <<"/PR:">>,
        encode_pr(Cvss#cvss_v3.pr),
        <<"/UI:">>,
        encode_ui(Cvss#cvss_v3.ui),
        <<"/S:">>,
        encode_scope(Cvss#cvss_v3.s),
        <<"/C:">>,
        encode_cia(Cvss#cvss_v3.c),
        <<"/I:">>,
        encode_cia(Cvss#cvss_v3.i),
        <<"/A:">>,
        encode_cia(Cvss#cvss_v3.a)
    ],
    Temporal = cvss_common:encode_optional(
        [
            {<<"E">>, Cvss#cvss_v3.e, fun encode_exploit_maturity/1},
            {<<"RL">>, Cvss#cvss_v3.rl, fun encode_remediation_level/1},
            {<<"RC">>, Cvss#cvss_v3.rc, fun encode_report_confidence/1}
        ],
        [undefined, not_defined]
    ),
    Environmental = cvss_common:encode_optional(
        [
            {<<"CR">>, Cvss#cvss_v3.cr, fun encode_requirement/1},
            {<<"IR">>, Cvss#cvss_v3.ir, fun encode_requirement/1},
            {<<"AR">>, Cvss#cvss_v3.ar, fun encode_requirement/1},
            {<<"MAV">>, Cvss#cvss_v3.mav, fun encode_av/1},
            {<<"MAC">>, Cvss#cvss_v3.mac, fun encode_ac/1},
            {<<"MPR">>, Cvss#cvss_v3.mpr, fun encode_pr/1},
            {<<"MUI">>, Cvss#cvss_v3.mui, fun encode_ui/1},
            {<<"MS">>, Cvss#cvss_v3.ms, fun encode_scope/1},
            {<<"MC">>, Cvss#cvss_v3.mc, fun encode_cia/1},
            {<<"MI">>, Cvss#cvss_v3.mi, fun encode_cia/1},
            {<<"MA">>, Cvss#cvss_v3.ma, fun encode_cia/1}
        ],
        [undefined, not_defined]
    ),
    [Base, Temporal, Environmental].

-doc """
Check whether a CVSS 3.x value is valid.

Accepts either a vector string or a parsed record.

```erlang
> cvss_v3:valid(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
true

> cvss_v3:valid(#cvss_v3{version = '3.1', av = network, ac = low,
                         pr = none, ui = none, s = unchanged,
                         c = high, i = high, a = high}).
true

> cvss_v3:valid(<<"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
false
```
""".
-spec valid(iodata() | cvss_v3:cvss()) -> boolean().
valid(#cvss_v3{} = Cvss) ->
    ValidVersion = lists:member(Cvss#cvss_v3.version, ['3.0', '3.1']),
    ValidBase =
        lists:member(Cvss#cvss_v3.av, [network, adjacent, local, physical]) andalso
            lists:member(Cvss#cvss_v3.ac, [low, high]) andalso
            lists:member(Cvss#cvss_v3.pr, [none, low, high]) andalso
            lists:member(Cvss#cvss_v3.ui, [none, required]) andalso
            lists:member(Cvss#cvss_v3.s, [unchanged, changed]) andalso
            lists:member(Cvss#cvss_v3.c, [none, low, high]) andalso
            lists:member(Cvss#cvss_v3.i, [none, low, high]) andalso
            lists:member(Cvss#cvss_v3.a, [none, low, high]),
    ValidTemporal =
        cvss_common:valid_optional(Cvss#cvss_v3.e, [unproven, poc, functional, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.rl, [
                official_fix, temporary_fix, workaround, unavailable, not_defined
            ]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.rc, [
                unknown, reasonable, confirmed, not_defined
            ]),
    ValidEnvironmental =
        cvss_common:valid_optional(Cvss#cvss_v3.cr, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.ir, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.ar, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.mav, [
                network, adjacent, local, physical, not_defined
            ]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.mac, [low, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.mpr, [none, low, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.mui, [none, required, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.ms, [unchanged, changed, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.mc, [none, low, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.mi, [none, low, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v3.ma, [none, low, high, not_defined]),
    ValidVersion andalso ValidBase andalso ValidTemporal andalso ValidEnvironmental;
valid(Vector) ->
    case parse(iolist_to_binary(Vector)) of
        {ok, Cvss} -> valid(Cvss);
        {error, _} -> false
    end.

-doc """
Calculate the CVSS 3.x score.
Returns the most relevant score: Environmental > Temporal > Base.

```erlang
> {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
> cvss_v3:score(Cvss).
9.8

> {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H">>).
> cvss_v3:score(Cvss2).
10.0

> {ok, Cvss3} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N">>).
> cvss_v3:score(Cvss3).
0.0
```
""".
-spec score(cvss_v3:cvss()) -> cvss:score().
score(#cvss_v3{} = Cvss) ->
    case has_environmental_metrics(Cvss) of
        true ->
            cvss_common:to_float(calculate_environmental_score(Cvss));
        false ->
            BaseScore = calculate_base_score(Cvss),
            cvss_common:to_float(calculate_temporal_score(Cvss, BaseScore))
    end.

-doc """
Calculate the CVSS 3.x Base Score.

```erlang
> {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>).
> cvss_v3:base_score(Cvss).
9.8
```
""".
-spec base_score(cvss_v3:cvss()) -> cvss:score().
base_score(#cvss_v3{} = Cvss) ->
    cvss_common:to_float(calculate_base_score(Cvss)).

-doc """
Calculate the CVSS 3.x Temporal Score. Returns the Base Score if no temporal metrics are present.

```erlang
> {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:U">>).
> cvss_v3:temporal_score(Cvss).
8.1
```
""".
-spec temporal_score(cvss_v3:cvss()) -> cvss:score().
temporal_score(#cvss_v3{} = Cvss) ->
    cvss_common:to_float(calculate_temporal_score(Cvss, calculate_base_score(Cvss))).

-doc """
Calculate the CVSS 3.x Environmental Score. Returns the Temporal Score if no environmental metrics are present.

```erlang
> {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N">>).
> cvss_v3:environmental_score(Cvss).
0.0
```
""".
-spec environmental_score(cvss_v3:cvss()) -> cvss:score().
environmental_score(#cvss_v3{} = Cvss) ->
    case has_environmental_metrics(Cvss) of
        true ->
            cvss_common:to_float(calculate_environmental_score(Cvss));
        false ->
            temporal_score(Cvss)
    end.

%%====================================================================
%% Internal - Parsing
%%====================================================================

parse_body(Version, Body) ->
    case cvss_common:parse_metrics(binary:split(Body, <<"/">>, [global]), fun parse_metric/2) of
        {ok, Metrics} ->
            build_record(Version, Metrics);
        {error, _} = Error ->
            Error
    end.

parse_metric(<<"AV">>, V) -> parse_av(av, V);
parse_metric(<<"AC">>, V) -> parse_ac(ac, V);
parse_metric(<<"PR">>, V) -> parse_pr(pr, V);
parse_metric(<<"UI">>, V) -> parse_ui(ui, V);
parse_metric(<<"S">>, V) -> parse_scope(s, V);
parse_metric(<<"C">>, V) -> parse_cia(c, V);
parse_metric(<<"I">>, V) -> parse_cia(i, V);
parse_metric(<<"A">>, V) -> parse_cia(a, V);
parse_metric(<<"E">>, V) -> parse_exploit_maturity(e, V);
parse_metric(<<"RL">>, V) -> parse_remediation_level(rl, V);
parse_metric(<<"RC">>, V) -> parse_report_confidence(rc, V);
parse_metric(<<"CR">>, V) -> parse_requirement(cr, V);
parse_metric(<<"IR">>, V) -> parse_requirement(ir, V);
parse_metric(<<"AR">>, V) -> parse_requirement(ar, V);
parse_metric(<<"MAV">>, V) -> parse_av(mav, V);
parse_metric(<<"MAC">>, V) -> parse_ac(mac, V);
parse_metric(<<"MPR">>, V) -> parse_pr(mpr, V);
parse_metric(<<"MUI">>, V) -> parse_ui(mui, V);
parse_metric(<<"MS">>, V) -> parse_scope(ms, V);
parse_metric(<<"MC">>, V) -> parse_cia(mc, V);
parse_metric(<<"MI">>, V) -> parse_cia(mi, V);
parse_metric(<<"MA">>, V) -> parse_cia(ma, V);
parse_metric(Key, Value) -> {error, {invalid_metric, Key, Value}}.

parse_av(Field, <<"N">>) -> {ok, {Field, network}};
parse_av(Field, <<"A">>) -> {ok, {Field, adjacent}};
parse_av(Field, <<"L">>) -> {ok, {Field, local}};
parse_av(Field, <<"P">>) -> {ok, {Field, physical}};
parse_av(Field, <<"X">>) when Field =/= av -> {ok, {Field, not_defined}};
parse_av(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_ac(Field, <<"L">>) -> {ok, {Field, low}};
parse_ac(Field, <<"H">>) -> {ok, {Field, high}};
parse_ac(Field, <<"X">>) when Field =/= ac -> {ok, {Field, not_defined}};
parse_ac(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_pr(Field, <<"N">>) -> {ok, {Field, none}};
parse_pr(Field, <<"L">>) -> {ok, {Field, low}};
parse_pr(Field, <<"H">>) -> {ok, {Field, high}};
parse_pr(Field, <<"X">>) when Field =/= pr -> {ok, {Field, not_defined}};
parse_pr(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_ui(Field, <<"N">>) -> {ok, {Field, none}};
parse_ui(Field, <<"R">>) -> {ok, {Field, required}};
parse_ui(Field, <<"X">>) when Field =/= ui -> {ok, {Field, not_defined}};
parse_ui(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_scope(Field, <<"U">>) -> {ok, {Field, unchanged}};
parse_scope(Field, <<"C">>) -> {ok, {Field, changed}};
parse_scope(Field, <<"X">>) when Field =/= s -> {ok, {Field, not_defined}};
parse_scope(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_cia(Field, <<"N">>) -> {ok, {Field, none}};
parse_cia(Field, <<"L">>) -> {ok, {Field, low}};
parse_cia(Field, <<"H">>) -> {ok, {Field, high}};
parse_cia(Field, <<"X">>) when Field =/= c, Field =/= i, Field =/= a -> {ok, {Field, not_defined}};
parse_cia(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_exploit_maturity(Field, <<"X">>) -> {ok, {Field, not_defined}};
parse_exploit_maturity(Field, <<"H">>) -> {ok, {Field, high}};
parse_exploit_maturity(Field, <<"F">>) -> {ok, {Field, functional}};
parse_exploit_maturity(Field, <<"P">>) -> {ok, {Field, poc}};
parse_exploit_maturity(Field, <<"U">>) -> {ok, {Field, unproven}};
parse_exploit_maturity(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_remediation_level(Field, <<"X">>) -> {ok, {Field, not_defined}};
parse_remediation_level(Field, <<"U">>) -> {ok, {Field, unavailable}};
parse_remediation_level(Field, <<"W">>) -> {ok, {Field, workaround}};
parse_remediation_level(Field, <<"T">>) -> {ok, {Field, temporary_fix}};
parse_remediation_level(Field, <<"O">>) -> {ok, {Field, official_fix}};
parse_remediation_level(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_report_confidence(Field, <<"X">>) -> {ok, {Field, not_defined}};
parse_report_confidence(Field, <<"C">>) -> {ok, {Field, confirmed}};
parse_report_confidence(Field, <<"R">>) -> {ok, {Field, reasonable}};
parse_report_confidence(Field, <<"U">>) -> {ok, {Field, unknown}};
parse_report_confidence(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

parse_requirement(Field, <<"X">>) -> {ok, {Field, not_defined}};
parse_requirement(Field, <<"H">>) -> {ok, {Field, high}};
parse_requirement(Field, <<"M">>) -> {ok, {Field, medium}};
parse_requirement(Field, <<"L">>) -> {ok, {Field, low}};
parse_requirement(Field, Value) -> {error, {invalid_metric, atom_to_binary(Field), Value}}.

build_record(Version, Metrics) ->
    Required = [av, ac, pr, ui, s, c, i, a],
    case cvss_common:check_required(Required, Metrics) of
        ok ->
            {ok, #cvss_v3{
                version = Version,
                av = maps:get(av, Metrics),
                ac = maps:get(ac, Metrics),
                pr = maps:get(pr, Metrics),
                ui = maps:get(ui, Metrics),
                s = maps:get(s, Metrics),
                c = maps:get(c, Metrics),
                i = maps:get(i, Metrics),
                a = maps:get(a, Metrics),
                e = maps:get(e, Metrics, undefined),
                rl = maps:get(rl, Metrics, undefined),
                rc = maps:get(rc, Metrics, undefined),
                cr = maps:get(cr, Metrics, undefined),
                ir = maps:get(ir, Metrics, undefined),
                ar = maps:get(ar, Metrics, undefined),
                mav = maps:get(mav, Metrics, undefined),
                mac = maps:get(mac, Metrics, undefined),
                mpr = maps:get(mpr, Metrics, undefined),
                mui = maps:get(mui, Metrics, undefined),
                ms = maps:get(ms, Metrics, undefined),
                mc = maps:get(mc, Metrics, undefined),
                mi = maps:get(mi, Metrics, undefined),
                ma = maps:get(ma, Metrics, undefined)
            }};
        {error, _} = Error ->
            Error
    end.

%%====================================================================
%% Internal - Encoding
%%====================================================================

encode_av(network) -> <<"N">>;
encode_av(adjacent) -> <<"A">>;
encode_av(local) -> <<"L">>;
encode_av(physical) -> <<"P">>;
encode_av(not_defined) -> <<"X">>.

encode_ac(low) -> <<"L">>;
encode_ac(high) -> <<"H">>;
encode_ac(not_defined) -> <<"X">>.

encode_pr(none) -> <<"N">>;
encode_pr(low) -> <<"L">>;
encode_pr(high) -> <<"H">>;
encode_pr(not_defined) -> <<"X">>.

encode_ui(none) -> <<"N">>;
encode_ui(required) -> <<"R">>;
encode_ui(not_defined) -> <<"X">>.

encode_scope(unchanged) -> <<"U">>;
encode_scope(changed) -> <<"C">>;
encode_scope(not_defined) -> <<"X">>.

encode_cia(none) -> <<"N">>;
encode_cia(low) -> <<"L">>;
encode_cia(high) -> <<"H">>;
encode_cia(not_defined) -> <<"X">>.

encode_exploit_maturity(not_defined) -> <<"X">>;
encode_exploit_maturity(high) -> <<"H">>;
encode_exploit_maturity(functional) -> <<"F">>;
encode_exploit_maturity(poc) -> <<"P">>;
encode_exploit_maturity(unproven) -> <<"U">>.

encode_remediation_level(not_defined) -> <<"X">>;
encode_remediation_level(unavailable) -> <<"U">>;
encode_remediation_level(workaround) -> <<"W">>;
encode_remediation_level(temporary_fix) -> <<"T">>;
encode_remediation_level(official_fix) -> <<"O">>.

encode_report_confidence(not_defined) -> <<"X">>;
encode_report_confidence(confirmed) -> <<"C">>;
encode_report_confidence(reasonable) -> <<"R">>;
encode_report_confidence(unknown) -> <<"U">>.

encode_requirement(not_defined) -> <<"X">>;
encode_requirement(high) -> <<"H">>;
encode_requirement(medium) -> <<"M">>;
encode_requirement(low) -> <<"L">>.

%%====================================================================
%% Internal - Scoring
%%====================================================================

-include("internal/decimal.hrl").

%% Coefficients from CVSS 3.x spec (decimal values)
av_coeff(network) -> ?D(<<"0.85">>);
av_coeff(adjacent) -> ?D(<<"0.62">>);
av_coeff(local) -> ?D(<<"0.55">>);
av_coeff(physical) -> ?D(<<"0.2">>).

ac_coeff(low) -> ?D(<<"0.77">>);
ac_coeff(high) -> ?D(<<"0.44">>).

%% PR depends on Scope
pr_coeff(none, _) -> ?D(<<"0.85">>);
pr_coeff(low, unchanged) -> ?D(<<"0.62">>);
pr_coeff(low, changed) -> ?D(<<"0.68">>);
pr_coeff(high, unchanged) -> ?D(<<"0.27">>);
pr_coeff(high, changed) -> ?D(<<"0.50">>).

ui_coeff(none) -> ?D(<<"0.85">>);
ui_coeff(required) -> ?D(<<"0.62">>).

cia_coeff(high) -> ?D(<<"0.56">>);
cia_coeff(low) -> ?D(<<"0.22">>);
cia_coeff(none) -> ?ZERO.

exploit_maturity_coeff(undefined) -> ?ONE;
exploit_maturity_coeff(not_defined) -> ?ONE;
exploit_maturity_coeff(high) -> ?ONE;
exploit_maturity_coeff(functional) -> ?D(<<"0.97">>);
exploit_maturity_coeff(poc) -> ?D(<<"0.94">>);
exploit_maturity_coeff(unproven) -> ?D(<<"0.91">>).

remediation_level_coeff(undefined) -> ?ONE;
remediation_level_coeff(not_defined) -> ?ONE;
remediation_level_coeff(unavailable) -> ?ONE;
remediation_level_coeff(workaround) -> ?D(<<"0.97">>);
remediation_level_coeff(temporary_fix) -> ?D(<<"0.96">>);
remediation_level_coeff(official_fix) -> ?D(<<"0.95">>).

report_confidence_coeff(undefined) -> ?ONE;
report_confidence_coeff(not_defined) -> ?ONE;
report_confidence_coeff(confirmed) -> ?ONE;
report_confidence_coeff(reasonable) -> ?D(<<"0.96">>);
report_confidence_coeff(unknown) -> ?D(<<"0.92">>).

requirement_coeff(undefined) -> ?ONE;
requirement_coeff(not_defined) -> ?ONE;
requirement_coeff(high) -> ?D(<<"1.5">>);
requirement_coeff(medium) -> ?ONE;
requirement_coeff(low) -> ?D(<<"0.5">>).

changed_impact_30(ISS) ->
    cvss_decimal:sub(
        cvss_decimal:mult(?D(<<"7.52">>), cvss_decimal:sub(ISS, ?D(<<"0.029">>))),
        cvss_decimal:mult(
            ?D(<<"3.25">>), cvss_common:dpow(cvss_decimal:sub(ISS, ?D(<<"0.02">>)), 15)
        )
    ).

changed_impact_31(ISS) ->
    cvss_decimal:sub(
        cvss_decimal:mult(?D(<<"7.52">>), cvss_decimal:sub(ISS, ?D(<<"0.029">>))),
        cvss_decimal:mult(
            ?D(<<"3.25">>),
            cvss_common:dpow(
                cvss_decimal:sub(
                    cvss_decimal:mult(ISS, ?D(<<"0.9731">>)),
                    ?D(<<"0.02">>)
                ),
                13
            )
        )
    ).

combine_scope_score(unchanged, Impact, Exploitability) ->
    cvss_common:dmin(cvss_decimal:add(Impact, Exploitability), ?D(10));
combine_scope_score(changed, Impact, Exploitability) ->
    cvss_common:dmin(
        cvss_decimal:mult(?D(<<"1.08">>), cvss_decimal:add(Impact, Exploitability)),
        ?D(10)
    ).

calculate_base_score(#cvss_v3{av = AV, ac = AC, pr = PR, ui = UI, s = S, c = C, i = I, a = A}) ->
    ISS = cvss_decimal:sub(
        ?ONE,
        cvss_decimal:mult(
            cvss_decimal:mult(
                cvss_decimal:sub(?ONE, cia_coeff(C)),
                cvss_decimal:sub(?ONE, cia_coeff(I))
            ),
            cvss_decimal:sub(?ONE, cia_coeff(A))
        )
    ),
    Impact =
        case S of
            unchanged ->
                cvss_decimal:mult(?D(<<"6.42">>), ISS);
            changed ->
                changed_impact_30(ISS)
        end,
    case cvss_decimal:cmp(Impact, ?ZERO, ?DECIMAL_OPTS) of
        -1 ->
            ?ZERO;
        0 ->
            ?ZERO;
        1 ->
            Exploitability = cvss_decimal:mult(
                cvss_decimal:mult(
                    cvss_decimal:mult(
                        cvss_decimal:mult(?D(<<"8.22">>), av_coeff(AV)),
                        ac_coeff(AC)
                    ),
                    pr_coeff(PR, S)
                ),
                ui_coeff(UI)
            ),
            Score = combine_scope_score(S, Impact, Exploitability),
            cvss_common:roundup(Score)
    end.

calculate_temporal_score(#cvss_v3{e = E, rl = RL, rc = RC}, BaseScore) ->
    case has_temporal_metrics(E, RL, RC) of
        false ->
            BaseScore;
        true ->
            Score = cvss_decimal:mult(
                cvss_decimal:mult(
                    cvss_decimal:mult(BaseScore, exploit_maturity_coeff(E)),
                    remediation_level_coeff(RL)
                ),
                report_confidence_coeff(RC)
            ),
            cvss_common:roundup(Score)
    end.

has_temporal_metrics(E, RL, RC) ->
    not is_all_undefined_or_not_defined([E, RL, RC]).

has_environmental_metrics(#cvss_v3{
    cr = CR,
    ir = IR,
    ar = AR,
    mav = MAV,
    mac = MAC,
    mpr = MPR,
    mui = MUI,
    ms = MS,
    mc = MC,
    mi = MI,
    ma = MA
}) ->
    not is_all_undefined_or_not_defined([CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA]).

is_all_undefined_or_not_defined([]) ->
    true;
is_all_undefined_or_not_defined([undefined | Rest]) ->
    is_all_undefined_or_not_defined(Rest);
is_all_undefined_or_not_defined([not_defined | Rest]) ->
    is_all_undefined_or_not_defined(Rest);
is_all_undefined_or_not_defined([_ | _]) ->
    false.

calculate_environmental_score(#cvss_v3{version = Version} = Cvss) ->
    %% Get effective values (modified or base)
    MAV = effective(Cvss#cvss_v3.mav, Cvss#cvss_v3.av),
    MAC = effective(Cvss#cvss_v3.mac, Cvss#cvss_v3.ac),
    MPR = effective(Cvss#cvss_v3.mpr, Cvss#cvss_v3.pr),
    MUI = effective(Cvss#cvss_v3.mui, Cvss#cvss_v3.ui),
    MS = effective(Cvss#cvss_v3.ms, Cvss#cvss_v3.s),
    MC = effective(Cvss#cvss_v3.mc, Cvss#cvss_v3.c),
    MI = effective(Cvss#cvss_v3.mi, Cvss#cvss_v3.i),
    MA = effective(Cvss#cvss_v3.ma, Cvss#cvss_v3.a),
    CR = requirement_coeff(Cvss#cvss_v3.cr),
    IR = requirement_coeff(Cvss#cvss_v3.ir),
    AR = requirement_coeff(Cvss#cvss_v3.ar),

    %% Calculate modified ISS (same formula for 3.0 and 3.1)
    MISS = cvss_common:dmin(
        cvss_decimal:sub(
            ?ONE,
            cvss_decimal:mult(
                cvss_decimal:mult(
                    cvss_decimal:sub(?ONE, cvss_decimal:mult(cia_coeff(MC), CR)),
                    cvss_decimal:sub(?ONE, cvss_decimal:mult(cia_coeff(MI), IR))
                ),
                cvss_decimal:sub(?ONE, cvss_decimal:mult(cia_coeff(MA), AR))
            )
        ),
        ?D(<<"0.915">>)
    ),

    %% Calculate modified impact
    ModifiedImpact =
        case MS of
            unchanged ->
                cvss_decimal:mult(?D(<<"6.42">>), MISS);
            changed ->
                case Version of
                    '3.0' ->
                        changed_impact_30(MISS);
                    '3.1' ->
                        changed_impact_31(MISS)
                end
        end,

    case cvss_decimal:cmp(ModifiedImpact, ?ZERO, ?DECIMAL_OPTS) of
        -1 ->
            ?ZERO;
        0 ->
            ?ZERO;
        1 ->
            ModifiedExploitability = cvss_decimal:mult(
                cvss_decimal:mult(
                    cvss_decimal:mult(
                        cvss_decimal:mult(?D(<<"8.22">>), av_coeff(MAV)),
                        ac_coeff(MAC)
                    ),
                    pr_coeff(MPR, MS)
                ),
                ui_coeff(MUI)
            ),
            ModifiedScore = combine_scope_score(MS, ModifiedImpact, ModifiedExploitability),
            %% Apply temporal factors
            E = exploit_maturity_coeff(Cvss#cvss_v3.e),
            RL = remediation_level_coeff(Cvss#cvss_v3.rl),
            RC = report_confidence_coeff(Cvss#cvss_v3.rc),
            cvss_common:roundup(
                cvss_decimal:mult(
                    cvss_decimal:mult(
                        cvss_decimal:mult(ModifiedScore, E),
                        RL
                    ),
                    RC
                )
            )
    end.

effective(undefined, Base) -> Base;
effective(not_defined, Base) -> Base;
effective(Modified, _Base) -> Modified.
