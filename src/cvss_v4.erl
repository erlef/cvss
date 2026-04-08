%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v4).
-moduledoc """
CVSS 4.0 parsing, composition, validation, and scoring.

Use this module when working with CVSS 4.0 vectors directly. If the
version is not known ahead of time, use `m:cvss` instead.

Vector format: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

See: https://www.first.org/cvss/v4.0/specification-document
""".

-include("cvss_v4.hrl").

-export([
    base_score/1, compose/1, environmental_score/1, parse/1, score/1, threat_score/1, valid/1
]).

-export_type([
    cvss/0,
    av/0,
    ac/0,
    at/0,
    pr/0,
    ui/0,
    cia/0,
    si_sa/0,
    exploit_maturity/0,
    requirement/0,
    safety/0,
    automatable/0,
    recovery/0,
    value_density/0,
    response_effort/0,
    urgency/0
]).

-type av() :: network | adjacent | local | physical.
-type ac() :: low | high.
-type at() :: none | present.
-type pr() :: none | low | high.
-type ui() :: none | passive | active.
-type cia() :: none | low | high.
-type si_sa() :: none | low | high | safety.
-type exploit_maturity() :: attacked | poc | unreported | not_defined.
-type requirement() :: low | medium | high | not_defined.
-type safety() :: negligible | present.
-type automatable() :: no | yes.
-type recovery() :: automatic | user | irrecoverable.
-type value_density() :: diffuse | concentrated.
-type response_effort() :: low | moderate | high.
-type urgency() :: clear | green | amber | red.

-type cvss() :: #cvss_v4{}.

%% Internal record for effective metric values
-record(eff, {
    av,
    ac,
    at,
    pr,
    ui,
    vc,
    vi,
    va,
    sc,
    si,
    sa,
    cr,
    ir,
    ar,
    e
}).

%%====================================================================
%% Public API
%%====================================================================

-doc """
Parse a CVSS 4.0 vector string.

```erlang
> cvss_v4:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>).
{ok, #cvss_v4{av = network, ac = low, at = none, pr = none, ui = none,
              vc = high, vi = high, va = high, sc = high, si = high, sa = high}}

> cvss_v4:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A">>).
{ok, #cvss_v4{av = network, ac = low, at = none, pr = none, ui = none,
              vc = high, vi = high, va = high, sc = high, si = high, sa = high,
              e = attacked}}

> cvss_v4:parse(<<"CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:S">>).
{ok, #cvss_v4{av = physical, ac = low, at = none, pr = none, ui = none,
              vc = high, vi = high, va = high, sc = high, si = safety, sa = safety}}

> cvss_v4:parse(<<"CVSS:4.0/AV:N">>).
{error, {missing_required_metric, ac}}
```
""".
-spec parse(binary()) -> {ok, cvss_v4:cvss()} | {error, cvss:parse_error()}.
parse(Vector) when is_binary(Vector) ->
    maybe
        {ok, Rest} ?= parse_prefix(Vector),
        {ok, Metrics} ?= parse_metrics(Rest),
        build_record(Metrics)
    end.

-doc """
Compose a CVSS 4.0 record into a vector string.

```erlang
> iolist_to_binary(cvss_v4:compose(#cvss_v4{av = network, ac = low, at = none,
                                           pr = none, ui = none,
                                           vc = high, vi = high, va = high,
                                           sc = high, si = high, sa = high})).
<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>
```
""".
-spec compose(cvss_v4:cvss()) -> iolist().
compose(#cvss_v4{} = Cvss) ->
    Prefix = "CVSS:4.0/",
    Base = [
        "AV:",
        av_to_string(Cvss#cvss_v4.av),
        "/AC:",
        ac_to_string(Cvss#cvss_v4.ac),
        "/AT:",
        at_to_string(Cvss#cvss_v4.at),
        "/PR:",
        pr_to_string(Cvss#cvss_v4.pr),
        "/UI:",
        ui_to_string(Cvss#cvss_v4.ui),
        "/VC:",
        cia_to_string(Cvss#cvss_v4.vc),
        "/VI:",
        cia_to_string(Cvss#cvss_v4.vi),
        "/VA:",
        cia_to_string(Cvss#cvss_v4.va),
        "/SC:",
        cia_to_string(Cvss#cvss_v4.sc),
        "/SI:",
        si_sa_to_string(Cvss#cvss_v4.si),
        "/SA:",
        si_sa_to_string(Cvss#cvss_v4.sa)
    ],
    Optional = cvss_common:encode_optional(
        [
            {"E", Cvss#cvss_v4.e, fun e_to_string/1},
            {"CR", Cvss#cvss_v4.cr, fun req_to_string/1},
            {"IR", Cvss#cvss_v4.ir, fun req_to_string/1},
            {"AR", Cvss#cvss_v4.ar, fun req_to_string/1},
            {"MAV", Cvss#cvss_v4.mav, fun av_to_string/1},
            {"MAC", Cvss#cvss_v4.mac, fun ac_to_string/1},
            {"MAT", Cvss#cvss_v4.mat, fun at_to_string/1},
            {"MPR", Cvss#cvss_v4.mpr, fun pr_to_string/1},
            {"MUI", Cvss#cvss_v4.mui, fun ui_to_string/1},
            {"MVC", Cvss#cvss_v4.mvc, fun cia_to_string/1},
            {"MVI", Cvss#cvss_v4.mvi, fun cia_to_string/1},
            {"MVA", Cvss#cvss_v4.mva, fun cia_to_string/1},
            {"MSC", Cvss#cvss_v4.msc, fun cia_to_string/1},
            {"MSI", Cvss#cvss_v4.msi, fun si_sa_to_string/1},
            {"MSA", Cvss#cvss_v4.msa, fun si_sa_to_string/1},
            {"S", Cvss#cvss_v4.safety, fun safety_to_string/1},
            {"AU", Cvss#cvss_v4.automatable, fun automatable_to_string/1},
            {"R", Cvss#cvss_v4.recovery, fun recovery_to_string/1},
            {"V", Cvss#cvss_v4.value_density, fun value_density_to_string/1},
            {"RE", Cvss#cvss_v4.response_effort, fun response_effort_to_string/1},
            {"U", Cvss#cvss_v4.urgency, fun urgency_to_string/1}
        ],
        [undefined]
    ),
    [Prefix, Base, Optional].

-doc """
Check whether a CVSS 4.0 value is valid.

Accepts either a vector string or a parsed record.

```erlang
> cvss_v4:valid(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>).
true

> cvss_v4:valid(#cvss_v4{av = network, ac = low, at = none, pr = none, ui = none,
                         vc = high, vi = high, va = high,
                         sc = high, si = high, sa = high}).
true

> cvss_v4:valid(<<"CVSS:4.0/AV:X">>).
false
```
""".
-spec valid(iodata() | cvss_v4:cvss()) -> boolean().
valid(#cvss_v4{} = Cvss) ->
    ValidBase =
        lists:member(Cvss#cvss_v4.av, [network, adjacent, local, physical]) andalso
            lists:member(Cvss#cvss_v4.ac, [low, high]) andalso
            lists:member(Cvss#cvss_v4.at, [none, present]) andalso
            lists:member(Cvss#cvss_v4.pr, [none, low, high]) andalso
            lists:member(Cvss#cvss_v4.ui, [none, passive, active]) andalso
            lists:member(Cvss#cvss_v4.vc, [none, low, high]) andalso
            lists:member(Cvss#cvss_v4.vi, [none, low, high]) andalso
            lists:member(Cvss#cvss_v4.va, [none, low, high]) andalso
            lists:member(Cvss#cvss_v4.sc, [none, low, high]) andalso
            lists:member(Cvss#cvss_v4.si, [none, low, high, safety]) andalso
            lists:member(Cvss#cvss_v4.sa, [none, low, high, safety]),
    ValidThreat =
        cvss_common:valid_optional(Cvss#cvss_v4.e, [attacked, poc, unreported, not_defined]),
    ValidEnvironmental =
        cvss_common:valid_optional(Cvss#cvss_v4.cr, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.ir, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.ar, [low, medium, high, not_defined]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mav, [network, adjacent, local, physical]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mac, [low, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mat, [none, present]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mpr, [none, low, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mui, [none, passive, active]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mvc, [none, low, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mvi, [none, low, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.mva, [none, low, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.msc, [none, low, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.msi, [none, low, high, safety]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.msa, [none, low, high, safety]),
    ValidSupplemental =
        cvss_common:valid_optional(Cvss#cvss_v4.safety, [negligible, present]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.automatable, [no, yes]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.recovery, [automatic, user, irrecoverable]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.value_density, [diffuse, concentrated]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.response_effort, [low, moderate, high]) andalso
            cvss_common:valid_optional(Cvss#cvss_v4.urgency, [clear, green, amber, red]),
    ValidBase andalso ValidThreat andalso ValidEnvironmental andalso ValidSupplemental;
valid(Vector) ->
    case parse(iolist_to_binary(Vector)) of
        {ok, Cvss} -> valid(Cvss);
        {error, _} -> false
    end.

-doc """
Calculate the CVSS 4.0 score (CVSS-BTE).
Uses all present metrics (Base + Threat + Environmental).
Metrics not explicitly set default per the CVSS 4.0 specification.

```erlang
> {ok, Cvss} = cvss_v4:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>).
> cvss_v4:score(Cvss).
10.0

> {ok, Cvss2} = cvss_v4:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N">>).
> cvss_v4:score(Cvss2).
0.0
```
""".
-spec score(cvss_v4:cvss()) -> cvss:score().
score(#cvss_v4{} = Cvss) ->
    calculate_with_effective(effective_values(Cvss)).

-doc """
Calculate the CVSS 4.0 Base Score (CVSS-B).
Only considers base metrics; threat and environmental metrics are ignored.

```erlang
> {ok, Cvss} = cvss_v4:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>).
> cvss_v4:base_score(Cvss).
10.0
```
""".
-spec base_score(cvss_v4:cvss()) -> cvss:score().
base_score(#cvss_v4{} = Cvss) ->
    calculate_with_effective(
        effective_values(
            Cvss#cvss_v4{
                e = undefined,
                cr = undefined,
                ir = undefined,
                ar = undefined,
                mav = undefined,
                mac = undefined,
                mat = undefined,
                mpr = undefined,
                mui = undefined,
                mvc = undefined,
                mvi = undefined,
                mva = undefined,
                msc = undefined,
                msi = undefined,
                msa = undefined
            }
        )
    ).

-doc """
Calculate the CVSS 4.0 Threat Score (CVSS-BT).
Considers base and threat metrics; environmental metrics are ignored.

```erlang
> {ok, Cvss} = cvss_v4:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A">>).
> cvss_v4:threat_score(Cvss).
10.0
```
""".
-spec threat_score(cvss_v4:cvss()) -> cvss:score().
threat_score(#cvss_v4{} = Cvss) ->
    calculate_with_effective(
        effective_values(
            Cvss#cvss_v4{
                cr = undefined,
                ir = undefined,
                ar = undefined,
                mav = undefined,
                mac = undefined,
                mat = undefined,
                mpr = undefined,
                mui = undefined,
                mvc = undefined,
                mvi = undefined,
                mva = undefined,
                msc = undefined,
                msi = undefined,
                msa = undefined
            }
        )
    ).

-doc """
Calculate the CVSS 4.0 Environmental Score (CVSS-BE).
Considers base and environmental metrics; threat metrics are ignored.

```erlang
> {ok, Cvss} = cvss_v4:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N">>).
> cvss_v4:environmental_score(Cvss).
0.0
```
""".
-spec environmental_score(cvss_v4:cvss()) -> cvss:score().
environmental_score(#cvss_v4{} = Cvss) ->
    calculate_with_effective(
        effective_values(
            Cvss#cvss_v4{e = undefined}
        )
    ).

calculate_with_effective(#eff{vc = VC, vi = VI, va = VA, sc = SC, si = SI, sa = SA} = Eff) ->
    case {VC, VI, VA, SC, SI, SA} of
        {none, none, none, none, none, none} -> 0.0;
        _ -> cvss_common:to_float(calculate_score_with_eff(Eff))
    end.

effective_values(#cvss_v4{} = C) ->
    #eff{
        av = effective(C#cvss_v4.mav, C#cvss_v4.av),
        ac = effective(C#cvss_v4.mac, C#cvss_v4.ac),
        at = effective(C#cvss_v4.mat, C#cvss_v4.at),
        pr = effective(C#cvss_v4.mpr, C#cvss_v4.pr),
        ui = effective(C#cvss_v4.mui, C#cvss_v4.ui),
        vc = effective(C#cvss_v4.mvc, C#cvss_v4.vc),
        vi = effective(C#cvss_v4.mvi, C#cvss_v4.vi),
        va = effective(C#cvss_v4.mva, C#cvss_v4.va),
        sc = effective(C#cvss_v4.msc, C#cvss_v4.sc),
        si = effective_si_sa(C#cvss_v4.msi, C#cvss_v4.si),
        sa = effective_si_sa(C#cvss_v4.msa, C#cvss_v4.sa),
        cr = effective_req(C#cvss_v4.cr),
        ir = effective_req(C#cvss_v4.ir),
        ar = effective_req(C#cvss_v4.ar),
        e = effective_e(C#cvss_v4.e)
    }.

-include("internal/decimal.hrl").

calculate_score_with_eff(#eff{} = E) ->
    EQ1 = calculate_eq1(E#eff.av, E#eff.pr, E#eff.ui),
    EQ2 = calculate_eq2(E#eff.ac, E#eff.at),
    EQ3 = calculate_eq3(E#eff.vc, E#eff.vi, E#eff.va),
    EQ4 = calculate_eq4(E#eff.sc, E#eff.si, E#eff.sa),
    EQ5 = calculate_eq5(E#eff.e),
    EQ6 = calculate_eq6(E#eff.cr, E#eff.ir, E#eff.ar, E#eff.vc, E#eff.vi, E#eff.va),

    case cvss_v4_lookup:lookup(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6) of
        undefined -> ?ZERO;
        BaseScore -> interpolate_score(BaseScore, E, EQ1, EQ2, EQ3, EQ4, EQ5, EQ6)
    end.

%%====================================================================
%% Internal: Parsing
%%====================================================================

-spec parse_prefix(binary()) -> {ok, binary()} | {error, cvss:parse_error()}.
parse_prefix(<<"CVSS:4.0/", Rest/binary>>) -> {ok, Rest};
parse_prefix(Vector) -> {error, {invalid_prefix, Vector}}.

-spec parse_metrics(binary()) -> {ok, [{binary(), binary()}]} | {error, cvss:parse_error()}.
parse_metrics(Vector) ->
    Parts = binary:split(Vector, <<"/">>, [global]),
    parse_metric_parts(Parts, #{}, []).

-spec parse_metric_parts([binary()], #{binary() => true}, [{binary(), binary()}]) ->
    {ok, [{binary(), binary()}]} | {error, cvss:parse_error()}.
parse_metric_parts([], _Seen, Acc) ->
    {ok, lists:reverse(Acc)};
parse_metric_parts([Part | Rest], Seen, Acc) ->
    case binary:split(Part, <<":">>) of
        [Key, Value] ->
            case maps:is_key(Key, Seen) of
                true -> {error, {duplicate_metric, Key}};
                false -> parse_metric_parts(Rest, Seen#{Key => true}, [{Key, Value} | Acc])
            end;
        _ ->
            {error, malformed_vector}
    end.

-spec build_record([{binary(), binary()}]) -> {ok, cvss_v4:cvss()} | {error, cvss:parse_error()}.
build_record(Metrics) ->
    case apply_metrics(Metrics, #{}) of
        {ok, Map} -> validate_required(Map);
        {error, _} = Error -> Error
    end.

apply_metrics([], Map) ->
    {ok, Map};
apply_metrics([{Key, Value} | Rest], Map) ->
    case apply_metric(Key, Value) of
        {ok, {K, V}} -> apply_metrics(Rest, Map#{K => V});
        {error, _} = Error -> Error
    end.

-spec apply_metric(binary(), binary()) -> {ok, {atom(), term()}} | {error, cvss:parse_error()}.
apply_metric(<<"AV">>, V) -> parse_into(av, V, fun parse_av/1);
apply_metric(<<"AC">>, V) -> parse_into(ac, V, fun parse_ac/1);
apply_metric(<<"AT">>, V) -> parse_into(at, V, fun parse_at/1);
apply_metric(<<"PR">>, V) -> parse_into(pr, V, fun parse_pr/1);
apply_metric(<<"UI">>, V) -> parse_into(ui, V, fun parse_ui/1);
apply_metric(<<"VC">>, V) -> parse_into(vc, V, fun parse_cia/1);
apply_metric(<<"VI">>, V) -> parse_into(vi, V, fun parse_cia/1);
apply_metric(<<"VA">>, V) -> parse_into(va, V, fun parse_cia/1);
apply_metric(<<"SC">>, V) -> parse_into(sc, V, fun parse_cia/1);
apply_metric(<<"SI">>, V) -> parse_into(si, V, fun parse_si_sa/1);
apply_metric(<<"SA">>, V) -> parse_into(sa, V, fun parse_si_sa/1);
apply_metric(<<"E">>, V) -> parse_into(e, V, fun parse_e/1);
apply_metric(<<"CR">>, V) -> parse_into(cr, V, fun parse_req/1);
apply_metric(<<"IR">>, V) -> parse_into(ir, V, fun parse_req/1);
apply_metric(<<"AR">>, V) -> parse_into(ar, V, fun parse_req/1);
apply_metric(<<"MAV">>, V) -> parse_into(mav, V, fun parse_av_x/1);
apply_metric(<<"MAC">>, V) -> parse_into(mac, V, fun parse_ac_x/1);
apply_metric(<<"MAT">>, V) -> parse_into(mat, V, fun parse_at_x/1);
apply_metric(<<"MPR">>, V) -> parse_into(mpr, V, fun parse_pr_x/1);
apply_metric(<<"MUI">>, V) -> parse_into(mui, V, fun parse_ui_x/1);
apply_metric(<<"MVC">>, V) -> parse_into(mvc, V, fun parse_cia_x/1);
apply_metric(<<"MVI">>, V) -> parse_into(mvi, V, fun parse_cia_x/1);
apply_metric(<<"MVA">>, V) -> parse_into(mva, V, fun parse_cia_x/1);
apply_metric(<<"MSC">>, V) -> parse_into(msc, V, fun parse_cia_x/1);
apply_metric(<<"MSI">>, V) -> parse_into(msi, V, fun parse_si_sa_x/1);
apply_metric(<<"MSA">>, V) -> parse_into(msa, V, fun parse_si_sa_x/1);
apply_metric(<<"S">>, V) -> parse_into(safety, V, fun parse_safety/1);
apply_metric(<<"AU">>, V) -> parse_into(automatable, V, fun parse_automatable/1);
apply_metric(<<"R">>, V) -> parse_into(recovery, V, fun parse_recovery/1);
apply_metric(<<"V">>, V) -> parse_into(value_density, V, fun parse_value_density/1);
apply_metric(<<"RE">>, V) -> parse_into(response_effort, V, fun parse_response_effort/1);
apply_metric(<<"U">>, V) -> parse_into(urgency, V, fun parse_urgency/1);
apply_metric(Key, Value) -> {error, {invalid_metric, Key, Value}}.

parse_into(Key, Value, Parser) ->
    case Parser(Value) of
        {ok, Parsed} -> {ok, {Key, Parsed}};
        {error, _} = Error -> Error
    end.

-spec validate_required(map()) -> {ok, cvss_v4:cvss()} | {error, cvss:parse_error()}.
validate_required(M) ->
    RequiredKeys = [av, ac, at, pr, ui, vc, vi, va, sc, si, sa],
    case cvss_common:check_required(RequiredKeys, M) of
        {error, _} = Error ->
            Error;
        ok ->
            {ok, #cvss_v4{
                av = maps:get(av, M),
                ac = maps:get(ac, M),
                at = maps:get(at, M),
                pr = maps:get(pr, M),
                ui = maps:get(ui, M),
                vc = maps:get(vc, M),
                vi = maps:get(vi, M),
                va = maps:get(va, M),
                sc = maps:get(sc, M),
                si = maps:get(si, M),
                sa = maps:get(sa, M),
                e = maps:get(e, M, undefined),
                cr = maps:get(cr, M, undefined),
                ir = maps:get(ir, M, undefined),
                ar = maps:get(ar, M, undefined),
                mav = maps:get(mav, M, undefined),
                mac = maps:get(mac, M, undefined),
                mat = maps:get(mat, M, undefined),
                mpr = maps:get(mpr, M, undefined),
                mui = maps:get(mui, M, undefined),
                mvc = maps:get(mvc, M, undefined),
                mvi = maps:get(mvi, M, undefined),
                mva = maps:get(mva, M, undefined),
                msc = maps:get(msc, M, undefined),
                msi = maps:get(msi, M, undefined),
                msa = maps:get(msa, M, undefined),
                safety = maps:get(safety, M, undefined),
                automatable = maps:get(automatable, M, undefined),
                recovery = maps:get(recovery, M, undefined),
                value_density = maps:get(value_density, M, undefined),
                response_effort = maps:get(response_effort, M, undefined),
                urgency = maps:get(urgency, M, undefined)
            }}
    end.

%%====================================================================
%% Internal: Metric Parsing
%%====================================================================

parse_av(<<"N">>) -> {ok, network};
parse_av(<<"A">>) -> {ok, adjacent};
parse_av(<<"L">>) -> {ok, local};
parse_av(<<"P">>) -> {ok, physical};
parse_av(V) -> {error, {invalid_metric, <<"AV">>, V}}.

parse_ac(<<"L">>) -> {ok, low};
parse_ac(<<"H">>) -> {ok, high};
parse_ac(V) -> {error, {invalid_metric, <<"AC">>, V}}.

parse_at(<<"N">>) -> {ok, none};
parse_at(<<"P">>) -> {ok, present};
parse_at(V) -> {error, {invalid_metric, <<"AT">>, V}}.

parse_pr(<<"N">>) -> {ok, none};
parse_pr(<<"L">>) -> {ok, low};
parse_pr(<<"H">>) -> {ok, high};
parse_pr(V) -> {error, {invalid_metric, <<"PR">>, V}}.

parse_ui(<<"N">>) -> {ok, none};
parse_ui(<<"P">>) -> {ok, passive};
parse_ui(<<"A">>) -> {ok, active};
parse_ui(V) -> {error, {invalid_metric, <<"UI">>, V}}.

parse_cia(<<"N">>) -> {ok, none};
parse_cia(<<"L">>) -> {ok, low};
parse_cia(<<"H">>) -> {ok, high};
parse_cia(V) -> {error, {invalid_metric, <<"VC/VI/VA/SC">>, V}}.

parse_si_sa(<<"N">>) -> {ok, none};
parse_si_sa(<<"L">>) -> {ok, low};
parse_si_sa(<<"H">>) -> {ok, high};
parse_si_sa(<<"S">>) -> {ok, safety};
parse_si_sa(V) -> {error, {invalid_metric, <<"SI/SA">>, V}}.

parse_e(<<"A">>) -> {ok, attacked};
parse_e(<<"P">>) -> {ok, poc};
parse_e(<<"U">>) -> {ok, unreported};
parse_e(<<"X">>) -> {ok, not_defined};
parse_e(V) -> {error, {invalid_metric, <<"E">>, V}}.

parse_req(<<"L">>) -> {ok, low};
parse_req(<<"M">>) -> {ok, medium};
parse_req(<<"H">>) -> {ok, high};
parse_req(<<"X">>) -> {ok, not_defined};
parse_req(V) -> {error, {invalid_metric, <<"CR/IR/AR">>, V}}.

parse_safety(<<"X">>) -> {ok, undefined};
parse_safety(<<"N">>) -> {ok, negligible};
parse_safety(<<"P">>) -> {ok, present};
parse_safety(V) -> {error, {invalid_metric, <<"S">>, V}}.

parse_automatable(<<"X">>) -> {ok, undefined};
parse_automatable(<<"N">>) -> {ok, no};
parse_automatable(<<"Y">>) -> {ok, yes};
parse_automatable(V) -> {error, {invalid_metric, <<"AU">>, V}}.

parse_recovery(<<"X">>) -> {ok, undefined};
parse_recovery(<<"A">>) -> {ok, automatic};
parse_recovery(<<"U">>) -> {ok, user};
parse_recovery(<<"I">>) -> {ok, irrecoverable};
parse_recovery(V) -> {error, {invalid_metric, <<"R">>, V}}.

parse_value_density(<<"X">>) -> {ok, undefined};
parse_value_density(<<"D">>) -> {ok, diffuse};
parse_value_density(<<"C">>) -> {ok, concentrated};
parse_value_density(V) -> {error, {invalid_metric, <<"V">>, V}}.

parse_response_effort(<<"X">>) -> {ok, undefined};
parse_response_effort(<<"L">>) -> {ok, low};
parse_response_effort(<<"M">>) -> {ok, moderate};
parse_response_effort(<<"H">>) -> {ok, high};
parse_response_effort(V) -> {error, {invalid_metric, <<"RE">>, V}}.

%% Modified metric parsers - accept "X" as undefined
parse_av_x(<<"X">>) -> {ok, undefined};
parse_av_x(V) -> parse_av(V).

parse_ac_x(<<"X">>) -> {ok, undefined};
parse_ac_x(V) -> parse_ac(V).

parse_at_x(<<"X">>) -> {ok, undefined};
parse_at_x(V) -> parse_at(V).

parse_pr_x(<<"X">>) -> {ok, undefined};
parse_pr_x(V) -> parse_pr(V).

parse_ui_x(<<"X">>) -> {ok, undefined};
parse_ui_x(V) -> parse_ui(V).

parse_cia_x(<<"X">>) -> {ok, undefined};
parse_cia_x(V) -> parse_cia(V).

parse_si_sa_x(<<"X">>) -> {ok, undefined};
parse_si_sa_x(V) -> parse_si_sa(V).

parse_urgency(<<"X">>) -> {ok, undefined};
parse_urgency(<<"Clear">>) -> {ok, clear};
parse_urgency(<<"Green">>) -> {ok, green};
parse_urgency(<<"Amber">>) -> {ok, amber};
parse_urgency(<<"Red">>) -> {ok, red};
parse_urgency(V) -> {error, {invalid_metric, <<"U">>, V}}.

%%====================================================================
%% Internal: Metric Composing
%%====================================================================

av_to_string(network) -> "N";
av_to_string(adjacent) -> "A";
av_to_string(local) -> "L";
av_to_string(physical) -> "P".

ac_to_string(low) -> "L";
ac_to_string(high) -> "H".

at_to_string(none) -> "N";
at_to_string(present) -> "P".

pr_to_string(none) -> "N";
pr_to_string(low) -> "L";
pr_to_string(high) -> "H".

ui_to_string(none) -> "N";
ui_to_string(passive) -> "P";
ui_to_string(active) -> "A".

cia_to_string(none) -> "N";
cia_to_string(low) -> "L";
cia_to_string(high) -> "H".

si_sa_to_string(none) -> "N";
si_sa_to_string(low) -> "L";
si_sa_to_string(high) -> "H";
si_sa_to_string(safety) -> "S".

e_to_string(attacked) -> "A";
e_to_string(poc) -> "P";
e_to_string(unreported) -> "U";
e_to_string(not_defined) -> "X".

req_to_string(low) -> "L";
req_to_string(medium) -> "M";
req_to_string(high) -> "H";
req_to_string(not_defined) -> "X".

safety_to_string(negligible) -> "N";
safety_to_string(present) -> "P".

automatable_to_string(no) -> "N";
automatable_to_string(yes) -> "Y".

recovery_to_string(automatic) -> "A";
recovery_to_string(user) -> "U";
recovery_to_string(irrecoverable) -> "I".

value_density_to_string(diffuse) -> "D";
value_density_to_string(concentrated) -> "C".

response_effort_to_string(low) -> "L";
response_effort_to_string(moderate) -> "M";
response_effort_to_string(high) -> "H".

urgency_to_string(clear) -> "Clear";
urgency_to_string(green) -> "Green";
urgency_to_string(amber) -> "Amber";
urgency_to_string(red) -> "Red".

%%====================================================================
%% Internal: Effective Values
%%====================================================================

effective(undefined, Base) -> Base;
effective(Modified, _Base) -> Modified.

effective_si_sa(undefined, Base) -> Base;
effective_si_sa(Modified, _Base) -> Modified.

%% CR/IR/AR: X defaults to H (high), not M (medium)
%% Per FIRST reference implementation
effective_req(undefined) -> high;
effective_req(not_defined) -> high;
effective_req(Value) -> Value.

effective_e(undefined) -> attacked;
effective_e(not_defined) -> attacked;
effective_e(Value) -> Value.

%%====================================================================
%% Internal: MacroVector Calculation (EQ1-EQ6)
%%====================================================================

%% EQ1: AV/PR/UI
%% 0: AV:N AND PR:N AND UI:N
%% 1: (AV:N OR PR:N OR UI:N) AND NOT level 0 AND AV != P
%% 2: AV:P OR none of AV/PR/UI is N/N/N
calculate_eq1(AV, PR, UI) ->
    case {AV, PR, UI} of
        {network, none, none} ->
            0;
        {physical, _, _} ->
            2;
        _ ->
            HasNetwork = (AV =:= network) orelse (PR =:= none) orelse (UI =:= none),
            case HasNetwork of
                true -> 1;
                false -> 2
            end
    end.

%% EQ2: AC/AT
calculate_eq2(AC, AT) ->
    case {AC, AT} of
        {low, none} -> 0;
        {_, _} -> 1
    end.

%% EQ3: VC/VI/VA
%% 0: VC:H and VI:H
%% 1: not (VC:H and VI:H) and (VC:H or VI:H or VA:H)
%% 2: not (VC:H or VI:H or VA:H)
calculate_eq3(VC, VI, VA) ->
    HasHigh = (VC =:= high) orelse (VI =:= high) orelse (VA =:= high),
    case {VC, VI, HasHigh} of
        {high, high, _} -> 0;
        {_, _, true} -> 1;
        {_, _, false} -> 2
    end.

%% EQ4: SC/SI/SA (with safety consideration)
%% 0: MSI:S or MSA:S
%% 1: not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
%% 2: not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)
calculate_eq4(SC, SI, SA) ->
    HasSafety = (SI =:= safety) orelse (SA =:= safety),
    HasHigh = (SC =:= high) orelse (SI =:= high) orelse (SA =:= high),
    case {HasSafety, HasHigh} of
        {true, _} -> 0;
        {false, true} -> 1;
        {false, false} -> 2
    end.

%% EQ5: E
calculate_eq5(E) ->
    case E of
        attacked -> 0;
        poc -> 1;
        unreported -> 2
    end.

%% EQ6: CR/IR/AR with VC/VI/VA
calculate_eq6(CR, IR, AR, VC, VI, VA) ->
    %% Check if any high requirement is paired with high impact
    HasHighReqHighImpact =
        (CR =:= high andalso VC =:= high) orelse
            (IR =:= high andalso VI =:= high) orelse
            (AR =:= high andalso VA =:= high),
    case HasHighReqHighImpact of
        true -> 0;
        false -> 1
    end.

%%====================================================================
%% Internal: Score Interpolation
%%====================================================================

interpolate_score(BaseScore, #eff{} = E, EQ1, EQ2, EQ3, EQ4, EQ5, EQ6) ->
    %% Get max composed vectors for each EQ level
    MaxEQ1 = max_composed_eq1(EQ1),
    MaxEQ2 = max_composed_eq2(EQ2),
    MaxEQ3EQ6 = max_composed_eq3eq6(EQ3, EQ6),
    MaxEQ4 = max_composed_eq4(EQ4),
    %% EQ5 max composed doesn't affect distance (always 0)

    %% Try each combination of max composed vectors
    case find_valid_distances(E, MaxEQ1, MaxEQ2, MaxEQ3EQ6, MaxEQ4) of
        none ->
            BaseScore;
        {D1, D2, D3EQ6, D4} ->
            %% Max severity depths
            Max1 = max_severity_eq1(EQ1),
            Max2 = max_severity_eq2(EQ2),
            Max3EQ6 = max_severity_eq3eq6(EQ3, EQ6),
            Max4 = max_severity_eq4(EQ4),

            %% Calculate MSD (Maximal Scoring Difference) for each EQ
            MSD1 = msd(BaseScore, EQ1 + 1, EQ2, EQ3, EQ4, EQ5, EQ6),
            MSD2 = msd(BaseScore, EQ1, EQ2 + 1, EQ3, EQ4, EQ5, EQ6),
            MSD3EQ6 = msd_eq3eq6(BaseScore, EQ1, EQ2, EQ3, EQ4, EQ5, EQ6),
            MSD4 = msd(BaseScore, EQ1, EQ2, EQ3, EQ4 + 1, EQ5, EQ6),
            MSD5 = msd(BaseScore, EQ1, EQ2, EQ3, EQ4, EQ5 + 1, EQ6),

            %% EQ5 distance is always 0 - each EQ5 level has only one possible E value
            EQs = [
                {MSD1, D1, Max1},
                {MSD2, D2, Max2},
                {MSD3EQ6, D3EQ6, Max3EQ6},
                {MSD4, D4, Max4},
                {MSD5, ?ZERO, ?D(<<"0.1">>)}
            ],

            {NormSum, Count} = lists:foldl(
                fun fold_eq_distance/2,
                {?ZERO, 0},
                EQs
            ),

            case Count of
                0 ->
                    BaseScore;
                _ ->
                    MeanDistance = cvss_decimal:divide(NormSum, ?D(Count), ?DECIMAL_OPTS),
                    cvss_common:dmax(
                        ?ZERO,
                        cvss_decimal:round(
                            round_half_up, cvss_decimal:sub(BaseScore, MeanDistance), 1
                        )
                    )
            end
    end.

fold_eq_distance({undefined, _D, _Max}, Acc) ->
    Acc;
fold_eq_distance({MSD, D, Max}, {Sum, N}) ->
    case cvss_decimal:is_zero(Max) of
        true ->
            {Sum, N};
        false ->
            Percent = cvss_decimal:divide(D, Max, ?DECIMAL_OPTS),
            {cvss_decimal:add(Sum, cvss_decimal:mult(MSD, Percent)), N + 1}
    end.

%% Try all combinations of max composed vectors to find one where
%% every individual metric distance is non-negative (matching JS reference).
find_valid_distances(E, MaxEQ1List, MaxEQ2List, MaxEQ3EQ6List, MaxEQ4List) ->
    MaxEQ5List = max_composed_eq5(E#eff.e),
    Combinations = [
        {M1, M2, M3EQ6, M4, M5}
     || M1 <- MaxEQ1List,
        M2 <- MaxEQ2List,
        M3EQ6 <- MaxEQ3EQ6List,
        M4 <- MaxEQ4List,
        M5 <- MaxEQ5List
    ],
    find_first_valid(E, Combinations).

find_first_valid(_E, []) ->
    none;
find_first_valid(E, [{Max1, Max2, Max3EQ6, Max4, _Max5} | Rest]) ->
    %% Compute individual metric distances
    #eff{
        av = AV,
        ac = AC,
        at = AT,
        pr = PR,
        ui = UI,
        vc = VC,
        vi = VI,
        va = VA,
        sc = SC,
        si = SI,
        sa = SA,
        cr = CR,
        ir = IR,
        ar = AR
    } = E,
    {MaxAV, MaxPR, MaxUI} = Max1,
    {MaxAC, MaxAT} = Max2,
    {MaxVC, MaxVI, MaxVA, MaxCR, MaxIR, MaxAR} = Max3EQ6,
    {MaxSC, MaxSI, MaxSA} = Max4,
    Dists = [
        cvss_decimal:sub(av_level(AV), av_level(MaxAV)),
        cvss_decimal:sub(pr_level(PR), pr_level(MaxPR)),
        cvss_decimal:sub(ui_level(UI), ui_level(MaxUI)),
        cvss_decimal:sub(ac_level(AC), ac_level(MaxAC)),
        cvss_decimal:sub(at_level(AT), at_level(MaxAT)),
        cvss_decimal:sub(vc_level(VC), vc_level(MaxVC)),
        cvss_decimal:sub(vi_level(VI), vi_level(MaxVI)),
        cvss_decimal:sub(va_level(VA), va_level(MaxVA)),
        cvss_decimal:sub(sc_level(SC), sc_level(MaxSC)),
        cvss_decimal:sub(si_level(SI), si_level(MaxSI)),
        cvss_decimal:sub(sa_level(SA), sa_level(MaxSA)),
        cvss_decimal:sub(cr_level(CR), cr_level(MaxCR)),
        cvss_decimal:sub(ir_level(IR), ir_level(MaxIR)),
        cvss_decimal:sub(ar_level(AR), ar_level(MaxAR))
    ],
    Opts = ?DECIMAL_OPTS,
    case lists:all(fun(D) -> cvss_decimal:cmp(D, ?ZERO, Opts) >= 0 end, Dists) of
        true ->
            [DAV, DPR, DUI, DAC, DAT, DVC, DVI, DVA, DSC, DSI, DSA, DCR, DIR, DAR] = Dists,
            D1 = cvss_decimal:add(cvss_decimal:add(DAV, DPR), DUI),
            D2 = cvss_decimal:add(DAC, DAT),
            D3EQ6 = cvss_decimal:add(
                cvss_decimal:add(
                    cvss_decimal:add(cvss_decimal:add(cvss_decimal:add(DVC, DVI), DVA), DCR),
                    DIR
                ),
                DAR
            ),
            D4 = cvss_decimal:add(cvss_decimal:add(DSC, DSI), DSA),
            {D1, D2, D3EQ6, D4};
        false ->
            find_first_valid(E, Rest)
    end.

max_composed_eq5(attacked) -> [{attacked}];
max_composed_eq5(poc) -> [{poc}];
max_composed_eq5(unreported) -> [{unreported}].

%% Metric level values matching FIRST JS reference (0.1 step decimals)
av_level(network) -> ?ZERO;
av_level(adjacent) -> ?D(<<"0.1">>);
av_level(local) -> ?D(<<"0.2">>);
av_level(physical) -> ?D(<<"0.3">>).

pr_level(none) -> ?ZERO;
pr_level(low) -> ?D(<<"0.1">>);
pr_level(high) -> ?D(<<"0.2">>).

ui_level(none) -> ?ZERO;
ui_level(passive) -> ?D(<<"0.1">>);
ui_level(active) -> ?D(<<"0.2">>).

ac_level(low) -> ?ZERO;
ac_level(high) -> ?D(<<"0.1">>).

at_level(none) -> ?ZERO;
at_level(present) -> ?D(<<"0.1">>).

vc_level(high) -> ?ZERO;
vc_level(low) -> ?D(<<"0.1">>);
vc_level(none) -> ?D(<<"0.2">>).

vi_level(high) -> ?ZERO;
vi_level(low) -> ?D(<<"0.1">>);
vi_level(none) -> ?D(<<"0.2">>).

va_level(high) -> ?ZERO;
va_level(low) -> ?D(<<"0.1">>);
va_level(none) -> ?D(<<"0.2">>).

sc_level(high) -> ?D(<<"0.1">>);
sc_level(low) -> ?D(<<"0.2">>);
sc_level(none) -> ?D(<<"0.3">>).

si_level(safety) -> ?ZERO;
si_level(high) -> ?D(<<"0.1">>);
si_level(low) -> ?D(<<"0.2">>);
si_level(none) -> ?D(<<"0.3">>).

sa_level(safety) -> ?ZERO;
sa_level(high) -> ?D(<<"0.1">>);
sa_level(low) -> ?D(<<"0.2">>);
sa_level(none) -> ?D(<<"0.3">>).

cr_level(high) -> ?ZERO;
cr_level(medium) -> ?D(<<"0.1">>);
cr_level(low) -> ?D(<<"0.2">>).

ir_level(high) -> ?ZERO;
ir_level(medium) -> ?D(<<"0.1">>);
ir_level(low) -> ?D(<<"0.2">>).

ar_level(high) -> ?ZERO;
ar_level(medium) -> ?D(<<"0.1">>);
ar_level(low) -> ?D(<<"0.2">>).

%% MSD for combined EQ3+EQ6
msd_eq3eq6(BaseScore, EQ1, EQ2, EQ3, EQ4, EQ5, EQ6) ->
    case {EQ3, EQ6} of
        {0, 0} ->
            %% Two paths: 00->01 or 00->10, take the one with higher score
            Left = lookup_eq(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6 + 1),
            Right = lookup_eq(EQ1, EQ2, EQ3 + 1, EQ4, EQ5, EQ6),
            case {Left, Right} of
                {undefined, undefined} -> undefined;
                {undefined, R} -> cvss_decimal:sub(BaseScore, R);
                {L, undefined} -> cvss_decimal:sub(BaseScore, L);
                {L, R} -> cvss_decimal:sub(BaseScore, cvss_common:dmax(L, R))
            end;
        {1, 1} ->
            %% 11 -> 21
            msd(BaseScore, EQ1, EQ2, EQ3 + 1, EQ4, EQ5, EQ6);
        {0, 1} ->
            %% 01 -> 11
            msd(BaseScore, EQ1, EQ2, EQ3 + 1, EQ4, EQ5, EQ6);
        {1, 0} ->
            %% 10 -> 11
            msd(BaseScore, EQ1, EQ2, EQ3, EQ4, EQ5, EQ6 + 1);
        {2, 1} ->
            %% 21 -> 32 (does not exist, so undefined)
            undefined;
        _ ->
            undefined
    end.

msd(BaseScore, EQ1, EQ2, EQ3, EQ4, EQ5, EQ6) ->
    case lookup_eq(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6) of
        undefined -> undefined;
        LowerScore -> cvss_decimal:sub(BaseScore, LowerScore)
    end.

lookup_eq(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6) when
    EQ1 >= 0,
    EQ1 =< 2,
    EQ2 >= 0,
    EQ2 =< 1,
    EQ3 >= 0,
    EQ3 =< 2,
    EQ4 >= 0,
    EQ4 =< 2,
    EQ5 >= 0,
    EQ5 =< 2,
    EQ6 >= 0,
    EQ6 =< 1
->
    cvss_v4_lookup:lookup(EQ1, EQ2, EQ3, EQ4, EQ5, EQ6);
lookup_eq(_, _, _, _, _, _) ->
    undefined.

%% Max severity depths per EQ (decimal values, step=0.1)
max_severity_eq1(0) -> ?D(<<"0.1">>);
max_severity_eq1(1) -> ?D(<<"0.4">>);
max_severity_eq1(2) -> ?D(<<"0.5">>).

max_severity_eq2(0) -> ?D(<<"0.1">>);
max_severity_eq2(1) -> ?D(<<"0.2">>).

max_severity_eq3eq6(0, 0) -> ?D(<<"0.7">>);
max_severity_eq3eq6(0, 1) -> ?D(<<"0.6">>);
max_severity_eq3eq6(1, 0) -> ?D(<<"0.8">>);
max_severity_eq3eq6(1, 1) -> ?D(<<"0.8">>);
max_severity_eq3eq6(2, 1) -> ?D(<<"1.0">>);
max_severity_eq3eq6(_, _) -> ?ZERO.

max_severity_eq4(0) -> ?D(<<"0.6">>);
max_severity_eq4(1) -> ?D(<<"0.5">>);
max_severity_eq4(2) -> ?D(<<"0.4">>).

%% Max composed vectors for each EQ level
%% Returns list of {MetricValue, ...} tuples representing max severity vectors
max_composed_eq1(0) -> [{network, none, none}];
max_composed_eq1(1) -> [{adjacent, none, none}, {network, low, none}, {network, none, passive}];
max_composed_eq1(2) -> [{physical, none, none}, {adjacent, low, passive}].

max_composed_eq2(0) -> [{low, none}];
max_composed_eq2(1) -> [{high, none}, {low, present}].

max_composed_eq3eq6(0, 0) ->
    [{high, high, high, high, high, high}];
max_composed_eq3eq6(0, 1) ->
    [{high, high, low, medium, medium, high}, {high, high, high, medium, medium, medium}];
max_composed_eq3eq6(1, 0) ->
    [{low, high, high, high, high, high}, {high, low, high, high, high, high}];
max_composed_eq3eq6(1, 1) ->
    [
        {low, high, low, high, medium, high},
        {low, high, high, high, medium, medium},
        {high, low, high, medium, high, medium},
        {high, low, low, medium, high, high},
        {low, low, high, high, high, medium}
    ];
max_composed_eq3eq6(2, 1) ->
    [{low, low, low, high, high, high}];
max_composed_eq3eq6(_, _) ->
    [].

max_composed_eq4(0) -> [{high, safety, safety}];
max_composed_eq4(1) -> [{high, high, high}];
max_composed_eq4(2) -> [{low, low, low}].
