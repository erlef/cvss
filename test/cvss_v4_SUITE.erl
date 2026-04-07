%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v4_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("cvss/include/cvss_v4.hrl").
-include("internal/decimal.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([
    doctest/1,
    parse_base_test/1,
    parse_threat_test/1,
    parse_environmental_test/1,
    parse_supplemental_test/1,
    compose_test/1,
    validate_test/1,
    score_base_test/1,
    score_zero_impact_test/1,
    score_with_threat_test/1,
    score_with_environmental_test/1,
    lookup_table_test/1,
    first_macro_scores_test/1,
    first_reference_scores_test/1,
    redhat_simple_v4_test/1,
    redhat_base_v4_test/1,
    redhat_threat_v4_test/1,
    redhat_security_v4_test/1,
    redhat_supplemental_v4_test/1,
    redhat_modified_v4_test/1,
    redhat_random_v4_test/1
]).

all() ->
    [{group, v4_tests}, {group, first_vectors}, {group, redhat_vectors}].

groups() ->
    [
        {v4_tests, [parallel], [
            doctest,
            parse_base_test,
            parse_threat_test,
            parse_environmental_test,
            parse_supplemental_test,
            compose_test,
            validate_test,
            score_base_test,
            score_zero_impact_test,
            score_with_threat_test,
            score_with_environmental_test,
            lookup_table_test
        ]},
        {first_vectors, [], [
            first_macro_scores_test,
            first_reference_scores_test
        ]},
        {redhat_vectors, [], [
            redhat_simple_v4_test,
            redhat_base_v4_test,
            redhat_threat_v4_test,
            redhat_security_v4_test,
            redhat_supplemental_v4_test,
            redhat_modified_v4_test,
            redhat_random_v4_test
        ]}
    ].

init_per_suite(Config) ->
    Config1 = cvss_test_util:ensure_dataset(first, Config),
    cvss_test_util:ensure_dataset(redhat, Config1).

end_per_suite(_Config) ->
    ok.

doctest(_Config) ->
    doctest:module(cvss_v4, #{
        records => [{cvss_v4, record_info(fields, cvss_v4)}]
    }),
    ok.

parse_base_test(_Config) ->
    {ok, Cvss} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>
    ),
    ?assertEqual(network, Cvss#cvss_v4.av),
    ?assertEqual(low, Cvss#cvss_v4.ac),
    ?assertEqual(none, Cvss#cvss_v4.at),
    ?assertEqual(none, Cvss#cvss_v4.pr),
    ?assertEqual(none, Cvss#cvss_v4.ui),
    ?assertEqual(high, Cvss#cvss_v4.vc),
    ?assertEqual(high, Cvss#cvss_v4.vi),
    ?assertEqual(high, Cvss#cvss_v4.va),
    ?assertEqual(high, Cvss#cvss_v4.sc),
    ?assertEqual(high, Cvss#cvss_v4.si),
    ?assertEqual(high, Cvss#cvss_v4.sa),

    %% Different base values
    {ok, Cvss2} = cvss_v4:parse(
        <<"CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L">>
    ),
    ?assertEqual(adjacent, Cvss2#cvss_v4.av),
    ?assertEqual(high, Cvss2#cvss_v4.ac),
    ?assertEqual(present, Cvss2#cvss_v4.at),
    ?assertEqual(low, Cvss2#cvss_v4.pr),
    ?assertEqual(passive, Cvss2#cvss_v4.ui),
    ?assertEqual(low, Cvss2#cvss_v4.vc),

    {ok, Cvss3} = cvss_v4:parse(
        <<"CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N">>
    ),
    ?assertEqual(local, Cvss3#cvss_v4.av),
    ?assertEqual(high, Cvss3#cvss_v4.pr),
    ?assertEqual(active, Cvss3#cvss_v4.ui),
    ?assertEqual(none, Cvss3#cvss_v4.vc),

    {ok, Cvss4} = cvss_v4:parse(
        <<"CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:S">>
    ),
    ?assertEqual(physical, Cvss4#cvss_v4.av),
    ?assertEqual(safety, Cvss4#cvss_v4.si),
    ?assertEqual(safety, Cvss4#cvss_v4.sa),

    ok.

parse_threat_test(_Config) ->
    {ok, Cvss} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A">>
    ),
    ?assertEqual(attacked, Cvss#cvss_v4.e),

    {ok, Cvss2} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P">>
    ),
    ?assertEqual(poc, Cvss2#cvss_v4.e),

    {ok, Cvss3} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U">>
    ),
    ?assertEqual(unreported, Cvss3#cvss_v4.e),

    {ok, Cvss4} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X">>
    ),
    ?assertEqual(not_defined, Cvss4#cvss_v4.e),

    ok.

parse_environmental_test(_Config) ->
    {ok, Cvss} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:H/IR:H/AR:H">>
    ),
    ?assertEqual(high, Cvss#cvss_v4.cr),
    ?assertEqual(high, Cvss#cvss_v4.ir),
    ?assertEqual(high, Cvss#cvss_v4.ar),

    {ok, Cvss2} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:L/MAC:H/MAT:P/MPR:L/MUI:P">>
    ),
    ?assertEqual(local, Cvss2#cvss_v4.mav),
    ?assertEqual(high, Cvss2#cvss_v4.mac),
    ?assertEqual(present, Cvss2#cvss_v4.mat),
    ?assertEqual(low, Cvss2#cvss_v4.mpr),
    ?assertEqual(passive, Cvss2#cvss_v4.mui),

    {ok, Cvss3} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:L/MVI:L/MVA:L/MSC:L/MSI:L/MSA:L">>
    ),
    ?assertEqual(low, Cvss3#cvss_v4.mvc),
    ?assertEqual(low, Cvss3#cvss_v4.mvi),
    ?assertEqual(low, Cvss3#cvss_v4.mva),
    ?assertEqual(low, Cvss3#cvss_v4.msc),
    ?assertEqual(low, Cvss3#cvss_v4.msi),
    ?assertEqual(low, Cvss3#cvss_v4.msa),

    ok.

parse_supplemental_test(_Config) ->
    {ok, Cvss} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/R:I/V:C/RE:H/U:Red">>
    ),
    ?assertEqual(present, Cvss#cvss_v4.safety),
    ?assertEqual(yes, Cvss#cvss_v4.automatable),
    ?assertEqual(irrecoverable, Cvss#cvss_v4.recovery),
    ?assertEqual(concentrated, Cvss#cvss_v4.value_density),
    ?assertEqual(high, Cvss#cvss_v4.response_effort),
    ?assertEqual(red, Cvss#cvss_v4.urgency),

    {ok, Cvss2} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:N/AU:N/R:A/V:D/RE:L/U:Clear">>
    ),
    ?assertEqual(negligible, Cvss2#cvss_v4.safety),
    ?assertEqual(no, Cvss2#cvss_v4.automatable),
    ?assertEqual(automatic, Cvss2#cvss_v4.recovery),
    ?assertEqual(diffuse, Cvss2#cvss_v4.value_density),
    ?assertEqual(low, Cvss2#cvss_v4.response_effort),
    ?assertEqual(clear, Cvss2#cvss_v4.urgency),

    {ok, Cvss3} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:U/RE:M/U:Green">>
    ),
    ?assertEqual(user, Cvss3#cvss_v4.recovery),
    ?assertEqual(moderate, Cvss3#cvss_v4.response_effort),
    ?assertEqual(green, Cvss3#cvss_v4.urgency),

    {ok, Cvss4} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/U:Amber">>
    ),
    ?assertEqual(amber, Cvss4#cvss_v4.urgency),

    %% X values parse as undefined (not defined)
    {ok, Cvss5} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:X/AU:X/R:X/V:X/RE:X/U:X">>
    ),
    ?assertEqual(undefined, Cvss5#cvss_v4.safety),
    ?assertEqual(undefined, Cvss5#cvss_v4.automatable),
    ?assertEqual(undefined, Cvss5#cvss_v4.recovery),
    ?assertEqual(undefined, Cvss5#cvss_v4.value_density),
    ?assertEqual(undefined, Cvss5#cvss_v4.response_effort),
    ?assertEqual(undefined, Cvss5#cvss_v4.urgency),

    %% X supplemental metrics are omitted in compose (roundtrip produces base-only vector)
    ?assertEqual(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>,
        iolist_to_binary(cvss_v4:compose(Cvss5))
    ),

    ok.

compose_test(_Config) ->
    %% Base only
    Cvss1 = #cvss_v4{
        av = network,
        ac = low,
        at = none,
        pr = none,
        ui = none,
        vc = high,
        vi = high,
        va = high,
        sc = high,
        si = high,
        sa = high
    },
    ?assertEqual(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>,
        iolist_to_binary(cvss_v4:compose(Cvss1))
    ),

    %% With threat
    Cvss2 = Cvss1#cvss_v4{e = attacked},
    ?assertEqual(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A">>,
        iolist_to_binary(cvss_v4:compose(Cvss2))
    ),

    %% With environmental
    Cvss3 = Cvss1#cvss_v4{cr = high, mav = local},
    ?assertEqual(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:H/MAV:L">>,
        iolist_to_binary(cvss_v4:compose(Cvss3))
    ),

    %% With safety values
    Cvss4 = #cvss_v4{
        av = network,
        ac = low,
        at = none,
        pr = none,
        ui = none,
        vc = high,
        vi = high,
        va = high,
        sc = high,
        si = safety,
        sa = safety
    },
    ?assertEqual(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:S">>,
        iolist_to_binary(cvss_v4:compose(Cvss4))
    ),

    %% With supplemental metrics
    Cvss5 = Cvss1#cvss_v4{
        safety = negligible,
        automatable = no,
        recovery = automatic,
        value_density = diffuse,
        response_effort = low,
        urgency = clear
    },
    ?assertEqual(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:N/AU:N/R:A/V:D/RE:L/U:Clear">>,
        iolist_to_binary(cvss_v4:compose(Cvss5))
    ),

    ok.

validate_test(_Config) ->
    Cvss1 = #cvss_v4{
        av = network,
        ac = low,
        at = none,
        pr = none,
        ui = none,
        vc = high,
        vi = high,
        va = high,
        sc = high,
        si = high,
        sa = high
    },
    ?assert(cvss_v4:valid(Cvss1)),

    Cvss2 = Cvss1#cvss_v4{
        e = attacked,
        cr = high,
        ir = high,
        ar = high,
        mav = local,
        mac = high,
        mat = present,
        mpr = low,
        mui = passive,
        mvc = low,
        mvi = low,
        mva = low,
        msc = low,
        msi = low,
        msa = low,
        safety = present,
        automatable = yes,
        recovery = irrecoverable,
        value_density = concentrated,
        response_effort = high,
        urgency = red
    },
    ?assert(cvss_v4:valid(Cvss2)),

    %% Invalid threat metric
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{e = garbage})),

    %% Invalid environmental metrics
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{cr = garbage})),
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{mav = garbage})),
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{msi = garbage})),

    %% Invalid supplemental metrics
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{safety = garbage})),
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{automatable = garbage})),
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{recovery = garbage})),
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{value_density = garbage})),
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{response_effort = garbage})),
    ?assertNot(cvss_v4:valid(Cvss1#cvss_v4{urgency = garbage})),

    %% Undefined optional metrics are valid
    ?assert(cvss_v4:valid(Cvss1#cvss_v4{e = undefined, cr = undefined, safety = undefined})),

    ok.

score_base_test(_Config) ->
    {ok, Cvss} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>
    ),
    ?assert(cvss_v4:score(Cvss) >= 9.0),

    {ok, Cvss2} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N">>
    ),
    Score2 = cvss_v4:score(Cvss2),
    ?assert(Score2 < 10.0),
    ?assert(Score2 > 0.0),

    ok.

score_zero_impact_test(_Config) ->
    {ok, Cvss} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N">>
    ),
    ?assertEqual(0.0, cvss_v4:score(Cvss)),

    ok.

score_with_threat_test(_Config) ->
    {ok, Cvss1} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A">>
    ),
    ?assert(cvss_v4:score(Cvss1) >= 9.0),

    {ok, Cvss2} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U">>
    ),
    ?assert(cvss_v4:score(Cvss2) =< 10.0),

    ok.

score_with_environmental_test(_Config) ->
    {ok, Cvss1} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N">>
    ),
    ?assertEqual(0.0, cvss_v4:score(Cvss1)),

    {ok, Cvss2} = cvss_v4:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L">>
    ),
    ?assert(cvss_v4:score(Cvss2) =< 10.0),

    ok.

lookup_table_test(_Config) ->
    ?assertEqual(?D(<<"10.0">>), cvss_v4_lookup:lookup(0, 0, 0, 0, 0, 0)),
    ?assertEqual(?D(<<"9.9">>), cvss_v4_lookup:lookup(0, 0, 0, 0, 0, 1)),
    ?assertEqual(?D(<<"0.1">>), cvss_v4_lookup:lookup(2, 1, 2, 2, 2, 1)),
    ?assertEqual(undefined, cvss_v4_lookup:lookup(9, 9, 9, 9, 9, 9)),

    ok.

%%====================================================================
%% FIRST vector tests
%%====================================================================

first_macro_scores_test(Config) ->
    FilePath = cvss_test_util:first_vector_file(Config, "macro-scores"),
    cvss_test_util:test_vectors(
        FilePath, fun cvss_test_util:parse_first_v4_line/1, fun score_v4/1, 0.1001
    ).

first_reference_scores_test(Config) ->
    FilePath = cvss_test_util:first_vector_file(Config, "reference-scores"),
    cvss_test_util:test_vectors(
        FilePath, fun cvss_test_util:parse_first_v4_line/1, fun score_v4/1, 0.1001
    ).

%%====================================================================
%% RedHat vector tests
%%====================================================================

redhat_simple_v4_test(Config) -> test_redhat_file(Config, "vectors_simple4").
redhat_base_v4_test(Config) -> test_redhat_file(Config, "vectors_base4").
redhat_threat_v4_test(Config) -> test_redhat_file(Config, "vectors_threat4").
redhat_security_v4_test(Config) -> test_redhat_file(Config, "vectors_security4").
redhat_supplemental_v4_test(Config) -> test_redhat_file(Config, "vectors_supplemental4").
redhat_modified_v4_test(Config) -> test_redhat_file(Config, "vectors_modified4").
redhat_random_v4_test(Config) -> test_redhat_file(Config, "vectors_random4").

test_redhat_file(Config, FileName) ->
    FilePath = cvss_test_util:redhat_vector_file(Config, FileName),
    cvss_test_util:test_vectors(
        FilePath, fun cvss_test_util:parse_redhat_v4_line/1, fun score_v4/1, 0.1001
    ).

%%====================================================================
%% Internal
%%====================================================================

score_v4(Vector) ->
    case cvss_v4:parse(Vector) of
        {ok, Cvss} -> {ok, cvss_v4:score(Cvss)};
        {error, Reason} -> {error, Reason}
    end.
