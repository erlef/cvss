%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v3_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("cvss/include/cvss_v3.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([
    doctest/1,
    parse_base_v30_test/1,
    parse_base_v31_test/1,
    parse_temporal_test/1,
    parse_environmental_test/1,
    compose_test/1,
    validate_test/1,
    score_base_v30_test/1,
    score_base_v31_test/1,
    score_temporal_test/1,
    score_environmental_v30_test/1,
    score_environmental_v31_test/1,
    score_scope_changed_test/1,
    score_specification_examples_test/1,
    redhat_simple_v30_test/1,
    redhat_simple_v31_test/1,
    redhat_random_v30_test/1,
    redhat_random_v31_test/1,
    redhat_calculator_v30_test/1,
    redhat_cvsslib_v30_test/1
]).

all() ->
    [{group, v3_tests}, {group, redhat_vectors}].

groups() ->
    [
        {v3_tests, [parallel], [
            doctest,
            parse_base_v30_test,
            parse_base_v31_test,
            parse_temporal_test,
            parse_environmental_test,
            compose_test,
            validate_test,
            score_base_v30_test,
            score_base_v31_test,
            score_temporal_test,
            score_environmental_v30_test,
            score_environmental_v31_test,
            score_scope_changed_test,
            score_specification_examples_test
        ]},
        {redhat_vectors, [], [
            redhat_simple_v30_test,
            redhat_simple_v31_test,
            redhat_random_v30_test,
            redhat_random_v31_test,
            redhat_calculator_v30_test,
            redhat_cvsslib_v30_test
        ]}
    ].

init_per_suite(Config) ->
    cvss_test_util:ensure_dataset(redhat, Config).

end_per_suite(_Config) ->
    ok.

doctest(_Config) ->
    doctest:module(cvss_v3, #{
        records => [{cvss_v3, record_info(fields, cvss_v3)}]
    }),
    ok.

parse_base_v30_test(_Config) ->
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),
    ?assertEqual('3.0', Cvss#cvss_v3.version),
    ?assertEqual(network, Cvss#cvss_v3.av),
    ?assertEqual(low, Cvss#cvss_v3.ac),
    ?assertEqual(none, Cvss#cvss_v3.pr),
    ?assertEqual(none, Cvss#cvss_v3.ui),
    ?assertEqual(unchanged, Cvss#cvss_v3.s),
    ?assertEqual(high, Cvss#cvss_v3.c),
    ?assertEqual(high, Cvss#cvss_v3.i),
    ?assertEqual(high, Cvss#cvss_v3.a),

    ok.

parse_base_v31_test(_Config) ->
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),
    ?assertEqual('3.1', Cvss#cvss_v3.version),
    ?assertEqual(network, Cvss#cvss_v3.av),

    %% Adjacent, physical
    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L">>),
    ?assertEqual(adjacent, Cvss2#cvss_v3.av),
    ?assertEqual(high, Cvss2#cvss_v3.ac),
    ?assertEqual(low, Cvss2#cvss_v3.pr),
    ?assertEqual(required, Cvss2#cvss_v3.ui),
    ?assertEqual(changed, Cvss2#cvss_v3.s),

    {ok, Cvss3} = cvss_v3:parse(<<"CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N">>),
    ?assertEqual(physical, Cvss3#cvss_v3.av),
    ?assertEqual(high, Cvss3#cvss_v3.pr),
    ?assertEqual(none, Cvss3#cvss_v3.c),

    {ok, Cvss4} = cvss_v3:parse(<<"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),
    ?assertEqual(local, Cvss4#cvss_v3.av),

    ok.

parse_temporal_test(_Config) ->
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:U/RC:C">>),
    ?assertEqual(high, Cvss#cvss_v3.e),
    ?assertEqual(unavailable, Cvss#cvss_v3.rl),
    ?assertEqual(confirmed, Cvss#cvss_v3.rc),

    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:U">>),
    ?assertEqual(unproven, Cvss2#cvss_v3.e),
    ?assertEqual(official_fix, Cvss2#cvss_v3.rl),
    ?assertEqual(unknown, Cvss2#cvss_v3.rc),

    {ok, Cvss3} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:T/RC:R">>),
    ?assertEqual(poc, Cvss3#cvss_v3.e),
    ?assertEqual(temporary_fix, Cvss3#cvss_v3.rl),
    ?assertEqual(reasonable, Cvss3#cvss_v3.rc),

    {ok, Cvss4} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W">>),
    ?assertEqual(functional, Cvss4#cvss_v3.e),
    ?assertEqual(workaround, Cvss4#cvss_v3.rl),

    {ok, Cvss5} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X">>),
    ?assertEqual(not_defined, Cvss5#cvss_v3.e),
    ?assertEqual(not_defined, Cvss5#cvss_v3.rl),
    ?assertEqual(not_defined, Cvss5#cvss_v3.rc),

    ok.

parse_environmental_test(_Config) ->
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H">>),
    ?assertEqual(high, Cvss#cvss_v3.cr),
    ?assertEqual(high, Cvss#cvss_v3.ir),
    ?assertEqual(high, Cvss#cvss_v3.ar),

    {ok, Cvss2} = cvss_v3:parse(
        <<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:L">>
    ),
    ?assertEqual(local, Cvss2#cvss_v3.mav),
    ?assertEqual(high, Cvss2#cvss_v3.mac),
    ?assertEqual(low, Cvss2#cvss_v3.mpr),
    ?assertEqual(required, Cvss2#cvss_v3.mui),
    ?assertEqual(changed, Cvss2#cvss_v3.ms),
    ?assertEqual(low, Cvss2#cvss_v3.mc),
    ?assertEqual(low, Cvss2#cvss_v3.mi),
    ?assertEqual(low, Cvss2#cvss_v3.ma),

    ok.

compose_test(_Config) ->
    %% Base only
    Cvss1 = #cvss_v3{
        version = '3.1',
        av = network,
        ac = low,
        pr = none,
        ui = none,
        s = unchanged,
        c = high,
        i = high,
        a = high
    },
    ?assertEqual(
        <<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, iolist_to_binary(cvss_v3:compose(Cvss1))
    ),

    %% v3.0
    Cvss2 = Cvss1#cvss_v3{version = '3.0'},
    ?assertEqual(
        <<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, iolist_to_binary(cvss_v3:compose(Cvss2))
    ),

    %% With temporal
    Cvss3 = Cvss1#cvss_v3{e = functional, rl = workaround, rc = reasonable},
    ?assertEqual(
        <<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:R">>,
        iolist_to_binary(cvss_v3:compose(Cvss3))
    ),

    %% With environmental
    Cvss4 = Cvss1#cvss_v3{mav = local, mac = high, mpr = low},
    ?assertEqual(
        <<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H/MPR:L">>,
        iolist_to_binary(cvss_v3:compose(Cvss4))
    ),

    ok.

validate_test(_Config) ->
    %% Valid base
    Cvss1 = #cvss_v3{
        version = '3.1',
        av = network,
        ac = low,
        pr = none,
        ui = none,
        s = unchanged,
        c = high,
        i = high,
        a = high
    },
    ?assert(cvss_v3:valid(Cvss1)),

    %% Valid with temporal
    Cvss2 = Cvss1#cvss_v3{e = functional, rl = workaround, rc = reasonable},
    ?assert(cvss_v3:valid(Cvss2)),

    %% Valid with environmental
    Cvss3 = Cvss1#cvss_v3{mav = local, mac = high, mpr = low, cr = high},
    ?assert(cvss_v3:valid(Cvss3)),

    ok.

score_base_v30_test(_Config) ->
    %% Maximum base score: Network, Low AC, No PR, No UI, Scope Unchanged, High C/I/A
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),
    Score = cvss_v3:score(Cvss),
    ?assertEqual(9.8, Score),

    %% No impacts should be 0.0
    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N">>),
    Score2 = cvss_v3:score(Cvss2),
    ?assertEqual(0.0, Score2),

    ok.

score_base_v31_test(_Config) ->
    %% Maximum base score for v3.1
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),
    Score = cvss_v3:score(Cvss),
    ?assertEqual(9.8, Score),

    %% No impacts should be 0.0
    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N">>),
    Score2 = cvss_v3:score(Cvss2),
    ?assertEqual(0.0, Score2),

    ok.

score_temporal_test(_Config) ->
    %% Base with temporal at worst (no reduction)
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:U/RC:C">>),
    Score = cvss_v3:score(Cvss),
    ?assertEqual(9.8, Score),

    %% With temporal that reduces
    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:U">>),
    Score2 = cvss_v3:score(Cvss2),
    ?assert(Score2 < 9.8),

    %% X (not defined) values should not affect score
    {ok, Cvss3} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X/RC:X">>),
    Score3 = cvss_v3:score(Cvss3),
    ?assertEqual(9.8, Score3),

    ok.

score_environmental_v30_test(_Config) ->
    %% With environmental metrics
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H">>),
    Score = cvss_v3:score(Cvss),
    ?assert(Score > 0.0),

    %% Modified metrics that reduce severity
    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N">>),
    Score2 = cvss_v3:score(Cvss2),
    ?assertEqual(0.0, Score2),

    ok.

score_environmental_v31_test(_Config) ->
    %% With environmental metrics
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H">>),
    Score = cvss_v3:score(Cvss),
    ?assert(Score > 0.0),

    %% Modified metrics that reduce severity
    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N">>),
    Score2 = cvss_v3:score(Cvss2),
    ?assertEqual(0.0, Score2),

    ok.

score_scope_changed_test(_Config) ->
    %% Scope Changed gives maximum 10.0
    {ok, Cvss} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H">>),
    Score = cvss_v3:score(Cvss),
    ?assertEqual(10.0, Score),

    %% Scope Unchanged with same metrics gives 9.8
    {ok, Cvss2} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),
    Score2 = cvss_v3:score(Cvss2),
    ?assertEqual(9.8, Score2),

    %% PR coefficient changes with scope
    {ok, Cvss3} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H">>),
    {ok, Cvss4} = cvss_v3:parse(<<"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H">>),
    Score3 = cvss_v3:score(Cvss3),
    Score4 = cvss_v3:score(Cvss4),
    ?assert(Score4 > Score3),

    ok.

score_specification_examples_test(_Config) ->
    %% CVSS 3.0 examples from FIRST specification
    V30Examples = [
        {<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N">>, 6.1},
        {<<"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N">>, 6.4},
        {<<"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N">>, 3.1},
        {<<"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H">>, 9.9},
        {<<"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L">>, 4.2},
        {<<"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H">>, 8.8},
        {<<"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H">>, 7.8},
        {<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N">>, 7.5},
        {<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, 9.8},
        {<<"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N">>, 6.8},
        {<<"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, 6.8},
        {<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N">>, 5.8},
        {<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N">>, 5.8},
        {<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H">>, 9.6},
        {<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H">>, 8.8},
        {<<"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N">>, 6.8},
        {<<"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, 8.8}
    ],

    %% CVSS 3.1 examples from FIRST specification
    V31Examples = [
        {<<"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N">>, 3.8},
        {<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N">>, 7.5},
        {<<"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, 6.8},
        {<<"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N">>, 6.4},
        {<<"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N">>, 3.1},
        {<<"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H">>, 9.9},
        {<<"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L">>, 4.2},
        {<<"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H">>, 7.2},
        {<<"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H">>, 7.8},
        {<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, 9.8},
        {<<"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N">>, 6.8},
        {<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H">>, 9.6},
        {<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H">>, 8.8},
        {<<"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N">>, 7.4},
        {<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N">>, 6.1},
        {<<"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H">>, 7.8},
        {<<"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N">>, 4.6},
        {<<"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>, 8.8}
    ],

    lists:foreach(
        fun({Vector, Expected}) ->
            {ok, Cvss} = cvss_v3:parse(Vector),
            Actual = cvss_v3:score(Cvss),
            ?assertEqual(Expected, Actual, #{vector => Vector})
        end,
        V30Examples ++ V31Examples
    ),

    ok.

redhat_simple_v30_test(Config) -> test_redhat_file(Config, "vectors_simple3").
redhat_simple_v31_test(Config) -> test_redhat_file(Config, "vectors_simple31").
redhat_random_v30_test(Config) -> test_redhat_file(Config, "vectors_random3").
redhat_random_v31_test(Config) -> test_redhat_file(Config, "vectors_random31").
redhat_calculator_v30_test(Config) -> test_redhat_file(Config, "vectors_calculator3").
redhat_cvsslib_v30_test(Config) -> test_redhat_file(Config, "vectors_cvsslib3").

test_redhat_file(Config, FileName) ->
    FilePath = cvss_test_util:redhat_vector_file(Config, FileName),
    ScoreFuns = fun(Vector) ->
        case cvss_v3:parse(Vector) of
            {ok, Cvss} ->
                {ok, {
                    cvss_v3:base_score(Cvss),
                    cvss_v3:temporal_score(Cvss),
                    cvss_v3:environmental_score(Cvss)
                }};
            {error, Reason} ->
                {error, Reason}
        end
    end,
    cvss_test_util:test_detailed_vectors(
        FilePath, fun cvss_test_util:parse_redhat_detailed_line/1, ScoreFuns, 0.1001
    ).
