%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v2_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("cvss/include/cvss_v2.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([
    doctest/1,
    parse_base_test/1,
    parse_temporal_test/1,
    parse_environmental_test/1,
    parse_parentheses_test/1,
    compose_test/1,
    validate_test/1,
    score_base_test/1,
    score_temporal_test/1,
    score_environmental_test/1,
    score_specification_examples_test/1,
    redhat_simple_v2_test/1,
    redhat_random_v2_test/1,
    redhat_calculator_v2_test/1,
    redhat_cvsslib_v2_test/1
]).

all() ->
    [{group, v2_tests}, {group, redhat_vectors}].

groups() ->
    [
        {v2_tests, [parallel], [
            doctest,
            parse_base_test,
            parse_temporal_test,
            parse_environmental_test,
            parse_parentheses_test,
            compose_test,
            validate_test,
            score_base_test,
            score_temporal_test,
            score_environmental_test,
            score_specification_examples_test
        ]},
        {redhat_vectors, [], [
            redhat_simple_v2_test,
            redhat_random_v2_test,
            redhat_calculator_v2_test,
            redhat_cvsslib_v2_test
        ]}
    ].

init_per_suite(Config) ->
    cvss_test_util:ensure_dataset(redhat, Config).

end_per_suite(_Config) ->
    ok.

doctest(_Config) ->
    doctest:module(cvss_v2, #{
        records => [{cvss_v2, record_info(fields, cvss_v2)}]
    }),
    ok.

parse_base_test(_Config) ->
    %% Network, low complexity, no auth, complete impacts
    {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>),
    ?assertEqual(network, Cvss#cvss_v2.av),
    ?assertEqual(low, Cvss#cvss_v2.ac),
    ?assertEqual(none, Cvss#cvss_v2.au),
    ?assertEqual(complete, Cvss#cvss_v2.c),
    ?assertEqual(complete, Cvss#cvss_v2.i),
    ?assertEqual(complete, Cvss#cvss_v2.a),

    %% Adjacent network, medium complexity, single auth
    {ok, Cvss2} = cvss_v2:parse(<<"AV:A/AC:M/Au:S/C:P/I:P/A:P">>),
    ?assertEqual(adjacent_network, Cvss2#cvss_v2.av),
    ?assertEqual(medium, Cvss2#cvss_v2.ac),
    ?assertEqual(single, Cvss2#cvss_v2.au),
    ?assertEqual(partial, Cvss2#cvss_v2.c),

    %% Local, high complexity, multiple auth
    {ok, Cvss3} = cvss_v2:parse(<<"AV:L/AC:H/Au:M/C:N/I:N/A:N">>),
    ?assertEqual(local, Cvss3#cvss_v2.av),
    ?assertEqual(high, Cvss3#cvss_v2.ac),
    ?assertEqual(multiple, Cvss3#cvss_v2.au),
    ?assertEqual(none, Cvss3#cvss_v2.c),

    ok.

parse_temporal_test(_Config) ->
    {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C">>),
    ?assertEqual(high, Cvss#cvss_v2.e),
    ?assertEqual(unavailable, Cvss#cvss_v2.rl),
    ?assertEqual(confirmed, Cvss#cvss_v2.rc),

    {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC">>),
    ?assertEqual(unproven, Cvss2#cvss_v2.e),
    ?assertEqual(official_fix, Cvss2#cvss_v2.rl),
    ?assertEqual(unconfirmed, Cvss2#cvss_v2.rc),

    {ok, Cvss3} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC/RL:TF/RC:UR">>),
    ?assertEqual(proof_of_concept, Cvss3#cvss_v2.e),
    ?assertEqual(temporary_fix, Cvss3#cvss_v2.rl),
    ?assertEqual(uncorroborated, Cvss3#cvss_v2.rc),

    {ok, Cvss4} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:W/RC:ND">>),
    ?assertEqual(functional, Cvss4#cvss_v2.e),
    ?assertEqual(workaround, Cvss4#cvss_v2.rl),
    ?assertEqual(not_defined, Cvss4#cvss_v2.rc),

    {ok, Cvss5} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND">>),
    ?assertEqual(not_defined, Cvss5#cvss_v2.e),
    ?assertEqual(not_defined, Cvss5#cvss_v2.rl),
    ?assertEqual(not_defined, Cvss5#cvss_v2.rc),

    ok.

parse_environmental_test(_Config) ->
    {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:H/AR:H">>),
    ?assertEqual(high, Cvss#cvss_v2.cdp),
    ?assertEqual(high, Cvss#cvss_v2.td),
    ?assertEqual(high, Cvss#cvss_v2.cr),
    ?assertEqual(high, Cvss#cvss_v2.ir),
    ?assertEqual(high, Cvss#cvss_v2.ar),

    {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:LM/TD:M/CR:M/IR:L/AR:ND">>),
    ?assertEqual(low_medium, Cvss2#cvss_v2.cdp),
    ?assertEqual(medium, Cvss2#cvss_v2.td),
    ?assertEqual(medium, Cvss2#cvss_v2.cr),
    ?assertEqual(low, Cvss2#cvss_v2.ir),
    ?assertEqual(not_defined, Cvss2#cvss_v2.ar),

    {ok, Cvss3} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:MH/TD:L">>),
    ?assertEqual(medium_high, Cvss3#cvss_v2.cdp),
    ?assertEqual(low, Cvss3#cvss_v2.td),

    {ok, Cvss4} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:N/TD:N">>),
    ?assertEqual(none, Cvss4#cvss_v2.cdp),
    ?assertEqual(none, Cvss4#cvss_v2.td),

    ok.

parse_parentheses_test(_Config) ->
    %% With parentheses
    {ok, Cvss} = cvss_v2:parse(<<"(AV:N/AC:L/Au:N/C:C/I:C/A:C)">>),
    ?assertEqual(network, Cvss#cvss_v2.av),
    ?assertEqual(low, Cvss#cvss_v2.ac),

    %% Without parentheses
    {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>),
    ?assertEqual(network, Cvss2#cvss_v2.av),
    ?assertEqual(low, Cvss2#cvss_v2.ac),

    ok.

compose_test(_Config) ->
    %% Base only
    Cvss1 = #cvss_v2{av = network, ac = low, au = none, c = complete, i = complete, a = complete},
    ?assertEqual(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>, iolist_to_binary(cvss_v2:compose(Cvss1))),

    %% With temporal
    Cvss2 = Cvss1#cvss_v2{e = high, rl = unavailable, rc = confirmed},
    ?assertEqual(
        <<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C">>, iolist_to_binary(cvss_v2:compose(Cvss2))
    ),

    %% With environmental
    Cvss3 = Cvss1#cvss_v2{cdp = high, td = high, cr = high, ir = medium, ar = low},
    ?assertEqual(
        <<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:M/AR:L">>,
        iolist_to_binary(cvss_v2:compose(Cvss3))
    ),

    ok.

validate_test(_Config) ->
    %% Valid base
    Cvss1 = #cvss_v2{av = network, ac = low, au = none, c = complete, i = complete, a = complete},
    ?assert(cvss_v2:valid(Cvss1)),

    %% Valid with all options
    Cvss2 = Cvss1#cvss_v2{
        e = high,
        rl = unavailable,
        rc = confirmed,
        cdp = high,
        td = high,
        cr = high,
        ir = high,
        ar = high
    },
    ?assert(cvss_v2:valid(Cvss2)),

    %% Valid with not_defined values
    Cvss3 = Cvss1#cvss_v2{
        e = not_defined,
        rl = not_defined,
        rc = not_defined,
        cdp = not_defined,
        td = not_defined,
        cr = not_defined,
        ir = not_defined,
        ar = not_defined
    },
    ?assert(cvss_v2:valid(Cvss3)),

    ok.

score_base_test(_Config) ->
    %% Maximum base score: Network, Low AC, No Auth, Complete C/I/A
    {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>),
    Score = cvss_v2:score(Cvss),
    ?assertEqual(10.0, Score),

    %% No impacts should be 0.0
    {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:N/I:N/A:N">>),
    Score2 = cvss_v2:score(Cvss2),
    ?assertEqual(0.0, Score2),

    %% Partial impacts
    {ok, Cvss3} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:P/I:P/A:P">>),
    Score3 = cvss_v2:score(Cvss3),
    ?assertEqual(7.5, Score3),

    %% Local access
    {ok, Cvss4} = cvss_v2:parse(<<"AV:L/AC:L/Au:N/C:C/I:C/A:C">>),
    Score4 = cvss_v2:score(Cvss4),
    ?assertEqual(7.2, Score4),

    ok.

score_temporal_test(_Config) ->
    %% Base score with temporal at worst (no reduction)
    {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C">>),
    Score = cvss_v2:score(Cvss),
    ?assertEqual(10.0, Score),

    %% With temporal that reduces
    {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC">>),
    Score2 = cvss_v2:score(Cvss2),
    %% 10.0 * 0.85 * 0.87 * 0.9 = 6.6555 -> 6.7
    ?assertEqual(6.7, Score2),

    %% ND values should not change score
    {ok, Cvss3} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/E:ND/RL:ND/RC:ND">>),
    Score3 = cvss_v2:score(Cvss3),
    ?assertEqual(10.0, Score3),

    ok.

score_environmental_test(_Config) ->
    %% With environmental high requirements
    {ok, Cvss} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:H/AR:H">>),
    Score = cvss_v2:score(Cvss),
    ?assertEqual(10.0, Score),

    %% With low target distribution
    {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:N/TD:L">>),
    Score2 = cvss_v2:score(Cvss2),
    %% Score reduced by TD
    ?assert(Score2 < 10.0),

    ok.

score_specification_examples_test(_Config) ->
    %% These are example vectors from the CVSS 2.0 specification
    %% CVE-2002-0392 example: AV:N/AC:L/Au:N/C:N/I:N/A:C
    {ok, Cvss1} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:N/I:N/A:C">>),
    Score1 = cvss_v2:score(Cvss1),
    ?assertEqual(7.8, Score1),

    %% CVE-2003-0818 example: AV:N/AC:L/Au:N/C:C/I:C/A:C
    {ok, Cvss2} = cvss_v2:parse(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>),
    Score2 = cvss_v2:score(Cvss2),
    ?assertEqual(10.0, Score2),

    %% CVE-2003-0062 example: AV:L/AC:H/Au:N/C:C/I:C/A:C
    {ok, Cvss3} = cvss_v2:parse(<<"AV:L/AC:H/Au:N/C:C/I:C/A:C">>),
    Score3 = cvss_v2:score(Cvss3),
    ?assertEqual(6.2, Score3),

    ok.

redhat_simple_v2_test(Config) ->
    test_redhat_file(Config, "vectors_simple2").

redhat_random_v2_test(Config) ->
    test_redhat_file(Config, "vectors_random2").

redhat_calculator_v2_test(Config) ->
    test_redhat_file(Config, "vectors_calculator2").

redhat_cvsslib_v2_test(Config) ->
    test_redhat_file(Config, "vectors_cvsslib2").

test_redhat_file(Config, FileName) ->
    FilePath = cvss_test_util:redhat_vector_file(Config, FileName),
    ScoreFuns = fun(Vector) ->
        case cvss_v2:parse(Vector) of
            {ok, Cvss} ->
                {ok, {
                    cvss_v2:base_score(Cvss),
                    cvss_v2:temporal_score(Cvss),
                    cvss_v2:environmental_score(Cvss)
                }};
            {error, Reason} ->
                {error, Reason}
        end
    end,
    cvss_test_util:test_detailed_vectors(
        FilePath, fun cvss_test_util:parse_redhat_detailed_line/1, ScoreFuns, 0.1001
    ).
