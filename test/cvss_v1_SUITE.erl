%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_v1_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("cvss/include/cvss_v1.hrl").

-export([all/0, groups/0]).
-export([
    doctest/1,
    parse_base_test/1,
    parse_temporal_test/1,
    parse_environmental_test/1,
    parse_impact_bias_test/1,
    compose_test/1,
    validate_test/1,
    score_base_test/1,
    score_temporal_test/1,
    score_environmental_test/1,
    score_impact_bias_test/1,
    score_specification_examples_test/1
]).

all() ->
    [{group, v1_tests}].

groups() ->
    [
        {v1_tests, [parallel], [
            doctest,
            parse_base_test,
            parse_temporal_test,
            parse_environmental_test,
            parse_impact_bias_test,
            compose_test,
            validate_test,
            score_base_test,
            score_temporal_test,
            score_environmental_test,
            score_impact_bias_test,
            score_specification_examples_test
        ]}
    ].

doctest(_Config) ->
    doctest:module(cvss_v1, #{
        records => [{cvss_v1, record_info(fields, cvss_v1)}]
    }),
    ok.

parse_base_test(_Config) ->
    %% Remote, low complexity, no auth, complete impacts
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>),
    ?assertEqual(remote, Cvss#cvss_v1.av),
    ?assertEqual(low, Cvss#cvss_v1.ac),
    ?assertEqual(not_required, Cvss#cvss_v1.au),
    ?assertEqual(complete, Cvss#cvss_v1.c),
    ?assertEqual(complete, Cvss#cvss_v1.i),
    ?assertEqual(complete, Cvss#cvss_v1.a),
    ?assertEqual(normal, Cvss#cvss_v1.ib),

    %% Local, high complexity, auth required, partial impacts
    {ok, Cvss2} = cvss_v1:parse(<<"AV:L/AC:H/Au:R/C:P/I:P/A:P">>),
    ?assertEqual(local, Cvss2#cvss_v1.av),
    ?assertEqual(high, Cvss2#cvss_v1.ac),
    ?assertEqual(required, Cvss2#cvss_v1.au),
    ?assertEqual(partial, Cvss2#cvss_v1.c),
    ?assertEqual(partial, Cvss2#cvss_v1.i),
    ?assertEqual(partial, Cvss2#cvss_v1.a),

    %% No impacts
    {ok, Cvss3} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:N/I:N/A:N">>),
    ?assertEqual(none, Cvss3#cvss_v1.c),
    ?assertEqual(none, Cvss3#cvss_v1.i),
    ?assertEqual(none, Cvss3#cvss_v1.a),

    ok.

parse_temporal_test(_Config) ->
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C">>),
    ?assertEqual(high, Cvss#cvss_v1.e),
    ?assertEqual(unavailable, Cvss#cvss_v1.rl),
    ?assertEqual(confirmed, Cvss#cvss_v1.rc),

    {ok, Cvss2} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:U/RL:OF/RC:UC">>),
    ?assertEqual(unproven, Cvss2#cvss_v1.e),
    ?assertEqual(official_fix, Cvss2#cvss_v1.rl),
    ?assertEqual(unconfirmed, Cvss2#cvss_v1.rc),

    {ok, Cvss3} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:POC/RL:TF/RC:UR">>),
    ?assertEqual(proof_of_concept, Cvss3#cvss_v1.e),
    ?assertEqual(temporary_fix, Cvss3#cvss_v1.rl),
    ?assertEqual(uncorroborated, Cvss3#cvss_v1.rc),

    {ok, Cvss4} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:F/RL:W">>),
    ?assertEqual(functional, Cvss4#cvss_v1.e),
    ?assertEqual(workaround, Cvss4#cvss_v1.rl),

    ok.

parse_environmental_test(_Config) ->
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:H/TD:H">>),
    ?assertEqual(high, Cvss#cvss_v1.cdp),
    ?assertEqual(high, Cvss#cvss_v1.td),

    {ok, Cvss2} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:N/TD:N">>),
    ?assertEqual(none, Cvss2#cvss_v1.cdp),
    ?assertEqual(none, Cvss2#cvss_v1.td),

    {ok, Cvss3} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:L/TD:L">>),
    ?assertEqual(low, Cvss3#cvss_v1.cdp),
    ?assertEqual(low, Cvss3#cvss_v1.td),

    {ok, Cvss4} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:M/TD:M">>),
    ?assertEqual(medium, Cvss4#cvss_v1.cdp),
    ?assertEqual(medium, Cvss4#cvss_v1.td),

    ok.

parse_impact_bias_test(_Config) ->
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/IB:C">>),
    ?assertEqual(confidentiality, Cvss#cvss_v1.ib),

    {ok, Cvss2} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/IB:I">>),
    ?assertEqual(integrity, Cvss2#cvss_v1.ib),

    {ok, Cvss3} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/IB:A">>),
    ?assertEqual(availability, Cvss3#cvss_v1.ib),

    {ok, Cvss4} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/IB:N">>),
    ?assertEqual(normal, Cvss4#cvss_v1.ib),

    ok.

compose_test(_Config) ->
    %% Base only
    Cvss1 = #cvss_v1{
        av = remote, ac = low, au = not_required, c = complete, i = complete, a = complete
    },
    ?assertEqual(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>, iolist_to_binary(cvss_v1:compose(Cvss1))),

    %% With impact bias
    Cvss2 = Cvss1#cvss_v1{ib = confidentiality},
    ?assertEqual(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/IB:C">>, iolist_to_binary(cvss_v1:compose(Cvss2))),

    %% With temporal
    Cvss3 = Cvss1#cvss_v1{e = high, rl = unavailable, rc = confirmed},
    ?assertEqual(
        <<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C">>, iolist_to_binary(cvss_v1:compose(Cvss3))
    ),

    %% With environmental
    Cvss4 = Cvss1#cvss_v1{cdp = high, td = high},
    ?assertEqual(
        <<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:H/TD:H">>, iolist_to_binary(cvss_v1:compose(Cvss4))
    ),

    ok.

validate_test(_Config) ->
    %% Valid
    Cvss1 = #cvss_v1{
        av = remote, ac = low, au = not_required, c = complete, i = complete, a = complete
    },
    ?assert(cvss_v1:valid(Cvss1)),

    %% Valid with all options
    Cvss2 = Cvss1#cvss_v1{
        ib = confidentiality,
        e = high,
        rl = unavailable,
        rc = confirmed,
        cdp = high,
        td = high
    },
    ?assert(cvss_v1:valid(Cvss2)),

    ok.

score_base_test(_Config) ->
    %% Maximum base score: Remote, Low AC, No Auth, Complete C/I/A
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>),
    Score = cvss_v1:score(Cvss),
    %% 10 * 1.0 * 1.0 * 1.0 * (1.0*0.333 + 1.0*0.333 + 1.0*0.333) = 9.99 -> 10.0
    ?assertEqual(10.0, Score),

    %% Minimum non-zero: Local, High AC, Auth required, None impacts
    {ok, Cvss2} = cvss_v1:parse(<<"AV:L/AC:H/Au:R/C:N/I:N/A:N">>),
    Score2 = cvss_v1:score(Cvss2),
    ?assertEqual(0.0, Score2),

    %% Local, Low AC, No Auth, Complete C/I/A
    {ok, Cvss3} = cvss_v1:parse(<<"AV:L/AC:L/Au:NR/C:C/I:C/A:C">>),
    Score3 = cvss_v1:score(Cvss3),
    %% 10 * 0.7 * 1.0 * 1.0 * 0.999 = 6.993 -> 7.0
    ?assertEqual(7.0, Score3),

    ok.

score_temporal_test(_Config) ->
    %% Base score with all temporal metrics at worst values (no reduction)
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C">>),
    Score = cvss_v1:score(Cvss),
    ?assertEqual(10.0, Score),

    %% With temporal metrics that reduce score
    {ok, Cvss2} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:U/RL:OF/RC:UC">>),
    Score2 = cvss_v1:score(Cvss2),
    %% 10.0 * 0.85 * 0.87 * 0.9 = 6.6555 -> 6.7
    ?assertEqual(6.7, Score2),

    ok.

score_environmental_test(_Config) ->
    %% Base + Temporal with environmental at highest
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H">>),
    Score = cvss_v1:score(Cvss),
    %% (10.0 + (10-10)*0.5) * 1.0 = 10.0
    ?assertEqual(10.0, Score),

    %% With reduced temporal and environmental
    {ok, Cvss2} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:L/TD:L">>),
    Score2 = cvss_v1:score(Cvss2),
    %% (10.0 + (10-10)*0.1) * 0.25 = 2.5
    ?assertEqual(2.5, Score2),

    ok.

score_impact_bias_test(_Config) ->
    %% Confidentiality bias with complete C
    {ok, Cvss} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:N/A:N/IB:C">>),
    Score = cvss_v1:score(Cvss),
    %% 10 * 1.0 * 1.0 * 1.0 * (1.0*0.5 + 0*0.25 + 0*0.25) = 5.0
    ?assertEqual(5.0, Score),

    %% Normal bias with same vector
    {ok, Cvss2} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:N/A:N">>),
    Score2 = cvss_v1:score(Cvss2),
    %% 10 * 1.0 * 1.0 * 1.0 * (1.0*0.333 + 0*0.333 + 0*0.333) = 3.33
    ?assertEqual(3.3, Score2),

    ok.

score_specification_examples_test(_Config) ->
    %% These are example vectors from the CVSS v1.0 specification

    %% CVE-2002-0392 (Apache Chunked-Encoding Memory Corruption)
    %% AV:R/AC:L/Au:NR/C:P/I:P/A:C/IB:A = 8.5
    {ok, Cvss1} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:P/I:P/A:C/IB:A">>),
    Score1 = cvss_v1:score(Cvss1),
    ?assertEqual(8.5, Score1),

    %% CVE-2003-0818 (Microsoft Windows ASN.1 Library Integer Handling)
    %% AV:R/AC:L/Au:NR/C:C/I:C/A:C = 10.0
    {ok, Cvss2} = cvss_v1:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>),
    Score2 = cvss_v1:score(Cvss2),
    ?assertEqual(10.0, Score2),

    %% CVE-2003-0062 (Buffer Overflow in NOD32 Antivirus)
    %% AV:L/AC:H/Au:NR/C:C/I:C/A:C = 5.6
    {ok, Cvss3} = cvss_v1:parse(<<"AV:L/AC:H/Au:NR/C:C/I:C/A:C">>),
    Score3 = cvss_v1:score(Cvss3),
    ?assertEqual(5.6, Score3),

    ok.
