%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("cvss/include/cvss.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([
    doctest/1,
    parse_v1_test/1,
    parse_v2_test/1,
    parse_v3_test/1,
    parse_v4_test/1,
    compose_roundtrip_v1_test/1,
    compose_roundtrip_v2_test/1,
    compose_roundtrip_v3_test/1,
    compose_roundtrip_v4_test/1,
    validate_test/1,
    score_test/1,
    rating_test/1,
    rating_boundaries_test/1,
    invalid_vectors_test/1,
    version_detection_test/1,
    valid_implies_composable_test/1,
    valid_implies_scorable_test/1,
    invalid_record_not_valid_test/1
]).

all() ->
    [{group, api}].

groups() ->
    [
        {api, [parallel], [
            doctest,
            parse_v1_test,
            parse_v2_test,
            parse_v3_test,
            parse_v4_test,
            compose_roundtrip_v1_test,
            compose_roundtrip_v2_test,
            compose_roundtrip_v3_test,
            compose_roundtrip_v4_test,
            validate_test,
            score_test,
            rating_test,
            rating_boundaries_test,
            invalid_vectors_test,
            version_detection_test,
            valid_implies_composable_test,
            valid_implies_scorable_test,
            invalid_record_not_valid_test
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

doctest(_Config) ->
    doctest:module(cvss, #{
        records => [
            {cvss_v1, record_info(fields, cvss_v1)},
            {cvss_v2, record_info(fields, cvss_v2)},
            {cvss_v3, record_info(fields, cvss_v3)},
            {cvss_v4, record_info(fields, cvss_v4)}
        ]
    }),
    doctest:module(cvss_common, #{}),
    ok.

parse_v1_test(_Config) ->
    %% Base only
    {ok, #cvss_v1{
        av = remote, ac = low, au = not_required, c = complete, i = complete, a = complete
    }} =
        cvss:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>),

    %% With temporal metrics
    {ok, #cvss_v1{e = high, rl = unavailable, rc = confirmed}} =
        cvss:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C">>),

    %% With environmental metrics
    {ok, #cvss_v1{cdp = high, td = high}} =
        cvss:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/CDP:H/TD:H">>),

    ok.

parse_v2_test(_Config) ->
    %% Base only
    {ok, #cvss_v2{av = network, ac = low, au = none, c = partial, i = partial, a = complete}} =
        cvss:parse(<<"AV:N/AC:L/Au:N/C:P/I:P/A:C">>),

    %% With parentheses
    {ok, #cvss_v2{av = network, ac = low}} =
        cvss:parse(<<"(AV:N/AC:L/Au:N/C:P/I:P/A:C)">>),

    %% With temporal
    {ok, #cvss_v2{e = functional, rl = workaround, rc = confirmed}} =
        cvss:parse(<<"AV:N/AC:L/Au:N/C:P/I:P/A:C/E:F/RL:W/RC:C">>),

    %% With environmental
    {ok, #cvss_v2{cr = high, ir = medium, ar = low}} =
        cvss:parse(<<"AV:N/AC:L/Au:N/C:P/I:P/A:C/CR:H/IR:M/AR:L">>),

    ok.

parse_v3_test(_Config) ->
    %% v3.0
    {ok, #cvss_v3{
        version = '3.0',
        av = network,
        ac = low,
        pr = none,
        ui = none,
        s = unchanged,
        c = high,
        i = high,
        a = high
    }} =
        cvss:parse(<<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),

    %% v3.1
    {ok, #cvss_v3{version = '3.1', av = network, s = changed}} =
        cvss:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H">>),

    %% With temporal
    {ok, #cvss_v3{e = functional, rl = workaround}} =
        cvss:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W">>),

    %% With environmental
    {ok, #cvss_v3{mav = local, mac = high}} =
        cvss:parse(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L/MAC:H">>),

    ok.

parse_v4_test(_Config) ->
    %% Base only
    {ok, #cvss_v4{
        av = network,
        ac = low,
        at = none,
        pr = high,
        ui = none,
        vc = low,
        vi = low,
        va = none,
        sc = none,
        si = none,
        sa = none
    }} =
        cvss:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N">>),

    %% With threat metric
    {ok, #cvss_v4{e = attacked}} =
        cvss:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A">>),

    %% With environmental
    {ok, #cvss_v4{mav = local, cr = high}} =
        cvss:parse(
            <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/MAV:L/CR:H">>
        ),

    %% With safety values
    {ok, #cvss_v4{si = safety, sa = safety}} =
        cvss:parse(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:S/SA:S">>),

    ok.

compose_roundtrip_v1_test(_Config) ->
    Vector = <<"AV:R/AC:L/Au:NR/C:C/I:C/A:C/E:H/RL:U/RC:C/CDP:H/TD:H">>,
    {ok, Cvss} = cvss:parse(Vector),
    Composed = iolist_to_binary(cvss:compose(Cvss)),
    ?assertEqual(Vector, Composed),
    ok.

compose_roundtrip_v2_test(_Config) ->
    Vector = <<"AV:N/AC:L/Au:N/C:P/I:P/A:C/E:F/RL:W/RC:C/CDP:H/TD:H/CR:H/IR:M/AR:L">>,
    {ok, Cvss} = cvss:parse(Vector),
    Composed = iolist_to_binary(cvss:compose(Cvss)),
    ?assertEqual(Vector, Composed),
    ok.

compose_roundtrip_v3_test(_Config) ->
    Vector =
        <<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:W/RC:R/CR:H/IR:M/AR:L/MAV:L/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:L">>,
    {ok, Cvss} = cvss:parse(Vector),
    Composed = iolist_to_binary(cvss:compose(Cvss)),
    ?assertEqual(Vector, Composed),
    ok.

compose_roundtrip_v4_test(_Config) ->
    Vector =
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A/CR:H/IR:M/AR:L">>,
    {ok, Cvss} = cvss:parse(Vector),
    Composed = iolist_to_binary(cvss:compose(Cvss)),
    ?assertEqual(Vector, Composed),
    ok.

validate_test(_Config) ->
    %% Valid vectors
    ?assert(cvss:valid(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>)),
    ?assert(cvss:valid(<<"AV:N/AC:L/Au:N/C:P/I:P/A:C">>)),
    ?assert(cvss:valid(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>)),
    ?assert(cvss:valid(<<"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N">>)),

    %% Invalid vectors
    ?assertNot(cvss:valid(<<"invalid">>)),
    ?assertNot(cvss:valid(<<"CVSS:5.0/AV:N">>)),
    ?assertNot(cvss:valid(<<"AV:X/AC:L/Au:N/C:P/I:P/A:C">>)),

    ok.

score_test(_Config) ->
    %% CVSS 3.1 critical vector
    ?assertEqual(9.8, cvss:score(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>)),

    %% CVSS 3.1 with scope changed
    ?assertEqual(10.0, cvss:score(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H">>)),

    %% CVSS 2.0
    Score2 = cvss:score(<<"AV:N/AC:L/Au:N/C:C/I:C/A:C">>),
    ?assert(Score2 >= 9.0),

    %% CVSS 4.0 base
    Score4 = cvss:score(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>
    ),
    ?assert(Score4 >= 9.0),

    %% Zero impact should be 0.0
    ?assertEqual(0.0, cvss:score(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N">>)),

    ok.

rating_test(_Config) ->
    ?assertEqual(critical, cvss:rating(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>)),
    ?assertEqual(none, cvss:rating(<<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N">>)),

    ok.

rating_boundaries_test(_Config) ->
    %% Test exact boundaries
    ?assertEqual(none, cvss_common:score_to_rating(0.0)),
    ?assertEqual(low, cvss_common:score_to_rating(0.1)),
    ?assertEqual(low, cvss_common:score_to_rating(3.9)),
    ?assertEqual(medium, cvss_common:score_to_rating(4.0)),
    ?assertEqual(medium, cvss_common:score_to_rating(6.9)),
    ?assertEqual(high, cvss_common:score_to_rating(7.0)),
    ?assertEqual(high, cvss_common:score_to_rating(8.9)),
    ?assertEqual(critical, cvss_common:score_to_rating(9.0)),
    ?assertEqual(critical, cvss_common:score_to_rating(10.0)),

    ok.

invalid_vectors_test(_Config) ->
    %% Missing required metrics
    {error, {missing_required_metric, _}} =
        cvss:parse(<<"CVSS:3.1/AV:N/AC:L">>),

    %% Invalid metric value
    {error, {invalid_metric, _, _}} =
        cvss:parse(<<"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),

    %% Duplicate metric
    {error, {duplicate_metric, _}} =
        cvss:parse(<<"CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),

    %% Invalid prefix
    {error, {invalid_prefix, _}} =
        cvss:parse(<<"CVSS:5.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>),

    %% Malformed
    {error, malformed_vector} =
        cvss:parse(<<"not a vector">>),

    ok.

%% Invariant: every valid record must be composable and the result must re-parse
valid_implies_composable_test(_Config) ->
    Records = sample_valid_records(),
    lists:foreach(
        fun(Cvss) ->
            ?assert(cvss:valid(Cvss)),
            Composed = iolist_to_binary(cvss:compose(Cvss)),
            {ok, Reparsed} = cvss:parse(Composed),
            ?assert(cvss:valid(Reparsed))
        end,
        Records
    ),
    ok.

%% Invariant: every valid record must be scorable without crashing
valid_implies_scorable_test(_Config) ->
    Records = sample_valid_records(),
    lists:foreach(
        fun(Cvss) ->
            ?assert(cvss:valid(Cvss)),
            Score = cvss:score(Cvss),
            ?assert(is_float(Score)),
            ?assert(Score >= 0.0 andalso Score =< 10.0),
            _Rating = cvss:rating(Cvss)
        end,
        Records
    ),
    ok.

%% Records with garbage field values must not pass valid/1
invalid_record_not_valid_test(_Config) ->
    %% V1: invalid optional field
    ?assertNot(
        cvss_v1:valid(#cvss_v1{
            av = remote,
            ac = low,
            au = not_required,
            c = complete,
            i = complete,
            a = complete,
            ib = normal,
            e = not_defined
        })
    ),
    %% V2: invalid base field
    ?assertNot(
        cvss_v2:valid(#cvss_v2{
            av = garbage,
            ac = low,
            au = none,
            c = partial,
            i = partial,
            a = complete
        })
    ),
    %% V3: not_defined in modified metric is valid (per spec)
    ?assert(
        cvss_v3:valid(#cvss_v3{
            version = '3.1',
            av = network,
            ac = low,
            pr = none,
            ui = none,
            s = unchanged,
            c = high,
            i = high,
            a = high,
            mav = not_defined
        })
    ),
    %% V3: garbage in modified metric is invalid
    ?assertNot(
        cvss_v3:valid(#cvss_v3{
            version = '3.1',
            av = network,
            ac = low,
            pr = none,
            ui = none,
            s = unchanged,
            c = high,
            i = high,
            a = high,
            mav = garbage
        })
    ),
    %% V4: garbage in supplemental metric is invalid
    ?assertNot(
        cvss_v4:valid(#cvss_v4{
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
            sa = high,
            urgency = garbage
        })
    ),
    ok.

sample_valid_records() ->
    [
        %% V1 base only
        #cvss_v1{
            av = remote,
            ac = low,
            au = not_required,
            c = complete,
            i = complete,
            a = complete,
            ib = normal
        },
        %% V1 with all optional metrics
        #cvss_v1{
            av = remote,
            ac = low,
            au = not_required,
            c = complete,
            i = complete,
            a = complete,
            ib = normal,
            e = high,
            rl = unavailable,
            rc = confirmed,
            cdp = high,
            td = high
        },
        %% V2 base only
        #cvss_v2{
            av = network,
            ac = low,
            au = none,
            c = partial,
            i = partial,
            a = complete
        },
        %% V2 with not_defined temporal
        #cvss_v2{
            av = network,
            ac = low,
            au = none,
            c = partial,
            i = partial,
            a = complete,
            e = not_defined,
            rl = not_defined,
            rc = not_defined
        },
        %% V3 base only
        #cvss_v3{
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
        %% V3 with not_defined modified metrics
        #cvss_v3{
            version = '3.1',
            av = network,
            ac = low,
            pr = none,
            ui = none,
            s = unchanged,
            c = high,
            i = high,
            a = high,
            mav = not_defined,
            mac = not_defined,
            mpr = not_defined,
            mui = not_defined,
            ms = not_defined,
            mc = not_defined,
            mi = not_defined,
            ma = not_defined
        },
        %% V3 with concrete modified metrics
        #cvss_v3{
            version = '3.1',
            av = network,
            ac = low,
            pr = none,
            ui = none,
            s = unchanged,
            c = high,
            i = high,
            a = high,
            mav = local,
            mac = high,
            mpr = low,
            mui = required,
            ms = changed,
            mc = low,
            mi = low,
            ma = low
        },
        %% V4 base only
        #cvss_v4{
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
        %% V4 with all optional metrics
        #cvss_v4{
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
            sa = high,
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
        %% V4 with not_defined threat/requirements
        #cvss_v4{
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
            sa = high,
            e = not_defined,
            cr = not_defined,
            ir = not_defined,
            ar = not_defined
        }
    ].

version_detection_test(_Config) ->
    %% v1 uses R for remote, v2 uses N for network
    {ok, #cvss_v1{}} = cvss:parse(<<"AV:R/AC:L/Au:NR/C:C/I:C/A:C">>),
    {ok, #cvss_v2{}} = cvss:parse(<<"AV:N/AC:L/Au:N/C:P/I:P/A:C">>),

    %% v1 uses Au:R/NR, v2 uses Au:M/S/N
    {ok, #cvss_v1{}} = cvss:parse(<<"AV:L/AC:L/Au:R/C:C/I:C/A:C">>),
    {ok, #cvss_v2{}} = cvss:parse(<<"AV:L/AC:L/Au:S/C:P/I:P/A:C">>),

    %% v3 and v4 have explicit prefixes
    {ok, #cvss_v3{version = '3.0'}} = cvss:parse(
        <<"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>
    ),
    {ok, #cvss_v3{version = '3.1'}} = cvss:parse(
        <<"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">>
    ),
    {ok, #cvss_v4{}} = cvss:parse(
        <<"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H">>
    ),

    ok.
