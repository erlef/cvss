%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

-module(cvss_test_util).
-moduledoc "Shared test utilities for downloading, caching, and parsing external CVSS test vector datasets.".

-export([
    ensure_dataset/2,
    redhat_vector_file/2,
    first_vector_file/2,
    test_vectors/4,
    test_detailed_vectors/4,
    parse_redhat_line/1,
    parse_redhat_detailed_line/1,
    parse_redhat_v4_line/1,
    parse_first_v4_line/1,
    parse_score/1
]).

-define(REDHAT_REPO_SHA, "2f149099257ae06b98cef252efc440bddafe61e5").
-define(REDHAT_REPO_URL,
    "https://github.com/RedHatProductSecurity/cvss/archive/" ?REDHAT_REPO_SHA ".tar.gz"
).

-define(FIRST_REPO_SHA, "48f85d84a036de9c610668f9496c12b5040a9ae3").
-define(FIRST_REPO_URL,
    "https://github.com/FIRSTdotorg/cvss-resources/archive/" ?FIRST_REPO_SHA ".tar.gz"
).

-doc """
Ensure a dataset is downloaded and cached.
Returns updated Config with the cache dir. Call from init_per_suite.

Example:
```
Config1 = cvss_test_util:ensure_dataset(redhat, Config),
Config2 = cvss_test_util:ensure_dataset(first, Config1).
```
""".
-spec ensure_dataset(redhat | first, [{atom(), term()}]) -> [{atom(), term()}].
ensure_dataset(Dataset, Config) ->
    ok = application:ensure_started(inets),
    ok = application:ensure_started(ssl),
    {Key, CacheSubdir, RepoSHA, URL} = dataset_info(Dataset),
    PrivDir = proplists:get_value(priv_dir, Config),
    CacheDir = filename:join(PrivDir, CacheSubdir),
    ok = filelib:ensure_dir(filename:join(CacheDir, "dummy")),
    ExtractedDir = filename:join(CacheDir, extract_dir_name(Dataset, RepoSHA)),
    case filelib:is_dir(ExtractedDir) of
        true ->
            ok;
        false ->
            download_and_extract(URL, RepoSHA, CacheDir)
    end,
    [{Key, CacheDir} | Config].

-doc "Return the path to a RedHat test vector file.".
-spec redhat_vector_file([{atom(), term()}], string()) -> file:filename().
redhat_vector_file(Config, FileName) ->
    CacheDir = proplists:get_value(redhat_cache_dir, Config),
    filename:join([CacheDir, "cvss-" ?REDHAT_REPO_SHA, "tests", FileName]).

-doc "Return the path to a FIRST test vector file.".
-spec first_vector_file([{atom(), term()}], string()) -> file:filename().
first_vector_file(Config, FileName) ->
    CacheDir = proplists:get_value(first_cache_dir, Config),
    filename:join([CacheDir, "cvss-resources-" ?FIRST_REPO_SHA, "vectorFiles", FileName]).

-doc """
Test all vectors in a file.

`ParseFun` parses a line into `{ok, Vector, ExpectedScore} | skip`.
`ScoreFun` takes a vector binary and returns `{ok, float()} | {error, term()}`.
`Tolerance` is the max allowed absolute difference.
""".
-spec test_vectors(file:filename(), fun(), fun(), float()) -> ok.
test_vectors(FilePath, ParseFun, ScoreFun, Tolerance) ->
    {ok, Data} = file:read_file(FilePath),
    Lines = binary:split(Data, <<"\n">>, [global, trim_all]),
    FileName = filename:basename(FilePath),
    ct:pal("Testing ~p vectors from ~s", [length(Lines), FileName]),
    Failures = lists:filtermap(
        fun(Line) -> test_single_vector(Line, ParseFun, ScoreFun, Tolerance) end,
        Lines
    ),
    case Failures of
        [] ->
            ok;
        _ ->
            ct:pal("~p failures (showing first 10):~n~p", [
                length(Failures), lists:sublist(Failures, 10)
            ]),
            ct:fail("~p vector tests failed", [length(Failures)])
    end.

-doc """
Parse a RedHat-format line: `"vector - (base, temporal, environmental)"`.
Returns the last non-None score (matching what `score` returns).
""".
-spec parse_redhat_line(binary()) -> {ok, binary(), float()} | skip.
parse_redhat_line(Line) ->
    case binary:split(Line, <<" - ">>) of
        [Vector, ScorePart] ->
            case re:run(ScorePart, <<"\\(([^)]+)\\)">>, [{capture, all_but_first, binary}]) of
                {match, [InnerBin]} ->
                    Scores = binary:split(InnerBin, <<", ">>, [global]),
                    case parse_last_score(Scores) of
                        skip -> skip;
                        Score -> {ok, string:trim(Vector), Score}
                    end;
                nomatch ->
                    skip
            end;
        _ ->
            skip
    end.

-doc """
Parse a RedHat-format line returning all three scores: `{base, temporal, environmental}`.
Each score is either a float or `skip` if `None`.
""".
-spec parse_redhat_detailed_line(binary()) ->
    {ok, binary(), {float() | skip, float() | skip, float() | skip}} | skip.
parse_redhat_detailed_line(Line) ->
    case binary:split(Line, <<" - ">>) of
        [Vector, ScorePart] ->
            case re:run(ScorePart, <<"\\(([^)]+)\\)">>, [{capture, all_but_first, binary}]) of
                {match, [InnerBin]} ->
                    Scores = binary:split(InnerBin, <<", ">>, [global]),
                    case parse_all_scores(Scores) of
                        {skip, skip, skip} -> skip;
                        ScoreTuple -> {ok, string:trim(Vector), ScoreTuple}
                    end;
                nomatch ->
                    skip
            end;
        _ ->
            skip
    end.

-doc """
Parse a RedHat v4 line: `"CVSS:4.0/... - score"` or `"CVSS:4.0/... - (score,)"`.
""".
-spec parse_redhat_v4_line(binary()) -> {ok, binary(), float()} | skip.
parse_redhat_v4_line(Line) ->
    case binary:split(Line, <<" - ">>) of
        [Vector, ScorePart] ->
            ScoreBin = case re:run(ScorePart, <<"\\(([0-9.]+),?\\)">>, [{capture, all_but_first, binary}]) of
                {match, [S]} -> S;
                nomatch -> string:trim(ScorePart)
            end,
            {ok, string:trim(Vector), parse_score(ScoreBin)};
        _ ->
            skip
    end.

-doc """
Parse a FIRST v4 line: `{'vector': 'CVSS:4.0/...', 'score': 10, 'severity': '...'}`.
""".
-spec parse_first_v4_line(binary()) -> {ok, binary(), float()} | skip.
parse_first_v4_line(Line) ->
    case re:run(Line, <<"'vector': '([^']+)', 'score': ([0-9.]+)">>, [{capture, all_but_first, binary}]) of
        {match, [Vector, ScoreBin]} ->
            {ok, Vector, parse_score(ScoreBin)};
        nomatch ->
            skip
    end.

-doc "Parse a score binary, handling `-0.0` and `None`.".
-spec parse_score(binary()) -> float() | skip.
parse_score(<<"-0.0">>) -> 0.0;
parse_score(<<"None">>) -> skip;
parse_score(Bin) ->
    case binary:match(Bin, <<".">>) of
        nomatch -> float(binary_to_integer(Bin));
        _ -> binary_to_float(Bin)
    end.

-doc """
Test all vectors in a file, comparing detailed (base, temporal, environmental) scores.

`ParseFun` parses a line into `{ok, Vector, {BaseScore, TemporalScore, EnvScore}} | skip`.
Each score in the tuple can be `skip` if the expected value is `None`.
`ScoreFun` takes a vector binary and returns `{ok, {BaseScore, TemporalScore, EnvScore}} | {error, term()}`.
`Tolerance` is the max allowed absolute difference per score.
""".
-spec test_detailed_vectors(file:filename(), fun(), fun(), float()) -> ok.
test_detailed_vectors(FilePath, ParseFun, ScoreFun, Tolerance) ->
    {ok, Data} = file:read_file(FilePath),
    Lines = binary:split(Data, <<"\n">>, [global, trim_all]),
    FileName = filename:basename(FilePath),
    ct:pal("Testing ~p vectors (detailed) from ~s", [length(Lines), FileName]),
    Failures = lists:filtermap(
        fun(Line) -> test_single_detailed_vector(Line, ParseFun, ScoreFun, Tolerance) end,
        Lines
    ),
    case Failures of
        [] ->
            ok;
        _ ->
            ct:pal("~p failures (showing first 10):~n~p", [
                length(Failures), lists:sublist(Failures, 10)
            ]),
            ct:fail("~p detailed vector tests failed", [length(Failures)])
    end.

%%====================================================================
%% Internal
%%====================================================================

dataset_info(redhat) ->
    {redhat_cache_dir, "redhat-cvss-" ?REDHAT_REPO_SHA, ?REDHAT_REPO_SHA, ?REDHAT_REPO_URL};
dataset_info(first) ->
    {first_cache_dir, "first-cvss-" ?FIRST_REPO_SHA, ?FIRST_REPO_SHA, ?FIRST_REPO_URL}.

extract_dir_name(redhat, SHA) -> "cvss-" ++ SHA;
extract_dir_name(first, SHA) -> "cvss-resources-" ++ SHA.

download_and_extract(URL, SHA, CacheDir) ->
    TarFile = filename:join(CacheDir, SHA ++ ".tar.gz"),
    ct:pal("Downloading vectors from ~s", [URL]),
    {ok, {{_, 200, _}, _, Body}} = httpc:request(get, {URL, []}, [], [{body_format, binary}]),
    ok = file:write_file(TarFile, Body),
    ct:pal("Extracting to ~s", [CacheDir]),
    ok = erl_tar:extract(TarFile, [{cwd, CacheDir}, compressed]).

test_single_vector(Line, ParseFun, ScoreFun, Tolerance) ->
    case ParseFun(Line) of
        {ok, Vector, ExpectedScore} ->
            case ScoreFun(Vector) of
                {ok, ActualScore} ->
                    case abs(ActualScore - ExpectedScore) < Tolerance of
                        true -> false;
                        false -> {true, {Vector, ExpectedScore, ActualScore}}
                    end;
                {error, Reason} ->
                    {true, {Vector, ExpectedScore, {error, Reason}}}
            end;
        skip ->
            false
    end.

parse_last_score(Scores) ->
    lists:foldl(
        fun(Bin, Acc) ->
            case parse_score(string:trim(Bin)) of
                skip -> Acc;
                Score -> Score
            end
        end,
        skip,
        Scores
    ).

parse_all_scores(Scores) ->
    Parsed = [parse_score(string:trim(Bin)) || Bin <- Scores],
    case Parsed of
        [Base] -> {Base, skip, skip};
        [Base, Temporal] -> {Base, Temporal, skip};
        [Base, Temporal, Env | _] -> {Base, Temporal, Env}
    end.

test_single_detailed_vector(Line, ParseFun, ScoreFun, Tolerance) ->
    case ParseFun(Line) of
        {ok, Vector, ExpectedScores} ->
            case ScoreFun(Vector) of
                {ok, ActualScores} ->
                    case compare_detailed_scores(ExpectedScores, ActualScores, Tolerance) of
                        ok -> false;
                        {mismatch, Details} -> {true, {Vector, Details}}
                    end;
                {error, Reason} ->
                    {true, {Vector, ExpectedScores, {error, Reason}}}
            end;
        skip ->
            false
    end.

compare_detailed_scores(Expected, Actual, Tolerance) ->
    Pairs = lists:zip(tuple_to_list(Expected), tuple_to_list(Actual)),
    Labels = [base, temporal, environmental],
    Failures = lists:filtermap(
        fun({Label, {skip, ActualScore}}) ->
            %% No expected score for this type, skip comparison
            {true, {Label, skip, ActualScore, ok}};
        ({Label, {ExpectedScore, ActualScore}}) ->
            case abs(ActualScore - ExpectedScore) < Tolerance of
                true -> false;
                false -> {true, {Label, ExpectedScore, ActualScore, mismatch}}
            end
        end,
        lists:zip(Labels, Pairs)
    ),
    case [F || {_, _, _, mismatch} = F <- Failures] of
        [] -> ok;
        Mismatches -> {mismatch, Mismatches}
    end.