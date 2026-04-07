%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

%%====================================================================
%% CVSS 1.0 Records - https://www.first.org/cvss/v1/guide
%%====================================================================

-record(cvss_v1, {
    av :: cvss_v1:av(),
    ac :: cvss_v1:ac(),
    au :: cvss_v1:au(),
    c :: cvss_v1:impact(),
    i :: cvss_v1:impact(),
    a :: cvss_v1:impact(),
    ib = normal :: cvss_v1:impact_bias(),
    e = undefined :: cvss_v1:exploitability() | undefined,
    rl = undefined :: cvss_v1:remediation_level() | undefined,
    rc = undefined :: cvss_v1:report_confidence() | undefined,
    cdp = undefined :: cvss_v1:cdp() | undefined,
    td = undefined :: cvss_v1:td() | undefined
}).
