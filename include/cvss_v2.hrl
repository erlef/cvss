%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

%%====================================================================
%% CVSS 2.0 Records - https://www.first.org/cvss/v2/guide
%%====================================================================

-record(cvss_v2, {
    av :: cvss_v2:av(),
    ac :: cvss_v2:ac(),
    au :: cvss_v2:au(),
    c :: cvss_v2:impact(),
    i :: cvss_v2:impact(),
    a :: cvss_v2:impact(),
    e = undefined :: cvss_v2:exploitability() | undefined,
    rl = undefined :: cvss_v2:remediation_level() | undefined,
    rc = undefined :: cvss_v2:report_confidence() | undefined,
    cdp = undefined :: cvss_v2:cdp() | undefined,
    td = undefined :: cvss_v2:td() | undefined,
    cr = undefined :: cvss_v2:requirement() | undefined,
    ir = undefined :: cvss_v2:requirement() | undefined,
    ar = undefined :: cvss_v2:requirement() | undefined
}).
