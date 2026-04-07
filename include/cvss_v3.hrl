%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

%%====================================================================
%% CVSS 3.x Records - https://www.first.org/cvss/v3.1/specification-document
%%====================================================================

-record(cvss_v3, {
    version :: cvss_v3:version(),
    av :: cvss_v3:av(),
    ac :: cvss_v3:ac(),
    pr :: cvss_v3:pr(),
    ui :: cvss_v3:ui(),
    s :: cvss_v3:scope(),
    c :: cvss_v3:cia(),
    i :: cvss_v3:cia(),
    a :: cvss_v3:cia(),
    e = undefined :: cvss_v3:exploit_maturity() | undefined,
    rl = undefined :: cvss_v3:remediation_level() | undefined,
    rc = undefined :: cvss_v3:report_confidence() | undefined,
    cr = undefined :: cvss_v3:requirement() | undefined,
    ir = undefined :: cvss_v3:requirement() | undefined,
    ar = undefined :: cvss_v3:requirement() | undefined,
    mav = undefined :: cvss_v3:av() | not_defined | undefined,
    mac = undefined :: cvss_v3:ac() | not_defined | undefined,
    mpr = undefined :: cvss_v3:pr() | not_defined | undefined,
    mui = undefined :: cvss_v3:ui() | not_defined | undefined,
    ms = undefined :: cvss_v3:scope() | not_defined | undefined,
    mc = undefined :: cvss_v3:cia() | not_defined | undefined,
    mi = undefined :: cvss_v3:cia() | not_defined | undefined,
    ma = undefined :: cvss_v3:cia() | not_defined | undefined
}).
