%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

%%====================================================================
%% CVSS 4.0 Records - https://www.first.org/cvss/v4.0/specification-document
%%====================================================================

-record(cvss_v4, {
    %% Base Metrics (required)
    av :: cvss_v4:av(),
    ac :: cvss_v4:ac(),
    at :: cvss_v4:at(),
    pr :: cvss_v4:pr(),
    ui :: cvss_v4:ui(),
    vc :: cvss_v4:cia(),
    vi :: cvss_v4:cia(),
    va :: cvss_v4:cia(),
    sc :: cvss_v4:cia(),
    si :: cvss_v4:si_sa(),
    sa :: cvss_v4:si_sa(),
    %% Threat Metrics (optional)
    e = undefined :: cvss_v4:exploit_maturity() | undefined,
    %% Environmental Metrics (optional)
    cr = undefined :: cvss_v4:requirement() | undefined,
    ir = undefined :: cvss_v4:requirement() | undefined,
    ar = undefined :: cvss_v4:requirement() | undefined,
    mav = undefined :: cvss_v4:av() | undefined,
    mac = undefined :: cvss_v4:ac() | undefined,
    mat = undefined :: cvss_v4:at() | undefined,
    mpr = undefined :: cvss_v4:pr() | undefined,
    mui = undefined :: cvss_v4:ui() | undefined,
    mvc = undefined :: cvss_v4:cia() | undefined,
    mvi = undefined :: cvss_v4:cia() | undefined,
    mva = undefined :: cvss_v4:cia() | undefined,
    msc = undefined :: cvss_v4:cia() | undefined,
    msi = undefined :: cvss_v4:si_sa() | undefined,
    msa = undefined :: cvss_v4:si_sa() | undefined,
    %% Supplemental Metrics (optional, do NOT affect score)
    safety = undefined :: cvss_v4:safety() | undefined,
    automatable = undefined :: cvss_v4:automatable() | undefined,
    recovery = undefined :: cvss_v4:recovery() | undefined,
    value_density = undefined :: cvss_v4:value_density() | undefined,
    response_effort = undefined :: cvss_v4:response_effort() | undefined,
    urgency = undefined :: cvss_v4:urgency() | undefined
}).
