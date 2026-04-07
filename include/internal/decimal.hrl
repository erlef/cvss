%% SPDX-License-Identifier: Apache-2.0
%% SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

%% Common macros for decimal arithmetic used across CVSS scoring modules.

-ifndef(CVSS_DECIMAL_HRL).
-define(CVSS_DECIMAL_HRL, true).

%% Decimal precision — tune down for performance, up for accuracy.
-define(DECIMAL_PRECISION, 20).
-define(DECIMAL_OPTS, #{precision => ?DECIMAL_PRECISION, rounding => round_half_up}).

-define(D(V), cvss_common:d(V)).
-define(ZERO, ?D(0)).
-define(ONE, ?D(1)).

-endif.
