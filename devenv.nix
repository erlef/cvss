# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

{ pkgs, lib, config, inputs, ... }:
{
  packages = with pkgs; [
    git
    reuse
  ];

  languages.erlang = {
    enable = true;
  };

  git-hooks.hooks = {
    erlfmt = {
      enable = true;
      name = "Erlfmt Check";
      entry = "rebar3 fmt --check";
      files = "\\.(erl|hrl|app.src|config)$";
      pass_filenames = false;
    };
    elvis = {
      enable = true;
      name = "Elvis Linter";
      entry = "rebar3 lint";
      files = "\\.(erl|hrl)$";
      pass_filenames = false;
    };
    ct = {
      enable = true;
      name = "Common Test";
      entry = "rebar3 ct";
      files = "\\.(erl|hrl|app.src)$";
      pass_filenames = false;
    };
    reuse = {
      enable = true;
      name = "REUSE Compliance";
      entry = "reuse lint";
      pass_filenames = false;
    };
  };
}