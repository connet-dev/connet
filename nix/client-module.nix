{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "client";
  ports = settings:
    let
      addr = lib.attrByPath [ "client" "direct-addr" ] ":19192" settings;
      parts = lib.splitString ":" addr;
      port = lib.toInt (lib.last parts);
    in
    [ port ];
}
