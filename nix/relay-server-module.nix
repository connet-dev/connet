{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "relay";
  ports = settings:
    let
      addr = lib.attrByPath [ "relay" "addr" ] ":19191" settings;
      parts = lib.splitString ":" addr;
      port = lib.toInt (lib.last parts);
    in
    [ port ];
}
