{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "server";
  ports = settings:
    let
      addr = lib.attrByPath [ "server" "addr" ] ":19190" settings;
      parts = lib.splitString ":" addr;
      port = lib.toInt (lib.last parts);
    in
    [ port ];
}
