{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "server";
  ports = [
    { path = [ "server" "addr" ]; default = ":19190"; }
  ];
}
