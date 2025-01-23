{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "server";
  hasCerts = true;
  hasStorage = true;
  ports = [
    { path = [ "server" "addr" ]; default = ":19190"; }
  ];
}
