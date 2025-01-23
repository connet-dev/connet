{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "server";
  usesCerts = true;
  ports = [
    { path = [ "server" "addr" ]; default = ":19190"; }
  ];
}
