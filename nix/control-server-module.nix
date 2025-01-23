{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "control";
  hasCerts = true;
  hasStorage = true;
  ports = [
    { path = [ "control" "clients-addr" ]; default = ":19190"; }
    { path = [ "control" "relays-addr" ]; default = ":19189"; }
  ];
}
