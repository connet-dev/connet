{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "relay";
  hasStorage = true;
  ports = [
    { path = [ "relay" "addr" ]; default = ":19191"; }
  ];
}
