{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "relay";
  ports = [
    { path = [ "relay" "addr" ]; default = ":19191"; }
  ];
}
