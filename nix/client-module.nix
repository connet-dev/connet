{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "client";
  ports = [
    { path = [ "client" "direct-addr" ]; default = ":19192"; }
  ];
}
