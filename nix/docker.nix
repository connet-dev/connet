{ pkgs }:
let
  connet = pkgs.callPackage ./package.nix { };
in
pkgs.dockerTools.buildLayeredImage {
  name = "ghcr.io/connet-dev/connet";
  tag = "latest";
  contents = with pkgs; [ cacert ];
  config = {
    Entrypoint = [ "${connet}/bin/connet" ];
    Cmd = [ "--help" ];
    ExposedPorts = {
      "19190/udp" = { };
      "19191/udp" = { };
      "19192/udp" = { };
    };
    Volumes = {
      "/tmp" = { };
    };
  };
}
