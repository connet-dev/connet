{ pkgs }:
let
  connet = pkgs.callPackage ./package.nix { };
in
pkgs.dockerTools.buildLayeredImage {
  name = "ghcr.io/connet-dev/connet";
  tag = "latest-${if pkgs.stdenv.hostPlatform.isAarch then "arm64" else "amd64"}";
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
