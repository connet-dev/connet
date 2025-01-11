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
      # working ports
      "19190/udp" = { };
      "19191/udp" = { };
      "19192/udp" = { };
      # status ports
      "19180/tcp" = { };
      "19181/tcp" = { };
      "19182/tcp" = { };
    };
    Volumes = {
      "/tmp" = { };
    };
  };
}
