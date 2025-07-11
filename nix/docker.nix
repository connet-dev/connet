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
      "19189/udp" = { }; # control listens for relays
      "19190/udp" = { }; # control listens for clients
      "19191/udp" = { }; # relay listens for clients
      "19192/udp" = { }; # client listens for clients
    };
    Env = [
      "CONNET_STATE_DIR=/data" # server to store data
      "CONNET_CACHE_DIR=/cache" # client to store caches
    ];
    Volumes = {
      "/data" = { }; # server to store data
      "/cache" = { }; # client to store caches
    };
  };
}
