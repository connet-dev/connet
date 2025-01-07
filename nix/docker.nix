{ pkgs }:
let
  connet = pkgs.callPackage ./package.nix { };
in
pkgs.dockerTools.buildLayeredImage {
  name = "ghcr.io/connet-dev/connet";
  tag = "latest";
  contents = with pkgs; [ cacert ];
  config.entrypoint = "${connet}/bin/connet";
}
