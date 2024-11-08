{ pkgs, lib, ... }:
let
  sourceFiles = lib.fileset.difference ./. (lib.fileset.unions [
    (lib.fileset.maybeMissing ./result)
    ./.envrc
    ./.gitignore
    ./flake.lock
    ./flake.nix
    ./Makefile
    ./package.nix
    ./process-compose.yaml
  ]);
in
lib.fileset.trace sourceFiles
  pkgs.buildGoModule
{
  name = "connet";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = sourceFiles;
  };
  vendorHash = "sha256-u+wh34KCoC1Rh/aULIf4U4WP/bRDndl05BGrGrj1qgI=";
  subPackages = [ "cmd/connet" "cmd/connet-server" ];
}
