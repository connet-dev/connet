{ pkgs, lib, ... }:
let
  sourceFiles = lib.fileset.difference ./. (lib.fileset.unions [
    (lib.fileset.maybeMissing ./result)
    ./.envrc
    ./.gitignore
    ./examples
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

  vendorHash = "sha256-ALmcCl81+U+3xks1xQhztQuvm40LCn9ZMdGnYT59Hzo=";
  subPackages = [ "cmd/connet" ];

  meta = with lib; {
    description = "A reverse proxy, written in Golang";
    homepage = "https://github.com/keihaya-com/connet";
    license = licenses.asl20;
    mainProgram = "connet";
  };
}
