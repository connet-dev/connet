{ pkgs, lib, ... }:
let
  sourceFiles = lib.fileset.difference ../. (lib.fileset.unions [
    (lib.fileset.maybeMissing ../result)
    ../.envrc
    ../.gitignore
    ../examples
    ../flake.lock
    ../flake.nix
    ../LICENSE
    ../Makefile
    ../nix
    ../process-compose.yaml
    ../README.md
  ]);
in
# lib.fileset.trace sourceFiles
pkgs.buildGoModule
{
  name = "connet";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = sourceFiles;
  };

  vendorHash = "sha256-nw68Mv9KkqsPVVHUdDOi97QMlPk+4vvaePP/AgBmgNI=";
  subPackages = [ "cmd/connet" ];
  ldflags = [ "-X 'github.com/connet-dev/connet/model.Version=${lib.strings.fileContents ../VERSION}'" ];

  nativeBuildInputs = [ pkgs.installShellFiles ];
  postInstall = lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
    installShellCompletion --cmd connet \
      --bash <($out/bin/connet completion bash) \
      --fish <($out/bin/connet completion fish) \
      --zsh <($out/bin/connet completion zsh)
  '';

  meta = with lib; {
    description = "A p2p reverse proxy, written in Golang";
    homepage = "https://github.com/connet-dev/connet";
    license = licenses.asl20;
    mainProgram = "connet";
  };
}
