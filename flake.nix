{
  description = "A flake for connet project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    {
      nixosModules.default = ./nix/client-module.nix;
      nixosModules.server = ./nix/server-module.nix;
      nixosModules.control-server = ./nix/control-server-module.nix;
      nixosModules.relay-server = ./nix/relay-server-module.nix;
    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        formatter = pkgs.nixpkgs-fmt;
        packages = {
          default = pkgs.callPackage ./nix/package.nix { };
          docker = pkgs.callPackage ./nix/docker.nix { };
        };
        devShells.default = pkgs.mkShellNoCC {
          buildInputs = with pkgs; [
            go
            gopls
            golangci-lint
            fd
            manifest-tool
            protobuf
            protoc-gen-go
            process-compose
            skopeo
            static-web-server
            (pkgs.writeShellScriptBin "gen-local-certs" ''
              set -euo pipefail
              cd .direnv
              ${minica}/bin/minica -domains localhost -ip-addresses 127.0.0.1
              cd ..
            '')
            (writeShellScriptBin "clean-local-certs" ''
              set -euo pipefail
              rm -rf .direnv/localhost
              rm .direnv/minica.pem
              rm .direnv/minica-key.pem
            '')
          ];
        };
      });
}
