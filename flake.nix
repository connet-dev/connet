{
  description = "A flake for connet project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        formatter = pkgs.nixpkgs-fmt;
        devShell = pkgs.mkShellNoCC {
          buildInputs = with pkgs; [
            go
            gopls
            static-web-server
            process-compose
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
