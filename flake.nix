{
  description = "A flake for connet.dev project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nixos-24-05.url = "github:NixOS/nixpkgs/nixos-24.05";
  };

  outputs = { self, nixpkgs, flake-utils, nixos-24-05 }:
    let
      systems = flake-utils.lib.eachDefaultSystem (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
        in
        {
          formatter = pkgs.nixpkgs-fmt;
          devShell = pkgs.mkShellNoCC {
            buildInputs = with pkgs; [
              age
              caddy
              colmena
              opentofu
              go
              gopls
            ];
          };
        });
    in
    systems // {
      colmena = {
        meta = {
          nixpkgs = import nixos-24-05 {
            system = "x86_64-linux";
            overlays = [
              (final: prev: {
                klev = systems.packages."x86_64-linux".default;
              })
            ];
          };
        };
      };
    };
}
