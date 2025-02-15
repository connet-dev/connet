{
  description = "A flake for connet project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
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
        testCerts = pkgs.runCommand "test-certs" { } ''
          mkdir $out && cd $out
          ${pkgs.minica}/bin/minica -ip-addresses 192.168.1.3
        '';
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
        checks = {
          moduleTest = pkgs.testers.runNixOSTest {
            name = "moduleTest";
            nodes.server = {
              imports = [ self.nixosModules.server ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.3/cert.pem";
              };
              environment.etc."server.key" = {
                source = "${testCerts}/192.168.1.3/key.pem";
              };
              environment.etc."tokens" = {
                text = "abcba";
              };
              services.connet-server = {
                enable = true;
                openFirewall = true;
                settings.server = {
                  cert-file = "/etc/server.cert";
                  key-file = "/etc/server.key";
                  tokens-file = "/etc/tokens";
                };
              };
            };
            nodes.clientDst = {
              imports = [ self.nixosModules.default ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.3/cert.pem";
              };
              environment.etc."tokens" = {
                text = "abcba";
              };
              services.connet-client = {
                enable = true;
                openFirewall = true;
                settings.client = {
                  token-file = "/etc/tokens";
                  server-addr = "192.168.1.3:19190";
                  server-cas = "/etc/server.cert";
                  destinations.abc = {
                    addr = ":3000";
                  };
                };
              };
            };
            nodes.clientSrc = {
              imports = [ self.nixosModules.default ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.3/cert.pem";
              };
              environment.etc."tokens" = {
                text = "abcba";
              };
              services.connet-client = {
                enable = true;
                openFirewall = true;
                settings.client = {
                  token-file = "/etc/tokens";
                  server-addr = "192.168.1.3:19190";
                  server-cas = "/etc/server.cert";
                  sources.abc = {
                    addr = ":3000";
                  };
                };
              };
            };

            testScript = ''
              start_all()
              server.wait_for_unit("connet-server.service")
              clientDst.wait_for_unit("connet-client.service")
              clientSrc.wait_for_unit("connet-client.service")
            '';
          };
        };
      });
}
