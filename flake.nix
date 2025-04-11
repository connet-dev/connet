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
          ${pkgs.minica}/bin/minica -ip-addresses 192.168.1.2
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
            zip
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
            nodes.destination = {
              imports = [ self.nixosModules.default ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.2/cert.pem";
              };
              environment.etc."tokens" = {
                text = "token-dst";
              };
              services.connet-client = {
                enable = true;
                openFirewall = true;
                settings = {
                  log-level = "debug";
                  client = {
                    token-file = "/etc/tokens";
                    server-addr = "192.168.1.2:19190";
                    server-cas = "/etc/server.cert";
                    destinations.files = {
                      http.static-server-root = ".";
                    };
                  };
                };
              };
            };

            nodes.source = {
              imports = [ self.nixosModules.default ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.2/cert.pem";
              };
              environment.etc."tokens" = {
                text = "token-src";
              };
              services.connet-client = {
                enable = true;
                openFirewall = true;
                settings = {
                  log-level = "debug";
                  client = {
                    token-file = "/etc/tokens";
                    server-addr = "192.168.1.2:19190";
                    server-cas = "/etc/server.cert";
                    sources.files = {
                      tcp.addr = ":3000";
                    };
                  };
                };
              };
            };

            nodes.server = {
              imports = [ self.nixosModules.server ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.2/cert.pem";
              };
              environment.etc."server.key" = {
                source = "${testCerts}/192.168.1.2/key.pem";
              };
              environment.etc."tokens" = {
                text = "token-dst\ntoken-src";
              };
              services.connet-server = {
                enable = true;
                openFirewall = true;
                settings = {
                  log-level = "debug";
                  server = {
                    cert-file = "/etc/server.cert";
                    key-file = "/etc/server.key";
                    tokens-file = "/etc/tokens";
                  };
                };
              };
            };

            testScript = ''
              start_all()
              server.wait_for_unit("connet-server.service")
              destination.wait_for_unit("connet-client.service")
              source.wait_for_unit("connet-client.service")
              source.execute("${pkgs.curl}/bin/curl http://localhost:3000")
            '';
          };
        };
      });
}
