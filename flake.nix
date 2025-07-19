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
                source = "${testCerts}/192.168.1.3/cert.pem";
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
                    server-addr = "192.168.1.3:19190";
                    server-cas-file = "/etc/server.cert";
                    destinations = {
                      files.url = "file:.";
                      filesd = {
                        url = "file:.";
                        route = "direct";
                      };
                      filesr = {
                        url = "file:.";
                        route = "relay";
                      };
                    };
                  };
                };
              };
            };

            nodes.source = {
              imports = [ self.nixosModules.default ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.3/cert.pem";
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
                    server-addr = "192.168.1.3:19190";
                    server-cas-file = "/etc/server.cert";
                    sources = {
                      files.url = "tcp://:3000";
                      filesd = {
                        url = "tcp://:3001";
                        route = "direct";
                      };
                      filesr = {
                        url = "tcp://:3002";
                        route = "relay";
                      };
                    };
                  };
                };
              };
            };

            nodes.docker = {
              environment.etc."connet-server.cert" = {
                source = "${testCerts}/192.168.1.3/cert.pem";
              };
              environment.etc."connet-token" = {
                text = "token-src";
              };
              environment.etc."connet-config.toml" = {
                source = (pkgs.formats.toml { }).generate "connet-config.toml" {
                  log-level = "debug";
                  client = {
                    server-addr = "192.168.1.3:19190";
                    server-cas-file = "connet-server.cert";
                    token-file = "connet-token";
                    sources = {
                      files.url = "tcp://:3000";
                    };
                  };
                };
              };
              virtualisation.containers.enable = true;
              virtualisation.docker.enable = true;
              virtualisation.oci-containers = {
                backend = "docker";
                containers.connet = {
                  image = "ghcr.io/connet-dev/connet:latest-amd64";
                  imageFile = self.packages.${system}.docker;
                  cmd = [ "--config" "connet-config.toml" ];
                  volumes = [
                    "/etc/connet-server.cert:/connet-server.cert"
                    "/etc/connet-token:/connet-token"
                    "/etc/connet-config.toml:/connet-config.toml"
                  ];
                  extraOptions = [ "--network=host" ];
                };
              };
            };

            nodes.server = {
              imports = [ self.nixosModules.server ];
              environment.etc."server.cert" = {
                source = "${testCerts}/192.168.1.3/cert.pem";
              };
              environment.etc."server.key" = {
                source = "${testCerts}/192.168.1.3/key.pem";
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
                    tokens-file = "/etc/tokens";
                    ingress = [{
                      cert-file = "/etc/server.cert";
                      key-file = "/etc/server.key";
                    }];
                    relay-ingress = [{
                      hostports = [ "server" ];
                    }];
                  };
                };
              };
            };

            testScript = ''
              start_all()

              server.wait_for_unit("connet-server.service")
              destination.wait_for_unit("connet-client.service")
              source.wait_for_unit("connet-client.service")
              source.wait_for_open_port(3000)
              source.wait_until_succeeds("${pkgs.curl}/bin/curl http://localhost:3000", timeout=10)
              source.wait_for_open_port(3001)
              source.wait_until_succeeds("${pkgs.curl}/bin/curl http://localhost:3001", timeout=10)
              source.wait_for_open_port(3002)
              source.wait_until_succeeds("${pkgs.curl}/bin/curl http://localhost:3002", timeout=10)

              docker.wait_for_unit("docker-connet.service")
              docker.wait_for_open_port(3000)
              docker.wait_until_succeeds("${pkgs.curl}/bin/curl http://localhost:3000", timeout=10)
            '';
          };
        };
      });
}
