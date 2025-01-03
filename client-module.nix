{ config, lib, pkgs, ... }:
let
  cfg = config.services.connet;
in
{
  options.services.connet = {
    enable = lib.mkEnableOption "connet client";

    package = lib.mkPackageOption pkgs "connet" { };

    user = lib.mkOption {
      default = "connet";
      type = lib.types.str;
      description = ''
        User account under which connet runs.

        ::: {.note}
        If left as the default value this user will automatically be created
        on system activation, otherwise you are responsible for
        ensuring the user exists before the connet service starts.
        :::
      '';
    };

    group = lib.mkOption {
      default = "connet";
      type = lib.types.str;
      description = ''
        Group under which connet runs.

        ::: {.note}
        If left as the default value this group will automatically be created
        on system activation, otherwise you are responsible for
        ensuring the group exists before the connet service starts.
        :::
      '';
    };

    openFirewall = lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Whether to open the firewall for the specified port.";
    };

    logLevel = lib.mkOption {
      default = "info";
      type = lib.types.enum [ "debug" "info" "warn" "error" ];
      description = "Client log level to use";
    };

    logFormat = lib.mkOption {
      default = "text";
      type = lib.types.enum [ "text" "json" ];
      description = "Client log format to use";
    };

    tokenFile = lib.mkOption {
      type = lib.types.path;
      description = "The file to read the token from";
    };

    serverAddr = lib.mkOption {
      type = lib.types.str;
      description = "Server address to connect to";
      example = "localhost:19190";
    };

    serverCA = lib.mkOption {
      default = null;
      type = lib.types.nullOr lib.types.path;
      description = "Server Certificate Authority file to use, required when running self-signed server";
    };

    directPort = lib.mkOption {
      default = 19192;
      type = lib.types.port;
      description = "The port to listen for incoming direct connections.";
    };

    destinations = lib.mkOption {
      default = { };
      type = lib.types.attrsOf
        (lib.types.submodule {
          options = {
            addr = lib.mkOption {
              type = lib.types.str;
              description = "The address of the destination";
            };
            route = lib.mkOption {
              default = "any";
              type = lib.types.enum [ "any" "direct" "relay" ];
              description = "The route to use for this destination";
            };
          };
        });
      example = ''
        express.addr = "localhost:3000";
      '';
    };

    sources = lib.mkOption {
      default = { };
      type = lib.types.attrsOf
        (lib.types.submodule {
          options = {
            addr = lib.mkOption {
              type = lib.types.str;
              description = "The address of the source";
            };
            route = lib.mkOption {
              default = "any";
              type = lib.types.enum [ "any" "direct" "relay" ];
              description = "The route to use for this source";
            };
          };
        });
      example = ''
        express.addr = ":8000";
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernel.sysctl."net.core.rmem_max" = lib.mkDefault 7500000;
    boot.kernel.sysctl."net.core.wmem_max" = lib.mkDefault 7500000;

    users.users = lib.optionalAttrs (cfg.user == "connet") {
      connet = {
        isSystemUser = true;
        group = cfg.group;
      };
    };

    users.groups = lib.optionalAttrs (cfg.group == "connet") {
      connet = { };
    };

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.directPort ];

    environment.etc."connet.toml" = {
      user = cfg.user;
      group = cfg.group;
      source = (pkgs.formats.toml { }).generate "connet-config.toml" {
        log-level = cfg.logLevel;
        log-format = cfg.logFormat;
        client = {
          token-file = cfg.tokenFile;

          server-addr = cfg.serverAddr;
          direct-addr = ":${toString cfg.directPort}";

          destinations = cfg.destinations;
          sources = cfg.sources;
        } // lib.optionalAttrs (builtins.isPath cfg.serverCA) {
          server-cas = cfg.serverCA;
        };
      };
    };

    systemd.packages = [ cfg.package ];
    systemd.services.connet = {
      description = "connet client";
      after = [ "network.target" "network-online.target" ];
      requires = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      restartTriggers = [ config.environment.etc."connet.toml".source ];
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${pkgs.connet}/bin/connet --config /etc/connet.toml";
        Restart = "on-failure";
      };
    };
  };
}
