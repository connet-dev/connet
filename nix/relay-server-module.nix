{ config, lib, pkgs, ... }:
let
  cfg = config.services.connet-relay-server;
in
{
  options.services.connet-relay-server = {
    enable = lib.mkEnableOption "connet relay server";

    package = lib.mkOption {
      default = pkgs.callPackage ./package.nix { };
      type = lib.types.package;
    };

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
      description = "Server log level to use.";
    };

    logFormat = lib.mkOption {
      default = "text";
      type = lib.types.enum [ "text" "json" ];
      description = "Server log format to use.";
    };

    tokenFile = lib.mkOption {
      type = lib.types.path;
      description = "The file to read relay token from.";
    };

    relayPort = lib.mkOption {
      default = 19191;
      type = lib.types.port;
      description = "The port to listen for incoming relay connections.";
    };

    relayHostname = lib.mkOption {
      type = lib.types.str;
      description = "Relay hostname to advertise to clients.";
      example = "localhost";
    };

    controlAddr = lib.mkOption {
      type = lib.types.str;
      description = "Control server address to connect to";
      example = "localhost:19190";
    };

    controlCA = lib.mkOption {
      default = null;
      type = lib.types.nullOr lib.types.path;
      description = "Control server Certificate Authority file to use, required when running self-signed server";
    };

    statusAddr = lib.mkOption {
      default = null;
      type = lib.types.nullOr lib.types.str;
      description = ''
        The address to listen for status connections. 

        ::: {.note}
        openFirewall will not open the port of the status address
        :::
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

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.relayPort ];

    environment.etc."connet-relay-server.toml" = {
      user = cfg.user;
      group = cfg.group;
      source = (pkgs.formats.toml { }).generate "connet-relay-server-config.toml" {
        log-level = cfg.logLevel;
        log-format = cfg.logFormat;
        relay = {
          token-file = cfg.tokenFile;

          addr = ":${toString cfg.relayPort}";
          hostname = cfg.relayHostname;

          control-addr = cfg.controlAddr;

          store-dir = "/var/lib/connet-relay-server";
        } // lib.optionalAttrs (builtins.isPath cfg.controlCA) {
          control-cas = cfg.controlCA;
        } // lib.optionalAttrs (builtins.isString cfg.statusAddr) {
          status-addr = cfg.statusAddr;
        };
      };
    };

    systemd.packages = [ cfg.package ];
    systemd.services.connet-relay-server = {
      description = "connet relay server";
      after = [ "network.target" "network-online.target" ];
      requires = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      restartTriggers = [ config.environment.etc."connet-relay-server.toml".source ];
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/connet relay --config /etc/connet-relay-server.toml";
        Restart = "on-failure";
        StateDirectory = "connet-relay-server";
        StateDirectoryMode = "0700";
      };
    };
  };
}
