{ config, lib, pkgs, ... }:
let
  cfg = config.services.connet-server;
in
{
  options.services.connet-server = {
    enable = lib.mkEnableOption "connet server";

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

    tokensFile = lib.mkOption {
      type = lib.types.path;
      description = "The file to read client tokens from.";
    };

    controlPort = lib.mkOption {
      default = 19190;
      type = lib.types.port;
      description = "The port to listen for incoming connections.";
    };

    useACMEHost = lib.mkOption {
      default = null;
      type = lib.types.nullOr lib.types.str;
      description = ''
        A host of an existing ACME certificate to use.

        *Note that this option does not create any certificates, nor
        does it add subdomains to existing ones – you will need to create them
        manually using [](#opt-security.acme.certs).*
      '';
      example = "example.com";
    };

    serverCertFile = lib.mkOption {
      default = null;
      type = lib.types.nullOr lib.types.path;
      description = "Server certificate file to use";
    };

    serverKeyFile = lib.mkOption {
      default = null;
      type = lib.types.nullOr lib.types.path;
      description = "Server private key file to use";
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
  };

  config = lib.mkIf cfg.enable {
    warnings = [ ]
      ++ lib.optionals (builtins.isString cfg.useACMEHost && builtins.isPath cfg.serverCertFile)
      [ "When both useACMEHost and serverCertFile are set, connet will prefer useACMEHost" ];

    assertions = [
      {
        assertion = builtins.isNull cfg.useACMEHost && builtins.isNull cfg.serverCertFile;
        message = "connet server requires certificate, either provide useACMEHost or serverCertFile/serverKeyFile";
      }
      {
        assertion = builtins.isPath cfg.serverCertFile && builtins.isNull cfg.serverKeyFile;
        message = "serverKeyFile is required when serverCertFile is set";
      }
      {
        assertion = builtins.isNull cfg.serverCertFile && builtins.isPath cfg.serverKeyFile;
        message = "serverCertFile is required when serverKeyFile is set";
      }
    ];

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

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.controlPort cfg.relayPort ];

    environment.etc."connet-server.toml" = {
      user = cfg.user;
      group = cfg.group;
      source = (pkgs.formats.toml { }).generate "connet-server-config.toml" {
        log-level = cfg.logLevel;
        log-format = cfg.logFormat;
        server = {
          tokens-file = cfg.tokenFile;

          addr = ":${toString cfg.controlPort}";

          relay-addr = ":${toString cfg.relayPort}";
          relay-hostname = cfg.relayHostname;

          store-dir = "/var/lib/connet-server";
        } // (if (builtins.isString cfg.useACMEHost) then
          let
            sslCertDir = config.security.acme.certs.${cfg.useACMEHost}.directory;
          in
          {
            cert-file = "${sslCertDir}/cert.pem";
            key-file = "${sslCertDir}/key.pem";
          }
        else {
          cert-file = cfg.serverCertFile;
          key-file = cfg.serverKeyFile;
        });
      };
    };

    systemd.packages = [ cfg.package ];
    systemd.services.connet-server = {
      description = "connet server";
      after = [ "network.target" "network-online.target" ];
      requires = [ "network-online.target" ]
        ++ lib.optional (builtins.isString cfg.useACMEHost) [ "acme-finished-${cfg.useACMEHost}.target" ];
      wantedBy = [ "multi-user.target" ];
      restartTriggers = [ config.environment.etc."connet-server.toml".source ];
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/connet server --config /etc/connet-server.toml";
        Restart = "on-failure";
        StateDirectory = "connet-server";
        StateDirectoryMode = "0700";
      };
    };
  };
}
