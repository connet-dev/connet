{ config, lib, pkgs, ... }:
let
  cfg = config.services.connet-control-server;
in
{
  options.services.connet-control-server = {
    enable = lib.mkEnableOption "connet control server";

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
      description = "Server log level to use.";
    };

    logFormat = lib.mkOption {
      default = "text";
      type = lib.types.enum [ "text" "json" ];
      description = "Server log format to use.";
    };

    clientTokensFile = lib.mkOption {
      type = lib.types.path;
      description = "The file to read client tokens from.";
    };

    relayTokensFile = lib.mkOption {
      type = lib.types.path;
      description = "The file to read relay tokens from.";
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

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ cfg.controlPort ];

    environment.etc."connet-control-server.toml" = {
      user = cfg.user;
      group = cfg.group;
      source = (pkgs.formats.toml { }).generate "connet-control-server-config.toml" {
        log-level = cfg.logLevel;
        log-format = cfg.logFormat;
        control = {
          client-tokens-file = cfg.clientTokensFile;
          relay-tokens-file = cfg.relayTokensFile;

          addr = ":${toString cfg.controlPort}";

          store-dir = "/var/lib/connet-control-server";
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
    systemd.services.connet-control-server = {
      description = "connet control server";
      after = [ "network.target" "network-online.target" ];
      requires = [ "network-online.target" ]
        ++ lib.optional (builtins.isString cfg.useACMEHost) [ "acme-finished-${cfg.useACMEHost}.target" ];
      wantedBy = [ "multi-user.target" ];
      restartTriggers = [ config.environment.etc."connet-control-server.toml".source ];
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${pkgs.connet}/bin/connet control --config /etc/connet-control-server.toml";
        Restart = "on-failure";
        StateDirectory = "connet-control-server";
        StateDirectoryMode = "0700";
      };
    };
  };
}
