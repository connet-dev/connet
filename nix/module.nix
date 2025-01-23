{ role, ports, usesCerts ? false, config, lib, pkgs, ... }:
let
  cfg = config.services."connet-${role}";
  settingsFormat = pkgs.formats.toml { };
  portFromPath = { path, default }: lib.trivial.pipe cfg.settings [
    (lib.attrByPath path default)
    (lib.splitString ":")
    lib.last
    lib.toInt
  ];
  usesACME = usesCerts && builtins.isString cfg.useACMEHost;
in
{
  options.services."connet-${role}" = {
    enable = lib.mkEnableOption "connet ${role}";

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

    settings = lib.mkOption {
      description = "See docs at https://github.com/connet-dev/connet?tab=readme-ov-file#configuration";
      default = { };
      type = lib.types.submodule {
        freeformType = settingsFormat.type;
      };
    };

    openFirewall = lib.mkOption {
      default = false;
      type = lib.types.bool;
      description = "Whether to open the firewall for the specified port.";
    };
  } // lib.optionalAttrs usesCerts {
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
  };

  config = lib.mkIf cfg.enable {
    warnings = lib.flatten [
      (lib.optionals
        (usesACME && builtins.isString (lib.attrByPath [ "server" "cert-file" ] null cfg.settings))
        [ "ACME config for ${cfg.useACMEHost} overrides `server.cert-file`" ])
      (lib.optionals
        (usesACME && builtins.isString (lib.attrByPath [ "server" "key-file" ] null cfg.settings))
        [ "ACME config for ${cfg.useACMEHost} overrides `server.key-file`" ])
      (lib.optionals
        (usesACME && builtins.isString (lib.attrByPath [ "control" "cert-file" ] null cfg.settings))
        [ "ACME config for ${cfg.useACMEHost} overrides `control.cert-file`" ])
      (lib.optionals
        (usesACME && builtins.isString (lib.attrByPath [ "control" "key-file" ] null cfg.settings))
        [ "ACME config for ${cfg.useACMEHost} overrides `control.key-file`" ])
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

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall (builtins.map portFromPath ports);

    environment.etc."connet-${role}.toml" = {
      user = cfg.user;
      group = cfg.group;
      source = settingsFormat.generate "connet-config-${role}.toml"
        (cfg.settings // lib.optionalAttrs usesACME (
          let
            sslCertDir = config.security.acme.certs.${cfg.useACMEHost}.directory;
            sslCert = "${sslCertDir}/cert.pem";
            sslKey = "${sslCertDir}/key.pem";
          in
          {
            server.cert-file = sslCert;
            server.key-file = sslKey;
            control.cert-file = sslCert;
            control.key-file = sslKey;
          }
        ));
    };

    systemd.packages = [ cfg.package ];
    systemd.services."connet-${role}" = {
      description = "connet ${role}";
      after = [ "network.target" "network-online.target" ];
      requires = [ "network-online.target" ] ++ lib.optionals usesACME [ "acme-finished-${cfg.useACMEHost}.target" ];
      wantedBy = [ "multi-user.target" ];
      restartTriggers = [ config.environment.etc."connet-${role}.toml".source ];
      serviceConfig = {
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/connet ${if role == "client" then "" else "${role} "} --config /etc/connet.toml";
        Restart = "on-failure";
      } // lib.optionalAttrs (role != "client") {
        StateDirectory = "connet-${if role == "server" then "" else "${role}-"}server";
        StateDirectoryMode = "0700";
      };
    };
  };
}
