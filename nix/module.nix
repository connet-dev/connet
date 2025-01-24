{ role, ports, hasCerts ? false, hasStorage ? false, config, lib, pkgs, ... }:
let
  cfg = config.services."connet-${role}";
  settingsFormat = pkgs.formats.toml { };
  portFromPath = { path, default }: lib.trivial.pipe cfg.settings [
    (lib.attrByPath path default)
    (lib.splitString ":")
    lib.last
    lib.toInt
  ];
  usesACME = hasCerts && builtins.isString cfg.useACMEHost;
  noStorageSpec = hasStorage && builtins.isNull (lib.attrByPath [ role "store-dir" ] null cfg.settings);
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
  } // lib.optionalAttrs hasCerts {
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
        (usesACME && builtins.isString (lib.attrByPath [ role "cert-file" ] null cfg.settings))
        [ "ACME config for ${cfg.useACMEHost} overrides `${role}.cert-file`" ])
      (lib.optionals
        (usesACME && builtins.isString (lib.attrByPath [ role "key-file" ] null cfg.settings))
        [ "ACME config for ${cfg.useACMEHost} overrides `${role}.key-file`" ])
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
      source = settingsFormat.generate "connet-config-${role}.toml" (lib.recursiveUpdate
        cfg.settings
        (lib.recursiveUpdate
          (lib.optionalAttrs usesACME (
            let
              sslCertDir = config.security.acme.certs.${cfg.useACMEHost}.directory;
            in
            {
              ${role} = {
                cert-file = "${sslCertDir}/cert.pem";
                key-file = "${sslCertDir}/key.pem";
              };
            }
          ))
          (lib.optionalAttrs noStorageSpec {
            ${role} = { "store-dir" = "/var/lib/connet-${role}"; };
          })));
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
        ExecStart = "${cfg.package}/bin/connet ${if role == "client" then "" else "${role} "} --config /etc/connet-${role}.toml";
        Restart = "on-failure";
      } // lib.optionalAttrs noStorageSpec {
        StateDirectory = "connet-${role}";
        StateDirectoryMode = "0700";
      };
    };
  };
}
