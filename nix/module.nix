{ role, ports, config, lib, pkgs, ... }:
let
  cfg = config.services."connet-${role}";
  settingsFormat = pkgs.formats.toml { };
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

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall (ports cfg.settings);

    environment.etc."connet-${role}.toml" = {
      user = cfg.user;
      group = cfg.group;
      source = settingsFormat.generate "connet-config-${role}.toml" cfg.settings;
    };

    systemd.packages = [ cfg.package ];
    systemd.services."connet-${role}" = {
      description = "connet ${role}";
      after = [ "network.target" "network-online.target" ];
      requires = [ "network-online.target" ];
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
