{ config, lib, pkgs, ... }:
import ./module.nix {
  inherit config lib pkgs;
  role = "control";
  ports = settings:
    let
      clientsAddr = lib.attrByPath [ "control" "clients-addr" ] ":19190" settings;
      clientsParts = lib.splitString ":" clientsAddr;
      clientsPort = lib.toInt (lib.last clientsParts);

      relaysAddr = lib.attrByPath [ "control" "relays-addr" ] ":19189" settings;
      relaysParts = lib.splitString ":" relaysAddr;
      relaysPort = lib.toInt (lib.last relaysParts);
    in
    [ clientsPort relaysPort ];
}
