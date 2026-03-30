self:
{ pkgs, lib, config, ... }:

let
  cfg = config.services.borderless-storage;
in
{
  options.services.borderless-storage = {
    enable = lib.mkEnableOption "borderless-storage object storage server";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.default;
      defaultText = lib.literalExpression "self.packages.\${pkgs.system}.default";
      description = "The borderless-storage package to use.";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/borderless-storage";
      description = "Path to the data directory.";
    };

    address = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8080";
      description = "Socket address to bind (ip:port).";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      description = "Full domain for pre-signed URLs (e.g. https://storage.example.com).";
    };

    presignApiKey = lib.mkOption {
      type = lib.types.str;
      description = "API key for presign endpoints. Consider using a secrets manager.";
    };

    presignHmacSecret = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "HMAC secret for pre-signed URLs. If null, the server generates a random secret on startup. Consider using a secrets manager.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.borderless-storage = {
      isSystemUser = true;
      group = "borderless-storage";
      home = cfg.dataDir;
    };

    users.groups.borderless-storage = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.dataDir} 0750 borderless-storage borderless-storage -"
    ];

    systemd.services.borderless-storage = {
      description = "Borderless Storage - S3-style object storage server";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        DATA_DIR = cfg.dataDir;
        IP_ADDR = cfg.address;
        DOMAIN = cfg.domain;
        PRESIGN_API_KEY = cfg.presignApiKey;
      } // lib.optionalAttrs (cfg.presignHmacSecret != null) {
        PRESIGN_HMAC_SECRET = cfg.presignHmacSecret;
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/borderless-storage";
        User = "borderless-storage";
        Group = "borderless-storage";
        Restart = "on-failure";
        RestartSec = 5;

        # Hardening
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ReadWritePaths = [ cfg.dataDir ];
      };
    };
  };
}
