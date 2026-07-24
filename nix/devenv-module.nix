self:
{ pkgs, lib, config, ... }:

let
  cfg = config.services.borderless-storage;

  # Derive the readiness-probe target from the bound address (ip:port). A
  # wildcard bind isn't connectable as a client, so probe loopback instead.
  addrParts = lib.splitString ":" cfg.address;
  boundHost = builtins.elemAt addrParts 0;
  probeHost = if (boundHost == "0.0.0.0" || boundHost == "") then "127.0.0.1" else boundHost;
  probePort = lib.toInt (builtins.elemAt addrParts 1);
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
      default = "./data";
      description = "Path to the data directory.";
    };

    address = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8080";
      description = "Socket address to bind (ip:port).";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      default = "http://localhost:8080";
      description = "Full domain for pre-signed URLs.";
    };

    presignApiKey = lib.mkOption {
      type = lib.types.str;
      default = "dev-secret-api-key";
      description = "API key for presign endpoints.";
    };

    presignHmacSecret = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "HMAC secret for pre-signed URLs. If null, the server generates a random secret on startup.";
    };
  };

  config = lib.mkIf cfg.enable {
    env.DATA_DIR = cfg.dataDir;
    env.IP_ADDR = cfg.address;
    env.DOMAIN = cfg.domain;
    env.PRESIGN_API_KEY = cfg.presignApiKey;
    env.PRESIGN_HMAC_SECRET = lib.mkIf (cfg.presignHmacSecret != null) cfg.presignHmacSecret;

    enterShell = ''
      mkdir -p ${lib.escapeShellArg cfg.dataDir}
    '';

    processes.borderless-storage = {
      exec = "${cfg.package}/bin/borderless-storage";
      # The server merges /healthz into its main router (same port as the API),
      # so the service owns its own readiness probe. Lets consumers gate on
      # `depends_on.borderless-storage.condition = "process_healthy"`.
      process-compose.readiness_probe = {
        http_get = {
          host = probeHost;
          port = probePort;
          path = "/healthz";
        };
        initial_delay_seconds = 1;
        period_seconds = 2;
        timeout_seconds = 5;
        failure_threshold = 15;
      };
    };
  };
}
