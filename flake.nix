{
  description = "Borderless Storage - dev shell and buildable package (Rust)";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
    # optional compat for non-flake users
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        lib = pkgs.lib;

        # Package metadata
        pname = "borderless-storage";
        version = "0.1.1";

        # If you don't want to commit Cargo.lock, replace cargoLock with cargoHash = lib.fakeHash;
        # and run `nix build` once to get the real hash to paste back.
        borderlessPkg =
          pkgs.rustPlatform.buildRustPackage {
            inherit pname version;
            src = ./.;

            # Prefer a committed Cargo.lock:
            cargoLock.lockFile = ./Cargo.lock;

            # Expose useful metadata
            meta = with lib; {
              description = "A minimal S3-style object store with pre-signed URLs and chunked uploads (Axum/Tokio).";
              homepage = "https://github.com/borderless-tech/borderless-storage";
              license = with licenses; [ mit asl20 ];
              maintainers = [ ];
              platforms = platforms.unix;
              mainProgram = "borderless-storage";
            };
          };
        # Build a Docker image that contains only the runtime closure for the binary
        dockerImage =
          pkgs.dockerTools.buildLayeredImage {
            name = "borderless/${pname}";
            tag = version;

            # Include the compiled package and CA certs
            contents = [
              borderlessPkg
              pkgs.cacert
            ];

            # Docker image configuration
            config = {
              WorkingDir = "/";
              ExposedPorts = { "8080/tcp" = {}; };

              # Data volume - must be mounted at runtime
              Volumes = { "/data" = {}; };

              # The data directory and the port are fixed inside the container
              Env = [
                "DATA_DIR=/data"
                "IP_ADDR=0.0.0.0:8080"
              ];

              # Entrypoint/Cmd: keep simple so env vars are easy to inject at runtime
              Entrypoint = [ "${borderlessPkg}/bin/borderless-storage" ];
              Cmd = [ ];
            };

            # labels
            created = "now";
          };
      in
      {
        # nix develop
        devShells.default = with pkgs; mkShell {
          buildInputs = [
            # Toolchain for dev work (with llvm-tools-preview)
            (rust-bin.stable.latest.default.override {
              extensions = [ "llvm-tools-preview" ];
              targets = [ ];
            })
            rustc
            cargo
            cargo-tarpaulin
          ];

          # Some rust tools want this
          RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        };

        # nix build .#default
        packages.default = borderlessPkg;

        # convenience alias
        packages.${pname} = borderlessPkg;

        # Docker image target: nix build .#docker
        packages.docker = dockerImage;

        # nix run .  (runs the built binary)
        apps.default = {
          type = "app";
          program = "${borderlessPkg}/bin/borderless-storage";
        };

        # nix flake check  (useful for CI; builds + runs tests)
        checks.${pname} = borderlessPkg;
      }
    );
}
