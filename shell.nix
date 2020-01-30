with import <nixpkgs> {};
let
  src = fetchFromGitHub {
      owner = "mozilla";
      repo = "nixpkgs-mozilla";
      # commit from: 2019-05-15
      rev = "c482bfd3dab1bde9590b03e712d73ced15385be4";
      sha256 = "18sxl0fxhbdnrfmkbmgxwsn12qy8dbv6ccb3imyyqbjqb76j8dpi";
   };
in
with import "${src.out}/rust-overlay.nix" pkgs pkgs;
stdenv.mkDerivation {
  name = "rust-env";
  buildInputs = [
    (rustChannelOf { rustToolchain = ./rust-toolchain; }).rust
    # latest.rustChannels.nightly.rust
    # latest.rustChannels.stable.rust

    clang
    gettext
    nettle
    pkgconfig
  ];

  # Set Environment Variables
  RUST_BACKTRACE = 1;

  # compilation of -sys packages requires manually setting this :(
  shellHook = ''
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang}/lib";
  '';
}
