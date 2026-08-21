{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
        (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc rustfmt clippy openssl ];
          # sasl2-sys finds libsasl2 via these (nixpkgs' cyrus-sasl ships no .pc file).
          SASL2_LIB_DIR = "${pkgs.cyrus_sasl.out}/lib";
          SASL2_INCLUDE_DIR = "${pkgs.cyrus_sasl.dev}/include";
          # libpam for the PAM module (#[link(name = "pam")]).
          RUSTFLAGS = "-L ${pkgs.pam}/lib";
        };
      });
    };
}
