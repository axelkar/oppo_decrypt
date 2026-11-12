{
  description = "Oppo .ofp firmware decrypter and OnePlus .ops decrypter/encrypter";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs =
    { self, nixpkgs }:
    {
      packages = builtins.mapAttrs (system: pkgs: rec {
        default = oppo_decrypt;
        oppo_decrypt = import ./default.nix { inherit pkgs; };
      }) nixpkgs.legacyPackages;
    };
}
