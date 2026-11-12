{
  description = "Oppo .ofp firmware decrypter and OnePlus .ops decrypter/encrypter";

  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-26.05/nixexprs.tar.zst";

  outputs =
    { self, nixpkgs }:
    {
      packages = builtins.mapAttrs (system: pkgs: rec {
        default = oppo_decrypt;
        oppo_decrypt = import ./default.nix { inherit pkgs; };
      }) nixpkgs.legacyPackages;
    };
}
