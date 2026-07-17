{
  description = "CLI for trust-based, per-directory shell hooks via .sallyport.jsonc";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      version = self.shortRev or self.dirtyShortRev or "dev";
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.buildGoModule {
            pname = "sallyport";
            inherit version;
            src = pkgs.lib.cleanSource self;
            vendorHash = "sha256-/psOToI55ddjebWW891ScqwqEU7oMohD5nn+XEiYuLY=";
            ldflags = [ "-s" "-w" "-X" "github.com/corrupt952/sallyport/command.Version=${version}" ];
            meta.mainProgram = "sallyport";
          };
        });

      checks = forAllSystems (system: {
        default = self.packages.${system}.default;
      });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              go
              gopls
              gotools
              golangci-lint
              goreleaser
            ];
          };
        });
    };
}
