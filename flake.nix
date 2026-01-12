{
  description = "Bitcoin Core LogDebug extraction tool";

  inputs.nixpkgs.url = "nixpkgs";

  outputs = { self, nixpkgs }:
    let
      # Support multiple systems
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      
      forAllSystems = nixpkgs.lib.genAttrs systems;
      
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              clang
              libclang
              python3
              python3Packages.libclang
            ];
            
            # Set environment variables for libclang
            shellHook = ''
              export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
              echo "LogDebug extraction environment ready!"
              echo "Run: python3 extract_logdebug.py bitcoin/src [output.json]"
            '';
          };
        }
      );
    };
}

