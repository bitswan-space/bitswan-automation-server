{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go_1_24
    pkgs.gcc
    pkgs.gnumake
    pkgs.git # Assuming git might be needed for go modules or pre-commit hooks
    pkgs.gnumake # Some systems might require GNU make explicitly
  ];

  # Set GOPATH in the environment if needed, though with Go modules this is often not necessary
  # environment variables can be set if your application requires them
  shellHook = ''
    export GOPATH=$(pwd)/.go
  '';

  # Consider adding additional hooks or variables if your application requires them
}
