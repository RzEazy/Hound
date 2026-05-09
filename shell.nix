{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    python312
    python312Packages.pip
    osquery
    zlib
    stdenv.cc.cc.lib  # Provides libstdc++.so.6
  ];
  
  shellHook = ''
    export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$PWD"
    export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    echo "Hound development environment"
    echo "Python 3.12 with pip and osquery"
  '';
}
