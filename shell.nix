{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    python312
    python312Packages.pip
    python312Packages.virtualenv
    osquery
    zlib
    stdenv.cc.cc.lib
  ];
  
  shellHook = ''
    export LD_LIBRARY_PATH="${pkgs.stdenv.cc.cc.lib}/lib:${pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    # Recreate venv if missing or broken
    if [ ! -f "env/bin/python" ]; then
      echo "Creating virtual environment..."
      rm -rf env
      python -m venv env --clear
    fi

    # Activate venv
    source env/bin/activate
    export PYTHONPATH="$PWD''${PYTHONPATH:+:$PYTHONPATH}"

    # Install requirements if needed
    if [ requirements.txt -nt env/.deps_installed ]; then
      echo "Installing Python dependencies..."
      env/bin/pip install --quiet --upgrade pip
      env/bin/pip install --quiet -r requirements.txt
      touch env/.deps_installed
    fi

    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  HoundAI Development Environment        ║"
    echo "  ║  Python 3.12 • osquery • venv active    ║"
    echo "  ║                                         ║"
    echo "  ║  Run:  python tui.py                    ║"
    echo "  ║  Hunt: type 'hunt' in the TUI           ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
  '';
}