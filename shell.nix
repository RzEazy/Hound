{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    python312
    python312Packages.pip
    python312Packages.virtualenv
    osquery
    zlib
    stdenv.cc.cc.lib

    # Production services
    postgresql_16
    nats-server
    docker-compose

    # Dev tools
    openssl
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

    # Load .env if present
    if [ -f .env ]; then
      set -a
      source .env
      set +a
    fi

    # Local PostgreSQL data directory
    export PGDATA="$PWD/.pgdata"
    export PGHOST="$PWD/.pgdata"
    export PGPORT="5433"
    export HOUNDAI_DB_URL="postgresql+asyncpg://houndai:houndai@localhost:$PGPORT/houndai"

    # Initialize local PostgreSQL if not already set up
    if [ ! -d "$PGDATA" ]; then
      echo "Initializing local PostgreSQL..."
      initdb --no-locale --encoding=UTF8 -D "$PGDATA" > /dev/null 2>&1
      echo "unix_socket_directories = '$PGDATA'" >> "$PGDATA/postgresql.conf"
      echo "port = $PGPORT" >> "$PGDATA/postgresql.conf"
      echo "listen_addresses = 'localhost'" >> "$PGDATA/postgresql.conf"
    fi

    # Start PostgreSQL if not running
    if ! pg_isready -h "$PGDATA" -p "$PGPORT" > /dev/null 2>&1; then
      pg_ctl -D "$PGDATA" -l "$PGDATA/postgresql.log" start > /dev/null 2>&1
      sleep 1
      # Create database and user
      createuser -h "$PGDATA" -p "$PGPORT" houndai 2>/dev/null || true
      createdb -h "$PGDATA" -p "$PGPORT" -O houndai houndai 2>/dev/null || true
      psql -h "$PGDATA" -p "$PGPORT" -d houndai -c "ALTER USER houndai WITH PASSWORD 'houndai';" > /dev/null 2>&1 || true
    fi

    # Start NATS with JetStream if not running
    if ! pgrep -x nats-server > /dev/null; then
      nats-server --jetstream --store_dir "$PWD/.nats-data" --port 4222 \
        --pid "$PWD/.nats.pid" > "$PWD/.nats.log" 2>&1 &
      disown
    fi

    # Cleanup function
    houndai_stop() {
      echo "Stopping services..."
      pg_ctl -D "$PGDATA" stop > /dev/null 2>&1 || true
      [ -f "$PWD/.nats.pid" ] && kill $(cat "$PWD/.nats.pid") 2>/dev/null && rm "$PWD/.nats.pid"
      echo "Done."
    }
    export -f houndai_stop

    # Create DB tables if needed
    python -c "
from sqlalchemy import create_engine
from models.database import Base
try:
    engine = create_engine('postgresql://houndai:houndai@localhost:$PGPORT/houndai')
    Base.metadata.create_all(engine)
except Exception:
    pass
" 2>/dev/null

    echo ""
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║  HoundAI Production Environment                 ║"
    echo "  ║  Python 3.12 • osquery • PostgreSQL • NATS      ║"
    echo "  ║                                                  ║"
    echo "  ║  TUI:   python tui.py                           ║"
    echo "  ║  API:   uvicorn api.server:app --port 8000      ║"
    echo "  ║  Stop:  houndai_stop                            ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo ""
    echo "  PostgreSQL: localhost:$PGPORT | NATS: localhost:4222"
    echo ""
  '';
}