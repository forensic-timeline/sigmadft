# src/graph2web/__main__.py

"""Run the web app: PYTHONPATH=src python -m graph2web [--host 127.0.0.1] [--port 8765]"""

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(prog="graph2web")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: local only)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    print(f"Log Forensic Analysis (LFA) on http://{args.host}:{args.port}")
    uvicorn.run("graph2web.app:app", host=args.host, port=args.port, log_level="warning")


main()
