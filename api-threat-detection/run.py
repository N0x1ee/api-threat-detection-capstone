"""Start the system:  python run.py   then open http://localhost:8000"""
import os
import threading
import webbrowser

import sys

from app.auth import Auth, AuthError
from app.config import ConfigError, load_config
from app.pipeline import Pipeline
from app.server import create_app
from app.training import load_or_train

PORT = int(os.environ.get("PORT", 8000))

if __name__ == "__main__":
    try:
        cfg = load_config()
    except ConfigError as e:                      # FR-086: refuse to start, name the bad parameter
        raise SystemExit(f"config.json problem: {e}")
    if os.environ.get("UPSTREAM_URL"):           # Docker: point the gateway at the demo-api container
        cfg["gateway"]["upstream"] = os.environ["UPSTREAM_URL"]
        cfg["gateway"]["start_demo_api"] = False
    if cfg["gateway"]["start_demo_api"]:
        from demo_api.app import serve_in_thread
        serve_in_thread("127.0.0.1", cfg["gateway"]["demo_api_port"])
        print(f"  Demo shop API (protected, local only) -> http://127.0.0.1:{cfg['gateway']['demo_api_port']}")
    agents = load_or_train()
    db_path = os.environ.get("AUDIT_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit.db"))
    pipeline = Pipeline(agents, db_path, cfg=cfg)
    auth = Auth(db_path, cfg["auth"])
    try:
        for u in auth.seed_from_env(os.environ):
            print(f"  Created account {u!r} from environment variables")
    except AuthError as e:
        raise SystemExit(f"Could not create account from environment variables: {e}")
    if auth.user_count() == 0:                    # SEC-010: no default accounts, so ask for the first admin
        if not sys.stdin.isatty():
            raise SystemExit("No user accounts yet. Run:  python manage_users.py add <name> --role admin\n"
                             "or set ADMIN_USERNAME and ADMIN_PASSWORD before starting.")
        from manage_users import create_interactive
        print("\n  No accounts yet. Create the first administrator account.")
        create_interactive(auth, role="admin")
    app = create_app(pipeline, cfg, auth)
    print(f"\n  Dashboard ->  http://localhost:{PORT}"
          f"\n  Gateway   ->  http://localhost:{PORT}/gateway/<path>   (e.g. /gateway/products)"
          f"\n  Press Ctrl+C to stop.\n")
    if not os.environ.get("NO_BROWSER"):
        threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{PORT}")).start()
    app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)
