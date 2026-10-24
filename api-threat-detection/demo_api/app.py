"""Demo protected API: a small shop REST API the gateway sits in front of (SRS v1.1 FR-103, E-01).

It holds fake data only and does nothing with input except echo safe summaries back.
It is NOT deliberately vulnerable - it exists so the gateway has something real to forward to,
and so tests can prove that blocked requests never arrive here (AC-012, via access.log).

Run alone:  python -m demo_api.app        (listens on 127.0.0.1:8001 only, SEC-003 / SEC-035)
Normally `python run.py` starts it for you.
"""
import json
import os
import threading
import time

from flask import Flask, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
ACCESS_LOG = os.environ.get("DEMO_API_LOG", os.path.join(HERE, "access.log"))

PRODUCTS = [{"id": i, "name": n, "price": p} for i, (n, p) in enumerate([
    ("Running shoes", 2999), ("Wireless headphones", 4999), ("Coffee maker", 3499), ("Desk lamp", 1299),
    ("Cotton shirt", 899), ("Backpack", 1999), ("Python guide (book)", 699), ("Kitchen mixer", 5499)], start=1)]

_log_lock = threading.Lock()


def create_demo_api(log_path=ACCESS_LOG):
    app = Flask("demo_api")

    @app.after_request
    def access_log(resp):
        line = {"ts": time.time(), "method": request.method, "path": request.path,
                "status": resp.status_code, "request_id": request.headers.get("X-Request-ID")}
        with _log_lock, open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
        return resp

    def body():
        return request.get_json(silent=True) or {}

    DEMO_ACCOUNTS = {"alice": "demo-pass-1", "bob": "demo-pass-2", "carol": "demo-pass-3", "dave": "demo-pass-4"}

    @app.post("/login")
    def login():
        b = body()
        user = str(b.get("username", ""))[:40]
        pw = b.get("password")
        if not user or not pw or DEMO_ACCOUNTS.get(user) != pw:   # wrong or missing credentials -> 401
            return jsonify(ok=False, error="invalid credentials"), 401
        return jsonify(ok=True, user=user, token="demo-token")

    @app.post("/logout")
    def logout():
        return jsonify(ok=True)

    @app.get("/profile")
    def profile():
        return jsonify(name="Demo User", email="demo@example.com")

    @app.get("/products")
    def products():
        page = request.args.get("page", "1")
        return jsonify(page=page, items=PRODUCTS)

    @app.get("/products/<int:pid>")
    def product(pid):
        item = next((p for p in PRODUCTS if p["id"] == (pid % len(PRODUCTS)) + 1), PRODUCTS[0])
        return jsonify(item)

    @app.route("/cart", methods=["GET", "POST"])
    def cart():
        return jsonify(ok=True, items=1)

    @app.post("/checkout")
    def checkout():
        return jsonify(ok=True, order_id=1001)

    @app.get("/orders")
    def orders():
        return jsonify(items=[{"id": 1001, "status": "shipped"}, {"id": 1002, "status": "open"}])

    @app.get("/orders/<int:oid>")
    def order(oid):
        return jsonify(id=oid, status="shipped")

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        hits = [p for p in PRODUCTS if any(w in p["name"].lower() for w in q.lower().split())]
        return jsonify(query_length=len(q), results=hits)

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        return jsonify(ok=True)

    @app.get("/help")
    def help_page():
        return jsonify(text="Contact support@example.com")

    @app.post("/feedback")
    def feedback():
        return jsonify(ok=True, received_chars=len(str(body().get("message", ""))))

    @app.get("/files")
    def files():
        return jsonify(available=["invoice1.pdf", "report2.pdf", "manual3.pdf"])

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def not_allowed(_):
        return jsonify(error="method not allowed"), 405

    return app


def serve_in_thread(host="127.0.0.1", port=8001, log_path=ACCESS_LOG):
    """Start the demo API in a background thread. Returns the server (call .shutdown() to stop)."""
    from werkzeug.serving import make_server
    server = make_server(host, port, create_demo_api(log_path), threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    host = os.environ.get("DEMO_API_HOST", "127.0.0.1")
    port = int(os.environ.get("DEMO_API_PORT", 8001))
    print(f"Demo shop API on http://{host}:{port}")
    create_demo_api().run(host=host, port=port, threaded=True)
