"""RepairHub API - multi-vendor repair marketplace. Flask + SQLite."""
import math, os, secrets, sqlite3
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, abort, g, jsonify, make_response, request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

DB = os.environ.get("DB_PATH", "repairhub.db")
ser = URLSafeTimedSerializer(os.environ.get("SECRET_KEY", "dev-secret-change-me"))
app = Flask(__name__, static_folder="../frontend", static_url_path="")
DEVICES = ("mobile", "laptop", "appliance")
SEQ = ["requested", "accepted", "received", "diagnosed", "repairing",
       "quality_check", "ready", "delivered"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE,
  pw_hash TEXT, role TEXT CHECK(role IN('customer','shop','admin')), created_at TEXT);
CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY, owner_id INTEGER REFERENCES users(id),
  name TEXT, city TEXT, lat REAL, lng REAL, device_types TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES users(id),
  shop_id INTEGER REFERENCES shops(id), device_type TEXT, brand TEXT, model TEXT, issue TEXT,
  address TEXT, lat REAL, lng REAL, slot TEXT, status TEXT DEFAULT 'requested',
  quote REAL, quote_note TEXT, approved INTEGER DEFAULT 0, paid INTEGER DEFAULT 0,
  rejected_by TEXT DEFAULT '', created_at TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id),
  status TEXT, note TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id),
  sender_id INTEGER REFERENCES users(id), body TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id),
  amount REAL, ref TEXT, status TEXT, at TEXT);
"""

# ---------------------------------------------------------------- helpers
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d: d.close()

def q(sql, *a): return db().execute(sql, a).fetchall()
def q1(sql, *a): return db().execute(sql, a).fetchone()
def ex(sql, *a):
    c = db().execute(sql, a); db().commit(); return c.lastrowid

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def body(): return request.get_json(silent=True) or {}
def err(msg, code=400): abort(make_response(jsonify(error=msg), code))
def event(oid, status, note=""):
    ex("INSERT INTO events(order_id,status,note,at) VALUES(?,?,?,?)", oid, status, note, now())

@app.errorhandler(404)
def _404(e): return jsonify(error="Not found"), 404

def token_for(u): return ser.dumps(u["id"])

def auth(*roles):
    def deco(fn):
        @wraps(fn)
        def w(*a, **k):
            try: uid = ser.loads(request.headers.get("Authorization", "")[7:], max_age=7 * 86400)
            except BadSignature: err("Unauthorized", 401)
            u = q1("SELECT id,name,email,role FROM users WHERE id=?", uid)
            if not u: err("Unauthorized", 401)
            if roles and u["role"] not in roles: err("Forbidden", 403)
            g.user = u
            return fn(*a, **k)
        return w
    return deco

def dist(a, b, c, d):  # haversine, km
    p = math.pi / 180
    h = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 12742 * math.asin(math.sqrt(h))

def pick_shop(device, lat, lng, exclude=()):
    """Nearest active shop that handles the device; ties/no-location -> least busy."""
    rows = q("""SELECT s.*, (SELECT COUNT(*) FROM orders o WHERE o.shop_id=s.id
                AND o.status NOT IN('delivered','rejected')) AS load FROM shops s WHERE s.active=1""")
    ok = [s for s in rows if device in s["device_types"].split(",") and s["id"] not in exclude]
    if not ok: return None
    if lat is not None and lng is not None:
        return min(ok, key=lambda s: (dist(lat, lng, s["lat"], s["lng"]), s["load"]))
    return min(ok, key=lambda s: s["load"])

def load_order(oid):
    o = q1("""SELECT o.*, s.owner_id AS shop_owner, s.name AS shop_name, u.name AS customer_name
              FROM orders o LEFT JOIN shops s ON s.id=o.shop_id JOIN users u ON u.id=o.customer_id
              WHERE o.id=?""", oid)
    me = g.user
    if not o or not (me["role"] == "admin" or o["customer_id"] == me["id"] or o["shop_owner"] == me["id"]):
        abort(404)
    return o

def shop_only(o):
    if o["shop_owner"] != g.user["id"]: err("Not your order", 403)

def pub(o):
    d = dict(o); d.pop("rejected_by", None); return d

# ------------------------------------------------------------------- auth
@app.post("/api/auth/register")
def register():
    d = body(); role = d.get("role", "customer")
    name, email, pw = (d.get(k, "").strip() for k in ("name", "email", "password"))
    if role not in ("customer", "shop"): err("Invalid role", 422)
    if not name or "@" not in email or len(pw) < 6: err("Name, valid email and 6+ char password required", 422)
    if q1("SELECT 1 FROM users WHERE email=?", email.lower()): err("Email already registered", 409)
    uid = ex("INSERT INTO users(name,email,pw_hash,role,created_at) VALUES(?,?,?,?,?)",
             name, email.lower(), generate_password_hash(pw), role, now())
    if role == "shop":
        s = d.get("shop") or {}
        types = [t for t in s.get("device_types", []) if t in DEVICES]
        if not s.get("name") or not types: err("Shop name and at least one device type required", 422)
        ex("INSERT INTO shops(owner_id,name,city,lat,lng,device_types) VALUES(?,?,?,?,?,?)",
           uid, s["name"], s.get("city", ""), s.get("lat"), s.get("lng"), ",".join(types))
    u = q1("SELECT id,name,email,role FROM users WHERE id=?", uid)
    return jsonify(token=token_for(u), user=dict(u)), 201

@app.post("/api/auth/login")
def login():
    d = body()
    u = q1("SELECT * FROM users WHERE email=?", d.get("email", "").lower())
    if not u or not check_password_hash(u["pw_hash"], d.get("password", "")): err("Invalid credentials", 401)
    return jsonify(token=token_for(u), user={k: u[k] for k in ("id", "name", "email", "role")})

@app.get("/api/me")
@auth()
def me(): return jsonify(dict(g.user))

# ----------------------------------------------------------------- orders
@app.post("/api/orders")
@auth("customer")
def create_order():
    d = body()
    need = {k: str(d.get(k, "")).strip() for k in ("device_type", "brand", "model", "issue", "address", "slot")}
    if need["device_type"] not in DEVICES or not all(need.values()) or len(need["issue"]) < 10:
        err("Device type, brand, model, issue (10+ chars), address and slot are required", 422)
    try: lat = float(d["lat"]) if d.get("lat") not in (None, "") else None; lng = float(d["lng"]) if d.get("lng") not in (None, "") else None
    except ValueError: err("Invalid coordinates", 422)
    shop = pick_shop(need["device_type"], lat, lng)
    if not shop: err("No partner shop available for this device type yet", 409)
    oid = ex("""INSERT INTO orders(customer_id,shop_id,device_type,brand,model,issue,address,lat,lng,slot,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""", g.user["id"], shop["id"], need["device_type"], need["brand"],
            need["model"], need["issue"], need["address"], lat, lng, need["slot"], now())
    event(oid, "requested", f"Pickup requested for {need['slot']}; routed to {shop['name']}")
    return jsonify(id=oid, shop=shop["name"]), 201

@app.get("/api/orders")
@auth()
def list_orders():
    u, where, arg = g.user, "", ()
    if u["role"] == "customer": where, arg = "WHERE o.customer_id=?", (u["id"],)
    elif u["role"] == "shop": where, arg = "WHERE s.owner_id=?", (u["id"],)
    rows = q(f"""SELECT o.*, s.name AS shop_name, c.name AS customer_name FROM orders o
                 LEFT JOIN shops s ON s.id=o.shop_id JOIN users c ON c.id=o.customer_id {where}
                 ORDER BY o.id DESC""", *arg)
    return jsonify([pub(r) for r in rows])

@app.get("/api/orders/<int:oid>")
@auth()
def get_order(oid):
    o = load_order(oid)
    ev = q("SELECT status,note,at FROM events WHERE order_id=? ORDER BY id", oid)
    ms = q("""SELECT m.id,m.body,m.at,m.sender_id,u.name AS sender,u.role FROM messages m
              JOIN users u ON u.id=m.sender_id WHERE m.order_id=? ORDER BY m.id""", oid)
    return jsonify(order=pub(o), events=[dict(e) for e in ev], messages=[dict(m) for m in ms])

@app.post("/api/orders/<int:oid>/decision")
@auth("shop")
def decision(oid):
    o = load_order(oid); shop_only(o)
    if o["status"] != "requested": err("Order is not awaiting a decision", 409)
    if body().get("accept"):
        ex("UPDATE orders SET status='accepted' WHERE id=?", oid)
        event(oid, "accepted", f"Accepted by {o['shop_name']}. Pickup will be arranged for {o['slot']}")
    else:  # re-route to the next best shop
        rej = f"{o['rejected_by']},{o['shop_id']}"
        skip = {int(x) for x in rej.split(",") if x}
        s = pick_shop(o["device_type"], o["lat"], o["lng"], skip)
        if s:
            ex("UPDATE orders SET shop_id=?, rejected_by=? WHERE id=?", s["id"], rej, oid)
            event(oid, "requested", f"Re-routed to {s['name']}")
        else:
            ex("UPDATE orders SET status='rejected', rejected_by=? WHERE id=?", rej, oid)
            event(oid, "rejected", "No shop was able to take this job")
    return jsonify(ok=True)

@app.post("/api/orders/<int:oid>/status")
@auth("shop")
def set_status(oid):
    o = load_order(oid); shop_only(o)
    target = body().get("status")
    if o["status"] not in SEQ: err("Order is closed", 409)
    i = SEQ.index(o["status"])
    if i + 1 >= len(SEQ): err("Order already delivered", 409)
    nxt = SEQ[i + 1]
    if nxt == "diagnosed": err("Send a quote to move to 'diagnosed'", 409)
    if target != nxt: err(f"Next allowed step is '{nxt}'", 409)
    if nxt == "repairing" and not o["approved"]: err("Customer has not approved the quote yet", 409)
    if nxt == "delivered" and not o["paid"]: err("Payment is still pending", 409)
    ex("UPDATE orders SET status=? WHERE id=?", nxt, oid)
    event(oid, nxt, body().get("note", ""))
    return jsonify(ok=True)

@app.post("/api/orders/<int:oid>/quote")
@auth("shop")
def quote(oid):
    o = load_order(oid); shop_only(o); d = body()
    if o["status"] not in ("received", "diagnosed") or o["approved"]:
        err("Quote can be sent after the device is received and until the customer approves", 409)
    try: amt = round(float(d.get("amount")), 2); assert amt > 0
    except (TypeError, ValueError, AssertionError): err("Amount must be a positive number", 422)
    note = str(d.get("note", "")).strip()[:1000]
    ex("UPDATE orders SET quote=?, quote_note=?, status='diagnosed', approved=0 WHERE id=?", amt, note, oid)
    event(oid, "diagnosed", f"Quote {amt}. {note}".strip())
    return jsonify(ok=True)

@app.post("/api/orders/<int:oid>/approve")
@auth("customer")
def approve(oid):
    o = load_order(oid); d = body()
    if o["status"] != "diagnosed" or o["quote"] is None or o["approved"]: err("No quote awaiting approval", 409)
    if d.get("approve"):
        ex("UPDATE orders SET approved=1 WHERE id=?", oid); event(oid, "diagnosed", "Quote approved by customer")
    else:
        event(oid, "diagnosed", "Customer requested changes: " + str(d.get("note", ""))[:300])
    return jsonify(ok=True)

@app.post("/api/orders/<int:oid>/pay")
@auth("customer")
def pay(oid):
    """MOCK payment. Swap for Stripe PaymentIntent / Razorpay Order + webhook confirmation."""
    o = load_order(oid)
    if not o["approved"] or o["paid"]: err("Nothing to pay (quote not approved or already paid)", 409)
    ref = "MOCK-" + secrets.token_hex(5).upper()
    ex("INSERT INTO payments(order_id,amount,ref,status,at) VALUES(?,?,?,?,?)", oid, o["quote"], ref, "paid", now())
    ex("UPDATE orders SET paid=1 WHERE id=?", oid)
    event(oid, o["status"], f"Payment of {o['quote']} received (ref {ref})")
    return jsonify(ref=ref)

# --------------------------------------------------------------- messages
@app.post("/api/orders/<int:oid>/messages")
@auth()
def post_message(oid):
    load_order(oid); text = str(body().get("body", "")).strip()[:2000]
    if not text: err("Message is empty", 422)
    ex("INSERT INTO messages(order_id,sender_id,body,at) VALUES(?,?,?,?)", oid, g.user["id"], text, now())
    return jsonify(ok=True), 201

# ------------------------------------------------------------------ admin
@app.get("/api/admin/overview")
@auth("admin")
def overview():
    return jsonify(
        users={r["role"]: r["n"] for r in q("SELECT role, COUNT(*) n FROM users GROUP BY role")},
        orders={r["status"]: r["n"] for r in q("SELECT status, COUNT(*) n FROM orders GROUP BY status")},
        revenue=q1("SELECT COALESCE(SUM(amount),0) v FROM payments")["v"],
        shops=[dict(s) for s in q("SELECT id,name,city,device_types,active FROM shops")])

@app.get("/")
def index(): return app.send_static_file("index.html")

# ------------------------------------------------------------------- init
def init():
    c = sqlite3.connect(DB); c.executescript(SCHEMA)
    if not c.execute("SELECT 1 FROM users").fetchone():
        def user(n, e, p, r):
            return c.execute("INSERT INTO users(name,email,pw_hash,role,created_at) VALUES(?,?,?,?,?)",
                             (n, e, generate_password_hash(p), r, now())).lastrowid
        user("Admin", "admin@demo.com", "admin123", "admin")
        user("Demo Customer", "customer@demo.com", "demo123", "customer")
        for i, (n, city, lat, lng, t) in enumerate([
            ("FixIt Mobile Care", "Zone A", 12.97, 77.59, "mobile,laptop"),
            ("HomeFix Appliances", "Zone B", 13.03, 77.64, "appliance"),
            ("TechDoctor All-in-One", "Zone C", 12.91, 77.62, "mobile,laptop,appliance")], 1):
            c.execute("INSERT INTO shops(owner_id,name,city,lat,lng,device_types) VALUES(?,?,?,?,?,?)",
                      (user(n, f"shop{i}@demo.com", "demo123", "shop"), n, city, lat, lng, t))
        c.commit()
    c.close()

init()
if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", 5000)), debug=False)
