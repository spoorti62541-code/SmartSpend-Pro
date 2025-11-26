#!/usr/bin/env python3
"""
Expense App - All-in-One (bcrypt + validations)
 - Shared SQLite DB (users + expenses)
 - Tkinter GUI with login/register
 - Flask Web app with login/register
 - Export CSV, Monthly summary, Plot by category (matplotlib optional)

Run:
  python expense_app_all_in_one.py --mode gui
  python expense_app_all_in_one.py --mode web
"""

import argparse
import sqlite3
import hashlib
from datetime import datetime
import csv
import os
import re
import threading

# Optional plotting
try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception:
    tk = None

# Flask imports
try:
    from flask import Flask, render_template_string, request, redirect, url_for, session, flash, send_file
except Exception:
    Flask = None

# bcrypt (strong hashing)
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except Exception:
    bcrypt = None
    BCRYPT_AVAILABLE = False
    # fallback will be sha256 with a warning printed on startup

DB_FILE = "expense_app_all.db"
SECRET_KEY = "change_this_secret_for_demo"  # in production, set via env var

# ---------------------------
# VALIDATION HELPERS
# ---------------------------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')  # allowed chars: letters, digits, underscore, dot, hyphen

def validate_username(username: str):
    if not username:
        return False, "Username required"
    if not USERNAME_RE.match(username):
        return False, "Username must be 3-32 chars; letters, digits, underscore, dot, hyphen allowed"
    return True, ""

def validate_password(password: str):
    if not password:
        return False, "Password required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[a-z]', password):
        return False, "Password must include a lowercase letter"
    if not re.search(r'[A-Z]', password):
        return False, "Password must include an uppercase letter"
    if not re.search(r'\d', password):
        return False, "Password must include a digit"
    # Optional: require special char
    return True, ""

def validate_amount(amount_str: str):
    try:
        amt = float(amount_str)
        if amt <= 0:
            return False, "Amount must be greater than 0"
        return True, amt
    except ValueError:
        return False, "Invalid amount format"

def validate_title(title: str):
    if not title:
        return False, "Title required"
    if len(title) > 200:
        return False, "Title too long (max 200 chars)"
    return True, ""

def validate_category(category: str):
    if category is None:
        category = ""
    if len(category) > 50:
        return False, "Category too long (max 50 chars)"
    return True, ""

def sanitize_filename(fname: str):
    # keep basename only and ensure it ends with .csv
    base = os.path.basename(fname)
    if not base.lower().endswith('.csv'):
        base = base + '.csv'
    # limit length
    return base[:200]

# ---------------------------
# DATABASE / SHARED HELPERS
# ---------------------------
def get_db_connection(dbfile=DB_FILE):
    con = sqlite3.connect(dbfile, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT,
        date TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    con.commit()
    con.close()

# password hashing
def hash_password_bcrypt(password: str) -> str:
    # returns utf-8 string
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
    return hashed.decode('utf-8')

def verify_password_bcrypt(password: str, hashed_str: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_str.encode('utf-8'))
    except Exception:
        return False

# fallback (sha256) - use only if bcrypt not available
def hash_password_sha256(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password_sha256(password: str, hashed_str: str) -> bool:
    return hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed_str

def hash_password(password: str) -> str:
    if BCRYPT_AVAILABLE:
        return hash_password_bcrypt(password)
    else:
        # fallback
        return hash_password_sha256(password)

def verify_password(password: str, hashed_str: str) -> bool:
    if BCRYPT_AVAILABLE:
        return verify_password_bcrypt(password, hashed_str)
    else:
        return verify_password_sha256(password, hashed_str)

def register_user(username: str, password: str):
    # validate first
    ok, msg = validate_username(username)
    if not ok:
        return False, msg
    ok, msg = validate_password(password)
    if not ok:
        return False, msg

    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hash_password(password)))
        con.commit()
        return True, "Registered successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    finally:
        con.close()

def authenticate(username: str, password: str):
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None, "User not found"
    if verify_password(password, row["password_hash"]):
        return row["id"], "OK"
    return None, "Incorrect password"

def add_expense_db(user_id: int, title: str, amount: float, category: str, date: str=None):
    con = get_db_connection()
    cur = con.cursor()
    date = date or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO expenses (user_id, title, amount, category, date) VALUES (?, ?, ?, ?, ?)",
                (user_id, title, amount, category, date))
    con.commit()
    con.close()

def get_expenses_for_user(user_id: int, order_desc=True):
    con = get_db_connection()
    cur = con.cursor()
    q = "SELECT id, title, amount, category, date FROM expenses WHERE user_id = ?"
    if order_desc:
        q += " ORDER BY date DESC"
    cur.execute(q, (user_id,))
    rows = cur.fetchall()
    con.close()
    return rows

def delete_expense_db(user_id: int, expense_id: int):
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("DELETE FROM expenses WHERE id = ? AND user_id = ?", (expense_id, user_id))
    affected = cur.rowcount
    con.commit()
    con.close()
    return affected

def total_spent(user_id: int):
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("SELECT IFNULL(SUM(amount),0) as total FROM expenses WHERE user_id = ?", (user_id,))
    total = cur.fetchone()["total"]
    con.close()
    return total

def monthly_summary(user_id: int):
    con = get_db_connection()
    cur = con.cursor()
    cur.execute("""
        SELECT substr(date,1,7) as ym, IFNULL(SUM(amount),0) as total
        FROM expenses
        WHERE user_id = ?
        GROUP BY ym
        ORDER BY ym DESC
    """, (user_id,))
    rows = cur.fetchall()
    con.close()
    return rows

def export_expenses_csv(user_id: int, filename: str):
    filename = sanitize_filename(filename)
    rows = get_expenses_for_user(user_id)
    with open(filename, "w", newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(["id","title","amount","category","date"])
        for r in rows:
            w.writerow([r["id"], r["title"], r["amount"], r["category"], r["date"]])
    return len(rows), filename

def plot_spending_by_category(user_id: int, show=True, savepath=None):
    rows = get_expenses_for_user(user_id)
    if not rows:
        return False, "No data"
    data = {}
    for r in rows:
        cat = r["category"] or "Uncategorized"
        data[cat] = data.get(cat, 0) + float(r["amount"])
    if not plt:
        return False, "matplotlib not installed"
    cats = list(data.keys())
    totals = list(data.values())
    plt.figure(figsize=(7,5))
    plt.pie(totals, labels=cats, autopct="%1.1f%%", startangle=140)
    plt.title("Spending by Category")
    plt.axis('equal')
    if savepath:
        plt.savefig(savepath, bbox_inches='tight')
    if show:
        plt.show()
    else:
        plt.close()
    return True, "Plotted"

# Initialize DB on import
init_db()

# Show bcrypt fallback warning at startup if needed
if not BCRYPT_AVAILABLE:
    print("WARNING: bcrypt not installed. The app will use SHA-256 as fallback.\n"
          "Install bcrypt for production: pip install bcrypt")

# ---------------------------
# TKINTER GUI
# ---------------------------
def run_gui():
    if tk is None:
        print("Tkinter not available in this environment.")
        return

    class LoginWindow(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Expense Tracker - Login/Register")
            self.geometry("340x240")
            self.resizable(False, False)

            ttk.Label(self, text="Username:").pack(pady=(12,0))
            self.username_var = tk.StringVar()
            ttk.Entry(self, textvariable=self.username_var).pack()

            ttk.Label(self, text="Password:").pack(pady=(10,0))
            self.password_var = tk.StringVar()
            ttk.Entry(self, textvariable=self.password_var, show="*").pack()

            btnf = ttk.Frame(self)
            btnf.pack(pady=14)
            ttk.Button(btnf, text="Login", command=self.do_login).grid(row=0, column=0, padx=6)
            ttk.Button(btnf, text="Register", command=self.do_register).grid(row=0, column=1, padx=6)

        def do_login(self):
            u = self.username_var.get().strip()
            p = self.password_var.get().strip()
            if not u or not p:
                messagebox.showerror("Error", "Enter username & password")
                return
            user_id, msg = authenticate(u, p)
            if user_id:
                self.destroy()
                app = ExpenseApp(user_id, u)
                app.mainloop()
            else:
                messagebox.showerror("Login failed", msg)

        def do_register(self):
            u = self.username_var.get().strip()
            p = self.password_var.get().strip()
            ok, msg = register_user(u, p)
            if ok:
                messagebox.showinfo("Success", msg)
            else:
                messagebox.showerror("Error", msg)

    class ExpenseApp(tk.Tk):
        def __init__(self, user_id, username):
            super().__init__()
            self.user_id = user_id
            self.username = username
            self.title(f"Expense Tracker - {username}")
            self.geometry("900x520")

            # form
            f = ttk.Frame(self)
            f.pack(fill="x", padx=10, pady=8)

            ttk.Label(f, text="Title:").grid(row=0,column=0,sticky="w")
            self.title_var = tk.StringVar()
            ttk.Entry(f, textvariable=self.title_var, width=40).grid(row=0,column=1)

            ttk.Label(f, text="Amount:").grid(row=0,column=2,sticky="w", padx=(10,0))
            self.amount_var = tk.StringVar()
            ttk.Entry(f, textvariable=self.amount_var, width=12).grid(row=0,column=3)

            ttk.Label(f, text="Category:").grid(row=0,column=4,sticky="w", padx=(10,0))
            self.category_var = tk.StringVar()
            ttk.Entry(f, textvariable=self.category_var, width=18).grid(row=0,column=5)

            ttk.Button(f, text="Add", command=self.add_expense).grid(row=0,column=6, padx=8)

            # treeview
            cols = ("id","date","category","title","amount")
            self.tree = ttk.Treeview(self, columns=cols, show="headings")
            for c in cols:
                self.tree.heading(c, text=c.title())
            self.tree.column("id", width=40)
            self.tree.column("date", width=140)
            self.tree.column("category", width=120)
            self.tree.column("title", width=420)
            self.tree.column("amount", width=100, anchor="e")
            self.tree.pack(fill="both", expand=True, padx=10, pady=6)

            # bottom buttons
            btm = ttk.Frame(self)
            btm.pack(fill="x", padx=10, pady=(0,10))
            ttk.Button(btm, text="Delete Selected", command=self.delete_selected).pack(side="left")
            ttk.Button(btm, text="Total", command=self.show_total).pack(side="left", padx=6)
            ttk.Button(btm, text="Export CSV", command=self.export_csv).pack(side="left", padx=6)
            ttk.Button(btm, text="Monthly Summary", command=self.show_monthly).pack(side="left", padx=6)
            ttk.Button(btm, text="Plot by Category", command=self.plot_by_category).pack(side="left", padx=6)
            ttk.Button(btm, text="Logout", command=self.logout).pack(side="right")

            self.load_expenses()

        def load_expenses(self):
            for r in self.tree.get_children():
                self.tree.delete(r)
            rows = get_expenses_for_user(self.user_id)
            for r in rows:
                self.tree.insert("", "end", values=(r["id"], r["date"], r["category"], r["title"], f"₹{r['amount']:.2f}"))

        def add_expense(self):
            title = self.title_var.get().strip()
            amount = self.amount_var.get().strip()
            category = self.category_var.get().strip() or "Uncategorized"

            ok, msg = validate_title(title)
            if not ok:
                messagebox.showerror("Error", msg); return
            ok, result = validate_amount(amount)
            if not ok:
                messagebox.showerror("Error", result); return
            ok, msg = validate_category(category)
            if not ok:
                messagebox.showerror("Error", msg); return

            amt = float(amount)
            add_expense_db(self.user_id, title, amt, category)
            self.title_var.set("")
            self.amount_var.set("")
            self.category_var.set("")
            self.load_expenses()

        def delete_selected(self):
            sel = self.tree.selection()
            if not sel:
                messagebox.showinfo("Info", "Select an expense")
                return
            item = self.tree.item(sel[0])
            eid = item["values"][0]
            if messagebox.askyesno("Confirm", f"Delete expense ID {eid}?"):
                delete_expense_db(self.user_id, eid)
                self.load_expenses()

        def show_total(self):
            t = total_spent(self.user_id)
            messagebox.showinfo("Total Spending", f"Total: ₹{t:.2f}")

        def export_csv(self):
            default = f"expenses_{self.username}.csv"
            path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default,
                                                filetypes=[("CSV Files","*.csv")])
            if not path:
                return
            # sanitize filename
            safe = sanitize_filename(path)
            cnt, saved = export_expenses_csv(self.user_id, safe)
            messagebox.showinfo("Exported", f"Exported {cnt} rows to {saved}")

        def show_monthly(self):
            rows = monthly_summary(self.user_id)
            if not rows:
                messagebox.showinfo("Monthly Summary", "No data")
                return
            s = "\n".join([f"{r['ym']}: ₹{r['total']:.2f}" for r in rows])
            messagebox.showinfo("Monthly Summary", s)

        def plot_by_category(self):
            ok, msg = plot_spending_by_category(self.user_id, show=True)
            if not ok:
                messagebox.showerror("Plot error", msg)

        def logout(self):
            if messagebox.askyesno("Logout", "Logout now?"):
                self.destroy()
                LoginWindow().mainloop()

    # start GUI
    LoginWindow().mainloop()

# ---------------------------
# FLASK WEB APP
# ---------------------------
def run_web():
    if Flask is None:
        print("Flask not available in this environment.")
        return

    app = Flask(__name__)
    app.secret_key = SECRET_KEY  # production: set via env variable for security

    # Inline templates (simple)
    layout = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Expense App</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .nav { margin-bottom: 10px; }
        table, th, td { border: 1px solid #ccc; border-collapse: collapse; padding: 6px; }
        a.button { padding:6px 10px; background:#eee; border:1px solid #ccc; text-decoration:none; margin-right:6px; }
        form input { margin:4px 0; }
      </style>
    </head>
    <body>
      <div class="nav">
      {% if session.get('user_id') %}
        Logged in as <b>{{ session.get('username') }}</b> |
        <a href="{{ url_for('dashboard') }}" class="button">Dashboard</a>
        <a href="{{ url_for('export_csv_route') }}" class="button">Export CSV</a>
        <a href="{{ url_for('plot_route') }}" class="button">Plot</a>
        <a href="{{ url_for('logout') }}" class="button">Logout</a>
      {% else %}
        <a href="{{ url_for('login') }}" class="button">Login</a>
        <a href="{{ url_for('register') }}" class="button">Register</a>
      {% endif %}
      </div>
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <ul>{% for m in messages %}<li>{{ m }}</li>{% endfor %}</ul>
        {% endif %}
      {% endwith %}
      {% block body %}{% endblock %}
    </body>
    </html>
    """

    login_tpl = """
    {% extends "layout" %}
    {% block body %}
      <h2>Login</h2>
      <form method="post">
        <p>Username: <input name="username"></p>
        <p>Password: <input name="password" type="password"></p>
        <p><button type="submit">Login</button></p>
      </form>
    {% endblock %}
    """

    register_tpl = """
    {% extends "layout" %}
    {% block body %}
      <h2>Register</h2>
      <form method="post">
        <p>Username: <input name="username"></p>
        <p>Password: <input name="password" type="password"></p>
        <p><button type="submit">Register</button></p>
      </form>
    {% endblock %}
    """

    dashboard_tpl = """
    {% extends "layout" %}
    {% block body %}
      <h2>Dashboard</h2>
      <h3>Add Expense</h3>
      <form method="post" action="{{ url_for('add') }}">
        <p>Title: <input name="title"></p>
        <p>Amount: <input name="amount" type="number" step="0.01"></p>
        <p>Category: <input name="category"></p>
        <p><button type="submit">Add</button></p>
      </form>

      <h3>Your Expenses</h3>
      <table>
        <tr><th>ID</th><th>Date</th><th>Title</th><th>Category</th><th>Amount</th><th>Action</th></tr>
        {% for e in expenses %}
        <tr>
          <td>{{ e.id }}</td>
          <td>{{ e.date }}</td>
          <td>{{ e.title }}</td>
          <td>{{ e.category }}</td>
          <td>₹{{ "%.2f"|format(e.amount) }}</td>
          <td><a href="{{ url_for('delete', expense_id=e.id) }}">Delete</a></td>
        </tr>
        {% endfor %}
      </table>

      <h3>Total: ₹{{ "%.2f"|format(total) }}</h3>
      <h4>Monthly Summary</h4>
      <ul>
      {% for r in monthly %}
        <li>{{ r.ym }} : ₹{{ "%.2f"|format(r.total) }}</li>
      {% endfor %}
      </ul>
    {% endblock %}
    """

    @app.context_processor
    def inject_layout():
        return dict(layout=layout)

    @app.route("/")
    def home():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET","POST"])
    def login():
        if request.method == "POST":
            u = request.form.get("username","").strip()
            p = request.form.get("password","").strip()
            if not u or not p:
                flash("Enter username & password")
                return redirect(url_for("login"))
            user_id, msg = authenticate(u, p)
            if user_id:
                session["user_id"] = user_id
                session["username"] = u
                flash("Logged in")
                return redirect(url_for("dashboard"))
            flash(msg)
        return render_template_string(login_tpl)

    @app.route("/register", methods=["GET","POST"])
    def register():
        if request.method == "POST":
            u = request.form.get("username","").strip()
            p = request.form.get("password","").strip()
            ok, msg = validate_username(u)
            if not ok:
                flash(msg); return redirect(url_for("register"))
            ok, msg = validate_password(p)
            if not ok:
                flash(msg); return redirect(url_for("register"))
            ok, msg = register_user(u, p)
            flash(msg)
            if ok:
                return redirect(url_for("login"))
        return render_template_string(register_tpl)

    def login_required(f):
        from functools import wraps
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapped

    @app.route("/dashboard")
    @login_required
    def dashboard():
        uid = session["user_id"]
        expenses = get_expenses_for_user(uid)
        total = total_spent(uid)
        monthly = monthly_summary(uid)
        return render_template_string(dashboard_tpl, expenses=expenses, total=total, monthly=monthly)

    @app.route("/add", methods=["POST"])
    @login_required
    def add():
        uid = session["user_id"]
        title = request.form.get("title","").strip()
        amount = request.form.get("amount","").strip()
        category = request.form.get("category","").strip() or "Uncategorized"

        ok, msg = validate_title(title)
        if not ok:
            flash(msg); return redirect(url_for("dashboard"))
        ok, result = validate_amount(amount)
        if not ok:
            flash(result); return redirect(url_for("dashboard"))
        ok, msg = validate_category(category)
        if not ok:
            flash(msg); return redirect(url_for("dashboard"))

        amt = float(amount)
        add_expense_db(uid, title, amt, category)
        flash("Added")
        return redirect(url_for("dashboard"))

    @app.route("/delete/<int:expense_id>")
    @login_required
    def delete(expense_id):
        uid = session["user_id"]
        delete_expense_db(uid, expense_id)
        flash("Deleted")
        return redirect(url_for("dashboard"))

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out")
        return redirect(url_for("login"))

    @app.route("/export")
    @login_required
    def export_csv_route():
        uid = session["user_id"]
        fname = f"expenses_{session.get('username')}.csv"
        # sanitize filename server-side
        safe_name = sanitize_filename(fname)
        cnt, saved_name = export_expenses_csv(uid, safe_name)
        return send_file(saved_name, as_attachment=True, download_name=saved_name)

    @app.route("/plot")
    @login_required
    def plot_route():
        uid = session["user_id"]
        if not plt:
            flash("matplotlib not available on server")
            return redirect(url_for("dashboard"))
        out = f"expenses_plot_{uid}.png"
        ok, msg = plot_spending_by_category(uid, show=False, savepath=out)
        if not ok:
            flash(msg)
            return redirect(url_for("dashboard"))
        return send_file(out, mimetype='image/png', as_attachment=False)

    # run web server
    app.run(debug=True, threaded=True)

# ---------------------------
# ENTRYPOINT
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Expense App - All-in-one (GUI + Web)")
    parser.add_argument("--mode", choices=["gui","web"], default="gui", help="Run mode: gui or web")
    args = parser.parse_args()

    if args.mode == "gui":
        run_gui()
    else:
        # Run web app in main thread
        run_web()

if __name__ == "__main__":
    main()
