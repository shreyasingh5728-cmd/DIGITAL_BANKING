"""
NovaBank - Digital Banking App
------------------------------
A complete digital banking desktop application built with Tkinter + SQLite.
Run:  python digital_bank.py
Needs: Python 3.8+ (no extra libraries required)

Features
  * Secure registration & login (salted PBKDF2 password hashing)
  * Dashboard with balance card (hide/show), monthly income/expense, quick actions
  * Deposit & Withdraw (daily withdrawal limit)
  * Fund transfer to other accounts (password confirmation)
  * Bill payments & recharges (account or debit card)
  * Transaction history with search, filter and CSV export
  * Spending analytics (charts drawn on Canvas)
  * Virtual debit card with freeze / unfreeze
  * EMI & Fixed Deposit calculators
  * Profile management & change password
"""

import csv
import hashlib
import os
import random
import re
import sqlite3
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

# ----------------------------------------------------------------------------
# THEME
# ----------------------------------------------------------------------------
APP_NAME = "NovaBank"
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "novabank.db")

PRIMARY = "#4F46E5"      # indigo
PRIMARY_DARK = "#3730A3"
SIDEBAR = "#111827"
SIDEBAR_HOVER = "#1F2937"
BG = "#F3F4F6"
CARD = "#FFFFFF"
BORDER = "#E5E7EB"
TEXT = "#111827"
MUTED = "#6B7280"
SUCCESS = "#059669"
DANGER = "#DC2626"
WARNING = "#D97706"
CHART_COLORS = ["#4F46E5", "#06B6D4", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6", "#EC4899"]

FONT = "Segoe UI"
DAILY_WITHDRAW_LIMIT = 50000


def money(x):
    return f"\u20b9{x:,.2f}"


def shade(hex_color, factor=0.85):
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return "#%02x%02x%02x" % (int(r * factor), int(g * factor), int(b * factor))


# ----------------------------------------------------------------------------
# DATABASE LAYER
# ----------------------------------------------------------------------------
class Database:
    def __init__(self, path=DB_FILE):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                salt TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                account_no TEXT UNIQUE NOT NULL,
                balance REAL NOT NULL DEFAULT 0,
                card_no TEXT NOT NULL,
                card_cvv TEXT NOT NULL,
                card_expiry TEXT NOT NULL,
                card_frozen INTEGER NOT NULL DEFAULT 0,
                created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                category TEXT NOT NULL,
                amount REAL NOT NULL,
                balance_after REAL NOT NULL,
                description TEXT,
                date TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """
        )
        self.conn.commit()

    # -- security helpers ---------------------------------------------------
    @staticmethod
    def hash_pw(password, salt_hex):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 100_000).hex()

    def _unique_number(self, column, length, prefix=""):
        while True:
            num = prefix + "".join(random.choice("0123456789") for _ in range(length - len(prefix)))
            if not self.conn.execute(f"SELECT 1 FROM users WHERE {column}=?", (num,)).fetchone():
                return num

    # -- users ----------------------------------------------------------------
    def create_user(self, name, email, phone, password, opening=0.0):
        if self.conn.execute("SELECT 1 FROM users WHERE email=?", (email.lower(),)).fetchone():
            raise ValueError("An account with this email already exists.")
        salt = os.urandom(16).hex()
        now = datetime.now()
        expiry = f"{now.month:02d}/{(now.year + 5) % 100:02d}"
        cur = self.conn.execute(
            """INSERT INTO users(name,email,phone,salt,pw_hash,account_no,balance,card_no,card_cvv,card_expiry,created)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (name, email.lower(), phone, salt, self.hash_pw(password, salt),
             self._unique_number("account_no", 12, "5"), 0.0,
             self._unique_number("card_no", 16, "4"), f"{random.randint(100, 999)}",
             expiry, now.strftime("%Y-%m-%d %H:%M:%S")),
        )
        self.conn.commit()
        uid = cur.lastrowid
        if opening > 0:
            self.apply(uid, opening, "Credit", "Deposit", "Opening deposit")
        return uid

    def login(self, email, password):
        row = self.conn.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()
        if row and self.hash_pw(password, row["salt"]) == row["pw_hash"]:
            return row["id"]
        return None

    def verify_password(self, uid, password):
        row = self.get_user(uid)
        return self.hash_pw(password, row["salt"]) == row["pw_hash"]

    def get_user(self, uid):
        return self.conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    def update_profile(self, uid, name, phone):
        self.conn.execute("UPDATE users SET name=?, phone=? WHERE id=?", (name, phone, uid))
        self.conn.commit()

    def change_password(self, uid, new_password):
        salt = os.urandom(16).hex()
        self.conn.execute("UPDATE users SET salt=?, pw_hash=? WHERE id=?",
                          (salt, self.hash_pw(new_password, salt), uid))
        self.conn.commit()

    def set_card_frozen(self, uid, frozen):
        self.conn.execute("UPDATE users SET card_frozen=? WHERE id=?", (int(frozen), uid))
        self.conn.commit()

    # -- money ---------------------------------------------------------------
    def _log(self, uid, ttype, category, amount, balance_after, desc):
        self.conn.execute(
            "INSERT INTO transactions(user_id,type,category,amount,balance_after,description,date) VALUES(?,?,?,?,?,?,?)",
            (uid, ttype, category, amount, balance_after, desc, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

    def apply(self, uid, amount, ttype, category, desc=""):
        """Credit or debit a single account atomically. Returns new balance."""
        try:
            bal = self.get_user(uid)["balance"]
            new_bal = bal + amount if ttype == "Credit" else bal - amount
            if new_bal < 0:
                raise ValueError("Insufficient balance.")
            self.conn.execute("UPDATE users SET balance=? WHERE id=?", (new_bal, uid))
            self._log(uid, ttype, category, amount, new_bal, desc)
            self.conn.commit()
            return new_bal
        except Exception:
            self.conn.rollback()
            raise

    def withdrawn_today(self, uid):
        today = datetime.now().strftime("%Y-%m-%d")
        row = self.conn.execute(
            "SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE user_id=? AND category='Withdrawal' AND date LIKE ?",
            (uid, today + "%")).fetchone()
        return row["s"]

    def transfer(self, from_id, to_account, amount, remark):
        try:
            sender = self.get_user(from_id)
            receiver = self.conn.execute("SELECT * FROM users WHERE account_no=?", (to_account,)).fetchone()
            if not receiver:
                raise ValueError("Receiver account not found.")
            if receiver["id"] == from_id:
                raise ValueError("You cannot transfer money to your own account.")
            if sender["balance"] < amount:
                raise ValueError("Insufficient balance.")
            s_bal = sender["balance"] - amount
            r_bal = receiver["balance"] + amount
            self.conn.execute("UPDATE users SET balance=? WHERE id=?", (s_bal, from_id))
            self.conn.execute("UPDATE users SET balance=? WHERE id=?", (r_bal, receiver["id"]))
            note = f" - {remark}" if remark else ""
            self._log(from_id, "Debit", "Transfer", amount, s_bal, f"To {receiver['name']} ({to_account}){note}")
            self._log(receiver["id"], "Credit", "Transfer", amount, r_bal, f"From {sender['name']} ({sender['account_no']}){note}")
            self.conn.commit()
            return receiver["name"], s_bal
        except Exception:
            self.conn.rollback()
            raise

    # -- queries -------------------------------------------------------------
    def transactions(self, uid, limit=None):
        q = "SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        return self.conn.execute(q, (uid,)).fetchall()

    def month_totals(self, uid):
        month = datetime.now().strftime("%Y-%m")
        rows = self.conn.execute(
            "SELECT type, COALESCE(SUM(amount),0) s FROM transactions WHERE user_id=? AND date LIKE ? GROUP BY type",
            (uid, month + "%")).fetchall()
        d = {r["type"]: r["s"] for r in rows}
        return d.get("Credit", 0), d.get("Debit", 0)

    def spending_by_category(self, uid):
        return self.conn.execute(
            "SELECT category, SUM(amount) s FROM transactions WHERE user_id=? AND type='Debit' GROUP BY category ORDER BY s DESC",
            (uid,)).fetchall()


# ----------------------------------------------------------------------------
# REUSABLE UI WIDGETS
# ----------------------------------------------------------------------------
def make_button(parent, text, command, bg=PRIMARY, fg="white", font_size=10, padx=20, pady=9, **kw):
    hover = shade(bg, 0.88) if bg != CARD else BG
    b = tk.Button(parent, text=text, command=command, bg=bg, fg=fg, activebackground=hover,
                  activeforeground=fg, relief="flat", bd=0, cursor="hand2",
                  font=(FONT, font_size, "bold"), padx=padx, pady=pady, **kw)
    b.bind("<Enter>", lambda e: b.config(bg=hover))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b


def card_frame(parent, **kw):
    return tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, **kw)


class FormField(tk.Frame):
    """Label + bordered entry that highlights on focus."""

    def __init__(self, parent, label, show=None, bg=CARD, width=30):
        super().__init__(parent, bg=bg)
        tk.Label(self, text=label, bg=bg, fg=MUTED, font=(FONT, 9, "bold"), anchor="w").pack(fill="x")
        self.border = tk.Frame(self, bg=BORDER, padx=1, pady=1)
        self.border.pack(fill="x", pady=(3, 0))
        self.var = tk.StringVar()
        self.entry = tk.Entry(self.border, textvariable=self.var, show=show, relief="flat",
                              font=(FONT, 11), bg="white", fg=TEXT, width=width,
                              insertbackground=TEXT)
        self.entry.pack(fill="x", ipady=7, padx=2)
        self.entry.bind("<FocusIn>", lambda e: self.border.config(bg=PRIMARY))
        self.entry.bind("<FocusOut>", lambda e: self.border.config(bg=BORDER))

    def get(self):
        return self.var.get().strip()

    def set(self, v):
        self.var.set(v)

    def clear(self):
        self.var.set("")


def round_rect(canvas, x1, y1, x2, y2, r=20, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2,
           x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


def ask_password(app, title="Confirm Identity"):
    return simpledialog.askstring(title, "Enter your password to confirm:", show="*", parent=app)


# ----------------------------------------------------------------------------
# LOGIN / REGISTER SCREEN
# ----------------------------------------------------------------------------
class AuthScreen(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=CARD)
        self.app = app

        # Left brand panel
        left = tk.Frame(self, bg=PRIMARY, width=470)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="\u25c6", fg="white", bg=PRIMARY, font=(FONT, 40)).pack(pady=(110, 0))
        tk.Label(left, text=APP_NAME, fg="white", bg=PRIMARY, font=(FONT, 34, "bold")).pack()
        tk.Label(left, text="Banking that moves at your speed.", fg="#C7D2FE", bg=PRIMARY,
                 font=(FONT, 12)).pack(pady=(4, 40))
        for icon, txt in [("\U0001f512", "Bank-grade password security"), ("\u26a1", "Instant fund transfers"),
                          ("\U0001f4b3", "Virtual debit card controls"), ("\U0001f4ca", "Smart spending insights")]:
            row = tk.Frame(left, bg=PRIMARY)
            row.pack(anchor="w", padx=80, pady=6)
            tk.Label(row, text=icon, bg=PRIMARY, fg="white", font=(FONT, 13)).pack(side="left")
            tk.Label(row, text="  " + txt, bg=PRIMARY, fg="white", font=(FONT, 11)).pack(side="left")

        # Right form panel
        self.right = tk.Frame(self, bg=CARD)
        self.right.pack(side="left", fill="both", expand=True)
        self.container = tk.Frame(self.right, bg=CARD)
        self.container.place(relx=0.5, rely=0.5, anchor="center")
        self.show_login()

    def _clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    def show_login(self):
        self._clear()
        c = self.container
        tk.Label(c, text="Welcome back \U0001f44b", bg=CARD, fg=TEXT, font=(FONT, 22, "bold")).pack(anchor="w")
        tk.Label(c, text="Log in to access your account", bg=CARD, fg=MUTED, font=(FONT, 10)).pack(anchor="w", pady=(2, 22))
        self.l_email = FormField(c, "EMAIL", width=38)
        self.l_email.pack(fill="x", pady=6)
        self.l_pw = FormField(c, "PASSWORD", show="\u2022", width=38)
        self.l_pw.pack(fill="x", pady=6)
        self.show_pw = tk.BooleanVar()
        tk.Checkbutton(c, text="Show password", variable=self.show_pw, bg=CARD, fg=MUTED, activebackground=CARD,
                       font=(FONT, 9), command=lambda: self.l_pw.entry.config(show="" if self.show_pw.get() else "\u2022")
                       ).pack(anchor="w")
        make_button(c, "Log In", self.do_login, pady=11).pack(fill="x", pady=(18, 10))
        row = tk.Frame(c, bg=CARD)
        row.pack()
        tk.Label(row, text="New to NovaBank?", bg=CARD, fg=MUTED, font=(FONT, 10)).pack(side="left")
        lnk = tk.Label(row, text=" Create an account", bg=CARD, fg=PRIMARY, font=(FONT, 10, "bold"), cursor="hand2")
        lnk.pack(side="left")
        lnk.bind("<Button-1>", lambda e: self.show_register())
        self.l_pw.entry.bind("<Return>", lambda e: self.do_login())
        self.l_email.entry.focus_set()

    def show_register(self):
        self._clear()
        c = self.container
        tk.Label(c, text="Open your account", bg=CARD, fg=TEXT, font=(FONT, 22, "bold")).pack(anchor="w")
        tk.Label(c, text="It takes less than a minute", bg=CARD, fg=MUTED, font=(FONT, 10)).pack(anchor="w", pady=(2, 14))
        self.r_name = FormField(c, "FULL NAME", width=38)
        self.r_email = FormField(c, "EMAIL", width=38)
        self.r_phone = FormField(c, "PHONE (10 digits)", width=38)
        self.r_pw = FormField(c, "PASSWORD (min 6 chars)", show="\u2022", width=38)
        self.r_pw2 = FormField(c, "CONFIRM PASSWORD", show="\u2022", width=38)
        self.r_open = FormField(c, "OPENING DEPOSIT (optional)", width=38)
        for f in (self.r_name, self.r_email, self.r_phone, self.r_pw, self.r_pw2, self.r_open):
            f.pack(fill="x", pady=3)
        make_button(c, "Create Account", self.do_register, pady=11).pack(fill="x", pady=(14, 8))
        row = tk.Frame(c, bg=CARD)
        row.pack()
        tk.Label(row, text="Already have an account?", bg=CARD, fg=MUTED, font=(FONT, 10)).pack(side="left")
        lnk = tk.Label(row, text=" Log in", bg=CARD, fg=PRIMARY, font=(FONT, 10, "bold"), cursor="hand2")
        lnk.pack(side="left")
        lnk.bind("<Button-1>", lambda e: self.show_login())

    def do_login(self):
        email, pw = self.l_email.get(), self.l_pw.var.get()
        if not email or not pw:
            return messagebox.showwarning("Missing details", "Please enter email and password.")
        uid = self.app.db.login(email, pw)
        if uid is None:
            return messagebox.showerror("Login failed", "Invalid email or password.")
        self.app.start_session(uid)

    def do_register(self):
        name, email, phone = self.r_name.get(), self.r_email.get(), self.r_phone.get()
        pw, pw2, opening = self.r_pw.var.get(), self.r_pw2.var.get(), self.r_open.get()
        if not (name and email and phone and pw):
            return messagebox.showwarning("Missing details", "Please fill in all required fields.")
        if not re.match(r"^[\w.+-]+@[\w-]+\.[\w.-]+$", email):
            return messagebox.showwarning("Invalid email", "Please enter a valid email address.")
        if not re.match(r"^\d{10}$", phone):
            return messagebox.showwarning("Invalid phone", "Phone number must be exactly 10 digits.")
        if len(pw) < 6:
            return messagebox.showwarning("Weak password", "Password must be at least 6 characters.")
        if pw != pw2:
            return messagebox.showwarning("Mismatch", "Passwords do not match.")
        try:
            amt = float(opening) if opening else 0.0
            if amt < 0:
                raise ValueError
        except ValueError:
            return messagebox.showwarning("Invalid amount", "Opening deposit must be a positive number.")
        try:
            uid = self.app.db.create_user(name, email, phone, pw, amt)
        except ValueError as e:
            return messagebox.showerror("Registration failed", str(e))
        messagebox.showinfo("Welcome!", "Your account has been created successfully.")
        self.app.start_session(uid)


# ----------------------------------------------------------------------------
# BASE PAGE
# ----------------------------------------------------------------------------
class Page(tk.Frame):
    def __init__(self, parent, app, title, subtitle=""):
        super().__init__(parent, bg=BG)
        self.app = app
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=32, pady=(26, 14))
        tk.Label(head, text=title, bg=BG, fg=TEXT, font=(FONT, 20, "bold")).pack(anchor="w")
        if subtitle:
            tk.Label(head, text=subtitle, bg=BG, fg=MUTED, font=(FONT, 10)).pack(anchor="w")
        self.body = tk.Frame(self, bg=BG)
        self.body.pack(fill="both", expand=True, padx=32, pady=(0, 24))

    def refresh(self):
        pass

    @property
    def db(self):
        return self.app.db

    @property
    def uid(self):
        return self.app.uid


def style_tree(tree):
    tree.tag_configure("odd", background="#FFFFFF")
    tree.tag_configure("even", background="#F9FAFB")
    tree.tag_configure("credit", foreground=SUCCESS)
    tree.tag_configure("debit", foreground=DANGER)


def fill_tree(tree, rows):
    tree.delete(*tree.get_children())
    for i, t in enumerate(rows):
        sign = "+" if t["type"] == "Credit" else "-"
        tag = "credit" if t["type"] == "Credit" else "debit"
        tree.insert("", "end", values=(
            t["date"], f"TXN{t['id']:06d}", t["category"], t["description"] or "",
            f"{sign} {money(t['amount'])}", money(t["balance_after"])),
            tags=(tag, "even" if i % 2 else "odd"))


def make_txn_tree(parent, height=8):
    cols = ("Date", "Reference", "Category", "Description", "Amount", "Balance")
    tree = ttk.Treeview(parent, columns=cols, show="headings", height=height)
    widths = (150, 90, 100, 300, 120, 120)
    for c, w in zip(cols, widths):
        tree.heading(c, text=c)
        tree.column(c, width=w, anchor="e" if c in ("Amount", "Balance") else "w")
    style_tree(tree)
    return tree


# ----------------------------------------------------------------------------
# DASHBOARD
# ----------------------------------------------------------------------------
class DashboardPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "Dashboard")
        self.hidden = False
        top = tk.Frame(self.body, bg=BG)
        top.pack(fill="x")

        # Balance card (canvas for rounded look)
        self.bal_canvas = tk.Canvas(top, width=470, height=190, bg=BG, highlightthickness=0)
        self.bal_canvas.pack(side="left")

        # Stat cards
        stats = tk.Frame(top, bg=BG)
        stats.pack(side="left", fill="both", expand=True, padx=(20, 0))
        self.income_lbl = self._stat(stats, "Income this month", SUCCESS, "\u2193")
        self.expense_lbl = self._stat(stats, "Spent this month", DANGER, "\u2191")

        # Quick actions
        tk.Label(self.body, text="Quick Actions", bg=BG, fg=TEXT, font=(FONT, 13, "bold")).pack(anchor="w", pady=(20, 8))
        qa = tk.Frame(self.body, bg=BG)
        qa.pack(fill="x")
        for i, (icon, label, page) in enumerate([("\u2795", "Deposit / Withdraw", "Money"), ("\u21c4", "Transfer", "Transfer"),
                                                   ("\U0001f4a1", "Pay Bills", "Bills"), ("\U0001f4b3", "My Card", "Card"),
                                                   ("\U0001f4c8", "Analytics", "Analytics")]):
            b = tk.Button(qa, text=f"{icon}\n{label}", command=lambda p=page: app.show_page(p), bg=CARD, fg=TEXT,
                          relief="flat", bd=0, cursor="hand2", font=(FONT, 10, "bold"), width=15, height=3,
                          highlightbackground=BORDER, highlightthickness=1, activebackground="#EEF2FF")
            b.grid(row=0, column=i, padx=(0, 12))
            b.bind("<Enter>", lambda e, w=b: w.config(bg="#EEF2FF"))
            b.bind("<Leave>", lambda e, w=b: w.config(bg=CARD))

        # Recent transactions
        row = tk.Frame(self.body, bg=BG)
        row.pack(fill="x", pady=(20, 8))
        tk.Label(row, text="Recent Transactions", bg=BG, fg=TEXT, font=(FONT, 13, "bold")).pack(side="left")
        lnk = tk.Label(row, text="View all \u2192", bg=BG, fg=PRIMARY, font=(FONT, 10, "bold"), cursor="hand2")
        lnk.pack(side="right")
        lnk.bind("<Button-1>", lambda e: app.show_page("History"))
        wrap = card_frame(self.body)
        wrap.pack(fill="both", expand=True)
        self.tree = make_txn_tree(wrap, 6)
        self.tree.pack(fill="both", expand=True)

    def _stat(self, parent, title, color, icon):
        f = card_frame(parent)
        f.pack(fill="both", expand=True, pady=(0, 10))
        tk.Label(f, text=icon, bg=CARD, fg=color, font=(FONT, 20, "bold")).pack(side="left", padx=18)
        inner = tk.Frame(f, bg=CARD)
        inner.pack(side="left", pady=12)
        tk.Label(inner, text=title, bg=CARD, fg=MUTED, font=(FONT, 9)).pack(anchor="w")
        lbl = tk.Label(inner, text="\u20b90.00", bg=CARD, fg=TEXT, font=(FONT, 17, "bold"))
        lbl.pack(anchor="w")
        return lbl

    def toggle(self, _=None):
        self.hidden = not self.hidden
        self.draw_balance()

    def draw_balance(self):
        u = self.db.get_user(self.uid)
        c = self.bal_canvas
        c.delete("all")
        round_rect(c, 2, 2, 468, 188, 22, fill=PRIMARY, outline="")
        c.create_oval(330, -60, 520, 130, fill="#6366F1", outline="")
        c.create_oval(380, 90, 540, 250, fill="#4338CA", outline="")
        c.create_text(28, 30, text="Total Balance", anchor="w", fill="#C7D2FE", font=(FONT, 11))
        bal = "\u20b9 \u2022\u2022\u2022\u2022\u2022\u2022" if self.hidden else money(u["balance"])
        c.create_text(28, 72, text=bal, anchor="w", fill="white", font=(FONT, 28, "bold"))
        eye = c.create_text(440, 30, text="\U0001f441", fill="white", font=(FONT, 14), anchor="e")
        c.tag_bind(eye, "<Button-1>", self.toggle)
        c.create_text(28, 130, text="ACCOUNT NUMBER", anchor="w", fill="#A5B4FC", font=(FONT, 8, "bold"))
        acc = u["account_no"]
        c.create_text(28, 150, text=f"{acc[:4]} {acc[4:8]} {acc[8:]}", anchor="w", fill="white", font=(FONT, 13, "bold"))
        c.create_text(440, 160, text=u["name"].upper(), anchor="e", fill="white", font=(FONT, 10, "bold"))

    def refresh(self):
        u = self.db.get_user(self.uid)
        self.draw_balance()
        inc, exp = self.db.month_totals(self.uid)
        self.income_lbl.config(text=money(inc))
        self.expense_lbl.config(text=money(exp))
        fill_tree(self.tree, self.db.transactions(self.uid, 6))


# ----------------------------------------------------------------------------
# DEPOSIT / WITHDRAW
# ----------------------------------------------------------------------------
class MoneyPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "Deposit & Withdraw", "Add money to or take money out of your account")
        card = card_frame(self.body)
        card.pack(anchor="nw", ipadx=24, ipady=18)
        inner = tk.Frame(card, bg=CARD)
        inner.pack(padx=28, pady=20)

        self.mode = tk.StringVar(value="Deposit")
        seg = tk.Frame(inner, bg=BG)
        seg.pack(fill="x", pady=(0, 18))
        self.seg_btns = {}
        for m in ("Deposit", "Withdraw"):
            b = tk.Label(seg, text=m, font=(FONT, 11, "bold"), padx=40, pady=9, cursor="hand2")
            b.pack(side="left", expand=True, fill="x")
            b.bind("<Button-1>", lambda e, mm=m: self.set_mode(mm))
            self.seg_btns[m] = b
        self.bal_lbl = tk.Label(inner, bg=CARD, fg=MUTED, font=(FONT, 10))
        self.bal_lbl.pack(anchor="w", pady=(0, 10))
        self.amount = FormField(inner, "AMOUNT (\u20b9)", width=40)
        self.amount.pack(fill="x", pady=6)
        self.note = FormField(inner, "NOTE (optional)", width=40)
        self.note.pack(fill="x", pady=6)

        chips = tk.Frame(inner, bg=CARD)
        chips.pack(anchor="w", pady=6)
        for v in (500, 1000, 5000, 10000):
            make_button(chips, f"+{v:,}", lambda x=v: self.amount.set(str(x)), bg="#EEF2FF", fg=PRIMARY,
                        padx=12, pady=5, font_size=9).pack(side="left", padx=(0, 8))
        self.limit_lbl = tk.Label(inner, bg=CARD, fg=WARNING, font=(FONT, 9))
        self.limit_lbl.pack(anchor="w", pady=(8, 0))
        self.submit = make_button(inner, "Deposit Now", self.submit_txn, pady=11)
        self.submit.pack(fill="x", pady=(16, 0))
        self.set_mode("Deposit")

    def set_mode(self, mode):
        self.mode.set(mode)
        for m, b in self.seg_btns.items():
            b.config(bg=PRIMARY if m == mode else BG, fg="white" if m == mode else MUTED)
        self.submit.config(text=f"{mode} Now", bg=SUCCESS if mode == "Deposit" else DANGER)
        color = SUCCESS if mode == "Deposit" else DANGER
        self.submit.bind("<Enter>", lambda e: self.submit.config(bg=shade(color, 0.88)))
        self.submit.bind("<Leave>", lambda e: self.submit.config(bg=color))
        self.limit_lbl.config(text=f"Daily withdrawal limit: {money(DAILY_WITHDRAW_LIMIT)}" if mode == "Withdraw" else "")

    def refresh(self):
        self.bal_lbl.config(text=f"Available balance: {money(self.db.get_user(self.uid)['balance'])}")

    def submit_txn(self):
        try:
            amt = float(self.amount.get())
            if amt <= 0:
                raise ValueError
        except ValueError:
            return messagebox.showwarning("Invalid amount", "Enter a valid amount greater than zero.")
        mode, note = self.mode.get(), self.note.get()
        try:
            if mode == "Deposit":
                if amt > 1_000_000:
                    return messagebox.showwarning("Limit exceeded", "Maximum single deposit is \u20b910,00,000.")
                self.db.apply(self.uid, amt, "Credit", "Deposit", note or "Cash deposit")
            else:
                if self.db.withdrawn_today(self.uid) + amt > DAILY_WITHDRAW_LIMIT:
                    return messagebox.showwarning("Daily limit", f"This exceeds your daily limit of {money(DAILY_WITHDRAW_LIMIT)}.")
                self.db.apply(self.uid, amt, "Debit", "Withdrawal", note or "Cash withdrawal")
        except ValueError as e:
            return messagebox.showerror("Transaction failed", str(e))
        messagebox.showinfo("Success", f"{mode} of {money(amt)} completed successfully.")
        self.amount.clear()
        self.note.clear()
        self.refresh()


# ----------------------------------------------------------------------------
# TRANSFER
# ----------------------------------------------------------------------------
class TransferPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "Transfer Money", "Send money instantly to any NovaBank account")
        card = card_frame(self.body)
        card.pack(anchor="nw")
        inner = tk.Frame(card, bg=CARD)
        inner.pack(padx=32, pady=26)
        self.bal_lbl = tk.Label(inner, bg=CARD, fg=MUTED, font=(FONT, 10))
        self.bal_lbl.pack(anchor="w", pady=(0, 10))
        self.acc = FormField(inner, "RECEIVER ACCOUNT NUMBER (12 digits)", width=42)
        self.acc.pack(fill="x", pady=6)
        self.amount = FormField(inner, "AMOUNT (\u20b9)", width=42)
        self.amount.pack(fill="x", pady=6)
        self.remark = FormField(inner, "REMARK (optional)", width=42)
        self.remark.pack(fill="x", pady=6)
        tk.Label(inner, text="\U0001f512 You will be asked to confirm with your password.", bg=CARD, fg=MUTED,
                 font=(FONT, 9)).pack(anchor="w", pady=(8, 0))
        make_button(inner, "Send Money", self.send, pady=11).pack(fill="x", pady=(16, 0))

    def refresh(self):
        self.bal_lbl.config(text=f"Available balance: {money(self.db.get_user(self.uid)['balance'])}")

    def send(self):
        acc = self.acc.get().replace(" ", "")
        if not re.match(r"^\d{12}$", acc):
            return messagebox.showwarning("Invalid account", "Account number must be 12 digits.")
        try:
            amt = float(self.amount.get())
            if amt <= 0:
                raise ValueError
        except ValueError:
            return messagebox.showwarning("Invalid amount", "Enter a valid amount greater than zero.")
        if not messagebox.askyesno("Confirm transfer", f"Send {money(amt)} to account {acc}?"):
            return
        pw = ask_password(self.app)
        if pw is None:
            return
        if not self.db.verify_password(self.uid, pw):
            return messagebox.showerror("Authentication failed", "Incorrect password.")
        try:
            name, new_bal = self.db.transfer(self.uid, acc, amt, self.remark.get())
        except ValueError as e:
            return messagebox.showerror("Transfer failed", str(e))
        messagebox.showinfo("Transfer successful", f"{money(amt)} sent to {name}.\nNew balance: {money(new_bal)}")
        for f in (self.acc, self.amount, self.remark):
            f.clear()
        self.refresh()


# ----------------------------------------------------------------------------
# BILLS & RECHARGE
# ----------------------------------------------------------------------------
class BillsPage(Page):
    SERVICES = {
        "Electricity": "\u26a1", "Water": "\U0001f4a7", "Mobile Recharge": "\U0001f4f1",
        "Internet / Broadband": "\U0001f310", "DTH / Cable TV": "\U0001f4fa", "Gas": "\U0001f525",
    }

    def __init__(self, parent, app):
        super().__init__(parent, app, "Bill Payments", "Pay utilities and recharge in a few clicks")
        self.selected = tk.StringVar(value="Electricity")
        grid = tk.Frame(self.body, bg=BG)
        grid.pack(anchor="w")
        self.tiles = {}
        for i, (name, icon) in enumerate(self.SERVICES.items()):
            t = tk.Label(grid, text=f"{icon}\n{name}", width=16, height=4, bg=CARD, fg=TEXT, cursor="hand2",
                         font=(FONT, 10, "bold"), highlightthickness=2, highlightbackground=BORDER)
            t.grid(row=i // 3, column=i % 3, padx=(0, 12), pady=(0, 12))
            t.bind("<Button-1>", lambda e, n=name: self.select(n))
            self.tiles[name] = t

        card = card_frame(self.body)
        card.pack(anchor="w", fill="x", pady=(6, 0))
        inner = tk.Frame(card, bg=CARD)
        inner.pack(padx=28, pady=20, anchor="w")
        self.title_lbl = tk.Label(inner, bg=CARD, fg=TEXT, font=(FONT, 13, "bold"))
        self.title_lbl.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        self.consumer = FormField(inner, "CONSUMER / MOBILE NUMBER", width=30)
        self.consumer.grid(row=1, column=0, padx=(0, 20), pady=6)
        self.amount = FormField(inner, "AMOUNT (\u20b9)", width=30)
        self.amount.grid(row=1, column=1, pady=6)
        pay = tk.Frame(inner, bg=CARD)
        pay.grid(row=2, column=0, columnspan=2, sticky="w", pady=8)
        tk.Label(pay, text="Pay using:", bg=CARD, fg=MUTED, font=(FONT, 10)).pack(side="left")
        self.method = tk.StringVar(value="Account")
        for m in ("Account", "Debit Card"):
            tk.Radiobutton(pay, text=m, variable=self.method, value=m, bg=CARD, activebackground=CARD,
                           font=(FONT, 10), fg=TEXT).pack(side="left", padx=10)
        make_button(inner, "Pay Bill", self.pay, pady=10).grid(row=3, column=0, columnspan=2, sticky="we", pady=(8, 0))
        self.select("Electricity")

    def select(self, name):
        self.selected.set(name)
        for n, t in self.tiles.items():
            t.config(highlightbackground=PRIMARY if n == name else BORDER, bg="#EEF2FF" if n == name else CARD)
        self.title_lbl.config(text=f"Pay {name}")

    def pay(self):
        cons = self.consumer.get()
        if len(cons) < 5:
            return messagebox.showwarning("Invalid details", "Please enter a valid consumer / mobile number.")
        try:
            amt = float(self.amount.get())
            if amt <= 0:
                raise ValueError
        except ValueError:
            return messagebox.showwarning("Invalid amount", "Enter a valid amount greater than zero.")
        if self.method.get() == "Debit Card" and self.db.get_user(self.uid)["card_frozen"]:
            return messagebox.showerror("Card frozen", "Your debit card is frozen. Unfreeze it from the Card page.")
        try:
            self.db.apply(self.uid, amt, "Debit", "Bills", f"{self.selected.get()} - {cons} ({self.method.get()})")
        except ValueError as e:
            return messagebox.showerror("Payment failed", str(e))
        messagebox.showinfo("Payment successful", f"{self.selected.get()} bill of {money(amt)} paid successfully.")
        self.consumer.clear()
        self.amount.clear()


# ----------------------------------------------------------------------------
# HISTORY
# ----------------------------------------------------------------------------
class HistoryPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "Transaction History", "Search, filter and export your statement")
        bar = tk.Frame(self.body, bg=BG)
        bar.pack(fill="x", pady=(0, 10))
        self.search = tk.StringVar()
        self.ftype = tk.StringVar(value="All")
        e = tk.Entry(bar, textvariable=self.search, font=(FONT, 11), relief="flat", highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=PRIMARY, width=32)
        e.pack(side="left", ipady=7, padx=(0, 10))
        tk.Label(bar, text="\U0001f50d search", bg=BG, fg=MUTED, font=(FONT, 9)).pack(side="left", padx=(0, 20))
        cb = ttk.Combobox(bar, textvariable=self.ftype, values=("All", "Credit", "Debit"), state="readonly", width=10)
        cb.pack(side="left")
        make_button(bar, "\u2b07 Export CSV", self.export, bg=SUCCESS, pady=7).pack(side="right")
        self.search.trace_add("write", lambda *a: self.refresh())
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh())

        wrap = card_frame(self.body)
        wrap.pack(fill="both", expand=True)
        self.tree = make_txn_tree(wrap, 16)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.count_lbl = tk.Label(self.body, bg=BG, fg=MUTED, font=(FONT, 9))
        self.count_lbl.pack(anchor="w", pady=(6, 0))
        self.rows = []

    def refresh(self):
        q = self.search.get().lower()
        t = self.ftype.get()
        self.rows = [r for r in self.db.transactions(self.uid)
                     if (t == "All" or r["type"] == t)
                     and (not q or q in (r["description"] or "").lower() or q in r["category"].lower()
                          or q in r["date"] or q in f"txn{r['id']:06d}".lower())]
        fill_tree(self.tree, self.rows)
        self.count_lbl.config(text=f"{len(self.rows)} transaction(s)")

    def export(self):
        if not self.rows:
            return messagebox.showinfo("Nothing to export", "There are no transactions to export.")
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV file", "*.csv")],
                                            initialfile="statement.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Date", "Reference", "Type", "Category", "Description", "Amount", "Balance"])
            for r in self.rows:
                w.writerow([r["date"], f"TXN{r['id']:06d}", r["type"], r["category"], r["description"],
                            r["amount"], r["balance_after"]])
        messagebox.showinfo("Exported", f"Statement saved to:\n{path}")


# ----------------------------------------------------------------------------
# ANALYTICS
# ----------------------------------------------------------------------------
class AnalyticsPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "Spending Analytics", "Understand where your money goes")
        row = tk.Frame(self.body, bg=BG)
        row.pack(fill="both", expand=True)
        left = card_frame(row)
        left.pack(side="left", fill="both", expand=True, padx=(0, 14))
        tk.Label(left, text="Spending by category", bg=CARD, fg=TEXT, font=(FONT, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 0))
        self.bars = tk.Canvas(left, bg=CARD, highlightthickness=0, height=340)
        self.bars.pack(fill="both", expand=True, padx=10, pady=10)
        right = card_frame(row)
        right.pack(side="left", fill="both", expand=True)
        tk.Label(right, text="Income vs expenses (all time)", bg=CARD, fg=TEXT, font=(FONT, 12, "bold")).pack(anchor="w", padx=20, pady=(16, 0))
        self.pie = tk.Canvas(right, bg=CARD, highlightthickness=0, height=340)
        self.pie.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh(self):
        self.update_idletasks()
        # --- bar chart
        c = self.bars
        c.delete("all")
        data = self.db.spending_by_category(self.uid)
        if not data:
            c.create_text(220, 150, text="No spending yet.\nMake a payment to see insights.", fill=MUTED,
                          font=(FONT, 11), justify="center")
        else:
            mx = max(r["s"] for r in data)
            for i, r in enumerate(data[:7]):
                y = 20 + i * 44
                c.create_text(10, y + 12, text=r["category"], anchor="w", fill=TEXT, font=(FONT, 10, "bold"))
                w = max(6, 230 * r["s"] / mx)
                round_rect(c, 110, y, 110 + w, y + 24, 8, fill=CHART_COLORS[i % len(CHART_COLORS)], outline="")
                c.create_text(118 + w, y + 12, text=money(r["s"]), anchor="w", fill=MUTED, font=(FONT, 9))
        # --- donut chart
        p = self.pie
        p.delete("all")
        inc = exp = 0.0
        for t in self.db.transactions(self.uid):
            if t["type"] == "Credit":
                inc += t["amount"]
            else:
                exp += t["amount"]
        total = inc + exp
        if total == 0:
            p.create_text(200, 150, text="No transactions yet.", fill=MUTED, font=(FONT, 11))
            return
        box = (90, 30, 310, 250)
        p.create_arc(*box, start=90, extent=-360 * inc / total, fill=SUCCESS, outline="white", width=2)
        p.create_arc(*box, start=90 - 360 * inc / total, extent=-360 * exp / total, fill=DANGER, outline="white", width=2)
        p.create_oval(135, 75, 265, 205, fill=CARD, outline=CARD)
        p.create_text(200, 140, text=f"{100 * exp / total:.0f}%\nspent", fill=TEXT, font=(FONT, 13, "bold"), justify="center")
        p.create_rectangle(70, 285, 84, 299, fill=SUCCESS, outline="")
        p.create_text(90, 292, text=f"Income {money(inc)}", anchor="w", fill=TEXT, font=(FONT, 9))
        p.create_rectangle(70, 308, 84, 322, fill=DANGER, outline="")
        p.create_text(90, 315, text=f"Expenses {money(exp)}", anchor="w", fill=TEXT, font=(FONT, 9))


# ----------------------------------------------------------------------------
# VIRTUAL CARD
# ----------------------------------------------------------------------------
class CardPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "My Debit Card", "Manage your virtual card")
        self.show_details = False
        self.canvas = tk.Canvas(self.body, width=440, height=270, bg=BG, highlightthickness=0)
        self.canvas.pack(anchor="w")
        btns = tk.Frame(self.body, bg=BG)
        btns.pack(anchor="w", pady=16)
        self.eye_btn = make_button(btns, "\U0001f441 Show Details", self.toggle_details, bg=CARD, fg=TEXT)
        self.eye_btn.pack(side="left", padx=(0, 12))
        self.freeze_btn = make_button(btns, "\u2744 Freeze Card", self.toggle_freeze, bg=WARNING)
        self.freeze_btn.pack(side="left")
        tk.Label(self.body, text="Frozen cards cannot be used for bill payments until unfrozen.", bg=BG, fg=MUTED,
                 font=(FONT, 9)).pack(anchor="w")

    def toggle_details(self):
        if not self.show_details:
            pw = ask_password(self.app)
            if pw is None:
                return
            if not self.db.verify_password(self.uid, pw):
                return messagebox.showerror("Authentication failed", "Incorrect password.")
        self.show_details = not self.show_details
        self.refresh()

    def toggle_freeze(self):
        u = self.db.get_user(self.uid)
        new = not u["card_frozen"]
        self.db.set_card_frozen(self.uid, new)
        messagebox.showinfo("Card updated", "Your card has been frozen." if new else "Your card is active again.")
        self.refresh()

    def refresh(self):
        u = self.db.get_user(self.uid)
        frozen = bool(u["card_frozen"])
        c = self.canvas
        c.delete("all")
        base = "#6B7280" if frozen else PRIMARY
        round_rect(c, 4, 4, 436, 266, 26, fill=base, outline="")
        c.create_oval(280, -80, 500, 140, fill="#818CF8" if not frozen else "#9CA3AF", outline="")
        c.create_oval(330, 120, 520, 310, fill=PRIMARY_DARK if not frozen else "#4B5563", outline="")
        c.create_text(32, 40, text=APP_NAME, anchor="w", fill="white", font=(FONT, 16, "bold"))
        c.create_text(410, 40, text="DEBIT", anchor="e", fill="white", font=(FONT, 11, "bold"))
        round_rect(c, 32, 80, 84, 116, 6, fill="#FBBF24", outline="")
        n = u["card_no"]
        num = " ".join(n[i:i + 4] for i in range(0, 16, 4)) if self.show_details else f"\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 {n[-4:]}"
        c.create_text(32, 152, text=num, anchor="w", fill="white", font=("Consolas", 19, "bold"))
        c.create_text(32, 200, text="CARD HOLDER", anchor="w", fill="#C7D2FE", font=(FONT, 7, "bold"))
        c.create_text(32, 220, text=u["name"].upper(), anchor="w", fill="white", font=(FONT, 11, "bold"))
        c.create_text(280, 200, text="EXPIRES", anchor="w", fill="#C7D2FE", font=(FONT, 7, "bold"))
        c.create_text(280, 220, text=u["card_expiry"], anchor="w", fill="white", font=(FONT, 11, "bold"))
        c.create_text(370, 200, text="CVV", anchor="w", fill="#C7D2FE", font=(FONT, 7, "bold"))
        c.create_text(370, 220, text=u["card_cvv"] if self.show_details else "\u2022\u2022\u2022", anchor="w", fill="white", font=(FONT, 11, "bold"))
        if frozen:
            c.create_text(220, 135, text="\u2744 FROZEN", fill="white", font=(FONT, 28, "bold"))
        self.eye_btn.config(text="\U0001f441 Hide Details" if self.show_details else "\U0001f441 Show Details")
        self.freeze_btn.config(text="\U0001f525 Unfreeze Card" if frozen else "\u2744 Freeze Card",
                               bg=SUCCESS if frozen else WARNING)


# ----------------------------------------------------------------------------
# CALCULATORS (EMI + FD)
# ----------------------------------------------------------------------------
class ToolsPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "Loan & Deposit Calculators", "Plan your finances with EMI and Fixed Deposit tools")
        nb = ttk.Notebook(self.body)
        nb.pack(fill="both", expand=True)
        # EMI
        emi = tk.Frame(nb, bg=CARD)
        nb.add(emi, text="  EMI Calculator  ")
        f = tk.Frame(emi, bg=CARD)
        f.pack(anchor="w", padx=30, pady=24)
        self.e_p = FormField(f, "LOAN AMOUNT (\u20b9)", width=28)
        self.e_r = FormField(f, "INTEREST RATE (% per year)", width=28)
        self.e_n = FormField(f, "TENURE (months)", width=28)
        for w in (self.e_p, self.e_r, self.e_n):
            w.pack(pady=6, anchor="w")
        make_button(f, "Calculate EMI", self.calc_emi, pady=10).pack(fill="x", pady=(12, 0))
        self.emi_out = tk.Label(emi, bg="#EEF2FF", fg=TEXT, font=(FONT, 12), justify="left", padx=24, pady=18)
        self.emi_out.pack(anchor="w", padx=30)
        # FD
        fd = tk.Frame(nb, bg=CARD)
        nb.add(fd, text="  Fixed Deposit  ")
        g = tk.Frame(fd, bg=CARD)
        g.pack(anchor="w", padx=30, pady=24)
        self.f_p = FormField(g, "DEPOSIT AMOUNT (\u20b9)", width=28)
        self.f_r = FormField(g, "INTEREST RATE (% per year)", width=28)
        self.f_t = FormField(g, "TENURE (years)", width=28)
        for w in (self.f_p, self.f_r, self.f_t):
            w.pack(pady=6, anchor="w")
        make_button(g, "Calculate Maturity", self.calc_fd, bg=SUCCESS, pady=10).pack(fill="x", pady=(12, 0))
        self.fd_out = tk.Label(fd, bg="#ECFDF5", fg=TEXT, font=(FONT, 12), justify="left", padx=24, pady=18)
        self.fd_out.pack(anchor="w", padx=30)

    def calc_emi(self):
        try:
            p, r, n = float(self.e_p.get()), float(self.e_r.get()), int(self.e_n.get())
            if p <= 0 or r < 0 or n <= 0:
                raise ValueError
        except ValueError:
            return messagebox.showwarning("Invalid input", "Please enter valid positive numbers.")
        m = r / 12 / 100
        emi = p / n if m == 0 else p * m * (1 + m) ** n / ((1 + m) ** n - 1)
        total = emi * n
        self.emi_out.config(text=f"Monthly EMI:      {money(emi)}\nTotal interest:   {money(total - p)}\nTotal payable:    {money(total)}")

    def calc_fd(self):
        try:
            p, r, t = float(self.f_p.get()), float(self.f_r.get()), float(self.f_t.get())
            if p <= 0 or r < 0 or t <= 0:
                raise ValueError
        except ValueError:
            return messagebox.showwarning("Invalid input", "Please enter valid positive numbers.")
        maturity = p * (1 + r / 400) ** (4 * t)
        self.fd_out.config(text=f"Invested amount:   {money(p)}\nInterest earned:   {money(maturity - p)}\nMaturity value:    {money(maturity)}\n(Compounded quarterly)")


# ----------------------------------------------------------------------------
# PROFILE
# ----------------------------------------------------------------------------
class ProfilePage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app, "My Profile", "Manage your personal details and security")
        row = tk.Frame(self.body, bg=BG)
        row.pack(anchor="nw")
        a = card_frame(row)
        a.pack(side="left", anchor="n", padx=(0, 18))
        ia = tk.Frame(a, bg=CARD)
        ia.pack(padx=28, pady=22)
        tk.Label(ia, text="Personal details", bg=CARD, fg=TEXT, font=(FONT, 13, "bold")).pack(anchor="w", pady=(0, 8))
        self.name = FormField(ia, "FULL NAME", width=30)
        self.name.pack(pady=5)
        self.email = FormField(ia, "EMAIL (cannot be changed)", width=30)
        self.email.pack(pady=5)
        self.email.entry.config(state="disabled", disabledbackground="#F3F4F6", disabledforeground=MUTED)
        self.phone = FormField(ia, "PHONE", width=30)
        self.phone.pack(pady=5)
        self.info = tk.Label(ia, bg=CARD, fg=MUTED, font=(FONT, 9), justify="left")
        self.info.pack(anchor="w", pady=6)
        make_button(ia, "Save Changes", self.save, pady=10).pack(fill="x", pady=(6, 0))

        b = card_frame(row)
        b.pack(side="left", anchor="n")
        ib = tk.Frame(b, bg=CARD)
        ib.pack(padx=28, pady=22)
        tk.Label(ib, text="Change password", bg=CARD, fg=TEXT, font=(FONT, 13, "bold")).pack(anchor="w", pady=(0, 8))
        self.old = FormField(ib, "CURRENT PASSWORD", show="\u2022", width=30)
        self.new = FormField(ib, "NEW PASSWORD", show="\u2022", width=30)
        self.new2 = FormField(ib, "CONFIRM NEW PASSWORD", show="\u2022", width=30)
        for w in (self.old, self.new, self.new2):
            w.pack(pady=5)
        make_button(ib, "Update Password", self.change_pw, bg=DANGER, pady=10).pack(fill="x", pady=(14, 0))

    def refresh(self):
        u = self.db.get_user(self.uid)
        self.name.set(u["name"])
        self.phone.set(u["phone"])
        self.email.entry.config(state="normal")
        self.email.set(u["email"])
        self.email.entry.config(state="disabled")
        self.info.config(text=f"Account No: {u['account_no']}\nMember since: {u['created'][:10]}")

    def save(self):
        name, phone = self.name.get(), self.phone.get()
        if not name:
            return messagebox.showwarning("Missing name", "Name cannot be empty.")
        if not re.match(r"^\d{10}$", phone):
            return messagebox.showwarning("Invalid phone", "Phone number must be exactly 10 digits.")
        self.db.update_profile(self.uid, name, phone)
        self.app.update_sidebar()
        messagebox.showinfo("Saved", "Profile updated successfully.")

    def change_pw(self):
        if not self.db.verify_password(self.uid, self.old.var.get()):
            return messagebox.showerror("Error", "Current password is incorrect.")
        if len(self.new.var.get()) < 6:
            return messagebox.showwarning("Weak password", "New password must be at least 6 characters.")
        if self.new.var.get() != self.new2.var.get():
            return messagebox.showwarning("Mismatch", "New passwords do not match.")
        self.db.change_password(self.uid, self.new.var.get())
        for w in (self.old, self.new, self.new2):
            w.clear()
        messagebox.showinfo("Success", "Password changed successfully.")


# ----------------------------------------------------------------------------
# MAIN SHELL (sidebar + pages)
# ----------------------------------------------------------------------------
class MainShell(tk.Frame):
    NAV = [("Dashboard", "\U0001f3e0", DashboardPage), ("Money", "\U0001f4b5", MoneyPage),
           ("Transfer", "\u21c4", TransferPage), ("Bills", "\U0001f4a1", BillsPage),
           ("History", "\U0001f4c4", HistoryPage), ("Analytics", "\U0001f4c8", AnalyticsPage),
           ("Card", "\U0001f4b3", CardPage), ("Tools", "\U0001f9ee", ToolsPage),
           ("Profile", "\U0001f464", ProfilePage)]
    LABELS = {"Money": "Deposit / Withdraw", "Bills": "Pay Bills", "Tools": "Calculators"}

    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app
        self.sidebar = tk.Frame(self, bg=SIDEBAR, width=240)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        tk.Label(self.sidebar, text="\u25c6 " + APP_NAME, bg=SIDEBAR, fg="white", font=(FONT, 17, "bold")).pack(anchor="w", padx=22, pady=(26, 18))

        self.user_lbl = tk.Label(self.sidebar, bg=SIDEBAR, fg="white", font=(FONT, 11, "bold"), anchor="w")
        self.user_lbl.pack(fill="x", padx=22)
        self.acc_lbl = tk.Label(self.sidebar, bg=SIDEBAR, fg="#9CA3AF", font=(FONT, 9), anchor="w")
        self.acc_lbl.pack(fill="x", padx=22, pady=(0, 16))

        self.nav_btns = {}
        for key, icon, _ in self.NAV:
            b = tk.Label(self.sidebar, text=f"  {icon}   {self.LABELS.get(key, key)}", bg=SIDEBAR, fg="#D1D5DB",
                         font=(FONT, 11), anchor="w", padx=14, pady=10, cursor="hand2")
            b.pack(fill="x", padx=12, pady=1)
            b.bind("<Button-1>", lambda e, k=key: self.show(k))
            b.bind("<Enter>", lambda e, w=b, k=key: w.config(bg=SIDEBAR_HOVER) if self.current != k else None)
            b.bind("<Leave>", lambda e, w=b, k=key: w.config(bg=SIDEBAR) if self.current != k else None)
            self.nav_btns[key] = b
        logout = tk.Label(self.sidebar, text="  \u23fb   Log Out", bg=SIDEBAR, fg="#FCA5A5", font=(FONT, 11, "bold"),
                          anchor="w", padx=14, pady=10, cursor="hand2")
        logout.pack(side="bottom", fill="x", padx=12, pady=18)
        logout.bind("<Button-1>", lambda e: app.logout())

        self.content = tk.Frame(self, bg=BG)
        self.content.pack(side="left", fill="both", expand=True)
        self.pages = {}
        for key, _, cls in self.NAV:
            self.pages[key] = cls(self.content, app)
        self.current = None
        self.update_sidebar()

    def update_sidebar(self):
        u = self.app.db.get_user(self.app.uid)
        self.user_lbl.config(text=f"\U0001f464 {u['name']}")
        self.acc_lbl.config(text=f"A/C  \u2022\u2022\u2022\u2022 {u['account_no'][-4:]}")

    def show(self, key):
        if self.current:
            self.pages[self.current].pack_forget()
            self.nav_btns[self.current].config(bg=SIDEBAR, fg="#D1D5DB")
        self.current = key
        self.nav_btns[key].config(bg=PRIMARY, fg="white")
        page = self.pages[key]
        page.pack(fill="both", expand=True)
        page.refresh()


# ----------------------------------------------------------------------------
# APPLICATION
# ----------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} - Digital Banking")
        w, h = 1180, 740
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth() - w) // 2}+{max(0, (self.winfo_screenheight() - h) // 2 - 30)}")
        self.minsize(1100, 700)
        self.configure(bg=BG)
        self.db = Database()
        self.uid = None
        self.screen = None
        self.shell = None
        self._style()
        self.show_auth()

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("Treeview", background="white", fieldbackground="white", foreground=TEXT,
                    rowheight=34, font=(FONT, 10), borderwidth=0)
        s.configure("Treeview.Heading", background="#F9FAFB", foreground=MUTED, font=(FONT, 10, "bold"),
                    relief="flat", padding=8)
        s.map("Treeview", background=[("selected", "#E0E7FF")], foreground=[("selected", TEXT)])
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", font=(FONT, 10, "bold"), padding=(10, 8))
        s.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", PRIMARY)])
        s.configure("TCombobox", padding=6)

    def show_auth(self):
        if self.shell:
            self.shell.destroy()
            self.shell = None
        self.screen = AuthScreen(self, self)
        self.screen.pack(fill="both", expand=True)

    def start_session(self, uid):
        self.uid = uid
        if self.screen:
            self.screen.destroy()
            self.screen = None
        self.shell = MainShell(self, self)
        self.shell.pack(fill="both", expand=True)
        self.shell.show("Dashboard")

    def show_page(self, key):
        self.shell.show(key)

    def update_sidebar(self):
        self.shell.update_sidebar()

    def logout(self):
        if messagebox.askyesno("Log out", "Are you sure you want to log out?"):
            self.uid = None
            self.show_auth()


if __name__ == "__main__":
    App().mainloop()