import hashlib
import os
import random
import re
import secrets
import sqlite3
import subprocess
import time
from pathlib import Path
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("BETSHIP_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("BETSHIP_SECRET_KEY must be configured.")
DATABASE_PATH = Path(__file__).with_name("betship.db")

BETSHIP_BASE_URL = os.environ.get("BETSHIP_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
BETSHIP_EMAIL = os.environ.get("BETSHIP_EMAIL", "")
VERIFICATION_TOKEN_TTL = 60 * 60
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with get_db_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0,
                email TEXT,
                email_verified INTEGER NOT NULL DEFAULT 0,
                verification_token_hash TEXT,
                verification_expires_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS bets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                creator INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                yesodds REAL NOT NULL,
                noodds REAL NOT NULL,
                state TEXT NOT NULL DEFAULT 'open',
                result TEXT,
                FOREIGN KEY (creator) REFERENCES users (id)
            );

            CREATE TABLE IF NOT EXISTS wagers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                us_id INTEGER NOT NULL,
                bet_id INTEGER NOT NULL,
                selected_result TEXT NOT NULL CHECK (selected_result IN ('yes', 'no')),
                amount_betted REAL NOT NULL CHECK (amount_betted > 0),
                FOREIGN KEY (us_id) REFERENCES users (id),
                FOREIGN KEY (bet_id) REFERENCES bets (id)
            );
            """
        )
        _ensure_column(connection, "bets", "title", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(connection, "bets", "description", "TEXT DEFAULT ''")
        _ensure_column(connection, "users", "email", "TEXT")
        _ensure_column(connection, "users", "email_verified", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(connection, "users", "verification_token_hash", "TEXT")
        _ensure_column(connection, "users", "verification_expires_at", "INTEGER")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique "
            "ON users(email) WHERE email IS NOT NULL"
        )


def _ensure_column(connection, table_name: str, column_name: str, column_definition: str):
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table_name})")}
    if column_name not in columns:
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")


def fetch_one(query: str, parameters: tuple = ()):
    with get_db_connection() as connection:
        return connection.execute(query, parameters).fetchone()


def fetch_all(query: str, parameters: tuple = ()):
    with get_db_connection() as connection:
        return connection.execute(query, parameters).fetchall()


def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))


def session_user_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)

    return wrapped_view


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if not user["email_verified"]:
            flash("Please verify your email address before continuing.")
            return redirect(url_for("setup_email"))
        return view_function(*args, **kwargs)

    return wrapped_view


def ensure_default_balance(user_id: int):
    with get_db_connection() as connection:
        connection.execute("UPDATE users SET balance = 1000 WHERE id = ?", (user_id,))
        connection.commit()


def validate_email(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Please enter a valid email address.")
    return email


def create_verification_token():
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    expires_at = int(time.time()) + VERIFICATION_TOKEN_TTL
    return raw_token, token_hash, expires_at


def send_verification_email(email: str, username: str, raw_token: str):
    if not BETSHIP_EMAIL:
        raise RuntimeError("BETSHIP_EMAIL is not configured.")

    verification_url = f"{BETSHIP_BASE_URL}/verify-email/{raw_token}"

    message = f"""From: {BETSHIP_EMAIL}
To: {email}
Subject: Verify your Betship account
Content-Type: text/plain; charset=UTF-8

Hello {username},

Welcome to Betship.

Please verify your email address by opening this link:

{verification_url}

This link expires in 1 hour.

If you did not create a Betship account, you can ignore this email.

Betship
"""

    try:
        subprocess.run(
            ["msmtp", "-t"],
            input=message,
            text=True,
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError("msmtp is not installed or is not in PATH.") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() if error.stderr else "msmtp returned an error."
        raise RuntimeError(f"Could not send verification email: {detail}") from error


def create_verification_for_user(user_id: int):
    user = fetch_one("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    if user is None:
        raise ValueError("User not found.")
    if not user["email"]:
        raise ValueError("An email address is required.")
    if user["email_verified"]:
        return

    raw_token, token_hash, expires_at = create_verification_token()

    with get_db_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET verification_token_hash = ?,
                verification_expires_at = ?
            WHERE id = ?
            """,
            (token_hash, expires_at, user_id),
        )
        connection.commit()

    send_verification_email(user["email"], user["username"], raw_token)


def register_user(username: str, email: str, password: str):
    username = username.strip()
    email = validate_email(email)

    if not username:
        raise ValueError("Username is required.")
    if not password:
        raise ValueError("Password is required.")

    raw_token, token_hash, expires_at = create_verification_token()

    with get_db_connection() as connection:
        existing_user = connection.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        ).fetchone()
        if existing_user is not None:
            raise ValueError("Username or email is already registered.")

        cursor = connection.execute(
            """
            INSERT INTO users (
                username,
                password,
                balance,
                email,
                email_verified,
                verification_token_hash,
                verification_expires_at
            )
            VALUES (?, ?, 1000, ?, 0, ?, ?)
            """,
            (
                username,
                generate_password_hash(password),
                email,
                token_hash,
                expires_at,
            ),
        )
        connection.commit()
        user_id = cursor.lastrowid

    try:
        send_verification_email(email, username, raw_token)
    except RuntimeError as error:
        raise RuntimeError(
            "Your account was created, but the verification email could not be sent. "
            "Please use the resend option."
        ) from error

    return user_id


def authenticate_user(username: str, password: str):
    user = fetch_one("SELECT * FROM users WHERE username = ?", (username,))
    if user is None:
        return None

    stored_password = user["password"]
    if stored_password.startswith(("pbkdf2:", "scrypt:")):
        if not check_password_hash(stored_password, password):
            return None
    elif stored_password == password:
        with get_db_connection() as connection:
            connection.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(password), user["id"]),
            )
            connection.commit()
    else:
        return None

    return fetch_one("SELECT * FROM users WHERE id = ?", (user["id"],))

def update_user_profile(user_id: int, username: str, password: str | None = None):
    username = username.strip()
    if not username:
        raise ValueError("Username is required")

    with get_db_connection() as connection:
        existing_user = connection.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id)).fetchone()
        if existing_user is not None:
            raise ValueError("Username is already taken")

        if password:
            connection.execute(
                "UPDATE users SET username = ?, password = ? WHERE id = ?",
                (username, generate_password_hash(password), user_id),
            )
        else:
            connection.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
        connection.commit()


def delete_account(user_id: int):
    with get_db_connection() as connection:
        created_bet_ids = [
            row["id"]
            for row in connection.execute(
                "SELECT id FROM bets WHERE creator = ? AND state = 'open'",
                (user_id,),
            ).fetchall()
        ]
        wager_ids = [
            row["id"]
            for row in connection.execute(
                """
                SELECT wagers.id
                FROM wagers
                JOIN bets ON bets.id = wagers.bet_id
                WHERE wagers.us_id = ? AND bets.state = 'open'
                """,
                (user_id,),
            ).fetchall()
        ]

    for bet_id in created_bet_ids:
        delete_bet(bet_id)

    with get_db_connection() as connection:
        for wager_id in wager_ids:
            wager = connection.execute("SELECT * FROM wagers WHERE id = ?", (wager_id,)).fetchone()
            if wager is None:
                continue
            connection.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (wager["amount_betted"], wager["us_id"]))
            connection.execute("DELETE FROM wagers WHERE id = ?", (wager_id,))
        connection.execute(
            """
            UPDATE users
            SET username = ?,
                password = ?,
                balance = 0,
                email = NULL,
                email_verified = 0,
                verification_token_hash = NULL,
                verification_expires_at = NULL
            WHERE id = ?
            """,
            (f"deleted-user-{user_id}", generate_password_hash("deleted"), user_id),
        )
        connection.commit()


def generate_odds(more_feasible_result: str):
    if more_feasible_result not in {"yes", "no"}:
        raise ValueError("more_feasible_result must be 'yes' or 'no'")

    lower_odds = max(1.01, round(random.gauss(1.5, 0.5), 2))
    higher_odds = max(lower_odds + 0.01, round(random.gauss(5.0, 1.75), 2))

    if more_feasible_result == "yes":
        return lower_odds, higher_odds
    return higher_odds, lower_odds


def create_bet(creator_id: int, title: str, description: str, more_feasible_result: str):
    title = title.strip()
    if not title:
        raise ValueError("Bet title is required")

    yesodds, noodds = generate_odds(more_feasible_result)

    with get_db_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO bets (creator, title, description, yesodds, noodds)
            VALUES (?, ?, ?, ?, ?)
            """,
            (creator_id, title, description, yesodds, noodds),
        )
        connection.commit()
        return cursor.lastrowid, yesodds, noodds


def place_wager(user_id: int, bet_id: int, selected_result: str, amount_betted: float):
    if selected_result not in {"yes", "no"}:
        raise ValueError("selected_result must be 'yes' or 'no'")

    with get_db_connection() as connection:
        user = connection.execute("SELECT balance FROM users WHERE id = ?", (user_id,)).fetchone()
        bet = connection.execute(
            "SELECT id, creator, state, yesodds, noodds FROM bets WHERE id = ?",
            (bet_id,),
        ).fetchone()
        if user is None or bet is None:
            raise ValueError("User or bet not found")
        if bet["creator"] == user_id:
            raise ValueError("You cannot wager on your own bet")
        if bet["state"] != "open":
            raise ValueError("Bet is not open")
        if user["balance"] < amount_betted:
            raise ValueError("Insufficient balance")

        connection.execute(
            """
            INSERT INTO wagers (us_id, bet_id, selected_result, amount_betted)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, bet_id, selected_result, amount_betted),
        )
        connection.execute(
            "UPDATE users SET balance = balance - ? WHERE id = ?",
            (amount_betted, user_id),
        )
        connection.commit()


def payout_for_wager(wager_row, bet_row):
    odds = bet_row["yesodds"] if wager_row["selected_result"] == "yes" else bet_row["noodds"]
    return wager_row["amount_betted"] * odds


def close_bet(bet_id: int, result: str):
    if result not in {"yes", "no"}:
        raise ValueError("result must be 'yes' or 'no'")

    with get_db_connection() as connection:
        bet = connection.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()
        if bet is None:
            raise ValueError("Bet not found")
        if bet["state"] != "open":
            raise ValueError("Bet is already closed")

        connection.execute(
            "UPDATE bets SET state = 'closed', result = ? WHERE id = ?",
            (result, bet_id),
        )

        wagers = connection.execute(
            "SELECT * FROM wagers WHERE bet_id = ? AND selected_result = ?",
            (bet_id, result),
        ).fetchall()
        for wager_row in wagers:
            connection.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (payout_for_wager(wager_row, bet), wager_row["us_id"]),
            )

        connection.commit()


def get_user_balance(user_id: int):
    user = fetch_one("SELECT balance FROM users WHERE id = ?", (user_id,))
    if user is None:
        return 0
    return user["balance"]


def delete_wager(wager_id: int):
    with get_db_connection() as connection:
        wager = connection.execute("SELECT * FROM wagers WHERE id = ?", (wager_id,)).fetchone()
        if wager is None:
            raise ValueError("Wager not found")
        refund = wager["amount_betted"] / 2
        connection.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (refund, wager["us_id"]))
        connection.execute("DELETE FROM wagers WHERE id = ?", (wager_id,))
        connection.commit()


def delete_bet(bet_id: int):
    with get_db_connection() as connection:
        bet = connection.execute("SELECT * FROM bets WHERE id = ?", (bet_id,)).fetchone()
        if bet is None:
            raise ValueError("Bet not found")

        wagers = connection.execute("SELECT * FROM wagers WHERE bet_id = ?", (bet_id,)).fetchall()
        for wager_row in wagers:
            connection.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (wager_row["amount_betted"], wager_row["us_id"]),
            )
        connection.execute("DELETE FROM wagers WHERE bet_id = ?", (bet_id,))
        connection.execute("DELETE FROM bets WHERE id = ?", (bet_id,))
        connection.commit()


def get_profile_data(user_id: int):
    created_bets = fetch_all(
        "SELECT * FROM bets WHERE creator = ? ORDER BY id DESC",
        (user_id,),
    )
    wagers = fetch_all(
        """
        SELECT wagers.*, bets.title AS bet_title, bets.state AS bet_state, bets.result AS bet_result
        FROM wagers
        JOIN bets ON bets.id = wagers.bet_id
        WHERE wagers.us_id = ?
        ORDER BY wagers.id DESC
        """,
        (user_id,),
    )
    return created_bets, wagers


def get_bets(exclude_creator_id: int | None = None):
    if exclude_creator_id is None:
        return fetch_all(
            """
            SELECT bets.*, users.username AS creator_name
            FROM bets
            JOIN users ON users.id = bets.creator
            ORDER BY bets.id DESC
            """
        )

    return fetch_all(
        """
        SELECT bets.*, users.username AS creator_name
        FROM bets
        JOIN users ON users.id = bets.creator
        WHERE bets.creator != ?
        ORDER BY bets.id DESC
        """,
        (exclude_creator_id,),
    )


def get_bet_detail(bet_id: int):
    bet = fetch_one(
        """
        SELECT bets.*, users.username AS creator_name
        FROM bets
        JOIN users ON users.id = bets.creator
        WHERE bets.id = ?
        """,
        (bet_id,),
    )
    wagers = fetch_all(
        "SELECT wagers.*, users.username FROM wagers JOIN users ON users.id = wagers.us_id WHERE bet_id = ? ORDER BY wagers.id DESC",
        (bet_id,),
    )
    return bet, wagers


@app.route("/")
def hello():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    bets = get_bets(user["id"])
    created_bets = fetch_all(
        "SELECT * FROM bets WHERE creator = ? ORDER BY id DESC",
        (user["id"],),
    )
    return render_template("home.html", user=user, open_bets=bets, created_bets=created_bets)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user() is not None:
        return redirect(url_for("hello"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            register_user(username, email, password)
        except ValueError as error:
            flash(str(error))
            return render_template("register.html", user=None)
        except RuntimeError as error:
            flash(str(error))
            return redirect(url_for("resend_verification"))

        flash("Account created. Check your email to verify your account.")
        return redirect(url_for("login"))

    return render_template("register.html", user=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return render_template("login.html", user=current_user())

        user = authenticate_user(username, password)
        if user is None:
            flash("Invalid username or password.")
            return render_template("login.html", user=current_user())

        if not user["email"]:
            session["user_id"] = user["id"]
            flash("Please add an email address to your account.")
            return redirect(url_for("setup_email"))

        if not user["email_verified"]:
            flash("Please verify your email address before logging in.")
            return redirect(url_for("resend_verification"))

        session["user_id"] = user["id"]
        return redirect(url_for("hello"))

    return render_template("login.html", user=current_user())


@app.route("/setup-email", methods=["GET", "POST"])
@session_user_required
def setup_email():
    user = current_user()

    if user["email"] and user["email_verified"]:
        return redirect(url_for("hello"))

    if request.method == "POST":
        try:
            email = validate_email(request.form.get("email", ""))
        except ValueError as error:
            flash(str(error))
            return render_template("setup_email.html", user=current_user())

        existing_user = fetch_one(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            (email, user["id"]),
        )
        if existing_user is not None:
            flash("That email address is already registered.")
            return render_template("setup_email.html", user=current_user())

        with get_db_connection() as connection:
            connection.execute(
                """
                UPDATE users
                SET email = ?,
                    email_verified = 0,
                    verification_token_hash = NULL,
                    verification_expires_at = NULL
                WHERE id = ?
                """,
                (email, user["id"]),
            )
            connection.commit()

        try:
            create_verification_for_user(user["id"])
        except RuntimeError as error:
            flash(str(error))
            return render_template("setup_email.html", user=current_user())

        session.pop("user_id", None)
        flash("Verification email sent. Check your inbox before logging in.")
        return redirect(url_for("login"))

    return render_template("setup_email.html", user=user)


@app.route("/verify-email/<token>")
def verify_email(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())

    user = fetch_one(
        """
        SELECT id
        FROM users
        WHERE verification_token_hash = ?
          AND verification_expires_at > ?
          AND email_verified = 0
        """,
        (token_hash, now),
    )

    if user is None:
        flash("This verification link is invalid or has expired.")
        return redirect(url_for("resend_verification"))

    with get_db_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET email_verified = 1,
                verification_token_hash = NULL,
                verification_expires_at = NULL
            WHERE id = ?
            """,
            (user["id"],),
        )
        connection.commit()

    flash("Your email has been verified. You can now log in.")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if EMAIL_RE.fullmatch(email):
            user = fetch_one(
                """
                SELECT id
                FROM users
                WHERE email = ?
                  AND email_verified = 0
                """,
                (email,),
            )

            if user is not None:
                try:
                    create_verification_for_user(user["id"])
                except RuntimeError:
                    pass

        flash(
            "If an unverified account exists for that email address, "
            "a new verification link has been sent."
        )
        return redirect(url_for("login"))

    return render_template("resend_verification.html", user=current_user())


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return redirect(url_for("hello"))


@app.route("/profile")
@login_required
def profile():
    user = current_user()
    created_bets, wagers = get_profile_data(user["id"])
    return render_template(
        "profile.html",
        user=user,
        balance=get_user_balance(user["id"]),
        created_bets=created_bets,
        wagers=wagers,
    )


@app.route("/profile/reset", methods=["POST"])
@login_required
def profile_reset():
    user = current_user()
    user_bet_ids = [
        row["id"]
        for row in fetch_all(
            "SELECT id FROM bets WHERE creator = ? AND state = 'open'",
            (user["id"],),
        )
    ]
    wager_ids = [
        row["id"]
        for row in fetch_all(
            """
            SELECT wagers.id
            FROM wagers
            JOIN bets ON bets.id = wagers.bet_id
            WHERE wagers.us_id = ? AND bets.state = 'open'
            """,
            (user["id"],),
        )
    ]

    for bet_id in user_bet_ids:
        delete_bet(bet_id)

    for wager_id in wager_ids:
        if fetch_one("SELECT 1 FROM wagers WHERE id = ?", (wager_id,)) is not None:
            delete_wager(wager_id)

    ensure_default_balance(user["id"])
    return redirect(url_for("profile"))


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    user = current_user()
    if request.method == "POST":
        username = request.form["username"]
        password = request.form.get("password", "").strip() or None
        try:
            update_user_profile(user["id"], username, password)
        except ValueError as error:
            flash(str(error))
            return render_template("profile_edit.html", user=current_user())
        flash("Profile updated.")
        return redirect(url_for("profile"))

    return render_template("profile_edit.html", user=user)


@app.route("/profile/delete", methods=["POST"])
@login_required
def profile_delete():
    user = current_user()
    delete_account(user["id"])
    session.pop("user_id", None)
    return redirect(url_for("hello"))


@app.route("/users")
@login_required
def users_page():
    users = fetch_all(
        "SELECT username, balance FROM users ORDER BY balance DESC, username ASC"
    )
    return render_template("users.html", user=current_user(), users=users)


@app.route("/create-bet", methods=["GET", "POST"])
@login_required
def create_bet_page():
    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form["description"].strip()
        more_feasible_result = request.form["more_feasible_result"]
        if not title:
            flash("Bet name is required.")
            return render_template("create_bet.html", user=current_user())

        bet_id, yesodds, noodds = create_bet(current_user()["id"], title, description, more_feasible_result)
        flash(f"Bet {bet_id} created.")
        return redirect(url_for("hello"))

    return render_template("create_bet.html", user=current_user())


@app.route("/bets")
@login_required
def bets_list():
    user = current_user()
    return render_template("make_bet.html", user=user, open_bets=get_bets(user["id"]))


@app.route("/bets/<int:bet_id>", methods=["GET", "POST"])
@login_required
def bet_detail(bet_id: int):
    bet, wagers = get_bet_detail(bet_id)
    if bet is None:
        abort(404)

    can_view_wagers = bet["state"] == "closed"

    if request.method == "POST":
        selected_result = request.form["selected_result"]
        amount_betted = float(request.form["amount_betted"])
        try:
            place_wager(current_user()["id"], bet_id, selected_result, amount_betted)
        except ValueError as error:
            flash(str(error))
            return render_template("bet_detail.html", user=current_user(), bet=bet, wagers=wagers)
        return redirect(url_for("profile"))

    expected_yes_win = round(request.args.get("amount", type=float, default=0) * bet["yesodds"], 2)
    expected_no_win = round(request.args.get("amount", type=float, default=0) * bet["noodds"], 2)
    return render_template(
        "bet_detail.html",
        user=current_user(),
        bet=bet,
        wagers=wagers if can_view_wagers else [],
        can_view_wagers=can_view_wagers,
        expected_yes_win=expected_yes_win,
        expected_no_win=expected_no_win,
    )


@app.route("/bets/<int:bet_id>/delete", methods=["POST"])
@login_required
def bet_delete(bet_id: int):
    bet = fetch_one("SELECT creator, state FROM bets WHERE id = ?", (bet_id,))
    if bet is None:
        abort(404)
    if bet["creator"] != current_user()["id"]:
        abort(403)
    if bet["state"] != "open":
        abort(400, description="Closed bets cannot be deleted")
    delete_bet(bet_id)
    return redirect(url_for("profile"))


@app.route("/bets/<int:bet_id>/close", methods=["POST"])
@login_required
def bet_close(bet_id: int):
    bet = fetch_one("SELECT creator FROM bets WHERE id = ?", (bet_id,))
    if bet is None:
        abort(404)
    if bet["creator"] != current_user()["id"]:
        abort(403)
    result = request.form["result"]
    close_bet(bet_id, result)
    return redirect(url_for("profile"))


@app.route("/wagers/<int:wager_id>/delete", methods=["POST"])
@login_required
def wager_delete(wager_id: int):
    wager = fetch_one("SELECT us_id FROM wagers WHERE id = ?", (wager_id,))
    if wager is None:
        abort(404)
    if wager["us_id"] != current_user()["id"]:
        abort(403)
    wager_state = fetch_one(
        "SELECT bets.state AS bet_state FROM wagers JOIN bets ON bets.id = wagers.bet_id WHERE wagers.id = ?",
        (wager_id,),
    )
    if wager_state is not None and wager_state["bet_state"] != "open":
        abort(400, description="Closed wagers cannot be erased")
    delete_wager(wager_id)
    return redirect(url_for("profile"))



@app.route("/api/bets", methods=["POST"])
def bets_create():
    payload = request.get_json(silent=True) or request.form
    creator_id = int(payload["creator_id"])
    more_feasible_result = payload["more_feasible_result"]
    title = payload.get("title", "")
    description = payload.get("description", "")

    try:
        bet_id, yesodds, noodds = create_bet(creator_id, title, description, more_feasible_result)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(
        {
            "bet_id": bet_id,
            "yesodds": yesodds,
            "noodds": noodds,
            "more_feasible_result": more_feasible_result,
        }
    ), 201


@app.route("/api/wagers", methods=["POST"])
def wagers_create():
    payload = request.get_json(silent=True) or request.form
    user_id = int(payload["user_id"])
    bet_id = int(payload["bet_id"])
    selected_result = payload["selected_result"]
    amount_betted = float(payload["amount_betted"])

    place_wager(user_id, bet_id, selected_result, amount_betted)
    return jsonify({"status": "created"}), 201


init_db()


if __name__ == '__main__':
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")