# Streamlit Exam Simulator MVP — single-file app.py
# -------------------------------------------------
# Features for this MVP per requirements:
# - Dummy university list of 10 entries with: code, name, total_quota, available_quota
# - Users register/login (Argon2 hashing to avoid bcrypt issues on Windows)
# - Each user enters their exam RANK (lower is better) and an ORDERED list of university CODES
# - Global allocation engine assigns users by best rank to first choice with available quota
# - When any user updates choices/rank, we recompute allocations for EVERYONE and refresh quotas
# - UI shows current user's assigned university and live quotas
#
# Run:
#   pip install streamlit pandas numpy argon2-cffi
#   python -m streamlit run app.py

import os
import sqlite3
from contextlib import contextmanager
from typing import List, Dict

import pandas as pd
import streamlit as st
from argon2 import PasswordHasher

DB_PATH = os.environ.get("EXAM_SIM_DB", "exam_sim.db")
MAX_CHOICES = 25
ph = PasswordHasher()

# ------------------------
# DB helpers
# ------------------------
@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()


def init_db():
    with get_conn() as conn:
        cur = conn.cursor()

        # --- helpers ---
        def col_exists(table: str, col: str) -> bool:
            rows = cur.execute(f"PRAGMA table_info({table})").fetchall()
            return any(r[1] == col for r in rows)

        def table_exists(table: str) -> bool:
            r = cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            return bool(r)

        # users
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            """
        )
        # add exam_rank if missing (migration from older schema)
        if not col_exists("users", "exam_rank"):
            cur.execute("ALTER TABLE users ADD COLUMN exam_rank INTEGER")

        # universities (new schema uses code,total_quota,available_quota)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS universities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL
            );
            """
        )
        # add quota columns if missing
        if not col_exists("universities", "total_quota"):
            cur.execute("ALTER TABLE universities ADD COLUMN total_quota INTEGER")
        if not col_exists("universities", "available_quota"):
            cur.execute("ALTER TABLE universities ADD COLUMN available_quota INTEGER")
        # if old 'quota' column exists, try to migrate values into new columns
        old_cols = [r[1] for r in cur.execute("PRAGMA table_info(universities)").fetchall()]
        if "quota" in old_cols:
            # fill total/available from quota where null
            cur.execute("UPDATE universities SET total_quota=COALESCE(total_quota, quota), available_quota=COALESCE(available_quota, quota)")

        # choices
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS choices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                rank INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # ensure uni_code column exists
        if not col_exists("choices", "uni_code"):
            cur.execute("ALTER TABLE choices ADD COLUMN uni_code TEXT")
        # uniqueness constraints can't be added easily post-hoc; we'll enforce in code

        # allocations
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS allocations (
                user_id INTEGER PRIMARY KEY,
                uni_code TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )

        # Seed 10 dummy universities if table empty (no rows with code)
        cur.execute("SELECT COUNT(*) FROM universities WHERE code IS NOT NULL;")
        (count,) = cur.fetchone()
        if count == 0:
            seed = [
                ("U01", "Alpha University - CS", 30),
                ("U02", "Alpha University - EE", 25),
                ("U03", "Beta Tech - CS", 20),
                ("U04", "Beta Tech - AI", 10),
                ("U05", "Gamma State - ME", 15),
                ("U06", "Delta College - CE", 12),
                ("U07", "Epsilon Univ - DS", 18),
                ("U08", "Zeta Institute - Math", 14),
                ("U09", "Eta University - Physics", 16),
                ("U10", "Theta Poly - Bio", 9),
            ]
            cur.executemany(
                "INSERT INTO universities(code, name, total_quota, available_quota) VALUES (?,?,?,?)",
                [(c, n, q, q) for (c, n, q) in seed],
            )


# ------------------------
# Auth
# ------------------------

def register_user(username: str, password: str) -> tuple[bool, str]:
    if not username or not password:
        return False, "Username and password required."
    try:
        pw_hash = ph.hash(password)
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users(username, password_hash) VALUES (?,?)",
                (username, pw_hash),
            )
        return True, "Registered successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    except Exception as e:
        return False, f"Registration failed: {e}"


def login_user(username: str, password: str) -> tuple[bool, str | int]:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            return False, "User not found."
        uid, pw_hash = row
        try:
            if ph.verify(pw_hash, password):
                return True, uid
        except Exception:
            pass
        return False, "Incorrect password."


# ------------------------
# Data access
# ------------------------

def list_unis_df() -> pd.DataFrame:
    with get_conn() as conn:
        return pd.read_sql_query(
            "SELECT code, name, total_quota, available_quota FROM universities ORDER BY code",
            conn,
        )


def set_exam_rank(uid: int, rank: int):
    with get_conn() as conn:
        conn.execute("UPDATE users SET exam_rank=? WHERE id=?", (rank, uid))


def get_user(uid: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, exam_rank FROM users WHERE id=?", (uid,))
        r = cur.fetchone()
        return None if not r else {"id": r[0], "username": r[1], "exam_rank": r[2]}


def get_user_choices(uid: int) -> pd.DataFrame:
    with get_conn() as conn:
        return pd.read_sql_query(
            "SELECT rank, uni_code FROM choices WHERE user_id=? ORDER BY rank",
            conn,
            params=(uid,),
        )


def replace_user_choices(uid: int, codes_in_order: List[str]):
    codes_in_order = [c.strip().upper() for c in codes_in_order if c.strip()][:MAX_CHOICES]
    if not codes_in_order:
        return
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM choices WHERE user_id=?", (uid,))
        cur.executemany(
            "INSERT INTO choices(user_id, uni_code, rank) VALUES (?,?,?)",
            [(uid, code, i + 1) for i, code in enumerate(codes_in_order)],
        )


def list_users_choices() -> tuple[pd.DataFrame, pd.DataFrame]:
    with get_conn() as conn:
        users = pd.read_sql_query("SELECT id as user_id, username, exam_rank FROM users", conn)
        choices = pd.read_sql_query("SELECT user_id, uni_code, rank FROM choices", conn)
    return users, choices


def update_available_quota(remaining: Dict[str, int]):
    with get_conn() as conn:
        # set available = remaining for each code
        cur = conn.cursor()
        for code, rem in remaining.items():
            cur.execute(
                "UPDATE universities SET available_quota=? WHERE code=?",
                (int(rem), code),
            )


def write_allocations(alloc_map: Dict[int, str | None]):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM allocations")
        cur.executemany(
            "INSERT INTO allocations(user_id, uni_code) VALUES (?,?)",
            [(uid, alloc_map.get(uid)) for uid in alloc_map.keys()],
        )


def get_my_allocation(uid: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT uni_code FROM allocations WHERE user_id=?", (uid,))
        row = cur.fetchone()
        return None if not row else row[0]


# ------------------------
# Allocation engine (global recompute)
# ------------------------

def recompute_allocations():
    # pull data
    users, choices = list_users_choices()
    unis = list_unis_df()
    if users.empty:
        return
    # remaining quotas start from total
    remaining = {row.code: int(row.total_quota) for row in unis.itertuples(index=False)}
    # sort users by ascending exam_rank (None -> very large)
    users = users.copy()
    users["exam_rank"] = users["exam_rank"].fillna(10**12)
    users = users.sort_values(["exam_rank", "user_id"])  # stable tiebreaker by id

    # build choices map
    chmap: Dict[int, List[str]] = {}
    for r in choices.sort_values(["user_id", "rank"]).itertuples(index=False):
        chmap.setdefault(int(r.user_id), []).append(str(r.uni_code).upper())

    # allocate
    alloc: Dict[int, str | None] = {}
    for row in users.itertuples(index=False):
        uid = int(row.user_id)
        allocated = None
        for code in chmap.get(uid, [])[:MAX_CHOICES]:
            if remaining.get(code, 0) > 0:
                remaining[code] -= 1
                allocated = code
                break
        alloc[uid] = allocated

    # persist: allocations + available_quota
    write_allocations(alloc)
    update_available_quota(remaining)


# ------------------------
# UI
# ------------------------

def login_panel():
    st.subheader("Login or Register")
    t1, t2 = st.tabs(["Login", "Register"])
    with t1:
        with st.form("login_form"):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            s = st.form_submit_button("Login")
        if s:
            ok, res = login_user(u, p)
            if ok:
                st.session_state["uid"] = res
                st.session_state["username"] = u
                st.success(f"Welcome, {u}!")
                st.rerun()
            else:
                st.error(res)
    with t2:
        with st.form("reg_form"):
            u = st.text_input("New username")
            p = st.text_input("New password", type="password")
            s = st.form_submit_button("Create account")
        if s:
            ok, msg = register_user(u, p)
            st.success(msg) if ok else st.error(msg)


def profile_panel(user: dict):
    st.sidebar.markdown(f"**Logged in as:** {user['username']}")
    if st.sidebar.button("Log out"):
        for k in ("uid", "username"):
            st.session_state.pop(k, None)
        st.rerun()

    st.subheader("1) Enter your exam rank (lower is better)")
    rank = st.number_input("Exam rank", min_value=1, value=int(user["exam_rank"] or 100000), step=1)
    if st.button("Save rank"):
        set_exam_rank(user["id"], int(rank))
        recompute_allocations()
        st.success("Rank saved & allocations recomputed.")

    st.divider()
    st.subheader("2) Enter your choice list as university CODES in order")
    uni_df = list_unis_df()
    st.caption("Available codes:")
    st.dataframe(uni_df, use_container_width=True)

    existing = get_user_choices(user["id"])  # to show what you had
    if not existing.empty:
        st.caption("Your current choices:")
        st.table(existing)

    codes_str = st.text_input("Comma-separated codes (e.g., U03,U05,U01)")
    if st.button("Save choices & recompute"):
        codes = [c.strip().upper() for c in codes_str.split(",") if c.strip()]
        # validate against known codes
        valid_codes = set(uni_df["code"].tolist())
        bad = [c for c in codes if c not in valid_codes]
        if bad:
            st.error(f"Unknown codes: {bad}")
        elif not codes:
            st.error("Please enter at least one valid code.")
        else:
            replace_user_choices(user["id"], codes)
            recompute_allocations()
            st.success("Choices saved & allocations recomputed.")
            st.rerun()


def results_panel(user: dict):
    st.subheader("3) Your result & live quotas")
    alloc = get_my_allocation(user["id"]) or "—"
    st.info(f"Your current placement: **{alloc}**")

    st.caption("University quotas (live):")
    uni_df = list_unis_df()
    uni_df["filled"] = uni_df["total_quota"] - uni_df["available_quota"]
    st.dataframe(uni_df, use_container_width=True)


# ------------------------
# Main helper pages
# ------------------------

def universities_panel():
    st.subheader("Universities")
    df = list_unis_df()
    # Show in requested order: code / name / available quota / total quota
    df = df[["code", "name", "available_quota", "total_quota"]]
    st.dataframe(df, use_container_width=True)

# ------------------------
# Main
# ------------------------

def main():
    st.set_page_config(page_title="Exam Simulator MVP", layout="wide")
    st.title("🎓 Exam Simulator — Rank & Choice Allocator (MVP)")
    init_db()

    uid = st.session_state.get("uid")
    if not uid:
        login_panel()
        return

    user = get_user(uid)
    if not user:
        st.error("User not found. Please log in again.")
        for k in ("uid", "username"):
            st.session_state.pop(k, None)
        st.rerun()
        return

    with st.sidebar:
        page = st.radio("Go to", ["Profile & Choices", "Results", "Universities"], index=0)

    if page == "Profile & Choices":
        profile_panel(user)
    elif page == "Results":
        results_panel(user)
    else:
        universities_panel()


if __name__ == "__main__":
    main()
