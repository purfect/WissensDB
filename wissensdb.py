import os
import re
import sqlite3
import sys
import tempfile
import tkinter as tk
import webbrowser
import subprocess
import tkinter.font as tkfont
import time
import hashlib
import hmac
import secrets
import struct
from collections import deque
from datetime import datetime
from textwrap import wrap
from tkinter import filedialog, messagebox, simpledialog



SQLITE_HEADER = b"SQLite format 3\x00"
ENCRYPTED_DB_MAGIC = b"WISSENSDBENC2\0"
ENCRYPTED_DB_SALT_SIZE = 16
ENCRYPTED_DB_NONCE_SIZE = 16
ENCRYPTED_DB_TAG_SIZE = 32
APP_DB_BASENAME = "wissensdb_v2"
TODO_INLINE_PATTERN = re.compile(r"todo\s*:?\s*(.*)", re.IGNORECASE)
TODO_WORD_PATTERN = re.compile(r"todo", re.IGNORECASE)
TODO_CHECKLIST_PATTERN = re.compile(r"^\s*[-*+]\s+\[([ xX])\]\s*(.+)$")
TODO_BULLET_PATTERN = re.compile(r"^\s*[-*+]\s+(.+)$")


class _DbStorageError(RuntimeError):
    pass


def _get_runtime_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _derive_encryption_keys(password, salt):
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64,
    )
    return derived[:32], derived[32:]


def _xor_keystream(data, key, nonce):
    output = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        block = hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest()
        block_len = min(len(block), len(data) - offset)
        for idx in range(block_len):
            output[offset + idx] = data[offset + idx] ^ block[idx]
        offset += block_len
        counter += 1
    return bytes(output)


def _encrypt_bytes(data, password):
    salt = secrets.token_bytes(ENCRYPTED_DB_SALT_SIZE)
    nonce = secrets.token_bytes(ENCRYPTED_DB_NONCE_SIZE)
    enc_key, mac_key = _derive_encryption_keys(password, salt)
    ciphertext = _xor_keystream(data, enc_key, nonce)
    payload = ENCRYPTED_DB_MAGIC + salt + nonce + ciphertext
    tag = hmac.new(mac_key, payload, hashlib.sha256).digest()
    return payload + tag


def _decrypt_bytes(data, password):
    min_len = (
        len(ENCRYPTED_DB_MAGIC)
        + ENCRYPTED_DB_SALT_SIZE
        + ENCRYPTED_DB_NONCE_SIZE
        + ENCRYPTED_DB_TAG_SIZE
    )
    if len(data) < min_len:
        raise _DbStorageError("Verschluesselte Datei ist unvollstaendig.")
    if not data.startswith(ENCRYPTED_DB_MAGIC):
        raise _DbStorageError("Unbekanntes Datenbankformat.")
    pos = len(ENCRYPTED_DB_MAGIC)
    salt = data[pos : pos + ENCRYPTED_DB_SALT_SIZE]
    pos += ENCRYPTED_DB_SALT_SIZE
    nonce = data[pos : pos + ENCRYPTED_DB_NONCE_SIZE]
    pos += ENCRYPTED_DB_NONCE_SIZE
    ciphertext = data[pos:-ENCRYPTED_DB_TAG_SIZE]
    tag = data[-ENCRYPTED_DB_TAG_SIZE:]
    enc_key, mac_key = _derive_encryption_keys(password, salt)
    expected_tag = hmac.new(mac_key, data[:-ENCRYPTED_DB_TAG_SIZE], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise _DbStorageError("Passwort falsch oder Datei beschaedigt.")
    plaintext = _xor_keystream(ciphertext, enc_key, nonce)
    if plaintext and not plaintext.startswith(SQLITE_HEADER):
        raise _DbStorageError("Entschluesselte Datei ist keine gueltige SQLite-Datenbank.")
    return plaintext


def _detect_db_file_kind(path):
    with open(path, "rb") as handle:
        prefix = handle.read(max(len(SQLITE_HEADER), len(ENCRYPTED_DB_MAGIC)))
    if prefix.startswith(SQLITE_HEADER):
        return "plain"
    if prefix.startswith(ENCRYPTED_DB_MAGIC):
        return "encrypted"
    if prefix.startswith(b"WISSENSDBENC1\0"):
        return "legacy_encrypted"
    return "unknown"


def _prompt_password(title, prompt, confirm=False):
    password = simpledialog.askstring(title, prompt, show="*")
    if password is None:
        return None
    if not password:
        messagebox.showwarning("Passwort", "Passwort darf nicht leer sein.")
        return None
    if not confirm:
        return password
    confirmation = simpledialog.askstring(title, "Passwort wiederholen:", show="*")
    if confirmation is None:
        return None
    if password != confirmation:
        messagebox.showerror("Passwort", "Die Passwoerter stimmen nicht ueberein.")
        return None
    return password


class _DbStorage:
    def __init__(self, db_path, create_encrypted=False, password=None):
        self.db_path = db_path
        self.create_encrypted = create_encrypted
        self.password = password
        self.is_encrypted = False
        self.sqlite_path = db_path
        self._temp_dir = None

    def prepare(self):
        if os.path.exists(self.db_path):
            file_kind = _detect_db_file_kind(self.db_path)
            if file_kind == "encrypted":
                if not self.password:
                    raise _DbStorageError("Fuer verschluesselte Datenbanken wird ein Passwort benoetigt.")
                self.is_encrypted = True
                self.sqlite_path = self._create_temp_sqlite_path()
                self._load_encrypted_file()
            elif file_kind == "legacy_encrypted":
                raise _DbStorageError(
                    "Diese Datei nutzt das alte Windows-gebundene Format und wird nicht mehr unterstuetzt."
                )
            elif file_kind in ("plain", "unknown"):
                self.sqlite_path = self.db_path
            return self.sqlite_path
        if self.create_encrypted:
            if not self.password:
                raise _DbStorageError("Fuer neue verschluesselte Datenbanken wird ein Passwort benoetigt.")
            self.is_encrypted = True
            self.sqlite_path = self._create_temp_sqlite_path()
        else:
            self.sqlite_path = self.db_path
        return self.sqlite_path

    def sync_to_disk(self):
        if not self.is_encrypted:
            return
        if not os.path.exists(self.sqlite_path):
            return
        with open(self.sqlite_path, "rb") as handle:
            raw_bytes = handle.read()
        encrypted_bytes = _encrypt_bytes(raw_bytes, self.password)
        tmp_path = f"{self.db_path}.tmp"
        with open(tmp_path, "wb") as handle:
            handle.write(encrypted_bytes)
        os.replace(tmp_path, self.db_path)

    def close(self):
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def _create_temp_sqlite_path(self):
        self._temp_dir = tempfile.TemporaryDirectory(prefix="wissensdb_")
        return os.path.join(self._temp_dir.name, "data.sqlite3")

    def _load_encrypted_file(self):
        with open(self.db_path, "rb") as handle:
            payload = handle.read()
        decrypted = _decrypt_bytes(payload, self.password)
        with open(self.sqlite_path, "wb") as handle:
            handle.write(decrypted)


def _looks_like_db_file(path):
    if not os.path.isfile(path):
        return False
    _, ext = os.path.splitext(path)
    return ext.lower() in (".db", ".sqlite", ".sqlite3")


def _show_startup_db_dialog(root, runtime_dir, db_paths, default_new_path, preferred_path=None):
    dialog = tk.Toplevel(root)
    dialog.title("Datenbankstart")
    dialog.resizable(True, True)
    dialog.geometry("760x420")

    result = {"value": None, "password": None, "create_encrypted": False}

    info_lines = [
        "Waehle die Datenbank, mit der gestartet werden soll.",
        "Du kannst eine vorhandene DB oeffnen oder eine neue Standard-DB anlegen.",
        "",
        f"Ordner: {runtime_dir}",
    ]

    info_label = tk.Label(
        dialog,
        text="\n".join(info_lines),
        justify="left",
        anchor="w",
    )
    info_label.pack(fill="x", padx=12, pady=(12, 8))

    list_frame = tk.Frame(dialog)
    list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

    listbox = tk.Listbox(list_frame, height=10)
    listbox.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
    scrollbar.pack(side="right", fill="y")
    listbox.config(yscrollcommand=scrollbar.set)

    for path in db_paths:
        listbox.insert(tk.END, os.path.basename(path))

    if db_paths:
        selected_index = 0
        if preferred_path and preferred_path in db_paths:
            selected_index = db_paths.index(preferred_path)
        listbox.selection_set(selected_index)
        listbox.activate(selected_index)
        listbox.see(selected_index)

    btn_frame = tk.Frame(dialog)
    btn_frame.pack(fill="x", padx=12, pady=(0, 12))

    def choose_selected(_event=None):
        selection = listbox.curselection()
        if not selection:
            return
        result["value"] = db_paths[selection[0]]
        dialog.destroy()

    def create_new():
        result["value"] = default_new_path
        dialog.destroy()

    def create_new_encrypted():
        path = filedialog.asksaveasfilename(
            title="Neue verschluesselte DB anlegen",
            defaultextension=".db",
            initialfile=os.path.basename(default_new_path),
            filetypes=[("SQLite DB", "*.db *.sqlite *.sqlite3"), ("All files", "*.*")],
        )
        if not path:
            return
        password = _prompt_password(
            "Neues Datenbank-Passwort",
            "Passwort fuer die neue Datenbank:",
            confirm=True,
        )
        if password is None:
            return
        result["value"] = path
        result["password"] = password
        result["create_encrypted"] = True
        dialog.destroy()

    def browse_existing():
        path = filedialog.askopenfilename(
            title="SQLite DB waehlen",
            filetypes=[("SQLite DB", "*.db *.sqlite *.sqlite3"), ("All files", "*.*")],
        )
        if not path:
            return
        file_kind = _detect_db_file_kind(path)
        if file_kind == "legacy_encrypted":
            messagebox.showerror(
                "Datenbank",
                "Diese Datei nutzt das alte Windows-gebundene Format und kann nicht mehr geoeffnet werden.",
            )
            return
        if file_kind == "encrypted":
            password = _prompt_password("Datenbank-Passwort", "Passwort fuer die Datenbank:")
            if password is None:
                return
            result["password"] = password
        result["value"] = path
        dialog.destroy()

    def cancel():
        dialog.destroy()

    open_btn = tk.Button(btn_frame, text="Markierte DB oeffnen", command=choose_selected)
    open_btn.pack(side="left")

    browse_btn = tk.Button(btn_frame, text="Andere DB waehlen...", command=browse_existing)
    browse_btn.pack(side="left", padx=(8, 0))

    new_btn = tk.Button(btn_frame, text="Neue Standard-DB", command=create_new)
    new_btn.pack(side="left", padx=(8, 0))

    new_encrypted_btn = tk.Button(
        btn_frame,
        text="Neue verschluesselte DB",
        command=create_new_encrypted,
    )
    new_encrypted_btn.pack(side="left", padx=(8, 0))

    cancel_btn = tk.Button(btn_frame, text="Abbrechen", command=cancel)
    cancel_btn.pack(side="right")

    listbox.bind("<Double-Button-1>", choose_selected)
    dialog.protocol("WM_DELETE_WINDOW", cancel)
    dialog.update_idletasks()
    dialog.deiconify()
    dialog.lift()
    dialog.attributes("-topmost", True)
    dialog.after(100, lambda: dialog.attributes("-topmost", False))
    dialog.grab_set()
    listbox.focus_set()
    root.wait_window(dialog)
    return result["value"], result["password"], result["create_encrypted"]


def _resolve_db_selection(root):
    args = sys.argv[1:]
    explicit_path = None

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--db" and idx + 1 < len(args):
            explicit_path = args[idx + 1]
            idx += 1
        elif not arg.startswith("-") and explicit_path is None:
            explicit_path = arg
        idx += 1

    if explicit_path:
        path = os.path.abspath(explicit_path)
        if not os.path.exists(path):
            raise _DbStorageError(f"Datenbankpfad nicht gefunden:\n{path}")
        file_kind = _detect_db_file_kind(path)
        if file_kind == "encrypted":
            password = _prompt_password("Datenbank-Passwort", "Passwort fuer die Datenbank:")
            return path, False, password
        if file_kind == "legacy_encrypted":
            raise _DbStorageError(
                "Diese Datei nutzt das alte Windows-gebundene Format und kann nicht mehr geoeffnet werden."
            )
        return path, False, None

    runtime_dir = _get_runtime_dir()
    preferred_names = [
        f"{APP_DB_BASENAME}.db",
        f"{APP_DB_BASENAME}.sqlite3",
        f"{APP_DB_BASENAME}.sqlite",
        "wissensdb_v2.db",
        "wissensdb.db",
        "data.sqlite3",
        "data.db",
    ]

    default_new_path = os.path.join(runtime_dir, f"{APP_DB_BASENAME}.db")
    local_db_paths = []
    try:
        for name in sorted(os.listdir(runtime_dir)):
            candidate = os.path.join(runtime_dir, name)
            if _looks_like_db_file(candidate):
                local_db_paths.append(candidate)
    except OSError:
        local_db_paths = []

    usable_db_paths = []
    for candidate in local_db_paths:
        file_kind = _detect_db_file_kind(candidate)
        if file_kind != "legacy_encrypted":
            usable_db_paths.append(candidate)

    preferred_path = None
    for name in preferred_names:
        candidate = os.path.join(runtime_dir, name)
        if candidate in usable_db_paths:
            preferred_path = candidate
            break

    selected, password, create_encrypted = _show_startup_db_dialog(
        root,
        runtime_dir,
        usable_db_paths,
        default_new_path,
        preferred_path=preferred_path,
    )
    if not selected:
        return None, False, None
    if create_encrypted:
        return selected, True, password
    if password is None and os.path.exists(selected):
        file_kind = _detect_db_file_kind(selected)
        if file_kind == "encrypted":
            password = _prompt_password("Datenbank-Passwort", "Passwort fuer die Datenbank:")
            if password is None:
                return None, False, None
        elif file_kind == "legacy_encrypted":
            messagebox.showerror(
                "Datenbank",
                "Diese Datei nutzt das alte Windows-gebundene Format und kann nicht mehr geoeffnet werden.",
            )
            return None, False, None
    return selected, False, password


def _normalize_table_name(raw_name):
    name = raw_name.strip().replace(" ", "_")
    name = re.sub(r"[^A-Za-z0-9_]", "", name)
    if not name:
        return None
    if name[0].isdigit():
        name = f"t_{name}"
    return name


class _DbConnection:
    def __init__(self, conn, logger, storage=None):
        self._conn = conn
        self._logger = logger
        self._storage = storage

    def execute(self, sql, params=None):
        start = time.perf_counter()
        try:
            if params is None:
                result = self._conn.execute(sql)
            else:
                result = self._conn.execute(sql, params)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if self._logger:
                self._logger("execute", sql, elapsed_ms, params=params, error=exc)
            raise
        finally:
            if "result" in locals():
                elapsed_ms = (time.perf_counter() - start) * 1000
                if self._logger:
                    self._logger("execute", sql, elapsed_ms, params=params)

    def executemany(self, sql, seq_of_params):
        start = time.perf_counter()
        try:
            result = self._conn.executemany(sql, seq_of_params)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if self._logger:
                self._logger("executemany", sql, elapsed_ms, params="...", error=exc)
            raise
        finally:
            if "result" in locals():
                elapsed_ms = (time.perf_counter() - start) * 1000
                if self._logger:
                    self._logger("executemany", sql, elapsed_ms, params="...")

    def commit(self):
        start = time.perf_counter()
        try:
            result = self._conn.commit()
            if self._storage:
                self._storage.sync_to_disk()
            return result
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if self._logger:
                self._logger("commit", "COMMIT", elapsed_ms)

    def close(self):
        try:
            self._conn.close()
        finally:
            if self._storage:
                self._storage.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


class WissensDbApp(tk.Tk):
    def __init__(self, db_path, create_encrypted=False, db_password=None):
        super().__init__()
        self.db_path = db_path
        self.db_storage = None
        self.conn = None
        try:
            self.db_storage = _DbStorage(
                db_path,
                create_encrypted=create_encrypted,
                password=db_password,
            )
            self.title("WissensDB")
            self._last_settings_error = None
            self._debug_log = deque(maxlen=2000)
            self._debug_window = None
            self._debug_text = None
            self._unterthema_preview_window = None
            self._unterthema_preview_text = None
            self._unterthema_preview_context_menu = None
            self._unterthema_preview_linenumbers = None
            self._unterthema_preview_scroll = None
            self._unterthema_preview_status_frame = None
            self._unterthema_preview_entry_id = None
            self._editing_in_preview = False
            self.metadata_expanded_var = tk.BooleanVar(value=False)
            self.current_metadata_fields = []
            sqlite_path = self.db_storage.prepare()
            raw_conn = sqlite3.connect(sqlite_path)
            self.conn = _DbConnection(raw_conn, self._log_db, storage=self.db_storage)
            self._ensure_settings_table()
            self.show_line_numbers_var = tk.BooleanVar(
                value=self._get_setting_bool("unterthema_line_numbers", default=True)
            )
            self.show_markdown_var = tk.BooleanVar(
                value=self._get_setting_bool("unterthema_markdown", default=True)
            )
            self.resizable(True, True)
            self.autosave_ms = 30000
            self.autosave_job = None
            self.auto_backup_job = None
            self.last_autosave_key = None
            self.is_editing = False
            self.autosave_delay_ms = 1500
            self.editing_thema = None
            self.editing_unterthema_id = None
            self.nav_back_stack = []
            self.nav_forward_stack = []
            self._suppress_navigation_history = False
            self._build_ui()
            self._schedule_auto_backup()
            self.protocol("WM_DELETE_WINDOW", self._on_close_app)
            # Apply after layout so geometry isn't overwritten by widget sizing.
            self.update_idletasks()
            default_size = self._parse_window_size("1440x420")
            self._load_window_size(default="1440x420")
            if default_size:
                self.after(150, lambda: self._reapply_window_size_if_needed(default_size))
        except Exception:
            try:
                if self.conn is not None:
                    self.conn.close()
                elif self.db_storage is not None:
                    self.db_storage.close()
            finally:
                self.destroy()
            raise

    def _build_ui(self):
        self._build_menu()

        header = tk.Label(
            self,
            text=self._get_db_header_text(),
            anchor="w",
        )
        header.pack(fill="x", padx=12, pady=(12, 6))

        body = tk.Frame(self)
        body.pack(side="top", fill="both", expand=True, padx=12, pady=(0, 12))

        sidebar_frame = tk.Frame(body)
        sidebar_frame.pack(side="left", fill="y")

        sidebar_toolbar = tk.Frame(sidebar_frame)
        sidebar_toolbar.pack(fill="x", pady=(0, 6))

        thema_order_label = tk.Label(sidebar_toolbar, text="Themen:")
        thema_order_label.pack(side="left")

        self.themen_order_var = tk.StringVar(value="A-Z")
        thema_order_menu = tk.OptionMenu(
            sidebar_toolbar,
            self.themen_order_var,
            "A-Z",
            "Z-A",
            "Neueste zuerst",
            "Aelteste zuerst",
        )
        thema_order_menu.config(width=16)
        thema_order_menu.pack(side="left", padx=(6, 0))
        self.themen_order_var.trace_add("write", self._on_change_themen_order)

        self.sidebar = tk.Listbox(sidebar_frame, width=28, height=20)
        self.sidebar.pack(side="left", fill="y")

        sidebar_scroll = tk.Scrollbar(sidebar_frame, orient="vertical", command=self.sidebar.yview)
        sidebar_scroll.pack(side="right", fill="y")
        self.sidebar.config(yscrollcommand=sidebar_scroll.set)

        divider = tk.Frame(body, width=1, bg="#c0c0c0")
        divider.pack(side="left", fill="y", padx=(8, 8))

        self.content = tk.Frame(body)
        self.content.pack(side="left", fill="both", expand=True)

        self.thema_label = tk.Label(self.content, text="Kein Thema gewaehlt", anchor="w")
        self.thema_label.pack(fill="x")

        toolbar = tk.Frame(self.content)
        toolbar.pack(fill="x", pady=(6, 6))

        add_delete_frame = tk.Frame(toolbar)
        add_delete_frame.pack(side="left")

        self.add_unterthema_btn = tk.Button(
            add_delete_frame,
            text="Neues Unterthema...",
            state="disabled",
            command=self._open_new_unterthema_dialog,
        )
        self.add_unterthema_btn.pack(fill="x")

        self.unterthema_actions_btn = tk.Menubutton(
            add_delete_frame,
            text="Aktionen",
            state="disabled",
            relief="raised",
        )
        self.unterthema_actions_btn.pack(fill="x", pady=(4, 0))
        self.unterthema_actions_menu = tk.Menu(
            self.unterthema_actions_btn,
            tearoff=0,
            postcommand=self._update_unterthema_actions_state,
        )
        self.unterthema_actions_menu.add_command(
            label="Archivieren",
            command=self._archive_unterthema,
        )
        self.unterthema_actions_menu.add_command(
            label="Wiederherstellen",
            command=self._restore_unterthema,
        )
        self.unterthema_actions_menu.add_separator()
        self.unterthema_actions_menu.add_command(
            label="Umbenennen...",
            command=self._rename_unterthema,
        )
        self.unterthema_actions_menu.add_command(
            label="Loeschen...",
            command=self._delete_unterthema,
        )
        self.unterthema_actions_menu.add_separator()
        self.unterthema_actions_menu.add_command(
            label="Gruppe setzen...",
            command=self._open_set_gruppe_dialog,
        )
        self.unterthema_actions_btn.config(menu=self.unterthema_actions_menu)

        order_label = tk.Label(toolbar, text="Reihenfolge:")
        order_label.pack(side="left", padx=(12, 4))

        self.unterthemen_order_var = tk.StringVar(value="Neueste zuerst")
        order_menu = tk.OptionMenu(
            toolbar,
            self.unterthemen_order_var,
            "Neueste zuerst",
            "Aelteste zuerst",
            "Zuletzt bearbeitet",
            "Laengst nicht bearbeitet",
        )
        order_menu.config(width=14)
        order_menu.pack(side="left")
        self.unterthemen_order_var.trace_add("write", self._on_change_unterthemen_order)

        self.show_archived_var = tk.BooleanVar(value=False)
        archived_toggle = tk.Checkbutton(
            toolbar,
            text="Archiv anzeigen",
            variable=self.show_archived_var,
            command=self._on_toggle_show_archived,
        )
        archived_toggle.pack(side="left", padx=(12, 0))

        self.nav_back_btn = tk.Button(
            toolbar,
            text="<--",
            state="disabled",
            width=4,
            command=self._go_navigation_back,
        )
        self.nav_back_btn.pack(side="left", padx=(12, 2))

        self.nav_forward_btn = tk.Button(
            toolbar,
            text="-->",
            state="disabled",
            width=4,
            command=self._go_navigation_forward,
        )
        self.nav_forward_btn.pack(side="left", padx=(0, 4))

        self.edit_unterthema_btn = tk.Button(
            toolbar,
            text="Bearbeiten",
            state="disabled",
            command=self._enable_inhalt_edit,
        )
        self.edit_unterthema_btn.pack(side="left", padx=(12, 4))

        self.save_unterthema_btn = tk.Button(
            toolbar,
            text="Speichern",
            state="disabled",
            command=self._save_inhalt_edit,
        )
        self.save_unterthema_btn.pack(side="left")

        content_body = tk.Frame(self.content)
        content_body.pack(fill="both", expand=True)

        unterthemen_frame = tk.Frame(content_body)
        unterthemen_frame.pack(side="left", fill="y")

        self.unterthemen_list = tk.Listbox(unterthemen_frame, width=28, height=18)
        self.unterthemen_list.pack(side="left", fill="y")
        self.unterthemen_list.bind("<<ListboxSelect>>", self._on_select_unterthema)
        self.unterthemen_list.bind("<Double-Button-1>", self._open_unterthema_for_edit)
        self.unterthemen_context_menu = tk.Menu(self, tearoff=0)
        self.unterthemen_context_menu.add_command(
            label="In separatem Fenster oeffnen",
            command=self._open_unterthema_in_separate_window,
        )
        self.unterthemen_context_menu.add_separator()
        self.unterthemen_context_menu.add_command(
            label="Namen kopieren", command=self._copy_unterthema_name
        )
        self.unterthemen_list.bind("<Button-3>", self._show_unterthemen_context_menu)
        self.unterthemen_list.bind("<Motion>", self._on_unterthemen_hover)
        self.unterthemen_list.bind("<Leave>", self._hide_unterthemen_tooltip)

        unterthemen_scroll = tk.Scrollbar(
            unterthemen_frame, orient="vertical", command=self.unterthemen_list.yview
        )
        unterthemen_scroll.pack(side="right", fill="y")
        self.unterthemen_list.config(yscrollcommand=unterthemen_scroll.set)

        divider2 = tk.Frame(content_body, width=1, bg="#c0c0c0")
        divider2.pack(side="left", fill="y", padx=(8, 8))

        inhalt_frame = tk.Frame(content_body)
        inhalt_frame.pack(side="left", fill="both", expand=True)

        title_bar = tk.Frame(inhalt_frame)
        title_bar.pack(fill="x", pady=(0, 4))

        self.unterthema_title_label = tk.Label(title_bar, text="", anchor="w")
        self.unterthema_title_label.pack(side="left", fill="x", expand=True)

        status_frame = tk.Frame(title_bar)
        status_frame.pack(side="right")

        self.edit_mode_status_frame = tk.Frame(status_frame)
        edit_mode_label = tk.Label(self.edit_mode_status_frame, text="Bearbeitung:", anchor="e")
        edit_mode_label.pack(side="left", padx=(0, 4))

        self.edit_mode_indicator = tk.Canvas(
            self.edit_mode_status_frame,
            width=10,
            height=10,
            highlightthickness=0,
            bd=0,
            bg=title_bar.cget("bg"),
        )
        self.edit_mode_indicator.pack(side="left")
        self.edit_mode_indicator.create_oval(
            1,
            1,
            9,
            9,
            fill="#2ecc71",
            outline="",
        )

        self.autosave_status_frame = tk.Frame(status_frame)
        self.autosave_status_frame.pack(side="left")

        status_label = tk.Label(self.autosave_status_frame, text="Autosave:", anchor="e")
        status_label.pack(side="left", padx=(0, 4))

        self.autosave_status_canvas = tk.Canvas(
            self.autosave_status_frame,
            width=10,
            height=10,
            highlightthickness=0,
            bd=0,
            bg=title_bar.cget("bg"),
        )
        self.autosave_status_canvas.pack(side="left")
        self.autosave_status_dot = self.autosave_status_canvas.create_oval(
            1,
            1,
            9,
            9,
            fill="#2ecc71",
            outline="",
        )

        self.markdown_status_label = tk.Label(status_frame, text="", anchor="e")
        self.markdown_status_label.pack(side="left", padx=(10, 0))
        self._update_markdown_status_label()

        self.metadata_frame = tk.Frame(inhalt_frame)
        self.metadata_frame.pack(fill="x", pady=(0, 4))

        metadata_header = tk.Frame(self.metadata_frame)
        metadata_header.pack(fill="x")

        self.metadata_toggle_btn = tk.Button(
            metadata_header,
            text="> Felder (0)",
            command=self._toggle_metadata_panel,
            anchor="w",
            relief="flat",
        )
        self.metadata_toggle_btn.pack(side="left", fill="x", expand=True)

        self.metadata_edit_btn = tk.Button(
            metadata_header,
            text="Felder...",
            command=self._open_metadata_dialog,
            state="disabled",
        )
        self.metadata_edit_btn.pack(side="right")

        self.metadata_body = tk.Frame(self.metadata_frame)
        self.metadata_empty_label = tk.Label(
            self.metadata_body,
            text="Keine Felder.",
            anchor="w",
            fg="#555555",
        )

        self.inhalt_linenumbers = tk.Text(
            inhalt_frame,
            wrap="none",
            height=18,
            width=4,
            state="disabled",
            takefocus=0,
            bd=0,
            padx=4,
            bg="#f0f0f0",
            fg="#555555",
        )

        self.inhalt_text = tk.Text(inhalt_frame, wrap="word", height=18, undo=True)
        self.inhalt_text.pack(side="left", fill="both", expand=True)
        self.inhalt_linenumbers.config(font=self.inhalt_text.cget("font"))
        self._apply_inhalt_line_numbers_visibility()
        self._prepare_link_handling(self.inhalt_text)
        self._prepare_code_handling(self.inhalt_text)
        self._prepare_bold_handling(self.inhalt_text)
        self._prepare_markdown_handling(self.inhalt_text)
        self.inhalt_context_menu = tk.Menu(self, tearoff=0)
        self.inhalt_context_menu.add_command(label="Kopieren", command=self._copy_inhalt_selection)
        self.inhalt_context_menu.add_command(
            label="Codeblock kopieren",
            command=self._copy_codeblock_from_context,
        )
        self.inhalt_context_menu.add_command(label="Alles markieren", command=self._select_all_inhalt)
        self.inhalt_context_menu.add_command(label="Einfuegen", command=self._paste_inhalt_clipboard)
        self.inhalt_context_menu.add_command(
            label="Interner Link...", command=self._insert_internal_link_from_context
        )
        self.inhalt_context_menu.add_command(
            label="Internet-Link...", command=self._insert_external_link_from_context
        )
        self.inhalt_context_menu.add_command(
            label="Checkbox umschalten", command=self._toggle_checklist_item_from_context
        )
        self.inhalt_context_menu.add_command(label="Als Codeblock", command=self._wrap_selection_code)
        self.inhalt_context_menu.add_command(
            label="Als Codeblock mit Sprache...", command=self._wrap_selection_code_with_language
        )
        self.inhalt_context_menu.add_command(label="Code entfernen", command=self._unwrap_selection_code)
        self.inhalt_context_menu.add_command(label="Hervorheben", command=self._wrap_selection_bold)
        self.inhalt_context_menu.add_command(label="Hervorhebung entfernen", command=self._unwrap_selection_bold)
        self.inhalt_context_menu.add_separator()
        self.inhalt_context_menu.add_command(
            label="Markdown an/aus", command=self._toggle_markdown_from_context
        )
        self.inhalt_text.bind("<Button-3>", self._show_inhalt_context_menu)

        inhalt_scroll = tk.Scrollbar(
            inhalt_frame,
            orient="vertical",
            command=self._on_inhalt_scrollbar,
        )
        inhalt_scroll.pack(side="right", fill="y")
        self.inhalt_scroll = inhalt_scroll
        self.inhalt_text.config(yscrollcommand=self._on_inhalt_scroll)
        self._set_inhalt_text("Waehle links ein Thema oder lege ein neues an.")

        self._refresh_themen()
        self.sidebar.bind("<<ListboxSelect>>", self._on_select_thema)
        self.bind_all("<Control-f>", self._open_search_shortcut)
        self.bind_all("<Control-b>", self._toggle_bold_shortcut)
        self.bind_all("<Control-Shift-C>", self._wrap_code_shortcut)
        self.bind_all("<Control-Shift-X>", self._toggle_checklist_shortcut)
        self.bind_all("<Control-n>", self._create_notes_shortcut)
        self.bind_all("<Control-z>", self._undo_shortcut)
        self.bind_all("<Control-y>", self._redo_shortcut)
        self.bind_all("<Alt-Left>", self._navigation_back_shortcut)
        self.bind_all("<Alt-Right>", self._navigation_forward_shortcut)
        self.current_thema = None
        self.unterthemen = []
        self._unterthemen_listbox_map = []
        self.current_unterthema_id = None
        self.current_unterthema_archived = False
        self._update_navigation_buttons()

    def _build_menu(self):
        menubar = tk.Menu(self)
        thema_menu = tk.Menu(menubar, tearoff=0)
        thema_menu.add_command(label="Neues Thema...", command=self._open_new_thema_dialog)
        menubar.add_cascade(label="Thema", menu=thema_menu)

        search_menu = tk.Menu(menubar, tearoff=0)
        search_menu.add_command(label="Stichwortsuche...", command=self._open_search_dialog)
        search_menu.add_command(label="ToDo-Liste...", command=self._open_todo_dialog)
        menubar.add_cascade(label="Suche", menu=search_menu)

        import_menu = tk.Menu(menubar, tearoff=0)
        import_menu.add_command(label="Textdatei importieren...", command=self._open_import_dialog)
        menubar.add_cascade(label="Import", menu=import_menu)

        export_menu = tk.Menu(menubar, tearoff=0)
        export_menu.add_command(label="Als TXT exportieren...", command=self._export_txt)
        export_menu.add_command(label="Als PDF exportieren...", command=self._export_pdf)
        export_menu.add_command(
            label="DB unverschluesselt sichern...",
            command=self._export_plain_db_backup,
        )
        export_menu.add_command(label="Export als...", command=self._export_custom)
        menubar.add_cascade(label="Export", menu=export_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Fenstergroesse...", command=self._open_window_size_dialog)
        settings_menu.add_command(label="Zeilennummern...", command=self._open_line_numbers_dialog)
        settings_menu.add_command(label="Automatisches Backup...", command=self._open_auto_backup_dialog)
        settings_menu.add_command(label="Tastenkuerzel...", command=self._open_shortcuts_dialog)
        settings_menu.add_command(label="Debug...", command=self._open_debug_dialog)
        menubar.add_cascade(label="Einstellungen", menu=settings_menu)
        self.config(menu=menubar)

    def _refresh_themen(self):
        self.sidebar.delete(0, tk.END)
        self.themen_display_map = {}
        for name in self._get_themen_tables():
            display_name = self._display_thema_name(name)
            if display_name in self.themen_display_map:
                display_name = name
            self.themen_display_map[display_name] = name
            self.sidebar.insert(tk.END, display_name)

    def _get_themen_tables(self):
        order_choice = self.themen_order_var.get()
        base_query = (
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT IN "
            "('app_settings', 'app_themen_meta', 'app_entry_fields') "
            "AND name NOT LIKE 'app_search_fts%'"
        )
        if order_choice in ("Neueste zuerst", "Aelteste zuerst"):
            self._ensure_themen_meta_table()
            try:
                names = [row[0] for row in self.conn.execute(base_query).fetchall()]
            except sqlite3.Error:
                return []
            if not names:
                return []
            self._backfill_themen_meta(names)
            placeholders = ",".join("?" for _ in names)
            order = "DESC" if order_choice == "Neueste zuerst" else "ASC"
            cursor = self.conn.execute(
                f"SELECT name FROM app_themen_meta WHERE name IN ({placeholders}) "
                f"ORDER BY erstellt_am {order}, name ASC",
                names,
            )
            return [row[0] for row in cursor.fetchall()]
        order = "ASC" if order_choice == "A-Z" else "DESC"
        cursor = self.conn.execute(f"{base_query} ORDER BY name {order}")
        return [row[0] for row in cursor.fetchall()]

    def _display_thema_name(self, name):
        if name.startswith("t_") and len(name) > 2 and name[2].isdigit():
            return name[2:]
        return name

    def _resolve_thema_name(self, name):
        if hasattr(self, "themen_display_map") and name in self.themen_display_map:
            return self.themen_display_map[name]
        return name

    def _on_select_thema(self, _event):
        selection = self.sidebar.curselection()
        if not selection:
            return
        display_name = self.sidebar.get(selection[0])
        self.current_thema = self._resolve_thema_name(display_name)
        self.thema_label.config(text=f"Thema: {display_name}")
        self.add_unterthema_btn.config(state="normal")
        self._load_unterthemen()

    def _update_unterthema_actions_state(self):
        if not hasattr(self, "unterthema_actions_btn"):
            return
        has_selection = bool(self.current_unterthema_id and self.current_thema)
        self.unterthema_actions_btn.config(state="normal" if has_selection else "disabled")
        archive_state = "disabled"
        restore_state = "disabled"
        rename_state = "disabled"
        delete_state = "disabled"
        if has_selection:
            rename_state = "normal"
            delete_state = "normal"
            if self.current_unterthema_archived:
                restore_state = "normal"
            else:
                archive_state = "normal"
        self.unterthema_actions_menu.entryconfig("Archivieren", state=archive_state)
        self.unterthema_actions_menu.entryconfig("Wiederherstellen", state=restore_state)
        self.unterthema_actions_menu.entryconfig("Umbenennen...", state=rename_state)
        self.unterthema_actions_menu.entryconfig("Loeschen...", state=delete_state)
        self.unterthema_actions_menu.entryconfig("Gruppe setzen...", state="normal" if has_selection else "disabled")

    def _get_current_navigation_location(self):
        if not self.current_thema or not self.current_unterthema_id:
            return None
        return (self.current_thema, self.current_unterthema_id)

    def _record_navigation_from(self, previous):
        current = self._get_current_navigation_location()
        if (
            self._suppress_navigation_history
            or previous is None
            or current is None
            or previous == current
        ):
            self._update_navigation_buttons()
            return
        self.nav_back_stack.append(previous)
        self.nav_back_stack = self.nav_back_stack[-100:]
        self.nav_forward_stack.clear()
        self._update_navigation_buttons()

    def _update_navigation_buttons(self):
        if not hasattr(self, "nav_back_btn"):
            return
        self.nav_back_btn.config(state="normal" if self.nav_back_stack else "disabled")
        self.nav_forward_btn.config(state="normal" if self.nav_forward_stack else "disabled")

    def _go_navigation_back(self):
        self._navigate_history(self.nav_back_stack, self.nav_forward_stack)

    def _go_navigation_forward(self):
        self._navigate_history(self.nav_forward_stack, self.nav_back_stack)

    def _navigate_history(self, source_stack, target_stack):
        if not source_stack:
            return
        target = source_stack.pop()
        current = self._get_current_navigation_location()
        if self._navigate_to_location(target):
            if current and current != target:
                target_stack.append(current)
        self._update_navigation_buttons()

    def _navigate_to_location_with_history(self, location):
        previous = self._get_current_navigation_location()
        if self._navigate_to_location(location):
            current = self._get_current_navigation_location()
            if previous and current and previous != current:
                self.nav_back_stack.append(previous)
                self.nav_back_stack = self.nav_back_stack[-100:]
                self.nav_forward_stack.clear()
                self._update_navigation_buttons()
            return True
        return False

    def _navigate_to_location(self, location):
        if not location:
            return False
        thema, entry_id = location
        previous_suppression = self._suppress_navigation_history
        self._suppress_navigation_history = True
        try:
            if self.current_thema != thema and not self._select_thema_by_name(thema):
                messagebox.showwarning("Navigation", f"Thema nicht gefunden:\n{thema}")
                return False
            if self.current_thema == thema and not self.unterthemen:
                self._load_unterthemen()
            if self._select_unterthema_by_id(entry_id):
                return True
            if not self.show_archived_var.get():
                self.show_archived_var.set(True)
                self._load_unterthemen()
                if self._select_unterthema_by_id(entry_id):
                    return True
            messagebox.showwarning("Navigation", "Unterthema nicht gefunden.")
            return False
        finally:
            self._suppress_navigation_history = previous_suppression

    def _select_thema_by_name(self, thema):
        for idx in range(self.sidebar.size()):
            display_name = self.sidebar.get(idx)
            internal_name = self._resolve_thema_name(display_name)
            if display_name == thema or internal_name == thema:
                self.sidebar.selection_clear(0, tk.END)
                self.sidebar.selection_set(idx)
                self.sidebar.activate(idx)
                self.sidebar.see(idx)
                self.sidebar.update_idletasks()
                self.current_thema = internal_name
                self.thema_label.config(text=f"Thema: {display_name}")
                self.add_unterthema_btn.config(state="normal")
                self._load_unterthemen()
                return True
        return False

    def _load_unterthemen(self):
        if not self.current_thema:
            return
        self._autosave_current_if_dirty()
        self.is_editing = False
        self._set_edit_mode_indicator(False)
        self.editing_thema = None
        self.editing_unterthema_id = None
        self._stop_autosave()
        self.inhalt_text.unbind("<<Modified>>")
        self.inhalt_text.unbind("<KeyRelease>")
        self.inhalt_text.unbind("<Escape>")
        self.unterthemen_list.delete(0, tk.END)
        self.unterthemen = []
        self._unterthemen_listbox_map = []
        self.current_unterthema_id = None
        self.current_unterthema_archived = False
        self.edit_unterthema_btn.config(state="disabled")
        self.save_unterthema_btn.config(state="disabled")
        self._update_unterthema_actions_state()
        order_choice = self.unterthemen_order_var.get()
        if order_choice in ("Neueste zuerst", "Aelteste zuerst"):
            order_field = "erstellt_am"
            order = "DESC" if order_choice == "Neueste zuerst" else "ASC"
        elif order_choice in ("Zuletzt bearbeitet", "Laengst nicht bearbeitet"):
            order_field = "COALESCE(bearbeitet_am, erstellt_am)"
            order = "DESC" if order_choice == "Zuletzt bearbeitet" else "ASC"
        else:
            order_field = "erstellt_am"
            order = "DESC"
        self._ensure_archived_column(self.current_thema)
        self._ensure_bearbeitet_column(self.current_thema)
        self._ensure_gruppe_column(self.current_thema)
        try:
            show_archived = bool(self.show_archived_var.get())
            where_clause = "" if show_archived else "WHERE archived = 0 "
            cursor = self.conn.execute(
                f"SELECT id, titel, inhalt, archived, gruppe FROM {self.current_thema} "
                f"{where_clause}"
                f"ORDER BY "
                f"CASE WHEN gruppe IS NULL OR gruppe = '' THEN 1 ELSE 0 END, "
                f"gruppe COLLATE NOCASE, "
                f"{order_field} {order}, id {order}"
            )
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthemen konnten nicht geladen werden: {exc}")
            return
        self._unterthemen_listbox_map = []
        current_gruppe = object()  # sentinel – matches nothing initially
        for row in cursor.fetchall():
            entry_id, titel, inhalt, archived, gruppe = row
            gruppe_key = (gruppe or "").strip()
            if gruppe_key and gruppe_key != current_gruppe:
                header_text = f"\u2500\u2500 {gruppe_key} \u2500\u2500"
                self.unterthemen_list.insert(tk.END, header_text)
                header_listbox_idx = self.unterthemen_list.size() - 1
                try:
                    bg = self.unterthemen_list.cget("bg")
                    self.unterthemen_list.itemconfig(
                        header_listbox_idx,
                        fg="#555555",
                        selectforeground="#555555",
                        selectbackground=bg,
                        background="#e8e8e8",
                    )
                except tk.TclError:
                    pass
                self._unterthemen_listbox_map.append(None)
                current_gruppe = gruppe_key
            unterthemen_idx = len(self.unterthemen)
            self.unterthemen.append(row)
            display_titel = titel if titel and titel.strip() else "(ohne Titel)"
            if archived:
                display_titel = f"[ARCHIV] {display_titel}"
            if gruppe_key:
                display_titel = f"  {display_titel}"
            self.unterthemen_list.insert(tk.END, display_titel)
            self._unterthemen_listbox_map.append(unterthemen_idx)
        if not self.unterthemen:
            self._set_unterthema_title("")
            self.current_unterthema_id = None
            self.current_unterthema_archived = False
            self._clear_metadata_panel()
            if self.show_archived_var.get():
                self._set_inhalt_text("Keine Unterthemen vorhanden.")
            else:
                self._set_inhalt_text("Noch keine Unterthemen vorhanden.")
        else:
            self._set_unterthema_title("")
            self.current_unterthema_id = None
            self.current_unterthema_archived = False
            self._clear_metadata_panel()
            self._set_inhalt_text("Waehle links ein Unterthema.")
        self._update_unterthema_actions_state()

    def _select_unterthema_by_id(self, entry_id):
        # Find the index in self.unterthemen
        unterthemen_idx = None
        for i, row in enumerate(self.unterthemen):
            if row[0] == entry_id:
                unterthemen_idx = i
                break
        if unterthemen_idx is None:
            return False
        # Find the corresponding listbox index via the map
        listbox_idx = None
        for i, v in enumerate(self._unterthemen_listbox_map):
            if v == unterthemen_idx:
                listbox_idx = i
                break
        if listbox_idx is None:
            return False
        row = self.unterthemen[unterthemen_idx]
        previous = self._get_current_navigation_location()
        self.unterthemen_list.selection_clear(0, tk.END)
        self.unterthemen_list.selection_set(listbox_idx)
        self.unterthemen_list.activate(listbox_idx)
        self.unterthemen_list.see(listbox_idx)
        self.unterthemen_list.update_idletasks()
        _, titel, inhalt, archived, _gruppe = row
        start = time.perf_counter()
        fresh = self._fetch_unterthema_by_id(entry_id, include_archived=bool(archived))
        if fresh:
            titel, inhalt, _code_spans, _bold_spans = fresh
        self.current_unterthema_id = entry_id
        self.current_unterthema_archived = bool(archived)
        self._record_navigation_from(previous)
        self._set_unterthema_title(titel, (time.perf_counter() - start) * 1000)
        self._load_metadata_panel(self.current_thema, entry_id)
        self._set_inhalt_text(inhalt)
        if self.current_unterthema_archived:
            self.edit_unterthema_btn.config(state="disabled")
        else:
            self.edit_unterthema_btn.config(state="normal")
        self.save_unterthema_btn.config(state="disabled")
        self._update_unterthema_actions_state()
        return True

    def _fetch_unterthema_by_id(self, entry_id, include_archived=False):
        if not self.current_thema:
            return None
        self._ensure_archived_column(self.current_thema)
        try:
            if include_archived:
                query = f"SELECT titel, inhalt FROM {self.current_thema} WHERE id = ?"
                params = (entry_id,)
            else:
                query = f"SELECT titel, inhalt FROM {self.current_thema} WHERE id = ? AND archived = 0"
                params = (entry_id,)
            row = self.conn.execute(
                query,
                params,
            ).fetchone()
        except sqlite3.Error:
            return None
        if not row:
            return None
        inhalt = row[1] or ""
        inhalt = self._convert_legacy_markup_to_markdown(inhalt)
        return row[0], inhalt, None, None

    def _on_change_unterthemen_order(self, *_args):
        if self.current_thema:
            self._load_unterthemen()

    def _on_change_themen_order(self, *_args):
        self._refresh_themen()

    def _on_select_unterthema(self, _event):
        selection = self.unterthemen_list.curselection()
        if not selection:
            return
        listbox_idx = selection[0]
        if listbox_idx >= len(self._unterthemen_listbox_map):
            return
        unterthemen_idx = self._unterthemen_listbox_map[listbox_idx]
        if unterthemen_idx is None:
            # Group header clicked — deselect it
            self.unterthemen_list.selection_clear(listbox_idx, listbox_idx)
            return
        self._autosave_current_if_dirty()
        self.is_editing = False
        self._set_edit_mode_indicator(False)
        self.editing_thema = None
        self.editing_unterthema_id = None
        self._stop_autosave()
        self.inhalt_text.unbind("<<Modified>>")
        self.inhalt_text.unbind("<KeyRelease>")
        self.inhalt_text.unbind("<Escape>")
        if unterthemen_idx >= len(self.unterthemen):
            return
        entry_id, titel, inhalt, archived, _gruppe = self.unterthemen[unterthemen_idx]
        previous = self._get_current_navigation_location()
        start = time.perf_counter()
        fresh = self._fetch_unterthema_by_id(entry_id, include_archived=bool(archived))
        if fresh:
            titel, inhalt, _code_spans, _bold_spans = fresh
        self.current_unterthema_id = entry_id
        self.current_unterthema_archived = bool(archived)
        self._record_navigation_from(previous)
        self._set_unterthema_title(titel, (time.perf_counter() - start) * 1000)
        self._load_metadata_panel(self.current_thema, entry_id)
        self._set_inhalt_text(inhalt)
        if self.current_unterthema_archived:
            self.edit_unterthema_btn.config(state="disabled")
        else:
            self.edit_unterthema_btn.config(state="normal")
        self.save_unterthema_btn.config(state="disabled")
        self._update_unterthema_actions_state()

    def _set_inhalt_text(self, text, code_spans=None, bold_spans=None):
        if not self.is_editing and self.show_markdown_var.get():
            rendered, spans = self._render_markdown(text)
            self.inhalt_text.config(state="normal")
            self.inhalt_text.delete("1.0", tk.END)
            self.inhalt_text.insert("1.0", rendered)
            self._clear_markdown_tags(self.inhalt_text)
            self._clear_link_targets(self.inhalt_text)
            self._apply_markdown_spans(self.inhalt_text, spans)
            self._linkify_text_widget(self.inhalt_text, rendered)
            self.inhalt_text.config(state="disabled")
            self._update_inhalt_line_numbers()
            self._set_autosave_status(saved=True)
            return
        self.inhalt_text.config(state="normal")
        self.inhalt_text.delete("1.0", tk.END)
        self.inhalt_text.insert("1.0", text)
        self._clear_markdown_tags(self.inhalt_text)
        self._clear_link_targets(self.inhalt_text)
        self._linkify_text_widget(self.inhalt_text, text)
        self.inhalt_text.config(state="disabled")
        self._update_inhalt_line_numbers()
        self._set_autosave_status(saved=True)

    def _set_widget_text_editable(self, widget, text, code_spans=None, bold_spans=None):
        widget.config(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        self._clear_markdown_tags(widget)
        self._clear_link_targets(widget)
        self._linkify_text_widget(widget, text)

    def _set_readonly_text_widget_content(self, widget, text):
        if self.show_markdown_var.get():
            rendered, spans = self._render_markdown(text)
            widget.config(state="normal")
            widget.delete("1.0", tk.END)
            widget.insert("1.0", rendered)
            self._clear_markdown_tags(widget)
            self._clear_link_targets(widget)
            self._apply_markdown_spans(widget, spans)
            self._linkify_text_widget(widget, rendered)
            widget.config(state="disabled")
            if widget is self._unterthema_preview_text:
                self._update_preview_line_numbers()
            return
        widget.config(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        self._clear_markdown_tags(widget)
        self._clear_link_targets(widget)
        self._linkify_text_widget(widget, text)
        widget.config(state="disabled")
        if widget is self._unterthema_preview_text:
            self._update_preview_line_numbers()

    def _set_inhalt_text_editable(self, text, code_spans=None, bold_spans=None):
        self._set_widget_text_editable(self.inhalt_text, text, code_spans, bold_spans)
        self._update_inhalt_line_numbers()

    def _update_line_numbers_for_widget(self, text_widget, line_numbers_widget):
        if not self.show_line_numbers_var.get():
            return
        if text_widget is None or line_numbers_widget is None:
            return
        try:
            if not text_widget.winfo_exists() or not line_numbers_widget.winfo_exists():
                return
        except tk.TclError:
            return
        line_count = int(text_widget.index("end-1c").split(".")[0])
        width = max(4, len(str(line_count)) + 1)
        numbers = "\n".join(str(i) for i in range(1, line_count + 1))
        line_numbers_widget.config(state="normal", width=width)
        line_numbers_widget.delete("1.0", tk.END)
        line_numbers_widget.insert("1.0", numbers)
        line_numbers_widget.config(state="disabled")

    def _update_inhalt_line_numbers(self):
        self._update_line_numbers_for_widget(self.inhalt_text, self.inhalt_linenumbers)

    def _update_preview_line_numbers(self):
        self._update_line_numbers_for_widget(
            self._unterthema_preview_text, self._unterthema_preview_linenumbers
        )

    def _apply_inhalt_line_numbers_visibility(self):
        show = self.show_line_numbers_var.get()
        if show:
            if not self.inhalt_linenumbers.winfo_ismapped():
                self.inhalt_linenumbers.pack(side="left", fill="y", padx=(0, 6))
            self._update_inhalt_line_numbers()
            first, _last = self.inhalt_text.yview()
            self.inhalt_linenumbers.yview_moveto(first)
        else:
            if self.inhalt_linenumbers.winfo_ismapped():
                self.inhalt_linenumbers.pack_forget()
        self._apply_preview_line_numbers_visibility()

    def _apply_preview_line_numbers_visibility(self):
        text = self._unterthema_preview_text
        numbers = self._unterthema_preview_linenumbers
        if text is None or numbers is None:
            return
        try:
            if not text.winfo_exists() or not numbers.winfo_exists():
                return
        except tk.TclError:
            return
        show = self.show_line_numbers_var.get()
        if show:
            if not numbers.winfo_ismapped():
                numbers.pack(side="left", fill="y", padx=(0, 6))
            self._update_preview_line_numbers()
            first, _last = text.yview()
            numbers.yview_moveto(first)
        else:
            if numbers.winfo_ismapped():
                numbers.pack_forget()

    def _on_inhalt_scroll(self, first, last):
        self.inhalt_scroll.set(first, last)
        if self.show_line_numbers_var.get():
            self.inhalt_linenumbers.yview_moveto(first)

    def _on_inhalt_scrollbar(self, *args):
        self.inhalt_text.yview(*args)
        if self.show_line_numbers_var.get():
            self.inhalt_linenumbers.yview(*args)

    def _on_preview_inhalt_scroll(self, first, last):
        if self._unterthema_preview_scroll is not None:
            self._unterthema_preview_scroll.set(first, last)
        if self.show_line_numbers_var.get() and self._unterthema_preview_linenumbers is not None:
            self._unterthema_preview_linenumbers.yview_moveto(first)

    def _on_preview_inhalt_scrollbar(self, *args):
        if self._unterthema_preview_text is None:
            return
        self._unterthema_preview_text.yview(*args)
        if self.show_line_numbers_var.get() and self._unterthema_preview_linenumbers is not None:
            self._unterthema_preview_linenumbers.yview(*args)

    def _set_unterthema_title(self, titel, load_ms=None):
        self.unterthema_title_label.config(text=titel)

    def _clear_metadata_panel(self):
        self.current_metadata_fields = []
        self._refresh_metadata_panel()

    def _load_metadata_panel(self, thema, entry_id):
        self.current_metadata_fields = self._get_entry_fields(thema, entry_id)
        self._refresh_metadata_panel()

    def _toggle_metadata_panel(self):
        self.metadata_expanded_var.set(not self.metadata_expanded_var.get())
        self._refresh_metadata_panel()

    def _refresh_metadata_panel(self):
        if not hasattr(self, "metadata_toggle_btn"):
            return
        count = len(self.current_metadata_fields)
        prefix = "v" if self.metadata_expanded_var.get() else ">"
        self.metadata_toggle_btn.config(text=f"{prefix} Felder ({count})")
        has_entry = bool(self.current_thema and self.current_unterthema_id)
        self.metadata_edit_btn.config(state="normal" if has_entry else "disabled")

        for child in self.metadata_body.winfo_children():
            child.pack_forget()
            child.grid_forget()
        if not self.metadata_expanded_var.get():
            self.metadata_body.pack_forget()
            return

        self.metadata_body.pack(fill="x", padx=(18, 0), pady=(2, 2))
        if not self.current_metadata_fields:
            self.metadata_empty_label.pack(fill="x", anchor="w")
            return

        for row_idx, (key, value) in enumerate(self.current_metadata_fields):
            key_label = tk.Label(
                self.metadata_body,
                text=key,
                anchor="w",
                width=18,
                fg="#333333",
            )
            key_label.grid(row=row_idx, column=0, sticky="nw", padx=(0, 8), pady=1)
            value_label = tk.Label(
                self.metadata_body,
                text=value,
                anchor="w",
                justify="left",
                wraplength=700,
            )
            url = self._get_metadata_value_url(value)
            if url:
                value_label.config(fg="#0a58ca", cursor="hand2")
                underline_font = tkfont.Font(font=value_label.cget("font"))
                underline_font.configure(underline=True)
                value_label.config(font=underline_font)
                value_label.bind(
                    "<Button-1>",
                    lambda _event, link=url: self._open_metadata_value_link(link),
                )
            value_label.bind(
                "<Button-3>",
                lambda event, text=value: self._show_metadata_value_context_menu(event, text),
            )
            value_label.grid(row=row_idx, column=1, sticky="we", pady=1)
        self.metadata_body.grid_columnconfigure(1, weight=1)

    def _show_metadata_value_context_menu(self, event, value):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(
            label="Kopieren",
            command=lambda text=value: self._copy_metadata_value(text),
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_metadata_value(self, value):
        self.clipboard_clear()
        self.clipboard_append(value or "")

    def _get_metadata_value_url(self, value):
        value = (value or "").strip()
        markdown_match = re.search(r"\[[^\]]+\]\(([^)]+)\)", value)
        if markdown_match:
            return markdown_match.group(1).strip()
        match = re.search(r"(wissensdb://[^\s]+|https?://[^\s]+|www\.[^\s]+)", value)
        if not match:
            return None
        url = match.group(0)
        while url and url[-1] in ".,;:)!?]":
            url = url[:-1]
        return url or None

    def _open_metadata_value_link(self, url):
        if not url:
            return "break"
        if url.startswith("wissensdb://"):
            self._open_internal_link(url)
            return "break"
        if url.startswith("www."):
            url = f"http://{url}"
        webbrowser.open(url)
        return "break"

    def _open_metadata_dialog(self):
        if not self.current_thema or not self.current_unterthema_id:
            messagebox.showwarning("Felder", "Bitte zuerst ein Unterthema auswaehlen.")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Felder bearbeiten")
        dialog.transient(self)
        dialog.resizable(True, True)

        table = tk.Frame(dialog)
        table.grid(row=0, column=0, columnspan=3, padx=12, pady=(12, 6), sticky="nsew")
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(1, weight=1)

        tk.Label(table, text="Feld", anchor="w").grid(row=0, column=0, sticky="we", padx=(0, 8))
        tk.Label(table, text="Wert", anchor="w").grid(row=0, column=1, sticky="we", padx=(0, 8))

        rows = []

        def redraw_rows():
            for child in table.grid_slaves():
                info = child.grid_info()
                if int(info.get("row", 0)) > 0:
                    child.destroy()
            for idx, row in enumerate(rows, start=1):
                key_entry = tk.Entry(table, textvariable=row["key"], width=20)
                key_entry.grid(row=idx, column=0, sticky="we", padx=(0, 8), pady=2)
                value_entry = tk.Entry(table, textvariable=row["value"], width=48)
                value_entry.grid(row=idx, column=1, sticky="we", padx=(0, 8), pady=2)
                remove_btn = tk.Button(
                    table,
                    text="X",
                    width=3,
                    command=lambda pos=idx - 1: remove_row(pos),
                )
                remove_btn.grid(row=idx, column=2, sticky="e", pady=2)

        def add_row(key="", value=""):
            rows.append(
                {
                    "key": tk.StringVar(value=key),
                    "value": tk.StringVar(value=value),
                }
            )
            redraw_rows()

        def remove_row(pos):
            if 0 <= pos < len(rows):
                del rows[pos]
                redraw_rows()

        def collect_fields():
            return [(row["key"].get(), row["value"].get()) for row in rows]

        def save():
            if not self._save_entry_fields(
                self.current_thema,
                self.current_unterthema_id,
                collect_fields(),
            ):
                return
            self._load_metadata_panel(self.current_thema, self.current_unterthema_id)
            dialog.destroy()

        for key, value in self.current_metadata_fields:
            add_row(key, value)
        if not rows:
            add_row()

        add_btn = tk.Button(dialog, text="+ Feld", command=add_row)
        add_btn.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="w")

        save_btn = tk.Button(dialog, text="Speichern", command=save)
        save_btn.grid(row=1, column=1, padx=12, pady=(0, 12), sticky="e")

        cancel_btn = tk.Button(dialog, text="Abbrechen", command=dialog.destroy)
        cancel_btn.grid(row=1, column=2, padx=12, pady=(0, 12), sticky="e")

    def _set_edit_mode_indicator(self, active):
        if not hasattr(self, "edit_mode_status_frame"):
            return
        if active:
            if not self.edit_mode_status_frame.winfo_ismapped():
                self.edit_mode_status_frame.pack(
                    side="left",
                    padx=(0, 10),
                    before=self.autosave_status_frame,
                )
        elif self.edit_mode_status_frame.winfo_ismapped():
            self.edit_mode_status_frame.pack_forget()
        preview_status = getattr(self, "_unterthema_preview_status_frame", None)
        if preview_status is None:
            return
        try:
            exists = preview_status.winfo_exists()
        except tk.TclError:
            exists = False
        if not exists:
            return
        if active:
            if not preview_status.winfo_ismapped():
                preview_status.pack(side="right")
        elif preview_status.winfo_ismapped():
            preview_status.pack_forget()

    def _show_inhalt_context_menu(self, event):
        try:
            self._inhalt_context_index = self.inhalt_text.index(f"@{event.x},{event.y}")
            self.inhalt_text.mark_set("insert", self._inhalt_context_index)
            self._refresh_markdown_context_label()
            self.inhalt_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.inhalt_context_menu.grab_release()

    def _show_unterthemen_context_menu(self, event):
        if self.unterthemen_list.size() == 0:
            return
        idx = self.unterthemen_list.nearest(event.y)
        if idx is None:
            return
        if idx < len(self._unterthemen_listbox_map) and self._unterthemen_listbox_map[idx] is None:
            return  # group header — no context menu
        self.unterthemen_list.selection_clear(0, tk.END)
        self.unterthemen_list.selection_set(idx)
        self.unterthemen_list.see(idx)
        try:
            self.unterthemen_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.unterthemen_context_menu.grab_release()

    def _show_unterthema_preview_context_menu(self, event):
        if self._unterthema_preview_text is None:
            return
        try:
            self._unterthema_preview_context_index = self._unterthema_preview_text.index(
                f"@{event.x},{event.y}"
            )
            self._unterthema_preview_text.mark_set("insert", self._unterthema_preview_context_index)
            self._unterthema_preview_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._unterthema_preview_context_menu.grab_release()

    def _get_selected_unterthema_row(self, warn=False):
        selection = self.unterthemen_list.curselection()
        if not selection:
            if warn:
                messagebox.showwarning("Kein Unterthema", "Bitte zuerst ein Unterthema auswaehlen.")
            return None
        listbox_idx = selection[0]
        if listbox_idx >= len(self._unterthemen_listbox_map):
            return None
        unterthemen_idx = self._unterthemen_listbox_map[listbox_idx]
        if unterthemen_idx is None:
            if warn:
                messagebox.showwarning("Kein Unterthema", "Bitte zuerst ein Unterthema auswaehlen.")
            return None
        if unterthemen_idx >= len(self.unterthemen):
            return None
        return self.unterthemen[unterthemen_idx]

    def _get_unterthema_content(self, row):
        entry_id, titel, inhalt, archived, _gruppe = row
        fresh = self._fetch_unterthema_by_id(entry_id, include_archived=bool(archived))
        if fresh:
            titel, inhalt, _code_spans, _bold_spans = fresh
        return entry_id, titel, inhalt, bool(archived)

    def _close_unterthema_preview_window(self):
        if self._editing_in_preview:
            self._save_inhalt_edit()
            if self._editing_in_preview:
                return
        if self._unterthema_preview_window is not None:
            try:
                self._unterthema_preview_window.destroy()
            except tk.TclError:
                pass
        self._unterthema_preview_window = None
        self._unterthema_preview_text = None
        self._unterthema_preview_context_menu = None
        self._unterthema_preview_status_frame = None
        self._unterthema_preview_linenumbers = None
        self._unterthema_preview_scroll = None
        self._unterthema_preview_entry_id = None

    def _ensure_unterthema_preview_window(self):
        if self._unterthema_preview_window is not None:
            try:
                if self._unterthema_preview_window.winfo_exists():
                    return self._unterthema_preview_window, self._unterthema_preview_text
            except tk.TclError:
                pass
        preview = tk.Toplevel(self)
        preview.title("Unterthema")
        preview.geometry("900x600")
        preview.minsize(480, 320)
        preview.protocol("WM_DELETE_WINDOW", self._close_unterthema_preview_window)

        header = tk.Frame(preview)
        header.pack(fill="x", padx=12, pady=(12, 0))

        self._unterthema_preview_status_frame = tk.Frame(header)
        preview_edit_label = tk.Label(
            self._unterthema_preview_status_frame, text="Bearbeitung:", anchor="e"
        )
        preview_edit_label.pack(side="left", padx=(0, 4))
        preview_indicator = tk.Canvas(
            self._unterthema_preview_status_frame,
            width=10,
            height=10,
            highlightthickness=0,
            bd=0,
            bg=header.cget("bg"),
        )
        preview_indicator.pack(side="left")
        preview_indicator.create_oval(1, 1, 9, 9, fill="#2ecc71", outline="")

        frame = tk.Frame(preview)
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        preview_linenumbers = tk.Text(
            frame,
            wrap="none",
            height=18,
            width=4,
            state="disabled",
            takefocus=0,
            bd=0,
            padx=4,
            bg="#f0f0f0",
            fg="#555555",
        )

        text = tk.Text(frame, wrap="word", state="disabled", takefocus=1)
        text.pack(side="left", fill="both", expand=True)
        preview_linenumbers.config(font=text.cget("font"))
        self._prepare_link_handling(text)
        self._prepare_code_handling(text)
        self._prepare_bold_handling(text)
        self._prepare_markdown_handling(text)
        text.bind("<Double-Button-1>", self._start_preview_inhalt_edit)
        self._unterthema_preview_context_menu = tk.Menu(preview, tearoff=0)
        self._unterthema_preview_context_menu.add_command(
            label="Kopieren", command=self._copy_unterthema_preview_selection
        )
        self._unterthema_preview_context_menu.add_command(
            label="Codeblock kopieren", command=self._copy_unterthema_preview_codeblock_from_context
        )
        text.bind("<Button-3>", self._show_unterthema_preview_context_menu)

        scroll = tk.Scrollbar(frame, orient="vertical", command=self._on_preview_inhalt_scrollbar)
        scroll.pack(side="right", fill="y")
        text.config(yscrollcommand=self._on_preview_inhalt_scroll)

        self._unterthema_preview_window = preview
        self._unterthema_preview_linenumbers = preview_linenumbers
        self._unterthema_preview_scroll = scroll
        self._unterthema_preview_text = text
        self._apply_preview_line_numbers_visibility()
        self._set_edit_mode_indicator(self.is_editing)
        return preview, text

    def _open_unterthema_in_separate_window(self):
        row = self._get_selected_unterthema_row(warn=True)
        if not row:
            return
        entry_id, titel, inhalt, archived = self._get_unterthema_content(row)
        preview, text = self._ensure_unterthema_preview_window()
        prefix = "[ARCHIV] " if archived else ""
        preview.title(f"Unterthema: {prefix}{titel or '(ohne Titel)'}")
        self._set_readonly_text_widget_content(text, inhalt or "")
        self._unterthema_preview_entry_id = entry_id
        preview.deiconify()
        preview.lift()
        text.focus_set()
        text.mark_set("insert", "1.0")
        text.see("1.0")

    def _copy_unterthema_name(self):
        row = self._get_selected_unterthema_row()
        if not row:
            return
        _entry_id, titel, _inhalt, archived, _gruppe = row
        name = titel or "(ohne Titel)"
        if archived:
            name = f"[ARCHIV] {name}"
        self.clipboard_clear()
        self.clipboard_append(name)

    def _copy_text_widget_selection(self, widget):
        try:
            selected = widget.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            return
        self.clipboard_clear()
        self.clipboard_append(selected)

    def _copy_unterthema_preview_selection(self):
        if self._unterthema_preview_text is None:
            return
        self._copy_text_widget_selection(self._unterthema_preview_text)

    def _get_active_inhalt_widget(self):
        if self._editing_in_preview and self._unterthema_preview_text is not None:
            try:
                if self._unterthema_preview_text.winfo_exists():
                    return self._unterthema_preview_text
            except tk.TclError:
                pass
        return self.inhalt_text

    def _start_preview_inhalt_edit(self, _event=None):
        if self._unterthema_preview_text is None or self._unterthema_preview_entry_id is None:
            return "break"
        if self.is_editing and not self._editing_in_preview:
            self._save_inhalt_edit()
            if self.is_editing:
                return "break"
        if self._editing_in_preview:
            return "break"
        if not self._select_unterthema_by_id(self._unterthema_preview_entry_id):
            return "break"
        if self.current_unterthema_archived:
            messagebox.showinfo("Archiv", "Archivierte Unterthemen koennen nicht bearbeitet werden.")
            return "break"
        self._enable_inhalt_edit(editor_widget=self._unterthema_preview_text)
        return "break"

    def _on_unterthemen_hover(self, event):
        if self.unterthemen_list.size() == 0:
            self._hide_unterthemen_tooltip(event)
            return
        idx = self.unterthemen_list.nearest(event.y)
        if idx is None:
            self._hide_unterthemen_tooltip(event)
            return
        # Don't show tooltip for group headers
        if idx < len(self._unterthemen_listbox_map) and self._unterthemen_listbox_map[idx] is None:
            self._hide_unterthemen_tooltip(event)
            return
        text = self.unterthemen_list.get(idx)
        if not text:
            self._hide_unterthemen_tooltip(event)
            return
        if getattr(self, "_unterthemen_tooltip_index", None) == idx:
            return
        self._unterthemen_tooltip_index = idx
        self._show_unterthemen_tooltip(event.x_root, event.y_root, text)

    def _show_unterthemen_tooltip(self, x_root, y_root, text):
        self._hide_unterthemen_tooltip()
        tip = tk.Toplevel(self)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x_root + 16}+{y_root + 16}")
        label = tk.Label(
            tip,
            text=text,
            background="#ffffe0",
            relief="solid",
            borderwidth=1,
            padx=6,
            pady=2,
        )
        label.pack()
        self._unterthemen_tooltip = tip

    def _hide_unterthemen_tooltip(self, _event=None):
        tip = getattr(self, "_unterthemen_tooltip", None)
        if tip is not None:
            try:
                tip.destroy()
            except tk.TclError:
                pass
        self._unterthemen_tooltip = None
        self._unterthemen_tooltip_index = None

    def _copy_inhalt_selection(self):
        self._copy_text_widget_selection(self.inhalt_text)

    def _copy_codeblock_from_context(self):
        index = getattr(self, "_inhalt_context_index", None) or self.inhalt_text.index(tk.INSERT)
        codeblock = self._get_codeblock_for_widget(
            self.inhalt_text,
            index,
            rendered_markdown=not self.is_editing and self.show_markdown_var.get(),
        )
        if not codeblock:
            messagebox.showinfo("Codeblock", "Am aktuellen Punkt wurde kein Codeblock gefunden.")
            return
        self.clipboard_clear()
        self.clipboard_append(codeblock)

    def _copy_unterthema_preview_codeblock_from_context(self):
        if self._unterthema_preview_text is None:
            return
        index = getattr(self, "_unterthema_preview_context_index", None)
        if not index:
            index = self._unterthema_preview_text.index(tk.INSERT)
        codeblock = self._get_codeblock_for_widget(
            self._unterthema_preview_text,
            index,
            rendered_markdown=self.show_markdown_var.get(),
        )
        if not codeblock:
            messagebox.showinfo("Codeblock", "Am aktuellen Punkt wurde kein Codeblock gefunden.")
            return
        self.clipboard_clear()
        self.clipboard_append(codeblock)

    def _get_codeblock_for_widget(self, widget, index, rendered_markdown=False):
        if not index:
            return None
        if rendered_markdown:
            return self._get_markdown_codeblock_for_widget(widget, index)
        return self._get_fenced_codeblock_for_widget(widget, index)

    def _get_markdown_codeblock_for_index(self, index):
        return self._get_markdown_codeblock_for_widget(self.inhalt_text, index)

    def _get_markdown_codeblock_for_widget(self, widget, index):
        line = int(widget.index(index).split(".")[0])
        if self._line_has_text_tag(widget, line, "md_codeblock_header"):
            line += 1
        if not self._line_has_text_tag(widget, line, "md_codeblock"):
            return None

        start_line = line
        while start_line > 1 and self._line_has_text_tag(widget, start_line - 1, "md_codeblock"):
            start_line -= 1

        end_line = line
        last_line = int(widget.index("end-1c").split(".")[0])
        while end_line < last_line and self._line_has_text_tag(widget, end_line + 1, "md_codeblock"):
            end_line += 1

        lines = []
        for current_line in range(start_line, end_line + 1):
            lines.append(widget.get(f"{current_line}.0", f"{current_line}.end"))
        return "\n".join(lines).rstrip("\n")

    def _line_has_text_tag(self, widget, line_no, tag_name):
        start = f"{line_no}.0"
        end = f"{line_no}.end"
        return bool(widget.tag_nextrange(tag_name, start, end))

    def _get_fenced_codeblock_for_index(self, index):
        return self._get_fenced_codeblock_for_widget(self.inhalt_text, index)

    def _get_fenced_codeblock_for_widget(self, widget, index):
        text = widget.get("1.0", "end-1c")
        lines = text.splitlines()
        if not lines:
            return None
        line_no = int(widget.index(index).split(".")[0]) - 1
        if line_no < 0 or line_no >= len(lines):
            return None

        start_line = None
        for pos in range(line_no, -1, -1):
            if re.match(r"^\s*```", lines[pos]):
                start_line = pos
                break
        if start_line is None:
            return None

        end_line = None
        for pos in range(start_line + 1, len(lines)):
            if re.match(r"^\s*```", lines[pos]):
                end_line = pos
                break
        if end_line is None or line_no <= start_line or line_no >= end_line:
            return None

        return "\n".join(lines[start_line + 1 : end_line]).rstrip("\n")

    def _refresh_markdown_context_label(self):
        if not hasattr(self, "inhalt_context_menu"):
            return
        try:
            state = self.show_markdown_var.get()
        except tk.TclError:
            return
        label = "Markdown ausschalten" if state else "Markdown einschalten"
        try:
            self.inhalt_context_menu.entryconfig("Markdown an/aus", label=label)
        except tk.TclError:
            pass

    def _update_markdown_status_label(self):
        if not hasattr(self, "markdown_status_label"):
            return
        state = "an" if self.show_markdown_var.get() else "aus"
        self.markdown_status_label.config(text=f"Markdown: {state}")

    def _toggle_markdown_from_context(self):
        value = not self.show_markdown_var.get()
        if self._set_setting("unterthema_markdown", "1" if value else "0"):
            self.show_markdown_var.set(value)
            self._update_markdown_status_label()
            if self.current_unterthema_id and not self.is_editing:
                self._select_unterthema_by_id(self.current_unterthema_id)
            elif not self.is_editing:
                current = self.inhalt_text.get("1.0", "end-1c")
                self._set_inhalt_text(current)

    def _select_all_inhalt(self):
        prev_state = self.inhalt_text.cget("state")
        if prev_state == "disabled":
            self.inhalt_text.config(state="normal")
        self.inhalt_text.tag_add("sel", "1.0", "end-1c")
        self.inhalt_text.mark_set("insert", "1.0")
        self.inhalt_text.see("insert")
        if prev_state == "disabled":
            self.inhalt_text.config(state="disabled")

    def _paste_inhalt_clipboard(self):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return
        prev_state = self.inhalt_text.cget("state")
        if prev_state == "disabled":
            self.inhalt_text.config(state="normal")
        self.inhalt_text.insert(tk.INSERT, text)
        if prev_state == "disabled":
            self.inhalt_text.config(state="disabled")

    def _toggle_checklist_item_from_context(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Umschalten bitte zuerst Bearbeiten klicken.")
            return
        editor = self._get_active_inhalt_widget()
        try:
            index = getattr(self, "_inhalt_context_index", None) or editor.index(tk.INSERT)
            line_no = editor.index(index).split(".")[0]
            start = f"{line_no}.0"
            end = f"{line_no}.end"
            line = editor.get(start, end)
        except tk.TclError:
            return

        match = re.match(r"^(\s*[-*+]\s+\[)([ xX])(\]\s+.*)$", line)
        if match:
            next_state = " " if match.group(2).lower() == "x" else "x"
            new_line = f"{match.group(1)}{next_state}{match.group(3)}"
        else:
            stripped = line.strip()
            new_line = "- [ ] " + stripped if stripped else "- [ ] "
        editor.delete(start, end)
        editor.insert(start, new_line)
        self._set_autosave_status(saved=False)
        self._schedule_autosave()

    def _insert_internal_link_from_context(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Verlinken bitte zuerst Bearbeiten klicken.")
            return
        editor = self._get_active_inhalt_widget()
        selection = self._get_link_label_selection(editor)
        if selection is None:
            messagebox.showinfo("Interner Link", "Bitte zuerst ein Wort oder Text markieren.")
            return
        start, end, label = selection
        target = self._choose_internal_link_target()
        if not target:
            return
        thema, entry_id, _titel = target
        clean_label = self._normalize_link_label(label)
        editor.delete(start, end)
        editor.insert(start, f"[{clean_label}](wissensdb://{thema}/{entry_id})")
        self._set_autosave_status(saved=False)
        self._schedule_autosave()

    def _insert_external_link_from_context(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Verlinken bitte zuerst Bearbeiten klicken.")
            return
        editor = self._get_active_inhalt_widget()
        selection = self._get_link_label_selection(editor)
        if selection is None:
            messagebox.showinfo("Internet-Link", "Bitte zuerst ein Wort oder Text markieren.")
            return
        start, end, label = selection
        url = simpledialog.askstring(
            "Internet-Link",
            "URL eingeben (z.B. https://example.org):",
            parent=self,
        )
        if url is None:
            return
        clean_url = self._normalize_external_link_target(url)
        if not clean_url:
            messagebox.showwarning("Internet-Link", "Bitte eine gueltige URL eingeben.")
            return
        clean_label = self._normalize_link_label(label)
        editor.delete(start, end)
        editor.insert(start, f"[{clean_label}]({clean_url})")
        self._set_autosave_status(saved=False)
        self._schedule_autosave()

    def _normalize_link_label(self, label):
        cleaned = (label or "").strip()
        # Avoid broken markdown like [[Titel]](wissensdb://...), which can happen
        # if bracketed text is selected as link label.
        if len(cleaned) >= 2 and cleaned.startswith("[") and cleaned.endswith("]"):
            inner = cleaned[1:-1].strip()
            if inner:
                cleaned = inner
        return cleaned or (label or "")

    def _normalize_external_link_target(self, value):
        url = (value or "").strip()
        if not url:
            return None
        if url.startswith("www."):
            return f"https://{url}"
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
            return url
        if re.match(r"^[^\s/]+\.[^\s/]+", url):
            return f"https://{url}"
        return None

    def _get_link_label_selection(self, widget):
        try:
            start = widget.index(tk.SEL_FIRST)
            end = widget.index(tk.SEL_LAST)
        except tk.TclError:
            cursor = getattr(self, "_inhalt_context_index", None) or widget.index(tk.INSERT)
            start = widget.index(f"{cursor} wordstart")
            end = widget.index(f"{cursor} wordend")
        label = widget.get(start, end)
        if not label or not label.strip() or "\n" in label:
            return None
        return start, end, label

    def _choose_internal_link_target(self):
        candidates = self._get_internal_link_candidates()
        if not candidates:
            messagebox.showinfo("Interner Link", "Keine Unterthemen zum Verlinken gefunden.")
            return None

        dialog = tk.Toplevel(self)
        dialog.title("Interner Link")
        dialog.transient(self)
        dialog.resizable(True, True)
        dialog.geometry("520x360")

        result = {"value": None}
        query_var = tk.StringVar()

        search_entry = tk.Entry(dialog, textvariable=query_var)
        search_entry.pack(fill="x", padx=12, pady=(12, 6))

        list_frame = tk.Frame(dialog)
        list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        listbox = tk.Listbox(list_frame, height=12)
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        scrollbar.pack(side="right", fill="y")
        listbox.config(yscrollcommand=scrollbar.set)

        visible = []

        def refresh_list(*_args):
            nonlocal visible
            query = query_var.get().strip().lower()
            listbox.delete(0, tk.END)
            visible = []
            for candidate in candidates:
                thema, entry_id, titel = candidate
                label = f"{self._display_thema_name(thema)} -> {titel or '(ohne Titel)'}"
                if query and query not in label.lower():
                    continue
                visible.append(candidate)
                listbox.insert(tk.END, label)
            if visible:
                listbox.selection_set(0)
                listbox.activate(0)

        def choose(_event=None):
            selection = listbox.curselection()
            if not selection:
                return
            idx = selection[0]
            if idx < len(visible):
                result["value"] = visible[idx]
                dialog.destroy()

        btn_frame = tk.Frame(dialog)
        btn_frame.pack(fill="x", padx=12, pady=(0, 12))
        tk.Button(btn_frame, text="Verlinken", command=choose).pack(side="left")
        tk.Button(btn_frame, text="Abbrechen", command=dialog.destroy).pack(side="right")

        query_var.trace_add("write", refresh_list)
        search_entry.bind("<Return>", choose)
        listbox.bind("<Double-Button-1>", choose)
        refresh_list()
        search_entry.focus_set()
        dialog.grab_set()
        self.wait_window(dialog)
        return result["value"]

    def _get_internal_link_candidates(self):
        candidates = []
        for thema in self._get_themen_tables():
            try:
                self._ensure_archived_column(thema)
                cursor = self.conn.execute(
                    f"SELECT id, titel FROM {thema} WHERE archived = 0 ORDER BY titel COLLATE NOCASE, id"
                )
            except sqlite3.Error:
                continue
            for entry_id, titel in cursor.fetchall():
                if thema == self.current_thema and entry_id == self.current_unterthema_id:
                    continue
                candidates.append((thema, entry_id, titel or "(ohne Titel)"))
        return candidates

    def _wrap_selection_code(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Codeblock bitte zuerst Bearbeiten klicken.")
            return
        editor = self._get_active_inhalt_widget()
        try:
            start = editor.index(tk.SEL_FIRST)
            end = editor.index(tk.SEL_LAST)
        except tk.TclError:
            return
        selected = editor.get(start, end)
        if "\n" in selected:
            editor.insert(end, "\n```")
            editor.insert(start, "```\n")
        else:
            editor.insert(end, "`")
            editor.insert(start, "`")
        self._set_autosave_status(saved=False)
        self._schedule_autosave()

    def _wrap_selection_code_with_language(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Codeblock bitte zuerst Bearbeiten klicken.")
            return
        editor = self._get_active_inhalt_widget()
        try:
            start = editor.index(tk.SEL_FIRST)
            end = editor.index(tk.SEL_LAST)
        except tk.TclError:
            return
        language = simpledialog.askstring(
            "Codeblock",
            "Sprache/Typ, z.B. bash, powershell, sql, yaml:",
            parent=self,
        )
        if language is None:
            return
        language = re.sub(r"[^A-Za-z0-9_.+-]", "", language.strip())
        selected = editor.get(start, end).strip("\n")
        fence = f"```{language}" if language else "```"
        editor.delete(start, end)
        editor.insert(start, f"{fence}\n{selected}\n```")
        self._set_autosave_status(saved=False)
        self._schedule_autosave()

    def _unwrap_selection_code(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Entfernen bitte zuerst Bearbeiten klicken.")
            return
        removed = False
        editor = self._get_active_inhalt_widget()
        try:
            start = editor.index(tk.SEL_FIRST)
            end = editor.index(tk.SEL_LAST)
            selected = editor.get(start, end)
            if selected.startswith("```\n") and selected.endswith("\n```"):
                editor.delete(start, end)
                editor.insert(start, selected[4:-4])
                removed = True
            elif selected.startswith("`") and selected.endswith("`") and len(selected) >= 2:
                editor.delete(start, end)
                editor.insert(start, selected[1:-1])
                removed = True
            else:
                try:
                    pre = editor.get(f"{start}-1c", start)
                    post = editor.get(end, f"{end}+1c")
                except tk.TclError:
                    pre = ""
                    post = ""
                if pre == "`" and post == "`":
                    editor.delete(end, f"{end}+1c")
                    editor.delete(f"{start}-1c", start)
                    removed = True
        except tk.TclError:
            pass
        if removed:
            self._set_autosave_status(saved=False)
            self._schedule_autosave()

    def _wrap_selection_bold(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Fett markieren bitte zuerst Bearbeiten klicken.")
            return
        editor = self._get_active_inhalt_widget()
        try:
            start = editor.index(tk.SEL_FIRST)
            end = editor.index(tk.SEL_LAST)
        except tk.TclError:
            return
        editor.insert(end, "**")
        editor.insert(start, "**")
        self._set_autosave_status(saved=False)
        self._schedule_autosave()

    def _unwrap_selection_bold(self):
        if not self.is_editing:
            messagebox.showinfo("Bearbeiten", "Zum Entfernen bitte zuerst Bearbeiten klicken.")
            return
        removed = False
        editor = self._get_active_inhalt_widget()
        try:
            start = editor.index(tk.SEL_FIRST)
            end = editor.index(tk.SEL_LAST)
            selected = editor.get(start, end)
            if selected.startswith("**") and selected.endswith("**") and len(selected) >= 4:
                editor.delete(start, end)
                editor.insert(start, selected[2:-2])
                removed = True
            else:
                try:
                    pre = editor.get(f"{start}-2c", start)
                    post = editor.get(end, f"{end}+2c")
                except tk.TclError:
                    pre = ""
                    post = ""
                if pre == "**" and post == "**":
                    editor.delete(end, f"{end}+2c")
                    editor.delete(f"{start}-2c", start)
                    removed = True
        except tk.TclError:
            pass
        if removed:
            self._set_autosave_status(saved=False)
            self._schedule_autosave()

    def _prepare_link_handling(self, widget):
        widget.tag_config("link", foreground="#0a58ca", underline=True)
        widget.tag_bind("link", "<Enter>", lambda _event: widget.config(cursor="hand2"))
        widget.tag_bind("link", "<Leave>", lambda _event: widget.config(cursor=""))
        widget.tag_bind(
            "link",
            "<Button-1>",
            lambda event: self._open_link_at_event(widget, event),
        )

    def _clear_link_targets(self, widget):
        widget.tag_remove("link", "1.0", tk.END)
        widget._wissensdb_link_targets = []

    def _add_link_target(self, widget, start_off, end_off, target):
        text_len = len(widget.get("1.0", "end-1c"))
        start_off = max(0, min(start_off, text_len))
        end_off = max(start_off, min(end_off, text_len))
        if end_off <= start_off:
            return
        start = f"1.0+{start_off}c"
        end = f"1.0+{end_off}c"
        widget.tag_add("link", start, end)
        targets = getattr(widget, "_wissensdb_link_targets", None)
        if targets is None:
            targets = []
            widget._wissensdb_link_targets = targets
        targets.append((start_off, end_off, target))

    def _linkify_text_widget(self, widget, text):
        for match in re.finditer(r"(https?://[^\s]+|www\.[^\s]+)", text):
            start_idx = match.start()
            end_idx = match.end()
            url = match.group(0)
            while url and url[-1] in ".,;:)!?]":
                url = url[:-1]
                end_idx -= 1
            if end_idx <= start_idx:
                continue
            self._add_link_target(widget, start_idx, end_idx, url)

    def _prepare_code_handling(self, widget):
        base = tkfont.Font(font=widget.cget("font"))
        mono = tkfont.Font(
            family="Consolas",
            size=base.cget("size"),
            weight=base.cget("weight"),
        )
        widget.tag_config(
            "code",
            font=mono,
            foreground="#202124",
            background="#f2f2f2",
            spacing1=2,
            spacing3=2,
        )

    def _prepare_bold_handling(self, widget):
        base = tkfont.Font(font=widget.cget("font"))
        bold = tkfont.Font(
            family=base.cget("family"),
            size=base.cget("size"),
            weight="bold",
        )
        widget.tag_config("bold", font=bold, foreground="#b00020")

    def _prepare_markdown_handling(self, widget):
        base = tkfont.Font(font=widget.cget("font"))
        h1 = tkfont.Font(
            family=base.cget("family"),
            size=max(10, base.cget("size") + 4),
            weight="bold",
        )
        h2 = tkfont.Font(
            family=base.cget("family"),
            size=max(10, base.cget("size") + 2),
            weight="bold",
        )
        h3 = tkfont.Font(
            family=base.cget("family"),
            size=max(10, base.cget("size") + 1),
            weight="bold",
        )
        bold_md = tkfont.Font(
            family=base.cget("family"),
            size=base.cget("size"),
            weight="bold",
        )
        italic = tkfont.Font(
            family=base.cget("family"),
            size=base.cget("size"),
            slant="italic",
        )
        mono = tkfont.Font(
            family="Consolas",
            size=base.cget("size"),
            weight=base.cget("weight"),
        )
        widget.tag_config("md_h1", font=h1, spacing1=6, spacing3=6)
        widget.tag_config("md_h2", font=h2, spacing1=4, spacing3=4)
        widget.tag_config("md_h3", font=h3, spacing1=2, spacing3=2)
        widget.tag_config("md_bold", font=bold_md, foreground="#b00020")
        widget.tag_config("md_italic", font=italic, foreground="#202124")
        widget.tag_config("md_code", font=mono, background="#f2f2f2")
        widget.tag_config(
            "md_codeblock_header",
            font=mono,
            background="#e2e8f0",
            foreground="#334155",
            spacing1=4,
        )
        widget.tag_config("md_codeblock", font=mono, background="#f2f2f2", spacing1=2, spacing3=2)
        widget.tag_config("md_checklist_open", foreground="#7a4f00")
        widget.tag_config("md_checklist_done", foreground="#207227")
        widget.tag_config("md_quote", foreground="#555555")

    def _clear_markdown_tags(self, widget):
        for tag in (
            "md_h1",
            "md_h2",
            "md_h3",
            "md_bold",
            "md_italic",
            "md_code",
            "md_codeblock_header",
            "md_codeblock",
            "md_checklist_open",
            "md_checklist_done",
            "md_quote",
        ):
            widget.tag_remove(tag, "1.0", tk.END)

    def _apply_markdown_spans(self, widget, spans):
        if not spans:
            return
        text_len = len(widget.get("1.0", "end-1c"))
        for span in spans:
            if len(span) == 4:
                tag, start_off, end_off, target = span
            else:
                tag, start_off, end_off = span
                target = None
            start_off = max(0, min(start_off, text_len))
            end_off = max(start_off, min(end_off, text_len))
            if end_off <= start_off:
                continue
            if tag == "md_link":
                self._add_link_target(widget, start_off, end_off, target)
                continue
            start = f"1.0+{start_off}c"
            end = f"1.0+{end_off}c"
            widget.tag_add(tag, start, end)

    def _render_markdown(self, text):
        spans = []
        output = []
        offset = 0
        in_code_block = False

        def add_inline(segment, base_offset):
            out = []
            i = 0
            cur_off = base_offset

            def is_word_char(pos):
                return 0 <= pos < len(segment) and (segment[pos].isalnum() or segment[pos] == "_")

            def is_valid_underscore_open(pos, width):
                return (
                    pos + width < len(segment)
                    and not segment[pos + width].isspace()
                    and not is_word_char(pos - 1)
                )

            def is_valid_underscore_close(pos, width):
                return (
                    pos > 0
                    and not segment[pos - 1].isspace()
                    and not is_word_char(pos + width)
                )

            def find_closing_delim(delim, start):
                pos = segment.find(delim, start)
                while pos != -1:
                    if delim.startswith("_") and not is_valid_underscore_close(pos, len(delim)):
                        pos = segment.find(delim, pos + 1)
                        continue
                    return pos
                return -1

            while i < len(segment):
                ch = segment[i]
                if ch == "`":
                    j = segment.find("`", i + 1)
                    if j != -1:
                        content = segment[i + 1 : j]
                        out.append(content)
                        spans.append(("md_code", cur_off, cur_off + len(content)))
                        cur_off += len(content)
                        i = j + 1
                        continue
                if segment.startswith("**", i) or segment.startswith("__", i):
                    delim = segment[i : i + 2]
                    if delim == "__" and not is_valid_underscore_open(i, 2):
                        j = -1
                    else:
                        j = find_closing_delim(delim, i + 2)
                    if j != -1:
                        content = segment[i + 2 : j]
                        out.append(content)
                        spans.append(("md_bold", cur_off, cur_off + len(content)))
                        cur_off += len(content)
                        i = j + 2
                        continue
                if ch in ("*", "_"):
                    if i + 1 < len(segment) and segment[i + 1] == ch:
                        pass
                    else:
                        if ch == "_" and not is_valid_underscore_open(i, 1):
                            j = -1
                        else:
                            j = find_closing_delim(ch, i + 1)
                        if j != -1:
                            content = segment[i + 1 : j]
                            out.append(content)
                            spans.append(("md_italic", cur_off, cur_off + len(content)))
                            cur_off += len(content)
                            i = j + 1
                            continue
                if ch == "[":
                    depth = 1
                    close = -1
                    pos = i + 1
                    while pos < len(segment):
                        current = segment[pos]
                        if current == "\\" and pos + 1 < len(segment):
                            pos += 2
                            continue
                        if current == "[":
                            depth += 1
                        elif current == "]":
                            depth -= 1
                            if depth == 0:
                                close = pos
                                break
                        pos += 1
                    if close != -1 and close + 1 < len(segment) and segment[close + 1] == "(":
                        end = segment.find(")", close + 2)
                        if end != -1:
                            label = segment[i + 1 : close]
                            if label.startswith("[") and label.endswith("]") and len(label) >= 2:
                                label = label[1:-1]
                            url = segment[close + 2 : end]
                            out.append(label)
                            spans.append(("md_link", cur_off, cur_off + len(label), url))
                            cur_off += len(label)
                            i = end + 1
                            continue
                out.append(ch)
                cur_off += 1
                i += 1
            return "".join(out), cur_off

        for line in text.splitlines(keepends=True):
            line_body = line.rstrip("\n")
            newline = "\n" if line.endswith("\n") else ""
            fence = re.match(r"^\s*```\s*([A-Za-z0-9_.+-]*)\s*$", line_body)
            if fence:
                if in_code_block:
                    in_code_block = False
                    continue
                in_code_block = True
                lang = fence.group(1).strip()
                if lang:
                    header = f"Code: {lang}"
                    output.append(header)
                    spans.append(("md_codeblock_header", offset, offset + len(header)))
                    offset += len(header)
                if newline:
                    output.append(newline)
                    offset += 1
                continue
            if in_code_block:
                output.append(line_body)
                spans.append(("md_codeblock", offset, offset + len(line_body)))
                offset += len(line_body)
                if newline:
                    output.append(newline)
                    offset += 1
                continue
            heading = re.match(r"^(#{1,3})\s+(.*)$", line_body)
            quote = re.match(r"^\s*>\s+(.*)$", line_body)
            checklist = re.match(r"^\s*[-*+]\s+\[([ xX])\]\s+(.*)$", line_body)
            bullet = re.match(r"^\s*[-*+]\s+(.*)$", line_body)
            if heading:
                level = len(heading.group(1))
                content, new_off = add_inline(heading.group(2), offset)
                output.append(content)
                spans.append((f"md_h{level}", offset, offset + len(content)))
                offset = new_off
            elif quote:
                content, _new_off = add_inline(quote.group(1), offset + 2)
                line_text = f"│ {content}"
                output.append(line_text)
                spans.append(("md_quote", offset, offset + len(line_text)))
                offset += len(line_text)
            elif checklist:
                done = checklist.group(1).lower() == "x"
                marker = "[x]" if done else "[ ]"
                content, _new_off = add_inline(checklist.group(2), offset + len(marker) + 1)
                line_text = f"{marker} {content}"
                output.append(line_text)
                spans.append(
                    (
                        "md_checklist_done" if done else "md_checklist_open",
                        offset,
                        offset + len(line_text),
                    )
                )
                offset += len(line_text)
            elif bullet:
                content, _new_off = add_inline(bullet.group(1), offset + 2)
                line_text = f"• {content}"
                output.append(line_text)
                offset += len(line_text)
            else:
                content, new_off = add_inline(line_body, offset)
                output.append(content)
                offset = new_off
            if newline:
                output.append(newline)
                offset += 1

        return "".join(output), spans

    def _apply_code_spans(self, widget, text, code_spans):
        widget.tag_remove("code", "1.0", tk.END)
        if not code_spans:
            return
        spans = code_spans
        if not isinstance(spans, list):
            return
        text_len = len(text)
        for span in spans:
            if not isinstance(span, (list, tuple)) or len(span) != 2:
                continue
            try:
                start_off = int(span[0])
                end_off = int(span[1])
            except (TypeError, ValueError):
                continue
            start_off = max(0, min(start_off, text_len))
            end_off = max(start_off, min(end_off, text_len))
            if end_off <= start_off:
                continue
            start = f"1.0+{start_off}c"
            end = f"1.0+{end_off}c"
            widget.tag_add("code", start, end)

    def _apply_bold_spans(self, widget, text, bold_spans):
        widget.tag_remove("bold", "1.0", tk.END)
        if not bold_spans:
            return
        spans = bold_spans
        if not isinstance(spans, list):
            return
        text_len = len(text)
        for span in spans:
            if not isinstance(span, (list, tuple)) or len(span) != 2:
                continue
            try:
                start_off = int(span[0])
                end_off = int(span[1])
            except (TypeError, ValueError):
                continue
            start_off = max(0, min(start_off, text_len))
            end_off = max(start_off, min(end_off, text_len))
            if end_off <= start_off:
                continue
            start = f"1.0+{start_off}c"
            end = f"1.0+{end_off}c"
            widget.tag_add("bold", start, end)

    def _get_code_spans_from_widget(self, widget):
        ranges = widget.tag_ranges("code")
        if not ranges:
            return []
        spans = []
        for idx in range(0, len(ranges), 2):
            start = ranges[idx]
            end = ranges[idx + 1]
            try:
                start_off = len(widget.get("1.0", start))
                end_off = len(widget.get("1.0", end))
            except tk.TclError:
                continue
            spans.append([int(start_off), int(end_off)])
        return spans

    def _get_bold_spans_from_widget(self, widget):
        ranges = widget.tag_ranges("bold")
        if not ranges:
            return []
        spans = []
        for idx in range(0, len(ranges), 2):
            start = ranges[idx]
            end = ranges[idx + 1]
            try:
                start_off = len(widget.get("1.0", start))
                end_off = len(widget.get("1.0", end))
            except tk.TclError:
                continue
            spans.append([int(start_off), int(end_off)])
        return spans

    def _parse_markup(self, text):
        code_spans = []
        bold_spans = []
        output = []
        output_len = 0
        pos = 0
        tag_re = re.compile(r"\[(code|b)\]")
        while True:
            match = tag_re.search(text, pos)
            if not match:
                output.append(text[pos:])
                break
            start = match.start()
            if start > pos:
                chunk = text[pos:start]
                output.append(chunk)
                output_len += len(chunk)
            tag = match.group(1)
            tag_end = match.end()
            close_tag = f"[/{tag}]"
            close_idx = text.find(close_tag, tag_end)
            if close_idx == -1:
                literal = text[start:tag_end]
                output.append(literal)
                output_len += len(literal)
                pos = tag_end
                continue
            inner = text[tag_end:close_idx]
            start_off = output_len
            output.append(inner)
            output_len += len(inner)
            end_off = output_len
            if tag == "code":
                code_spans.append([start_off, end_off])
            else:
                bold_spans.append([start_off, end_off])
            pos = close_idx + len(close_tag)
        return "".join(output), code_spans, bold_spans

    def _convert_legacy_markup_to_markdown(self, text):
        if "[code]" not in text and "[/code]" not in text and "[b]" not in text and "[/b]" not in text:
            return text
        plain, code_spans, bold_spans = self._parse_markup(text)
        text_len = len(plain)
        code_spans = self._normalize_spans(code_spans, text_len)
        bold_spans = self._normalize_spans(bold_spans, text_len)
        bold_spans = self._subtract_spans(bold_spans, code_spans)

        inserts = []
        for start, end in code_spans:
            segment = plain[start:end]
            if "\n" in segment:
                inserts.append((start, "```\n", False))
                inserts.append((end, "\n```", True))
            else:
                inserts.append((start, "`", False))
                inserts.append((end, "`", True))
        for start, end in bold_spans:
            inserts.append((start, "**", False))
            inserts.append((end, "**", True))

        if not inserts:
            return plain

        result = plain
        inserts.sort(key=lambda item: (-item[0], 0 if not item[2] else 1))
        for pos, marker, _is_end in inserts:
            result = result[:pos] + marker + result[pos:]
        return result

    def _normalize_spans(self, spans, text_len):
        normalized = []
        if not spans:
            return normalized
        for span in spans:
            if not isinstance(span, (list, tuple)) or len(span) != 2:
                continue
            try:
                start = int(span[0])
                end = int(span[1])
            except (TypeError, ValueError):
                continue
            start = max(0, min(start, text_len))
            end = max(start, min(end, text_len))
            if end > start:
                normalized.append((start, end))
        return sorted(normalized, key=lambda pair: pair[0])

    def _subtract_spans(self, spans, blocked):
        if not spans or not blocked:
            return spans
        result = []
        for start, end in spans:
            cur_start = start
            for block_start, block_end in blocked:
                if block_end <= cur_start:
                    continue
                if block_start >= end:
                    break
                if block_start > cur_start:
                    result.append((cur_start, min(block_start, end)))
                cur_start = max(cur_start, block_end)
                if cur_start >= end:
                    break
            if cur_start < end:
                result.append((cur_start, end))
        return result

    def _serialize_with_markup(self, text, code_spans, bold_spans):
        text_len = len(text)
        code_spans = self._normalize_spans(code_spans, text_len)
        bold_spans = self._normalize_spans(bold_spans, text_len)
        bold_spans = self._subtract_spans(bold_spans, code_spans)
        if not code_spans and not bold_spans:
            return text
        events = []
        for start, end in code_spans:
            events.append((start, "start", "code"))
            events.append((end, "end", "code"))
        for start, end in bold_spans:
            events.append((start, "start", "b"))
            events.append((end, "end", "b"))
        events.sort(key=lambda entry: (entry[0], 0 if entry[1] == "end" else 1))
        result = []
        last = 0
        for pos, kind, tag in events:
            pos = max(0, min(pos, text_len))
            if pos > last:
                result.append(text[last:pos])
            if kind == "start":
                result.append(f"[{tag}]")
            else:
                result.append(f"[/{tag}]")
            last = pos
        result.append(text[last:])
        return "".join(result)

    def _open_link_at_event(self, widget, event):
        index = widget.index(f"@{event.x},{event.y}")
        link_range = widget.tag_prevrange("link", index)
        if not link_range:
            return
        start, end = link_range
        if not (widget.compare(start, "<=", index) and widget.compare(index, "<", end)):
            return
        url = self._get_link_target_at_index(widget, index)
        if not url:
            url = widget.get(start, end)
        if url.startswith("wissensdb://"):
            self._open_internal_link(url)
            return "break"
        if url.startswith("www."):
            url = f"http://{url}"
        webbrowser.open(url)
        return "break"

    def _get_link_target_at_index(self, widget, index):
        try:
            offset = widget.count("1.0", index, "chars")[0]
        except (tk.TclError, TypeError):
            return None
        for start_off, end_off, target in getattr(widget, "_wissensdb_link_targets", []):
            if start_off <= offset < end_off:
                return target
        return None

    def _open_internal_link(self, url):
        match = re.match(r"^wissensdb://([^/]+)/(\d+)$", url)
        if not match:
            messagebox.showwarning("Interner Link", "Dieser interne Link ist ungueltig.")
            return
        thema = match.group(1)
        entry_id = int(match.group(2))
        if self.is_editing:
            self._autosave_current_if_dirty()
        self._navigate_to_location_with_history((thema, entry_id))

    def _enable_inhalt_edit(self, editor_widget=None):
        if not self.current_unterthema_id:
            return
        editor = editor_widget or self.inhalt_text
        self._editing_in_preview = editor is not self.inhalt_text
        editor.config(state="normal")
        self.save_unterthema_btn.config(state="normal")
        self.is_editing = True
        self._set_edit_mode_indicator(True)
        self.editing_thema = self.current_thema
        self.editing_unterthema_id = self.current_unterthema_id
        fresh = self._fetch_unterthema_by_id(
            self.current_unterthema_id, include_archived=self.current_unterthema_archived
        )
        if fresh:
            _titel, inhalt, _code_spans, _bold_spans = fresh
            self._set_widget_text_editable(editor, inhalt)
            if editor is self.inhalt_text:
                self._update_inhalt_line_numbers()
        self._prime_autosave_state()
        editor.edit_reset()
        editor.edit_modified(False)
        editor.bind("<<Modified>>", self._on_inhalt_modified)
        editor.bind("<KeyRelease>", self._on_inhalt_key)
        editor.bind("<Escape>", self._save_inhalt_edit_and_leave)
        self._set_autosave_status(saved=True)

    def _save_inhalt_edit(self):
        if not self.current_unterthema_id or not self.current_thema:
            return
        entry_id = self.current_unterthema_id
        editor = self._get_active_inhalt_widget()
        inhalt = editor.get("1.0", tk.END).rstrip()
        if not inhalt:
            messagebox.showwarning("Ungueltig", "Text darf nicht leer sein.")
            return
        titel = self.unterthema_title_label.cget("text").strip()
        if not titel:
            messagebox.showwarning("Ungueltig", "Titel fehlt.")
            return
        if not self._save_current_to_db(titel, inhalt):
            messagebox.showerror("Fehler", "Unterthema konnte nicht gespeichert werden.")
            return
        self._load_unterthemen()
        self._select_unterthema_by_id(entry_id)
        if self._editing_in_preview and self._unterthema_preview_text is not None:
            preview_prefix = "[ARCHIV] " if self.current_unterthema_archived else ""
            self._unterthema_preview_window.title(
                f"Unterthema: {preview_prefix}{titel or '(ohne Titel)'}"
            )
            self._set_readonly_text_widget_content(self._unterthema_preview_text, inhalt)
        editor.config(state="disabled")
        self.save_unterthema_btn.config(state="disabled")
        self.is_editing = False
        self._set_edit_mode_indicator(False)
        self.editing_thema = None
        self.editing_unterthema_id = None
        self._stop_autosave()
        editor.unbind("<<Modified>>")
        editor.unbind("<KeyRelease>")
        editor.unbind("<Escape>")
        self._editing_in_preview = False
        self._set_autosave_status(saved=True)

    def _save_inhalt_edit_and_leave(self, _event=None):
        self._save_inhalt_edit()
        return "break"

    def _archive_unterthema(self):
        if not self.current_unterthema_id or not self.current_thema:
            return
        if self.current_unterthema_archived:
            return
        if self.is_editing:
            self._autosave_current_if_dirty()
        self.is_editing = False
        self._set_edit_mode_indicator(False)
        self.editing_thema = None
        self.editing_unterthema_id = None
        self._stop_autosave()
        self.inhalt_text.unbind("<<Modified>>")
        self.inhalt_text.unbind("<KeyRelease>")
        self.inhalt_text.unbind("<Escape>")
        titel = self.unterthema_title_label.cget("text").strip()
        confirm = messagebox.askyesno(
            "Unterthema archivieren",
            f"Unterthema '{titel}' wirklich archivieren?",
        )
        if not confirm:
            return
        self._ensure_archived_column(self.current_thema)
        try:
            self.conn.execute(
                f"UPDATE {self.current_thema} SET archived = 1 WHERE id = ?",
                (self.current_unterthema_id,),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht archiviert werden: {exc}")
            return
        self.current_unterthema_id = None
        self.current_unterthema_archived = False
        self.edit_unterthema_btn.config(state="disabled")
        self.save_unterthema_btn.config(state="disabled")
        self._update_unterthema_actions_state()
        self._set_unterthema_title("")
        self._clear_metadata_panel()
        self._set_inhalt_text("Unterthema archiviert.")
        self._load_unterthemen()

    def _restore_unterthema(self):
        if not self.current_unterthema_id or not self.current_thema:
            return
        if not self.current_unterthema_archived:
            return
        titel = self.unterthema_title_label.cget("text").strip()
        confirm = messagebox.askyesno(
            "Unterthema wiederherstellen",
            f"Unterthema '{titel}' wirklich wiederherstellen?",
        )
        if not confirm:
            return
        self._ensure_archived_column(self.current_thema)
        try:
            self.conn.execute(
                f"UPDATE {self.current_thema} SET archived = 0 WHERE id = ?",
                (self.current_unterthema_id,),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht wiederhergestellt werden: {exc}")
            return
        self.current_unterthema_id = None
        self.current_unterthema_archived = False
        self.edit_unterthema_btn.config(state="disabled")
        self.save_unterthema_btn.config(state="disabled")
        self._update_unterthema_actions_state()
        self._set_unterthema_title("")
        self._clear_metadata_panel()
        self._set_inhalt_text("Unterthema wiederhergestellt.")
        self._load_unterthemen()

    def _rename_unterthema(self):
        if not self.current_unterthema_id or not self.current_thema:
            messagebox.showwarning("Kein Unterthema", "Bitte zuerst ein Unterthema auswaehlen.")
            return
        current_title = self.unterthema_title_label.cget("text").strip() or "(ohne Titel)"
        new_title = simpledialog.askstring(
            "Unterthema umbenennen",
            "Neuer Titel:",
            initialvalue=current_title,
            parent=self,
        )
        if new_title is None:
            return
        new_title = new_title.strip()
        if not new_title:
            messagebox.showwarning("Ungueltig", "Titel darf nicht leer sein.")
            return
        if self.is_editing:
            inhalt = self.inhalt_text.get("1.0", tk.END).rstrip()
            if not inhalt:
                messagebox.showwarning("Ungueltig", "Text darf nicht leer sein.")
                return
            if not self._save_current_to_db(new_title, inhalt):
                messagebox.showerror("Fehler", "Unterthema konnte nicht umbenannt werden.")
                return
            self._load_unterthemen()
            self._select_unterthema_by_id(self.current_unterthema_id)
            self.inhalt_text.config(state="disabled")
            self.save_unterthema_btn.config(state="disabled")
            self.is_editing = False
            self._set_edit_mode_indicator(False)
            self.editing_thema = None
            self.editing_unterthema_id = None
            self._stop_autosave()
            self.inhalt_text.unbind("<<Modified>>")
            self.inhalt_text.unbind("<KeyRelease>")
            self.inhalt_text.unbind("<Escape>")
            self._set_autosave_status(saved=True)
            return
        updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.conn.execute(
                f"UPDATE {self.current_thema} SET titel = ?, bearbeitet_am = ? WHERE id = ?",
                (new_title, updated, self.current_unterthema_id),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht umbenannt werden: {exc}")
            return
        entry_id = self.current_unterthema_id
        self._load_unterthemen()
        self._select_unterthema_by_id(entry_id)

    def _delete_unterthema(self):
        if not self.current_unterthema_id or not self.current_thema:
            messagebox.showwarning("Kein Unterthema", "Bitte zuerst ein Unterthema auswaehlen.")
            return
        if self.is_editing:
            self._autosave_current_if_dirty()
        titel = self.unterthema_title_label.cget("text").strip() or "(ohne Titel)"
        confirm = messagebox.askyesno(
            "Unterthema loeschen",
            f"Unterthema '{titel}' wirklich endgueltig loeschen?",
        )
        if not confirm:
            return
        self.is_editing = False
        self._set_edit_mode_indicator(False)
        self.editing_thema = None
        self.editing_unterthema_id = None
        self._stop_autosave()
        self.inhalt_text.unbind("<<Modified>>")
        self.inhalt_text.unbind("<KeyRelease>")
        self.inhalt_text.unbind("<Escape>")
        try:
            self.conn.execute(
                f"DELETE FROM {self.current_thema} WHERE id = ?",
                (self.current_unterthema_id,),
            )
            self._delete_entry_fields(self.current_thema, self.current_unterthema_id)
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht geloescht werden: {exc}")
            return
        self.current_unterthema_id = None
        self.current_unterthema_archived = False
        self.edit_unterthema_btn.config(state="disabled")
        self.save_unterthema_btn.config(state="disabled")
        self._update_unterthema_actions_state()
        self._set_unterthema_title("")
        self._clear_metadata_panel()
        self._set_inhalt_text("Unterthema geloescht.")
        self._load_unterthemen()

    def _open_set_gruppe_dialog(self):
        if not self.current_unterthema_id or not self.current_thema:
            messagebox.showwarning("Kein Unterthema", "Bitte zuerst ein Unterthema auswaehlen.")
            return
        self._ensure_gruppe_column(self.current_thema)
        try:
            row = self.conn.execute(
                f"SELECT gruppe FROM {self.current_thema} WHERE id = ?",
                (self.current_unterthema_id,),
            ).fetchone()
        except sqlite3.Error:
            row = None
        current_gruppe = (row[0] or "") if row else ""
        try:
            existing_groups = [
                r[0]
                for r in self.conn.execute(
                    f"SELECT DISTINCT gruppe FROM {self.current_thema} "
                    "WHERE gruppe IS NOT NULL AND gruppe != '' "
                    "ORDER BY gruppe COLLATE NOCASE"
                ).fetchall()
            ]
        except sqlite3.Error:
            existing_groups = []

        dialog = tk.Toplevel(self)
        dialog.title("Gruppe setzen")
        dialog.transient(self)
        dialog.resizable(False, False)
        dialog.grab_set()

        tk.Label(dialog, text="Gruppe (leer lassen = keine Gruppe):").grid(
            row=0, column=0, columnspan=2, padx=12, pady=(12, 6), sticky="w"
        )
        gruppe_var = tk.StringVar(value=current_gruppe)
        entry = tk.Entry(dialog, textvariable=gruppe_var, width=32)
        entry.grid(row=1, column=0, columnspan=2, padx=12, pady=(0, 6))
        entry.focus_set()
        entry.select_range(0, tk.END)

        if existing_groups:
            tk.Label(dialog, text="Vorhandene Gruppen:").grid(
                row=2, column=0, columnspan=2, padx=12, pady=(6, 2), sticky="w"
            )
            lb_frame = tk.Frame(dialog)
            lb_frame.grid(row=3, column=0, columnspan=2, padx=12, pady=(0, 8), sticky="ew")
            lb = tk.Listbox(lb_frame, height=min(len(existing_groups), 5), selectmode="single")
            lb.pack(fill="x")
            for g in existing_groups:
                lb.insert(tk.END, g)

            def on_lb_select(_event=None):
                sel = lb.curselection()
                if sel:
                    gruppe_var.set(lb.get(sel[0]))

            lb.bind("<<ListboxSelect>>", on_lb_select)

        result = {"saved": False}

        def save(_event=None):
            new_gruppe = gruppe_var.get().strip() or None
            try:
                self.conn.execute(
                    f"UPDATE {self.current_thema} SET gruppe = ? WHERE id = ?",
                    (new_gruppe, self.current_unterthema_id),
                )
                self.conn.commit()
            except sqlite3.Error as exc:
                messagebox.showerror("Fehler", f"Gruppe konnte nicht gesetzt werden: {exc}")
                return
            result["saved"] = True
            dialog.destroy()

        def clear_group():
            gruppe_var.set("")
            save()

        btn_row = 4 if existing_groups else 2
        btn_frame = tk.Frame(dialog)
        btn_frame.grid(row=btn_row, column=0, columnspan=2, padx=12, pady=(0, 12), sticky="ew")
        tk.Button(btn_frame, text="Speichern", command=save).pack(side="left")
        tk.Button(btn_frame, text="Gruppe entfernen", command=clear_group).pack(side="left", padx=(8, 0))
        tk.Button(btn_frame, text="Abbrechen", command=dialog.destroy).pack(side="right")

        entry.bind("<Return>", save)
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        self.wait_window(dialog)
        if result["saved"]:
            entry_id = self.current_unterthema_id
            self._load_unterthemen()
            self._select_unterthema_by_id(entry_id)

    def _highlight_inhalt_query(self, query):
        self.inhalt_text.config(state="normal")
        self.inhalt_text.tag_remove("match_main", "1.0", tk.END)
        first_match = None
        if query:
            start = "1.0"
            while True:
                pos = self.inhalt_text.search(query, start, stopindex=tk.END, nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(query)}c"
                self.inhalt_text.tag_add("match_main", pos, end)
                if first_match is None:
                    first_match = pos
                start = end
            self.inhalt_text.tag_config("match_main", background="#ffe08a")
        if first_match is not None:
            self.inhalt_text.mark_set("insert", first_match)
            self.inhalt_text.see(first_match)
        self.inhalt_text.config(state="disabled")

    def _get_current_unterthema_data(self):
        if not self.current_unterthema_id:
            messagebox.showwarning("Kein Unterthema", "Bitte zuerst ein Unterthema auswaehlen.")
            return None
        fresh = self._fetch_unterthema_by_id(
            self.current_unterthema_id,
            include_archived=self.current_unterthema_archived,
        )
        if fresh:
            titel, inhalt, _code_spans, _bold_spans = fresh
        else:
            titel = self.unterthema_title_label.cget("text").strip()
            inhalt = self.inhalt_text.get("1.0", tk.END).rstrip()
        if not titel or not inhalt:
            messagebox.showwarning("Ungueltig", "Titel oder Text fehlt.")
            return None
        return titel, inhalt

    def _format_metadata_for_export(self):
        fields = self._get_entry_fields(self.current_thema, self.current_unterthema_id)
        if not fields:
            return ""
        lines = ["Felder:"]
        for key, value in fields:
            lines.append(f"{key}: {value}")
        return "\n".join(lines)

    def _build_export_content(self, inhalt):
        metadata = self._format_metadata_for_export()
        if not metadata:
            return inhalt
        return f"{metadata}\n\n{inhalt}"

    def _export_txt(self):
        data = self._get_current_unterthema_data()
        if not data:
            return
        _titel, inhalt = data
        export_inhalt = self._build_export_content(inhalt)
        path = filedialog.asksaveasfilename(
            title="Unterthema als TXT speichern",
            defaultextension=".txt",
            filetypes=[("Textdatei", "*.txt"), ("Alle Dateien", "*.*")],
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(export_inhalt)
        messagebox.showinfo("Export", f"TXT gespeichert: {path}")

    def _read_text_file(self, path):
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            messagebox.showerror("Import", f"Datei konnte nicht gelesen werden: {exc}")
            return None
        for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")

    def _open_import_dialog(self):
        themen = self._get_themen_tables()
        if not themen:
            messagebox.showwarning("Kein Thema", "Bitte zuerst ein Thema anlegen.")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Textdatei importieren")
        dialog.transient(self)
        dialog.resizable(True, True)

        thema_label = tk.Label(dialog, text="Thema:")
        thema_label.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")

        thema_map = {}
        thema_labels = []
        for name in themen:
            display_name = self._display_thema_name(name)
            if display_name in thema_map:
                display_name = name
            thema_map[display_name] = name
            thema_labels.append(display_name)

        default_thema = thema_labels[0]
        if self.current_thema:
            current_label = self._display_thema_name(self.current_thema)
            if current_label in thema_map and thema_map[current_label] == self.current_thema:
                default_thema = current_label
            elif self.current_thema in thema_map:
                default_thema = self.current_thema

        thema_var = tk.StringVar(value=default_thema)
        thema_menu = tk.OptionMenu(dialog, thema_var, *thema_labels)
        thema_menu.config(width=24)
        thema_menu.grid(row=0, column=1, padx=12, pady=(12, 6), sticky="we")

        titel_label = tk.Label(dialog, text="Unterthema:")
        titel_label.grid(row=1, column=0, padx=12, pady=(0, 6), sticky="w")

        titel_var = tk.StringVar()
        titel_entry = tk.Entry(dialog, textvariable=titel_var, width=44)
        titel_entry.grid(row=1, column=1, padx=12, pady=(0, 6), sticky="we")

        path_label = tk.Label(dialog, text="Datei:")
        path_label.grid(row=2, column=0, padx=12, pady=(0, 6), sticky="w")

        path_var = tk.StringVar()
        path_entry = tk.Entry(dialog, textvariable=path_var, width=44)
        path_entry.grid(row=2, column=1, padx=12, pady=(0, 6), sticky="we")

        def on_browse():
            path = filedialog.askopenfilename(
                title="Textdatei importieren",
                filetypes=[
                    ("Textdateien", "*.txt *.json *.yml *.yaml *.md *.csv *.log *.ini *.cfg"),
                    ("Alle Dateien", "*.*"),
                ],
            )
            if not path:
                return
            path_var.set(path)
            if not titel_var.get().strip():
                basename = os.path.splitext(os.path.basename(path))[0]
                titel_var.set(basename)

        browse_btn = tk.Button(dialog, text="Durchsuchen...", command=on_browse)
        browse_btn.grid(row=2, column=2, padx=(0, 12), pady=(0, 6), sticky="e")

        dialog.grid_columnconfigure(1, weight=1)

        def on_import():
            path = path_var.get().strip()
            if not path or not os.path.isfile(path):
                messagebox.showwarning("Datei fehlt", "Bitte eine gueltige Datei auswaehlen.")
                return
            titel = titel_var.get()
            thema_display = thema_var.get()
            thema = thema_map.get(thema_display, thema_display)
            inhalt = self._read_text_file(path)
            if inhalt is None:
                return
            entry_id = self._insert_unterthema_into(thema, titel, inhalt, select_entry=True)
            if entry_id:
                messagebox.showinfo("Import", f"Datei importiert: {os.path.basename(path)}")
                dialog.destroy()

        import_btn = tk.Button(dialog, text="Importieren", command=on_import)
        import_btn.grid(row=3, column=0, padx=12, pady=(0, 12), sticky="w")

        cancel_btn = tk.Button(dialog, text="Abbrechen", command=dialog.destroy)
        cancel_btn.grid(row=3, column=1, padx=12, pady=(0, 12), sticky="e")

        titel_entry.focus_set()


    def _export_pdf(self):
        data = self._get_current_unterthema_data()
        if not data:
            return
        _titel, inhalt = data
        export_inhalt = self._build_export_content(inhalt)
        path = filedialog.asksaveasfilename(
            title="Unterthema als PDF speichern",
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf"), ("Alle Dateien", "*.*")],
        )
        if not path:
            return
        try:
            self._write_simple_pdf(path, "", export_inhalt)
        except OSError as exc:
            messagebox.showerror("PDF-Export", f"PDF konnte nicht gespeichert werden: {exc}")
            return
        messagebox.showinfo("Export", f"PDF gespeichert: {path}")

    def _export_custom(self):
        data = self._get_current_unterthema_data()
        if not data:
            return
        _titel, inhalt = data
        export_inhalt = self._build_export_content(inhalt)
        path = filedialog.asksaveasfilename(
            title="Export als...",
            filetypes=[("Alle Dateien", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(export_inhalt)
        except OSError as exc:
            messagebox.showerror("Export", f"Datei konnte nicht gespeichert werden: {exc}")
            return
        messagebox.showinfo("Export", f"Datei gespeichert: {path}")

    def _export_plain_db_backup(self):
        try:
            self._autosave_current_if_dirty()
        except Exception:
            pass
        default_name = f"{os.path.splitext(os.path.basename(self.db_path))[0]}_backup_plain.db"
        path = filedialog.asksaveasfilename(
            title="Unverschluesseltes DB-Backup speichern",
            defaultextension=".db",
            initialfile=default_name,
            filetypes=[("SQLite DB", "*.db *.sqlite *.sqlite3"), ("Alle Dateien", "*.*")],
        )
        if not path:
            return
        try:
            self._save_plain_db_backup(path)
        except (OSError, sqlite3.Error) as exc:
            messagebox.showerror(
                "DB-Backup",
                f"Unverschluesseltes Backup konnte nicht gespeichert werden:\n{exc}",
            )
            return
        messagebox.showinfo("DB-Backup", f"Unverschluesseltes Backup gespeichert: {path}")

    def _save_plain_db_backup(self, path):
        backup_conn = None
        try:
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            backup_conn = sqlite3.connect(path)
            self.conn.backup(backup_conn)
            backup_conn.commit()
            check_row = backup_conn.execute("PRAGMA integrity_check").fetchone()
            if not check_row or check_row[0] != "ok":
                details = check_row[0] if check_row and check_row[0] else "Unbekannter Fehler"
                raise sqlite3.DatabaseError(f"Integritaetspruefung fehlgeschlagen: {details}")
        finally:
            if backup_conn is not None:
                backup_conn.close()

    def _auto_backup_interval_options(self):
        return [
            ("Stuendlich", 60 * 60),
            ("Alle 3 Stunden", 3 * 60 * 60),
            ("Taeglich", 24 * 60 * 60),
            ("Alle 2 Tage", 2 * 24 * 60 * 60),
            ("1x pro Woche", 7 * 24 * 60 * 60),
        ]

    def _auto_backup_interval_seconds(self):
        raw = self._get_setting("auto_backup_interval", str(24 * 60 * 60))
        try:
            seconds = int(raw)
        except (TypeError, ValueError):
            seconds = 24 * 60 * 60
        allowed = {value for _label, value in self._auto_backup_interval_options()}
        if seconds not in allowed:
            seconds = 24 * 60 * 60
        return seconds

    def _auto_backup_path(self):
        raw_dir = self._get_setting("auto_backup_path", "")
        backup_dir = raw_dir.strip() if raw_dir else ""
        if not backup_dir:
            backup_dir = os.path.join(_get_runtime_dir(), "backups")
        base = os.path.splitext(os.path.basename(self.db_path))[0] or APP_DB_BASENAME
        return os.path.join(backup_dir, f"{base}_auto_backup_plain.db")

    def _schedule_auto_backup(self):
        self._stop_auto_backup()
        if not self._get_setting_bool("auto_backup_enabled", default=False):
            self._update_navigation_buttons()
            return
        interval = self._auto_backup_interval_seconds()
        last_raw = self._get_setting("auto_backup_last_ts", "")
        now = time.time()
        try:
            last_ts = float(last_raw)
        except (TypeError, ValueError):
            last_ts = 0.0
        remaining = max(0.0, interval - (now - last_ts))
        delay_ms = int(max(5, remaining) * 1000)
        self.auto_backup_job = self.after(delay_ms, self._auto_backup_tick)

    def _stop_auto_backup(self):
        if self.auto_backup_job is not None:
            try:
                self.after_cancel(self.auto_backup_job)
            except tk.TclError:
                pass
            self.auto_backup_job = None

    def _auto_backup_tick(self):
        self.auto_backup_job = None
        try:
            self._run_auto_backup()
        finally:
            self._schedule_auto_backup()

    def _run_auto_backup(self):
        if not self._get_setting_bool("auto_backup_enabled", default=False):
            return
        try:
            self._autosave_current_if_dirty()
        except Exception:
            pass
        path = self._auto_backup_path()
        try:
            self._save_plain_db_backup(path)
            self._set_setting("auto_backup_last_ts", str(time.time()))
            self._debug_log.append(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] auto_backup | {path}"
            )
        except (OSError, sqlite3.Error) as exc:
            self._debug_log.append(
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] auto_backup ERROR | {exc}"
            )

    def _open_auto_backup_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Automatisches Backup")
        dialog.transient(self)
        dialog.resizable(False, False)

        enabled_var = tk.BooleanVar(
            value=self._get_setting_bool("auto_backup_enabled", default=False)
        )
        path_var = tk.StringVar(
            value=self._get_setting("auto_backup_path", os.path.join(_get_runtime_dir(), "backups"))
        )
        interval_options = self._auto_backup_interval_options()
        interval_by_label = {label: value for label, value in interval_options}
        label_by_interval = {value: label for label, value in interval_options}
        interval_var = tk.StringVar(
            value=label_by_interval.get(self._auto_backup_interval_seconds(), "Taeglich")
        )

        enabled_check = tk.Checkbutton(
            dialog,
            text="Automatisches Backup aktivieren",
            variable=enabled_var,
        )
        enabled_check.grid(row=0, column=0, columnspan=3, padx=12, pady=(12, 8), sticky="w")

        path_label = tk.Label(dialog, text="Backuppfad:")
        path_label.grid(row=1, column=0, padx=12, pady=(0, 6), sticky="w")
        path_entry = tk.Entry(dialog, textvariable=path_var, width=48)
        path_entry.grid(row=1, column=1, padx=(0, 6), pady=(0, 6), sticky="we")

        def choose_path():
            selected = filedialog.askdirectory(
                title="Backuppfad waehlen",
                initialdir=path_var.get().strip() or _get_runtime_dir(),
            )
            if selected:
                path_var.set(selected)

        browse_btn = tk.Button(dialog, text="Waehlen...", command=choose_path)
        browse_btn.grid(row=1, column=2, padx=(0, 12), pady=(0, 6), sticky="e")

        interval_label = tk.Label(dialog, text="Intervall:")
        interval_label.grid(row=2, column=0, padx=12, pady=(0, 10), sticky="w")
        interval_menu = tk.OptionMenu(dialog, interval_var, *interval_by_label.keys())
        interval_menu.config(width=18)
        interval_menu.grid(row=2, column=1, padx=(0, 6), pady=(0, 10), sticky="w")

        info_label = tk.Label(
            dialog,
            text="Es wird immer genau eine unverschluesselte Backup-Datei ueberschrieben.",
            anchor="w",
        )
        info_label.grid(row=3, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="w")

        def save_settings():
            backup_dir = path_var.get().strip()
            if enabled_var.get() and not backup_dir:
                messagebox.showwarning("Backup", "Bitte einen Backuppfad angeben.")
                return
            if backup_dir:
                try:
                    os.makedirs(backup_dir, exist_ok=True)
                except OSError as exc:
                    messagebox.showerror("Backup", f"Backuppfad konnte nicht angelegt werden:\n{exc}")
                    return
            if not self._set_setting("auto_backup_enabled", "1" if enabled_var.get() else "0"):
                return
            if not self._set_setting("auto_backup_path", backup_dir):
                return
            interval_seconds = interval_by_label.get(interval_var.get(), 24 * 60 * 60)
            if not self._set_setting("auto_backup_interval", str(interval_seconds)):
                return
            self._schedule_auto_backup()
            dialog.destroy()

        button_frame = tk.Frame(dialog)
        button_frame.grid(row=4, column=0, columnspan=3, padx=12, pady=(0, 12), sticky="we")
        save_btn = tk.Button(button_frame, text="Uebernehmen", command=save_settings)
        save_btn.pack(side="left")
        cancel_btn = tk.Button(button_frame, text="Abbrechen", command=dialog.destroy)
        cancel_btn.pack(side="right")

    def _write_simple_pdf(self, path, titel, inhalt):
        page_width = 595
        page_height = 842
        margin = 40
        leading = 14
        title_leading = 18
        body_lines_per_page = int((page_height - 2 * margin) / leading)
        first_page_body_limit = max(body_lines_per_page - 2, 0) if titel else body_lines_per_page

        def escape_pdf(text):
            text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            try:
                text.encode("latin-1")
            except UnicodeEncodeError:
                text = text.encode("latin-1", "replace").decode("latin-1")
            return text

        body_lines = []
        for line in inhalt.splitlines():
            if line.strip():
                body_lines.extend(wrap(line, width=95))
            else:
                body_lines.append("")

        pages = []
        first_page_lines = body_lines[:first_page_body_limit]
        pages.append(first_page_lines)
        remaining = body_lines[first_page_body_limit:]
        while remaining:
            pages.append(remaining[:body_lines_per_page])
            remaining = remaining[body_lines_per_page:]

        objects = []

        def add_obj(data):
            objects.append(data)
            return len(objects)

        pages_obj_id = add_obj(b"")
        font_body_id = add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        font_title_id = add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

        page_ids = []
        for idx, lines in enumerate(pages):
            is_first = idx == 0
            content_parts = ["BT"]
            if is_first and titel:
                content_parts.append("/F2 14 Tf")
                content_parts.append(f"{margin} {page_height - margin} Td")
                content_parts.append(f"{title_leading} TL")
                content_parts.append(f"({escape_pdf(titel)}) Tj")
                content_parts.append("T*")
            content_parts.append("/F1 11 Tf")
            content_parts.append(f"{leading} TL")
            if not is_first or not titel:
                content_parts.append(f"{margin} {page_height - margin} Td")
            for line in lines:
                if not line:
                    content_parts.append("T*")
                    continue
                content_parts.append(f"({escape_pdf(line)}) Tj")
                content_parts.append("T*")
            content_parts.append("ET")
            content_stream = "\n".join(content_parts).encode("latin-1")
            content_obj = add_obj(
                b"<< /Length %d >>\nstream\n" % len(content_stream)
                + content_stream
                + b"\nendstream"
            )
            page_obj = add_obj(
                (
                    "<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %d %d] "
                    "/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> "
                    "/Contents %d 0 R >>"
                    % (
                        pages_obj_id,
                        page_width,
                        page_height,
                        font_body_id,
                        font_title_id,
                        content_obj,
                    )
                ).encode("latin-1")
            )
            page_ids.append(page_obj)

        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        pages_dict = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode(
            "latin-1"
        )
        objects[pages_obj_id - 1] = pages_dict
        catalog_id = add_obj(f"<< /Type /Catalog /Pages {pages_obj_id} 0 R >>".encode("latin-1"))

        pdf = b"%PDF-1.4\n"
        offsets = []
        for i, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf += f"{i} 0 obj\n".encode("latin-1") + obj + b"\nendobj\n"
        xref_pos = len(pdf)
        pdf += f"xref\n0 {len(objects) + 1}\n".encode("latin-1")
        pdf += b"0000000000 65535 f \n"
        for off in offsets:
            pdf += f"{off:010d} 00000 n \n".encode("latin-1")
        pdf += (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF"
        ).encode("latin-1")

        with open(path, "wb") as handle:
            handle.write(pdf)

    def _prime_autosave_state(self):
        titel = self.unterthema_title_label.cget("text").strip()
        inhalt = self._get_active_inhalt_widget().get("1.0", tk.END).rstrip()
        self.last_autosave_key = self._build_autosave_key(titel, inhalt)

    def _on_inhalt_modified(self, _event):
        if not self.is_editing:
            return
        editor = self._get_active_inhalt_widget()
        if not editor.edit_modified():
            return
        editor.edit_modified(False)
        if editor is self.inhalt_text:
            self._update_inhalt_line_numbers()
        elif editor is self._unterthema_preview_text:
            self._update_preview_line_numbers()
        self._schedule_autosave()
        self._set_autosave_status(saved=False)

    def _on_inhalt_key(self, _event):
        if not self.is_editing:
            return
        self._schedule_autosave()
        self._set_autosave_status(saved=False)

    def _schedule_autosave(self):
        if not self.is_editing:
            return
        self._stop_autosave()
        self.autosave_job = self.after(self.autosave_delay_ms, self._autosave_tick)

    def _stop_autosave(self):
        if self.autosave_job is not None:
            try:
                self.after_cancel(self.autosave_job)
            except tk.TclError:
                pass
            self.autosave_job = None

    def _autosave_tick(self):
        if not self.is_editing or not self.current_unterthema_id or not self.current_thema:
            return
        titel = self.unterthema_title_label.cget("text").strip()
        inhalt = self._get_active_inhalt_widget().get("1.0", tk.END).rstrip()
        current_key = self._build_autosave_key(titel, inhalt)
        if current_key != self.last_autosave_key:
            if self._save_current_to_db(titel, inhalt):
                self.last_autosave_key = current_key
                self._set_autosave_status(saved=True)
            else:
                self._set_autosave_status(error=True)
        self._schedule_autosave()

    def _save_current_to_db(self, titel, inhalt):
        thema = self.editing_thema or self.current_thema
        unterthema_id = self.editing_unterthema_id or self.current_unterthema_id
        if not unterthema_id or not thema:
            return False
        self._ensure_bearbeitet_column(thema)
        updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.conn.execute(
                f"UPDATE {thema} SET titel = ?, inhalt = ?, bearbeitet_am = ? WHERE id = ?",
                (titel, inhalt, updated, unterthema_id),
            )
            self.conn.commit()
        except sqlite3.Error:
            return False
        return True

    def _autosave_current_if_dirty(self):
        if not self.is_editing:
            return
        titel = self.unterthema_title_label.cget("text").strip()
        inhalt = self._get_active_inhalt_widget().get("1.0", tk.END).rstrip()
        current_key = self._build_autosave_key(titel, inhalt)
        if current_key == self.last_autosave_key:
            return
        if self._save_current_to_db(titel, inhalt):
            self.last_autosave_key = current_key
            self._set_autosave_status(saved=True)
        else:
            self._set_autosave_status(error=True)

    def _build_autosave_key(self, titel, inhalt):
        return (titel, inhalt)

    def _set_autosave_status(self, saved=None, error=None):
        if not hasattr(self, "autosave_status_canvas"):
            return
        if error:
            color = "#ff0000"
        elif saved:
            color = "#2ecc71"
        else:
            color = "#ff0000"
        self.autosave_status_canvas.itemconfig(self.autosave_status_dot, fill=color)


    def _create_table(self, raw):
        table = _normalize_table_name(raw)
        if not table:
            messagebox.showwarning("Ungueltig", "Bitte ein gueltiges Oberthema eingeben.")
            return

        try:
            self.conn.execute(
                f"CREATE TABLE IF NOT EXISTS {table} ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "titel TEXT NOT NULL, "
                "inhalt TEXT NOT NULL, "
                "erstellt_am TEXT NOT NULL, "
                "bearbeitet_am TEXT, "
                "archived INTEGER NOT NULL DEFAULT 0, "
                "gruppe TEXT"
                ")"
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Tabelle konnte nicht erstellt werden: {exc}")
            return

        self._register_thema_created(table)
        messagebox.showinfo("OK", f"Tabelle '{table}' ist bereit.")
        self._refresh_themen()

    def _ensure_table_exists(self, raw):
        table = _normalize_table_name(raw)
        if not table:
            return None
        try:
            self.conn.execute(
                f"CREATE TABLE IF NOT EXISTS {table} ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "titel TEXT NOT NULL, "
                "inhalt TEXT NOT NULL, "
                "erstellt_am TEXT NOT NULL, "
                "bearbeitet_am TEXT, "
                "archived INTEGER NOT NULL DEFAULT 0, "
                "gruppe TEXT"
                ")"
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Tabelle konnte nicht erstellt werden: {exc}")
            return None
        self._register_thema_created(table)
        self._refresh_themen()
        return table

    def _ensure_archived_column(self, table):
        if not table:
            return
        try:
            columns = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        except sqlite3.Error:
            return
        if any(col[1] == "archived" for col in columns):
            return
        try:
            self.conn.execute(
                f"ALTER TABLE {table} ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _ensure_bearbeitet_column(self, table):
        if not table:
            return
        try:
            columns = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        except sqlite3.Error:
            return
        if any(col[1] == "bearbeitet_am" for col in columns):
            return
        try:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN bearbeitet_am TEXT")
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _ensure_gruppe_column(self, table):
        if not table:
            return
        try:
            columns = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        except sqlite3.Error:
            return
        if any(col[1] == "gruppe" for col in columns):
            return
        try:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN gruppe TEXT")
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _insert_unterthema(self, titel, inhalt):
        return self._insert_unterthema_into(self.current_thema, titel, inhalt, select_entry=False)

    def _overwrite_unterthema_into(self, thema, titel, inhalt, select_entry=False, backup=False):
        if not thema:
            messagebox.showwarning("Kein Thema", "Bitte zuerst ein Thema auswaehlen.")
            return None, False
        titel = titel.strip()
        inhalt = inhalt.strip()
        if not titel or not inhalt:
            messagebox.showwarning("Ungueltig", "Titel und Text muessen ausgefuellt sein.")
            return None, False
        self._ensure_archived_column(thema)
        self._ensure_bearbeitet_column(thema)
        try:
            row = self.conn.execute(
                f"SELECT id, titel, inhalt FROM {thema} WHERE titel = ? COLLATE NOCASE "
                "ORDER BY id DESC LIMIT 1",
                (titel,),
            ).fetchone()
            count_row = self.conn.execute(
                f"SELECT COUNT(*) FROM {thema} WHERE titel = ? COLLATE NOCASE",
                (titel,),
            ).fetchone()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht gefunden werden: {exc}")
            return None, False
        if not row:
            return None, False
        entry_id, existing_title, existing_inhalt = row
        multi = bool(count_row and count_row[0] and count_row[0] > 1)
        created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if backup:
            stamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
            backup_title = f"{existing_title} (Backup {stamp})"
            try:
                backup_cursor = self.conn.execute(
                    f"INSERT INTO {thema} (titel, inhalt, erstellt_am, bearbeitet_am, archived) "
                    "VALUES (?, ?, ?, ?, 1)",
                    (backup_title, existing_inhalt, created, created),
                )
            except sqlite3.Error as exc:
                messagebox.showerror("Fehler", f"Backup konnte nicht angelegt werden: {exc}")
                return None, False
        try:
            self.conn.execute(
                f"UPDATE {thema} SET inhalt = ?, bearbeitet_am = ? WHERE id = ?",
                (inhalt, created, entry_id),
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht gespeichert werden: {exc}")
            return None, False
        if thema == self.current_thema:
            self._load_unterthemen()
            if select_entry and entry_id:
                self._select_unterthema_by_id(entry_id)
        return entry_id, multi

    def _insert_unterthema_into(self, thema, titel, inhalt, select_entry=False):
        if not thema:
            messagebox.showwarning("Kein Thema", "Bitte zuerst ein Thema auswaehlen.")
            return None
        titel = titel.strip()
        inhalt = inhalt.strip()
        if not titel or not inhalt:
            messagebox.showwarning("Ungueltig", "Titel und Text muessen ausgefuellt sein.")
            return None
        self._ensure_archived_column(thema)
        self._ensure_bearbeitet_column(thema)
        try:
            row = self.conn.execute(
                f"SELECT id FROM {thema} WHERE titel = ? COLLATE NOCASE LIMIT 1",
                (titel,),
            ).fetchone()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht geprueft werden: {exc}")
            return None
        if row:
            confirm = messagebox.askyesno(
                "Unterthema vorhanden",
                f"Unterthema '{titel}' existiert bereits.\nSoll es ueberschrieben werden?",
            )
            if not confirm:
                return None
            backup = messagebox.askyesno(
                "Backup anlegen",
                "Soll vor dem Ueberschreiben ein Backup als archiviertes Unterthema angelegt werden?",
            )
            entry_id, multi = self._overwrite_unterthema_into(
                thema, titel, inhalt, select_entry=select_entry, backup=backup
            )
            if entry_id and multi:
                messagebox.showinfo(
                    "Hinweis",
                    "Mehrere Unterthemen mit gleichem Titel gefunden. "
                    "Das neueste wurde ueberschrieben.",
                )
            return entry_id
        created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor = self.conn.execute(
                f"INSERT INTO {thema} (titel, inhalt, erstellt_am, bearbeitet_am) "
                "VALUES (?, ?, ?, ?)",
                (titel, inhalt, created, created),
            )
            entry_id = cursor.lastrowid
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht gespeichert werden: {exc}")
            return None
        if thema == self.current_thema:
            self._load_unterthemen()
            if select_entry and entry_id:
                self._select_unterthema_by_id(entry_id)
        return entry_id

    def _insert_empty_unterthema_into(self, thema, titel, select_entry=False):
        if not thema:
            return None
        titel = titel.strip()
        if not titel:
            return None
        self._ensure_archived_column(thema)
        self._ensure_bearbeitet_column(thema)
        created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            cursor = self.conn.execute(
                f"INSERT INTO {thema} (titel, inhalt, erstellt_am, bearbeitet_am) "
                "VALUES (?, ?, ?, ?)",
                (titel, "", created, created),
            )
            entry_id = cursor.lastrowid
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Fehler", f"Unterthema konnte nicht gespeichert werden: {exc}")
            return None
        if thema == self.current_thema:
            self._load_unterthemen()
            if select_entry and entry_id:
                self._select_unterthema_by_id(entry_id)
        return entry_id

    def _create_quick_note(self):
        thema = self._ensure_table_exists("NOTIZEN")
        if not thema:
            return
        titel = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not self._select_thema_by_name(thema):
            return
        entry_id = self._insert_empty_unterthema_into(thema, titel, select_entry=True)
        if not entry_id:
            return
        self._select_unterthema_by_id(entry_id)
        self._enable_inhalt_edit()

    def _open_new_thema_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Neues Thema")
        dialog.transient(self)
        dialog.resizable(False, False)

        label = tk.Label(dialog, text="Thema:")
        label.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")

        thema_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=thema_var, width=36)
        entry.grid(row=0, column=1, padx=12, pady=(12, 6))
        entry.focus_set()

        def on_save():
            raw = thema_var.get()
            self._create_table(raw)
            dialog.destroy()

        save_btn = tk.Button(dialog, text="Speichern", command=on_save)
        save_btn.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="w")

        cancel_btn = tk.Button(dialog, text="Abbrechen", command=dialog.destroy)
        cancel_btn.grid(row=1, column=1, padx=12, pady=(0, 12), sticky="e")

    def _get_current_window_size(self):
        match = re.match(r"^(\d+)x(\d+)", self.geometry())
        if match:
            return int(match.group(1)), int(match.group(2))
        return self.winfo_width(), self.winfo_height()

    def _parse_window_size(self, value):
        if not value:
            return None
        match = re.match(r"^(\d+)x(\d+)", str(value).strip())
        if not match:
            return None
        return int(match.group(1)), int(match.group(2))

    def _ensure_settings_table(self):
        try:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS app_settings ("
                "key TEXT PRIMARY KEY, "
                "value TEXT NOT NULL"
                ")"
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _ensure_themen_meta_table(self):
        try:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS app_themen_meta ("
                "name TEXT PRIMARY KEY, "
                "erstellt_am TEXT NOT NULL"
                ")"
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _ensure_entry_fields_table(self):
        try:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS app_entry_fields ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "thema TEXT NOT NULL, "
                "entry_id INTEGER NOT NULL, "
                "field_key TEXT NOT NULL, "
                "field_value TEXT NOT NULL, "
                "sort_order INTEGER NOT NULL DEFAULT 0"
                ")"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_app_entry_fields_entry "
                "ON app_entry_fields (thema, entry_id, sort_order, id)"
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _delete_entry_fields(self, thema, entry_id):
        if not thema or not entry_id:
            return
        self._ensure_entry_fields_table()
        try:
            self.conn.execute(
                "DELETE FROM app_entry_fields WHERE thema = ? AND entry_id = ?",
                (thema, entry_id),
            )
        except sqlite3.Error:
            pass

    def _get_entry_fields(self, thema, entry_id):
        if not thema or not entry_id:
            return []
        self._ensure_entry_fields_table()
        try:
            rows = self.conn.execute(
                "SELECT field_key, field_value FROM app_entry_fields "
                "WHERE thema = ? AND entry_id = ? "
                "ORDER BY sort_order ASC, id ASC",
                (thema, entry_id),
            ).fetchall()
        except sqlite3.Error:
            return []
        return [(row[0], row[1]) for row in rows]

    def _format_entry_fields_for_search(self, thema, entry_id):
        fields = self._get_entry_fields(thema, entry_id)
        return "\n".join(f"{key}: {value}" for key, value in fields)

    def _save_entry_fields(self, thema, entry_id, fields):
        if not thema or not entry_id:
            return False
        self._ensure_entry_fields_table()
        cleaned = []
        for key, value in fields:
            key = key.strip()
            value = value.strip()
            if not key and not value:
                continue
            if not key:
                continue
            cleaned.append((key, value))
        try:
            self.conn.execute(
                "DELETE FROM app_entry_fields WHERE thema = ? AND entry_id = ?",
                (thema, entry_id),
            )
            self.conn.executemany(
                "INSERT INTO app_entry_fields "
                "(thema, entry_id, field_key, field_value, sort_order) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (thema, entry_id, key, value, idx)
                    for idx, (key, value) in enumerate(cleaned)
                ],
            )
            self.conn.commit()
        except sqlite3.Error as exc:
            messagebox.showerror("Felder", f"Felder konnten nicht gespeichert werden:\n{exc}")
            return False
        return True

    def _register_thema_created(self, name, created=None):
        if not name:
            return
        self._ensure_themen_meta_table()
        created = created or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.conn.execute(
                "INSERT OR IGNORE INTO app_themen_meta (name, erstellt_am) VALUES (?, ?)",
                (name, created),
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _backfill_themen_meta(self, names):
        if not names:
            return
        self._ensure_themen_meta_table()
        placeholders = ",".join("?" for _ in names)
        try:
            rows = self.conn.execute(
                f"SELECT name FROM app_themen_meta WHERE name IN ({placeholders})",
                names,
            ).fetchall()
        except sqlite3.Error:
            return
        existing = {row[0] for row in rows}
        missing = [name for name in names if name not in existing]
        if not missing:
            return
        created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.conn.executemany(
                "INSERT OR IGNORE INTO app_themen_meta (name, erstellt_am) VALUES (?, ?)",
                [(name, created) for name in missing],
            )
            self.conn.commit()
        except sqlite3.Error:
            pass

    def _get_stored_window_size(self):
        self._ensure_settings_table()
        width = None
        height = None
        try:
            row = self.conn.execute(
                "SELECT value FROM app_settings WHERE key = ?",
                ("window_size",),
            ).fetchone()
            value = row[0] if row else None
            if value is None:
                rows = self.conn.execute(
                    "SELECT key, value FROM app_settings"
                ).fetchall()
                for key, val in rows:
                    if key and key.strip().lower() == "window_size":
                        value = val
                        break
            if value:
                size = self._parse_window_size(value)
                if size:
                    width, height = size
            self._last_settings_error = None
        except sqlite3.Error as exc:
            self._last_settings_error = str(exc)
            width = None
            height = None
        if width and height:
            return width, height
        return None

    def _load_window_size(self, default="1440x420"):
        size = self._get_stored_window_size()
        if size:
            width, height = size
            self.geometry(f"{width}x{height}")
            self.update_idletasks()
            return size
        self.geometry(default)
        self.update_idletasks()
        return self._parse_window_size(default)

    def _reapply_window_size_if_needed(self, default_size):
        size = self._get_stored_window_size()
        if not size:
            return
        current = self._get_current_window_size()
        if current == default_size:
            width, height = size
            self.geometry(f"{width}x{height}")
            self.update_idletasks()

    def _save_window_size(self, width, height):
        self._ensure_settings_table()
        try:
            # Clean up any malformed keys like " window_size ".
            self.conn.execute(
                "DELETE FROM app_settings "
                "WHERE lower(trim(key)) = 'window_size' AND key <> 'window_size'"
            )
            self.conn.execute(
                "INSERT INTO app_settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("window_size", f"{width}x{height}"),
            )
            self.conn.commit()
            self._last_settings_error = None
        except sqlite3.Error as exc:
            self._last_settings_error = str(exc)
            messagebox.showerror("Einstellungen", f"Fenstergroesse konnte nicht gespeichert werden:\n{exc}")

    def _get_setting(self, key, default=None):
        self._ensure_settings_table()
        try:
            row = self.conn.execute(
                "SELECT value FROM app_settings WHERE key = ?",
                (key,),
            ).fetchone()
            if row:
                return row[0]
        except sqlite3.Error as exc:
            self._last_settings_error = str(exc)
        return default

    def _get_setting_bool(self, key, default=False):
        value = self._get_setting(key, None)
        if value is None:
            return default
        raw = str(value).strip().lower()
        if raw in ("1", "true", "yes", "ja", "on"):
            return True
        if raw in ("0", "false", "no", "nein", "off"):
            return False
        return default

    def _set_setting(self, key, value):
        self._ensure_settings_table()
        try:
            self.conn.execute(
                "INSERT INTO app_settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
            self.conn.commit()
            self._last_settings_error = None
            return True
        except sqlite3.Error as exc:
            self._last_settings_error = str(exc)
            messagebox.showerror("Einstellungen", f"Einstellung konnte nicht gespeichert werden:\n{exc}")
            return False

    def _open_window_size_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Fenstergroesse")
        dialog.transient(self)
        dialog.resizable(False, False)

        current_width, current_height = self._get_current_window_size()
        width_var = tk.StringVar(value=str(current_width))
        height_var = tk.StringVar(value=str(current_height))

        width_label = tk.Label(dialog, text="Breite (px):")
        width_label.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")
        width_entry = tk.Entry(dialog, textvariable=width_var, width=12)
        width_entry.grid(row=0, column=1, padx=12, pady=(12, 6), sticky="w")

        height_label = tk.Label(dialog, text="Hoehe (px):")
        height_label.grid(row=1, column=0, padx=12, pady=(0, 6), sticky="w")
        height_entry = tk.Entry(dialog, textvariable=height_var, width=12)
        height_entry.grid(row=1, column=1, padx=12, pady=(0, 6), sticky="w")

        width_entry.focus_set()

        def apply_size():
            try:
                width = int(width_var.get().strip())
                height = int(height_var.get().strip())
            except ValueError:
                messagebox.showwarning("Ungueltig", "Bitte gueltige Zahlen eingeben.")
                return
            if width < 200 or height < 200:
                messagebox.showwarning("Ungueltig", "Breite und Hoehe muessen mindestens 200 px sein.")
                return
            self.geometry(f"{width}x{height}")
            self._save_window_size(width, height)
            dialog.destroy()

        save_btn = tk.Button(dialog, text="Uebernehmen", command=apply_size)
        save_btn.grid(row=2, column=0, padx=12, pady=(0, 12), sticky="w")

        cancel_btn = tk.Button(dialog, text="Abbrechen", command=dialog.destroy)
        cancel_btn.grid(row=2, column=1, padx=12, pady=(0, 12), sticky="e")

    def _open_line_numbers_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Zeilennummern")
        dialog.transient(self)
        dialog.resizable(False, False)

        var = tk.BooleanVar(value=self.show_line_numbers_var.get())
        toggle = tk.Checkbutton(
            dialog,
            text="Zeilennummern im Unterthemen-Text anzeigen",
            variable=var,
        )
        toggle.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")

        def apply_setting():
            value = var.get()
            if self._set_setting("unterthema_line_numbers", "1" if value else "0"):
                self.show_line_numbers_var.set(value)
                self._apply_inhalt_line_numbers_visibility()
                dialog.destroy()

        save_btn = tk.Button(dialog, text="Uebernehmen", command=apply_setting)
        save_btn.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="w")

        cancel_btn = tk.Button(dialog, text="Abbrechen", command=dialog.destroy)
        cancel_btn.grid(row=1, column=1, padx=12, pady=(0, 12), sticky="e")

    def _open_shortcuts_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Tastenkuerzel")
        dialog.transient(self)
        dialog.resizable(False, False)

        shortcuts = [
            ("Strg+F", "Stichwortsuche oeffnen"),
            ("Strg+N", "Schnellnotiz in NOTIZEN anlegen und direkt bearbeiten"),
            ("Strg+B", "Markierten Text hervorheben"),
            ("Strg+Shift+C", "Markierten Text in Codeblock umwandeln"),
            ("Strg+Shift+X", "Checkbox in aktueller Zeile umschalten"),
            ("Strg+Z", "Undo im Bearbeitungsmodus"),
            ("Strg+Y", "Redo im Bearbeitungsmodus"),
            ("Esc", "Speichern und Bearbeitungsmodus verlassen"),
        ]

        for row_idx, (shortcut, description) in enumerate(shortcuts):
            key_label = tk.Label(dialog, text=shortcut, anchor="w", width=14)
            key_label.grid(row=row_idx, column=0, padx=(12, 8), pady=(12 if row_idx == 0 else 4, 0), sticky="w")
            desc_label = tk.Label(dialog, text=description, anchor="w", justify="left")
            desc_label.grid(row=row_idx, column=1, padx=(0, 12), pady=(12 if row_idx == 0 else 4, 0), sticky="w")

        markdown_start_row = len(shortcuts) + 1
        markdown_title = tk.Label(
            dialog,
            text="Markdown-Funktionen",
            anchor="w",
            font=tkfont.Font(font=tkfont.nametofont("TkDefaultFont"), weight="bold"),
        )
        markdown_title.grid(
            row=markdown_start_row,
            column=0,
            columnspan=2,
            padx=12,
            pady=(14, 4),
            sticky="w",
        )

        markdown_items = [
            ("# Titel", "Ueberschrift Ebene 1"),
            ("## Titel", "Ueberschrift Ebene 2"),
            ("### Titel", "Ueberschrift Ebene 3"),
            ("**Text**", "Fett"),
            ("*Text*", "Kursiv"),
            ("`code`", "Inline-Code"),
            ("```bash", "Codeblock mit optionaler Sprache"),
            ("> Text", "Zitat"),
            ("- Punkt", "Aufzaehlung"),
            ("- [ ] Aufgabe", "Offene Checkbox"),
            ("- [x] Aufgabe", "Erledigte Checkbox"),
            ("[Text](URL)", "Link mit eigenem Text"),
            ("https://...", "Automatisch klickbarer Link"),
        ]

        for idx, (syntax, description) in enumerate(markdown_items, start=markdown_start_row + 1):
            syntax_label = tk.Label(dialog, text=syntax, anchor="w", width=14)
            syntax_label.grid(row=idx, column=0, padx=(12, 8), pady=(2, 0), sticky="w")
            desc_label = tk.Label(dialog, text=description, anchor="w", justify="left")
            desc_label.grid(row=idx, column=1, padx=(0, 12), pady=(2, 0), sticky="w")

        close_btn = tk.Button(dialog, text="Schliessen", command=dialog.destroy)
        close_btn.grid(
            row=markdown_start_row + len(markdown_items) + 1,
            column=0,
            columnspan=2,
            padx=12,
            pady=(12, 12),
            sticky="e",
        )

    def _open_debug_dialog(self):
        if self._debug_window and self._debug_window.winfo_exists():
            try:
                self._debug_window.lift()
                self._debug_window.focus_set()
            except tk.TclError:
                pass
            return

        dialog = tk.Toplevel(self)
        dialog.title("Debug")
        dialog.transient(self)
        dialog.resizable(True, True)
        self._debug_window = dialog

        text = tk.Text(dialog, width=80, height=20, wrap="none")
        text.pack(side="left", fill="both", expand=True, padx=12, pady=12)
        text.config(state="disabled")
        self._debug_text = text

        scroll = tk.Scrollbar(dialog, orient="vertical", command=text.yview)
        scroll.pack(side="right", fill="y", pady=12)
        text.config(yscrollcommand=scroll.set)

        btn_frame = tk.Frame(dialog)
        btn_frame.pack(fill="x", padx=12, pady=(0, 12))

        def clear_log():
            self._debug_log.clear()
            if self._debug_text and self._debug_text.winfo_exists():
                self._debug_text.config(state="normal")
                self._debug_text.delete("1.0", tk.END)
                self._debug_text.config(state="disabled")

        clear_btn = tk.Button(btn_frame, text="Leeren", command=clear_log)
        clear_btn.pack(side="left")

        close_btn = tk.Button(btn_frame, text="Schliessen", command=dialog.destroy)
        close_btn.pack(side="right")

        for entry in self._debug_log:
            self._append_debug_to_text(entry)

        def on_close():
            self._debug_window = None
            self._debug_text = None
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", on_close)

    def _log_db(self, kind, sql, elapsed_ms, params=None, error=None):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        msg = f"[{ts}] {kind} {elapsed_ms:.1f} ms | {sql}"
        if params is not None:
            msg += f" | params={params}"
        if error is not None:
            msg += f" | ERROR: {error}"
        self._debug_log.append(msg)
        if self._debug_text and self._debug_text.winfo_exists():
            self._append_debug_to_text(msg)

    def _append_debug_to_text(self, msg):
        if not self._debug_text or not self._debug_text.winfo_exists():
            return
        self._debug_text.config(state="normal")
        self._debug_text.insert(tk.END, msg + "\n")
        self._debug_text.see(tk.END)
        self._debug_text.config(state="disabled")

    def _open_new_unterthema_dialog(self):
        if not self.current_thema:
            messagebox.showwarning("Kein Thema", "Bitte zuerst ein Thema auswaehlen.")
            return
        dialog = tk.Toplevel(self)
        dialog.title("Neues Unterthema")
        dialog.transient(self)
        dialog.resizable(True, True)

        label = tk.Label(dialog, text="Titel:")
        label.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")

        titel_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=titel_var, width=40)
        entry.grid(row=0, column=1, padx=12, pady=(12, 6), sticky="we")
        entry.focus_set()

        text_label = tk.Label(dialog, text="Text:")
        text_label.grid(row=1, column=0, padx=12, pady=(0, 6), sticky="nw")

        text_box = tk.Text(dialog, width=50, height=10, wrap="word")
        text_box.grid(row=1, column=1, padx=12, pady=(0, 6), sticky="nsew")

        dialog.grid_columnconfigure(1, weight=1)
        dialog.grid_rowconfigure(1, weight=1)

        def on_save():
            titel = titel_var.get()
            inhalt = text_box.get("1.0", tk.END)
            self._insert_unterthema(titel, inhalt)
            dialog.destroy()

        save_btn = tk.Button(dialog, text="Speichern", command=on_save)
        save_btn.grid(row=2, column=0, padx=12, pady=(0, 12), sticky="w")

        cancel_btn = tk.Button(dialog, text="Abbrechen", command=dialog.destroy)
        cancel_btn.grid(row=2, column=1, padx=12, pady=(0, 12), sticky="e")

    def _search_query_tokens(self, query):
        tokens = []
        for match in re.finditer(r'"([^"]+)"|(\S+)', query):
            token = (match.group(1) or match.group(2) or "").strip().lower()
            if token:
                tokens.append(token)
        # Keep order, remove duplicates.
        return list(dict.fromkeys(tokens))

    def _normalize_todo_display_text(self, text):
        cleaned = (text or "").strip()
        if not cleaned:
            return ""
        cleaned = cleaned.replace("`", "").replace("*", "")
        cleaned = re.sub(r"^#+\s*", "", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip("-:[] ")

    def _extract_todo_items_from_text(self, text):
        items = []
        if not text:
            return items
        lines = text.splitlines()
        in_todo_block = False
        saw_todo_block_item = False

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip()
            stripped = line.strip()
            checklist_match = TODO_CHECKLIST_PATTERN.match(line)
            if checklist_match:
                items.append(
                    {
                        "text": self._normalize_todo_display_text(checklist_match.group(2)),
                        "line_no": line_no,
                        "checked": checklist_match.group(1).lower() == "x",
                    }
                )
                saw_todo_block_item = True
                continue

            todo_match = TODO_INLINE_PATTERN.search(line)
            if todo_match:
                in_todo_block = True
                saw_todo_block_item = False
                inline_text = self._normalize_todo_display_text(todo_match.group(1))
                if inline_text:
                    items.append(
                        {
                            "text": inline_text,
                            "line_no": line_no,
                            "checked": False,
                        }
                    )
                    saw_todo_block_item = True
                continue

            bullet_match = TODO_BULLET_PATTERN.match(line)
            if in_todo_block and bullet_match:
                bullet_text = self._normalize_todo_display_text(bullet_match.group(1))
                if bullet_text:
                    items.append(
                        {
                            "text": bullet_text,
                            "line_no": line_no,
                            "checked": False,
                        }
                    )
                    saw_todo_block_item = True
                continue

            if not in_todo_block:
                continue

            if not stripped or stripped == "---":
                continue
            if stripped.startswith("```"):
                in_todo_block = False
                saw_todo_block_item = False
                continue
            if stripped.startswith("#"):
                in_todo_block = False
                saw_todo_block_item = False
                continue
            if stripped.startswith("**") and saw_todo_block_item and not TODO_WORD_PATTERN.search(stripped):
                in_todo_block = False
                saw_todo_block_item = False

        deduped = []
        seen = set()
        for item in items:
            key = (item["line_no"], item["text"].lower())
            if not item["text"] or key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _collect_todo_results(self, include_archived=False):
        results = []
        for table in self._get_themen_tables():
            try:
                self._ensure_archived_column(table)
                if include_archived:
                    cursor = self.conn.execute(
                        f"SELECT id, titel, inhalt, archived FROM {table} ORDER BY id DESC"
                    )
                else:
                    cursor = self.conn.execute(
                        f"SELECT id, titel, inhalt, archived FROM {table} WHERE archived = 0 ORDER BY id DESC"
                    )
            except sqlite3.Error:
                continue
            for entry_id, titel, inhalt, archived in cursor.fetchall():
                todo_items = self._extract_todo_items_from_text(inhalt or "")
                if not todo_items:
                    continue
                safe_titel = titel or "(ohne Titel)"
                for item in todo_items:
                    results.append(
                        {
                            "thema": table,
                            "entry_id": entry_id,
                            "titel": safe_titel,
                            "inhalt": inhalt or "",
                            "archived": bool(archived),
                            "todo_text": item["text"],
                            "line_no": item["line_no"],
                            "checked": item["checked"],
                        }
                    )
        results.sort(
            key=lambda item: (
                item["checked"],
                self._display_thema_name(item["thema"]).lower(),
                item["titel"].lower(),
                item["line_no"],
            )
        )
        return results

    def _score_todo_match(self, query, tokens, todo_text, titel, thema):
        if not tokens:
            return 1
        todo_l = (todo_text or "").lower()
        titel_l = (titel or "").lower()
        thema_l = self._display_thema_name(thema or "").lower()
        combined = "\n".join([todo_l, titel_l, thema_l])
        for token in tokens:
            if token not in combined:
                return None
        score = 0
        query_l = (query or "").strip().lower()
        if query_l:
            score += todo_l.count(query_l) * 8
            score += titel_l.count(query_l) * 3
            score += thema_l.count(query_l) * 2
        for token in tokens:
            score += todo_l.count(token) * 5
            score += titel_l.count(token) * 2
            score += thema_l.count(token)
        return max(score, 1)

    def _highlight_text_in_widget(self, widget, query):
        widget.config(state="normal")
        widget.tag_remove("match", "1.0", tk.END)
        first_match = None
        query = (query or "").strip()
        if query:
            start = "1.0"
            while True:
                pos = widget.search(query, start, stopindex=tk.END, nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(query)}c"
                widget.tag_add("match", pos, end)
                if first_match is None:
                    first_match = pos
                start = end
            widget.tag_config("match", background="#ffe08a")
        if first_match is not None:
            widget.mark_set("insert", first_match)
            widget.see(first_match)
        widget.config(state="disabled")

    def _open_todo_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("ToDo-Liste")
        dialog.transient(self)
        dialog.resizable(True, True)

        query_label = tk.Label(dialog, text="Filter:")
        query_label.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")

        query_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=query_var, width=40)
        entry.grid(row=0, column=1, padx=12, pady=(12, 6), sticky="we")
        entry.focus_set()

        include_archived_var = tk.BooleanVar(value=False)
        archived_check = tk.Checkbutton(
            dialog,
            text="Archiv einbeziehen",
            variable=include_archived_var,
        )
        archived_check.grid(row=0, column=2, padx=(0, 12), pady=(12, 6), sticky="w")

        results_frame = tk.Frame(dialog)
        results_frame.grid(row=1, column=0, columnspan=3, padx=12, pady=(0, 6), sticky="nsew")

        results_list = tk.Listbox(results_frame, width=70, height=14)
        results_list.pack(side="left", fill="both", expand=True)

        results_scroll = tk.Scrollbar(results_frame, orient="vertical", command=results_list.yview)
        results_scroll.pack(side="right", fill="y")
        results_list.config(yscrollcommand=results_scroll.set)

        preview_frame = tk.Frame(dialog)
        preview_frame.grid(row=2, column=0, columnspan=3, padx=12, pady=(0, 6), sticky="nsew")

        preview_text = tk.Text(preview_frame, width=70, height=12, wrap="word")
        preview_text.pack(side="left", fill="both", expand=True)
        self._prepare_link_handling(preview_text)

        preview_scroll = tk.Scrollbar(preview_frame, orient="vertical", command=preview_text.yview)
        preview_scroll.pack(side="right", fill="y")
        preview_text.config(yscrollcommand=preview_scroll.set)
        preview_text.config(state="disabled")

        dialog.grid_columnconfigure(1, weight=1)
        dialog.grid_rowconfigure(1, weight=1)
        dialog.grid_rowconfigure(2, weight=1)

        todo_results = []
        filtered_results = []
        search_job = None

        def set_preview_text(text):
            preview_text.config(state="normal")
            preview_text.delete("1.0", tk.END)
            preview_text.insert("1.0", text)
            self._clear_link_targets(preview_text)
            self._linkify_text_widget(preview_text, text)
            preview_text.config(state="disabled")

        def refresh_source_results():
            nonlocal todo_results
            todo_results = self._collect_todo_results(include_archived=include_archived_var.get())

        def apply_filter():
            nonlocal filtered_results
            refresh_source_results()
            filtered_results = []
            results_list.delete(0, tk.END)
            set_preview_text("")
            query = query_var.get().strip()
            tokens = self._search_query_tokens(query)

            ranked = []
            for item in todo_results:
                score = self._score_todo_match(
                    query,
                    tokens,
                    item["todo_text"],
                    item["titel"],
                    item["thema"],
                )
                if score is None:
                    continue
                ranked.append((score, item))

            ranked.sort(
                key=lambda entry: (
                    entry[1]["checked"],
                    -entry[0],
                    self._display_thema_name(entry[1]["thema"]).lower(),
                    entry[1]["titel"].lower(),
                    entry[1]["line_no"],
                )
            )

            for score, item in ranked:
                filtered_results.append(item)
                status = "[x]" if item["checked"] else "[ ]"
                display_thema = self._display_thema_name(item["thema"])
                label = f"{status} {item['todo_text']}  |  {display_thema} -> {item['titel']}"
                if query:
                    label = f"{label} ({score})"
                results_list.insert(tk.END, label)
                if item["archived"]:
                    try:
                        results_list.itemconfig(tk.END, foreground="#b00020")
                    except tk.TclError:
                        pass
            if filtered_results:
                results_list.selection_clear(0, tk.END)
                results_list.selection_set(0)
                results_list.activate(0)
                results_list.see(0)
                on_select_result(None)
            else:
                set_preview_text("Keine ToDos gefunden.")

        def on_select_result(_event):
            selection = results_list.curselection()
            if not selection:
                return
            idx = selection[0]
            if idx >= len(filtered_results):
                return
            item = filtered_results[idx]
            display_thema = self._display_thema_name(item["thema"])
            status = "erledigt" if item["checked"] else "offen"
            archived_text = "\nStatus: Archiv" if item["archived"] else ""
            preview = (
                f"Thema: {display_thema}\n"
                f"Unterthema: {item['titel']}\n"
                f"ToDo-Zeile: {item['line_no']}\n"
                f"ToDo-Status: {status}{archived_text}\n\n"
                f"{item['todo_text']}\n\n"
                f"{item['inhalt']}"
            )
            set_preview_text(preview)
            self._highlight_text_in_widget(preview_text, item["todo_text"])

        def open_selected_result(_event=None):
            selection = results_list.curselection()
            if not selection and filtered_results:
                results_list.selection_set(0)
                selection = (0,)
            if not selection:
                return
            idx = selection[0]
            if idx >= len(filtered_results):
                return
            item = filtered_results[idx]
            if not self._select_thema_by_name(item["thema"]):
                return
            if item["archived"] and not self.show_archived_var.get():
                self.show_archived_var.set(True)
                self._load_unterthemen()
            if self._select_unterthema_by_id(item["entry_id"]):
                self._highlight_inhalt_query(item["todo_text"])
            dialog.destroy()

        def schedule_filter(*_args):
            nonlocal search_job
            if search_job is not None:
                dialog.after_cancel(search_job)
            search_job = dialog.after(180, run_scheduled_filter)

        def run_scheduled_filter():
            nonlocal search_job
            search_job = None
            if dialog.winfo_exists():
                apply_filter()

        refresh_btn = tk.Button(dialog, text="Aktualisieren", command=apply_filter)
        refresh_btn.grid(row=3, column=0, padx=12, pady=(0, 12), sticky="w")

        open_btn = tk.Button(dialog, text="Oeffnen", command=open_selected_result)
        open_btn.grid(row=3, column=1, padx=12, pady=(0, 12), sticky="e")

        close_btn = tk.Button(dialog, text="Schliessen", command=dialog.destroy)
        close_btn.grid(row=3, column=2, padx=12, pady=(0, 12), sticky="e")

        entry.bind("<Return>", lambda _event: apply_filter())
        query_var.trace_add("write", schedule_filter)
        include_archived_var.trace_add("write", schedule_filter)
        results_list.bind("<<ListboxSelect>>", on_select_result)
        results_list.bind("<Double-Button-1>", open_selected_result)

        apply_filter()

    def _score_search_match(self, query, tokens, titel, inhalt, felder):
        query_l = (query or "").strip().lower()
        titel_l = (titel or "").lower()
        inhalt_l = (inhalt or "").lower()
        felder_l = (felder or "").lower()
        combined = "\n".join([titel_l, inhalt_l, felder_l])

        # Require all query tokens somewhere in title/content/fields.
        for token in tokens:
            if token not in combined:
                return None

        score = 0
        if query_l:
            score += titel_l.count(query_l) * 10
            score += felder_l.count(query_l) * 6
            score += inhalt_l.count(query_l) * 3

        for token in tokens:
            score += titel_l.count(token) * 6
            score += felder_l.count(token) * 4
            score += inhalt_l.count(token) * 2

        return max(score, 1)

    def _open_search_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Stichwortsuche")
        dialog.transient(self)
        dialog.resizable(True, True)

        label = tk.Label(dialog, text="Suchbegriff:")
        label.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="w")

        query_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=query_var, width=40)
        entry.grid(row=0, column=1, padx=12, pady=(12, 6), sticky="we")
        entry.focus_set()

        search_archived_var = tk.BooleanVar(value=False)
        archived_check = tk.Checkbutton(
            dialog,
            text="Suche im Archiv",
            variable=search_archived_var,
        )
        archived_check.grid(row=0, column=2, padx=(0, 12), pady=(12, 6), sticky="w")

        results_frame = tk.Frame(dialog)
        results_frame.grid(row=1, column=0, columnspan=2, padx=12, pady=(0, 6), sticky="nsew")

        results_list = tk.Listbox(results_frame, width=50, height=10)
        results_list.pack(side="left", fill="both", expand=True)

        results_scroll = tk.Scrollbar(
            results_frame, orient="vertical", command=results_list.yview
        )
        results_scroll.pack(side="right", fill="y")
        results_list.config(yscrollcommand=results_scroll.set)

        result_frame = tk.Frame(dialog)
        result_frame.grid(row=2, column=0, columnspan=2, padx=12, pady=(0, 6), sticky="nsew")

        result_text = tk.Text(result_frame, width=60, height=10, wrap="word")
        result_text.pack(side="left", fill="both", expand=True)
        self._prepare_link_handling(result_text)

        result_scroll = tk.Scrollbar(
            result_frame, orient="vertical", command=result_text.yview
        )
        result_scroll.pack(side="right", fill="y")
        result_text.config(yscrollcommand=result_scroll.set)
        result_text.config(state="disabled")

        dialog.grid_columnconfigure(1, weight=1)
        dialog.grid_rowconfigure(1, weight=1)
        dialog.grid_rowconfigure(2, weight=1)

        results = []
        search_job = None

        def set_result_text(text):
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            result_text.insert("1.0", text)
            self._clear_link_targets(result_text)
            self._linkify_text_widget(result_text, text)
            result_text.config(state="disabled")

        def highlight_query(query):
            result_text.config(state="normal")
            result_text.tag_remove("match", "1.0", tk.END)
            first_match = None
            if query:
                start = "1.0"
                while True:
                    pos = result_text.search(query, start, stopindex=tk.END, nocase=True)
                    if not pos:
                        break
                    end = f"{pos}+{len(query)}c"
                    result_text.tag_add("match", pos, end)
                    if first_match is None:
                        first_match = pos
                    start = end
                result_text.tag_config("match", background="#ffe08a")
            if first_match is not None:
                result_text.mark_set("insert", first_match)
                result_text.see(first_match)
            result_text.config(state="disabled")

        def on_select_result(_event):
            selection = results_list.curselection()
            if not selection:
                return
            idx = selection[0]
            if idx >= len(results):
                return
            thema, _entry_id, titel, inhalt, archived, felder = results[idx]
            display_thema = self._display_thema_name(thema)
            fields_text = f"\nFelder:\n{felder}\n" if felder else ""
            if archived:
                set_result_text(
                    f"Thema: {display_thema}\nUnterthema: {titel}\nStatus: Archiv\n"
                    f"{fields_text}\n{inhalt}"
                )
            else:
                set_result_text(f"Thema: {display_thema}\nUnterthema: {titel}\n{fields_text}\n{inhalt}")
            highlight_query(query_var.get().strip())

        def select_first_result():
            if not results:
                return False
            results_list.selection_clear(0, tk.END)
            results_list.selection_set(0)
            results_list.activate(0)
            results_list.see(0)
            on_select_result(None)
            return True

        def perform_search():
            nonlocal results
            query = query_var.get().strip()
            results_list.delete(0, tk.END)
            results = []
            set_result_text("")
            if not query:
                return
            tokens = self._search_query_tokens(query)
            if not tokens:
                return
            ranked_results = []
            for table in self._get_themen_tables():
                try:
                    self._ensure_archived_column(table)
                    where_parts = []
                    params = []
                    for token in tokens:
                        where_parts.append("(titel LIKE ? COLLATE NOCASE OR inhalt LIKE ? COLLATE NOCASE)")
                        like_query = f"%{token}%"
                        params.extend([like_query, like_query])
                    where_parts = [f"({' OR '.join(where_parts)})"]
                    if not search_archived_var.get():
                        where_parts.append("archived = 0")
                    where_sql = " AND ".join(where_parts)
                    cursor = self.conn.execute(
                        f"SELECT id, titel, inhalt, archived FROM {table} "
                        f"WHERE {where_sql} ORDER BY id DESC",
                        params,
                    )
                except sqlite3.Error:
                    continue
                for entry_id, titel, inhalt, archived in cursor.fetchall():
                    safe_titel = titel or "(ohne Titel)"
                    safe_inhalt = inhalt or ""
                    safe_felder = self._format_entry_fields_for_search(table, entry_id)
                    match_score = self._score_search_match(
                        query,
                        tokens,
                        safe_titel,
                        safe_inhalt,
                        safe_felder,
                    )
                    if match_score is None:
                        continue
                    ranked_results.append(
                        (
                            match_score,
                            table,
                            entry_id,
                            safe_titel,
                            safe_inhalt,
                            archived,
                            safe_felder,
                        )
                    )

            ranked_results.sort(key=lambda item: (-item[0], item[1].lower(), -item[2]))

            for match_score, table, entry_id, safe_titel, safe_inhalt, archived, safe_felder in ranked_results:
                results.append((table, entry_id, safe_titel, safe_inhalt, archived, safe_felder))
                label = safe_titel
                if archived:
                    label = f"[ARCHIV] {label}"
                results_list.insert(tk.END, f"{table} -> {label} ({match_score})")
                if archived:
                    try:
                        results_list.itemconfig(tk.END, foreground="#b00020")
                    except tk.TclError:
                        pass
            if results:
                select_first_result()
            else:
                set_result_text("Keine Treffer.")

        def schedule_search(*_args):
            nonlocal search_job
            if search_job is not None:
                dialog.after_cancel(search_job)
            search_job = dialog.after(180, run_scheduled_search)

        def run_scheduled_search():
            nonlocal search_job
            search_job = None
            if dialog.winfo_exists():
                perform_search()

        def open_selected_result(_event=None):
            selection = results_list.curselection()
            if not selection and not select_first_result():
                return
            selection = results_list.curselection()
            idx = selection[0]
            if idx >= len(results):
                return
            thema, entry_id, _titel, _inhalt, archived, _felder = results[idx]
            if not self._select_thema_by_name(thema):
                return
            if archived and not self.show_archived_var.get():
                self.show_archived_var.set(True)
                self._load_unterthemen()
            self._select_unterthema_by_id(entry_id)
            self._highlight_inhalt_query(query_var.get().strip())
            dialog.destroy()

        search_btn = tk.Button(dialog, text="Suchen", command=perform_search)
        search_btn.grid(row=3, column=0, padx=12, pady=(0, 12), sticky="w")

        close_btn = tk.Button(dialog, text="Schliessen", command=dialog.destroy)
        close_btn.grid(row=3, column=1, padx=12, pady=(0, 12), sticky="e")

        entry.bind("<Return>", lambda _event: perform_search())
        query_var.trace_add("write", schedule_search)
        search_archived_var.trace_add("write", schedule_search)
        results_list.bind("<<ListboxSelect>>", on_select_result)
        results_list.bind("<Double-Button-1>", open_selected_result)

    def _open_search_shortcut(self, _event=None):
        self._open_search_dialog()
        return "break"

    def _on_toggle_show_archived(self):
        if self.current_thema:
            self._load_unterthemen()

    def _open_unterthema_for_edit(self, _event=None):
        self._on_select_unterthema(None)
        if self.current_unterthema_archived:
            messagebox.showinfo("Archiv", "Archivierte Unterthemen koennen nicht bearbeitet werden.")
            return "break"
        self._enable_inhalt_edit()
        return "break"

    def _toggle_bold_shortcut(self, _event=None):
        self._wrap_selection_bold()
        return "break"

    def _wrap_code_shortcut(self, _event=None):
        self._wrap_selection_code()
        return "break"

    def _toggle_checklist_shortcut(self, _event=None):
        widget = self._get_active_inhalt_widget()
        try:
            self._inhalt_context_index = widget.index(tk.INSERT)
        except tk.TclError:
            self._inhalt_context_index = None
        self._toggle_checklist_item_from_context()
        return "break"

    def _undo_shortcut(self, _event=None):
        if not self.is_editing:
            return "break"
        editor = self._get_active_inhalt_widget()
        try:
            editor.edit_undo()
        except tk.TclError:
            pass
        return "break"

    def _redo_shortcut(self, _event=None):
        if not self.is_editing:
            return "break"
        editor = self._get_active_inhalt_widget()
        try:
            editor.edit_redo()
        except tk.TclError:
            pass
        return "break"

    def _navigation_back_shortcut(self, _event=None):
        self._go_navigation_back()
        return "break"

    def _navigation_forward_shortcut(self, _event=None):
        self._go_navigation_forward()
        return "break"

    def _create_notes_shortcut(self, _event=None):
        self._create_quick_note()
        return "break"

    def _get_db_header_text(self):
        mode = "verschluesselt" if self.db_storage.is_encrypted else "normal"
        return f"Datenbank: {os.path.basename(self.db_path)} ({mode})"

    def _on_close_app(self):
        self._close_unterthema_preview_window()
        try:
            self._autosave_current_if_dirty()
        except Exception:
            pass
        try:
            self._stop_autosave()
        except Exception:
            pass
        try:
            self._stop_auto_backup()
        except Exception:
            pass
        try:
            self.conn.close()
        finally:
            self.destroy()


def main():
    root = tk.Tk()
    root.withdraw()
    try:
        db_path, create_encrypted, db_password = _resolve_db_selection(root)
    except (_DbStorageError, OSError) as exc:
        root.destroy()
        messagebox.showerror("Datenbank", f"Datenbank konnte nicht geoeffnet werden:\n{exc}")
        return
    root.destroy()
    if not db_path:
        return
    try:
        app = WissensDbApp(
            db_path,
            create_encrypted=create_encrypted,
            db_password=db_password,
        )
    except (_DbStorageError, OSError, sqlite3.Error) as exc:
        messagebox.showerror("Datenbank", f"Datenbank konnte nicht geoeffnet werden:\n{exc}")
        return
    app.mainloop()


if __name__ == "__main__":
    main()
