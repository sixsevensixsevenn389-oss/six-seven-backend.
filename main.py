"""
SIX SEVEN VPN — Render backend
Run command:
    uvicorn main:app --host 0.0.0.0 --port $PORT

Environment:
    TELEGRAM_BOT_TOKEN   optional; enables Telegram bot polling
    ADMIN_TELEGRAM_ID    Telegram numeric ID of the owner/admin
    OWNER_DEVICE_IDS     comma-separated permanent device IDs
    DB_PATH              SQLite path; use a Render persistent disk path
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.ext import (
        Application,
        CallbackQueryHandler,
        CommandHandler,
        ContextTypes,
    )
except ImportError:
    InlineKeyboardButton = InlineKeyboardMarkup = Update = None
    Application = CallbackQueryHandler = CommandHandler = ContextTypes = None


# ---------- Configuration ----------

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("sixseven")

DB_PATH = os.getenv("DB_PATH", "sixseven.sqlite3").strip() or "sixseven.sqlite3"
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()

def parse_admin_id() -> int:
    raw = os.getenv("ADMIN_TELEGRAM_ID", "").strip()
    if not raw:
        return 0
    try:
        return int(raw)
    except ValueError:
        log.error("ADMIN_TELEGRAM_ID must be a numeric Telegram ID; admin commands disabled.")
        return 0

ADMIN_ID = parse_admin_id()
OWNER_DEVICE_IDS = {
    item.strip()
    for item in os.getenv("OWNER_DEVICE_IDS", "").split(",")
    if item.strip() and not item.strip().startswith("REPLACE_")
}

app = FastAPI(title="SIX SEVEN VPN API", version="2.0.0")
bot_app = None


# ---------- Database ----------

@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        yield connection
    finally:
        connection.close()


def init_db() -> None:
    # Keep the existing table names and core columns so old data can be reused.
    with db() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                note TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                expires TEXT,
                max_devices INTEGER NOT NULL DEFAULT 3,
                revoked INTEGER NOT NULL DEFAULT 0,
                created TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activations (
                key_hash TEXT NOT NULL,
                device_id TEXT NOT NULL,
                created TEXT NOT NULL,
                UNIQUE(key_hash, device_id)
            );

            CREATE TABLE IF NOT EXISTS trial_claims (
                device_id TEXT PRIMARY KEY,
                started TEXT NOT NULL,
                expires TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_activations_device
                ON activations(device_id);
            CREATE INDEX IF NOT EXISTS idx_activations_key
                ON activations(key_hash);
            """
        )
    log.info("Database initialized at %s", DB_PATH)


# ---------- Shared helpers ----------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_key() -> str:
    return "S7-" + "-".join(secrets.token_hex(3).upper() for _ in range(4))


def parse_expiry(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


def is_owner_device(device_id: str) -> bool:
    return device_id in OWNER_DEVICE_IDS


# ---------- Request models ----------

class DeviceIn(BaseModel):
    device_id: str = Field(min_length=2, max_length=128)


class TrialIn(DeviceIn):
    pass


class ActivateIn(BaseModel):
    key: str = Field(min_length=4, max_length=100)
    device_id: str = Field(min_length=2, max_length=128)


class RequestIn(BaseModel):
    device_id: str = Field(min_length=2, max_length=128)
    note: str = Field(
        default="Запрос доступа из приложения",
        max_length=300,
    )


# ---------- Telegram bot ----------

def admin_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📊 Статистика", callback_data="panel:stats"),
            InlineKeyboardButton("📨 Заявки", callback_data="panel:requests"),
        ],
        [InlineKeyboardButton("🔑 Ключи", callback_data="panel:licenses")],
    ])


def is_admin_user(update: Update) -> bool:
    user = update.effective_user
    return bool(user and ADMIN_ID and user.id == ADMIN_ID)


async def deny_non_admin(update: Update) -> bool:
    if is_admin_user(update):
        return False
    if update.effective_message:
        await update.effective_message.reply_text("⛔ Нет доступа.")
    return True


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "Привет! Это бот SIX SEVEN VPN.\n"
        "Команда /whoami покажет твой Telegram ID.\n"
        "Для получения ключа следуй инструкциям проекта."
    )


async def whoami(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user:
        await update.effective_message.reply_text(f"Ваш Telegram ID: {user.id}")


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if await deny_non_admin(update):
        return
    await update.effective_message.reply_text(
        "🛠 Админ-панель SIX SEVEN\n\n"
        "/stats — статистика\n"
        "/requests — последние заявки\n"
        "/users — последние лицензии\n"
        "/whoami — Telegram ID",
        reply_markup=admin_keyboard(),
    )


async def stats_text() -> str:
    with db() as connection:
        requests_total = connection.execute(
            "SELECT COUNT(*) AS n FROM requests"
        ).fetchone()["n"]
        pending = connection.execute(
            "SELECT COUNT(*) AS n FROM requests WHERE status='pending'"
        ).fetchone()["n"]
        licenses_total = connection.execute(
            "SELECT COUNT(*) AS n FROM licenses"
        ).fetchone()["n"]
        active = connection.execute(
            "SELECT COUNT(*) AS n FROM licenses WHERE revoked=0"
        ).fetchone()["n"]
        activations = connection.execute(
            "SELECT COUNT(*) AS n FROM activations"
        ).fetchone()["n"]
    return (
        "📊 Статистика SIX SEVEN\n\n"
        f"Всего заявок: {requests_total}\n"
        f"Ожидают решения: {pending}\n"
        f"Всего лицензий: {licenses_total}\n"
        f"Не отозвано лицензий: {active}\n"
        f"Активаций устройств: {activations}"
    )


async def requests_text() -> str:
    with db() as connection:
        rows = connection.execute(
            "SELECT id, device_id, note, status, created "
            "FROM requests ORDER BY id DESC LIMIT 10"
        ).fetchall()
    if not rows:
        return "📨 Заявок пока нет."
    lines = ["📨 Последние заявки:"]
    for row in rows:
        lines.append(
            f"\n#{row['id']} — {row['status']}\n"
            f"Устройство: {row['device_id']}\n"
            f"Комментарий: {row['note'] or '—'}\n"
            f"Дата: {row['created']}"
        )
    return "\n".join(lines)


async def users_text() -> str:
    with db() as connection:
        rows = connection.execute(
            "SELECT l.id, l.expires, l.max_devices, l.revoked, l.created, "
            "COUNT(a.device_id) AS devices "
            "FROM licenses l LEFT JOIN activations a ON a.key_hash=l.key_hash "
            "GROUP BY l.id ORDER BY l.id DESC LIMIT 10"
        ).fetchall()
    if not rows:
        return "🔑 Выданных лицензий пока нет."
    lines = ["🔑 Последние лицензии:"]
    for row in rows:
        status = "отозвана" if row["revoked"] else "активна"
        lines.append(
            f"\nЛицензия #{row['id']} — {status}\n"
            f"Устройств: {row['devices']}/{row['max_devices']}\n"
            f"Истекает: {row['expires'] or 'без срока'}\n"
            f"Создана: {row['created']}"
        )
    return "\n".join(lines)


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await deny_non_admin(update):
        await update.effective_message.reply_text(await stats_text())


async def requests_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await deny_non_admin(update):
        await update.effective_message.reply_text(await requests_text())


async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await deny_non_admin(update):
        await update.effective_message.reply_text(await users_text())


async def panel_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query:
        return
    if not ADMIN_ID or query.from_user.id != ADMIN_ID:
        await query.answer("Нет доступа", show_alert=True)
        return
    await query.answer()
    section = (query.data or "").split(":", 1)[-1]
    if section == "stats":
        message = await stats_text()
    elif section == "requests":
        message = await requests_text()
    elif section == "licenses":
        message = await users_text()
    else:
        message = "Неизвестный раздел."
    await query.message.reply_text(message)


async def approve_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query or not query.data:
        return
    if not ADMIN_ID or query.from_user.id != ADMIN_ID:
        await query.answer("Нет доступа", show_alert=True)
        return

    try:
        _, request_id_text, days_text = query.data.split(":")
        request_id = int(request_id_text)
        days = int(days_text)
        if days not in (30, 90, 180, 365):
            raise ValueError
    except ValueError:
        await query.answer("Некорректная заявка", show_alert=True)
        return

    key = make_key()
    expires = (utcnow() + timedelta(days=days)).isoformat()

    try:
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            request = connection.execute(
                "SELECT * FROM requests WHERE id=? AND status='pending'",
                (request_id,),
            ).fetchone()
            if not request:
                connection.rollback()
                await query.answer("Заявка уже обработана")
                return
            connection.execute(
                "INSERT INTO licenses(key_hash, expires, max_devices, revoked, created) "
                "VALUES(?,?,3,0,?)",
                (hash_value(key), expires, iso_now()),
            )
            connection.execute(
                "UPDATE requests SET status='approved' WHERE id=?",
                (request_id,),
            )
            connection.commit()
    except sqlite3.Error:
        log.exception("Could not approve request %s", request_id)
        await query.answer("Ошибка базы данных", show_alert=True)
        return

    await query.edit_message_text(
        f"✅ Заявка #{request_id} одобрена.\n"
        f"Ключ на {days} дней:\n`{key}`\n"
        "Лимит устройств: 3",
        parse_mode="Markdown",
    )
    await query.answer("Ключ создан")


# ---------- FastAPI lifecycle ----------

@app.on_event("startup")
async def startup():
    global bot_app
    init_db()

    if not BOT_TOKEN:
        log.warning("TELEGRAM_BOT_TOKEN is not set; API starts without Telegram bot.")
        return
    if Application is None:
        log.error("python-telegram-bot is not installed; bot disabled.")
        return

    try:
        bot_app = Application.builder().token(BOT_TOKEN).build()
        bot_app.add_handler(CommandHandler("start", start_command))
        bot_app.add_handler(CommandHandler("whoami", whoami))
        bot_app.add_handler(CommandHandler("admin", admin_command))
        bot_app.add_handler(CommandHandler("stats", stats_command))
        bot_app.add_handler(CommandHandler("requests", requests_command))
        bot_app.add_handler(CommandHandler("users", users_command))
        bot_app.add_handler(CallbackQueryHandler(approve_callback, pattern=r"^approve:"))
        bot_app.add_handler(CallbackQueryHandler(panel_callback, pattern=r"^panel:"))
        await bot_app.initialize()
        await bot_app.start()
        if bot_app.updater:
            await bot_app.updater.start_polling()
        log.info("Telegram bot started.")
    except Exception:
        log.exception("Telegram bot failed to start; API remains available.")
        if bot_app:
            try:
                await bot_app.shutdown()
            except Exception:
                log.exception("Telegram cleanup failed.")
        bot_app = None


@app.on_event("shutdown")
async def shutdown():
    global bot_app
    if not bot_app:
        return
    try:
        if bot_app.updater and bot_app.updater.running:
            await bot_app.updater.stop()
        if bot_app.running:
            await bot_app.stop()
        await bot_app.shutdown()
        log.info("Telegram bot stopped.")
    except Exception:
        log.exception("Telegram bot shutdown error.")


# ---------- HTTP API ----------

@app.get("/")
def root():
    return {"ok": True, "service": "SIX SEVEN VPN API", "version": "2.0.0"}


@app.get("/health")
def health():
    return {"ok": True, "service": "sixseven-license", "version": "2.0.0"}


@app.post("/request-access")
async def request_access(data: RequestIn):
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "INSERT INTO requests(device_id, note, status, created) "
            "VALUES(?,?, 'pending', ?)",
            (data.device_id, data.note, iso_now()),
        )
        request_id = cursor.lastrowid
        connection.commit()

    if bot_app and ADMIN_ID:
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("30 дней", callback_data=f"approve:{request_id}:30"),
                InlineKeyboardButton("90 дней", callback_data=f"approve:{request_id}:90"),
            ],
            [
                InlineKeyboardButton("180 дней", callback_data=f"approve:{request_id}:180"),
                InlineKeyboardButton("365 дней", callback_data=f"approve:{request_id}:365"),
            ],
        ])
        try:
            await bot_app.bot.send_message(
                ADMIN_ID,
                f"🆕 Заявка SIX SEVEN #{request_id}\n"
                f"Устройство: {data.device_id}\n"
                f"Комментарий: {data.note}",
                reply_markup=keyboard,
            )
        except Exception:
            log.exception("Could not notify admin about request %s", request_id)

    return {
        "ok": True,
        "request_id": request_id,
        "message": "Заявка сохранена",
    }


@app.post("/start-trial")
@app.post("/start_trial")
def start_trial(data: TrialIn):
    if is_owner_device(data.device_id):
        return {
            "ok": True,
            "plan": "developer",
            "expires": None,
            "message": "Доступ разработчика активен навсегда",
        }

    started = utcnow()
    expires = started + timedelta(days=7)

    try:
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO trial_claims(device_id, started, expires) VALUES(?,?,?)",
                (data.device_id, started.isoformat(), expires.isoformat()),
            )
            connection.commit()
    except sqlite3.IntegrityError:
        with db() as connection:
            existing = connection.execute(
                "SELECT expires FROM trial_claims WHERE device_id=?",
                (data.device_id,),
            ).fetchone()
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Бесплатный пробный период уже использован на этом устройстве",
                "expires": existing["expires"] if existing else None,
            },
        )
    except sqlite3.Error:
        log.exception("Trial creation failed")
        raise HTTPException(status_code=500, detail="Не удалось создать пробный период")

    return {
        "ok": True,
        "plan": "trial",
        "started": started.isoformat(),
        "expires": expires.isoformat(),
        "days": 7,
        "message": "Пробный доступ активирован на 7 дней",
    }


@app.post("/activate")
def activate(data: ActivateIn):
    if is_owner_device(data.device_id):
        return {
            "ok": True,
            "plan": "developer",
            "expires": None,
            "max_devices": 999,
            "message": "Доступ разработчика активен навсегда",
        }

    key_hash = hash_value(data.key.strip().upper())
    try:
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            license_row = connection.execute(
                "SELECT * FROM licenses WHERE key_hash=?",
                (key_hash,),
            ).fetchone()

            if not license_row or license_row["revoked"]:
                connection.rollback()
                raise HTTPException(status_code=403, detail="Ключ недействителен или отозван")

            expiry = parse_expiry(license_row["expires"])
            if license_row["expires"] and (expiry is None or expiry <= utcnow()):
                connection.rollback()
                raise HTTPException(status_code=403, detail="Срок действия ключа истёк")

            existing = connection.execute(
                "SELECT 1 FROM activations WHERE key_hash=? AND device_id=?",
                (key_hash, data.device_id),
            ).fetchone()

            count = connection.execute(
                "SELECT COUNT(*) AS n FROM activations WHERE key_hash=?",
                (key_hash,),
            ).fetchone()["n"]

            if not existing and count >= license_row["max_devices"]:
                connection.rollback()
                raise HTTPException(
                    status_code=403,
                    detail=f"Достигнут лимит устройств: {license_row['max_devices']}",
                )

            connection.execute(
                "INSERT OR IGNORE INTO activations(key_hash, device_id, created) VALUES(?,?,?)",
                (key_hash, data.device_id, iso_now()),
            )
            connection.commit()
    except HTTPException:
        raise
    except sqlite3.Error:
        log.exception("Key activation failed")
        raise HTTPException(status_code=500, detail="Ошибка базы данных при активации")

    return {
        "ok": True,
        "plan": "user",
        "expires": license_row["expires"],
        "max_devices": license_row["max_devices"],
        "message": "Ключ успешно активирован",
    }


@app.get("/validate")
@app.post("/validate")
async def validate(request: Request, device_id: Optional[str] = None):
    if not device_id:
        try:
            body = await request.json()
            if isinstance(body, dict):
                device_id = body.get("device_id")
        except Exception:
            pass

    if not isinstance(device_id, str) or not device_id.strip():
        raise HTTPException(status_code=422, detail="device_id is required")
    device_id = device_id.strip()

    if is_owner_device(device_id):
        return {"ok": True, "plan": "developer", "expires": None}

    now = utcnow()
    with db() as connection:
        # Any valid activated license is enough; an expired last activation
        # must not hide another still-valid license on the same device.
        rows = connection.execute(
            "SELECT l.expires, l.revoked FROM activations a "
            "JOIN licenses l ON l.key_hash=a.key_hash "
            "WHERE a.device_id=? ORDER BY a.rowid DESC",
            (device_id,),
        ).fetchall()

        for row in rows:
            if row["revoked"]:
                continue
            expiry = parse_expiry(row["expires"])
            if row["expires"] is None or (expiry and expiry > now):
                return {"ok": True, "plan": "user", "expires": row["expires"]}

        trial = connection.execute(
            "SELECT started, expires FROM trial_claims WHERE device_id=?",
            (device_id,),
        ).fetchone()

    if trial:
        trial_expiry = parse_expiry(trial["expires"])
        if trial_expiry and trial_expiry > now:
            return {
                "ok": True,
                "plan": "trial",
                "started": trial["started"],
                "expires": trial["expires"],
                "message": "Пробный доступ активен",
            }

    return {
        "ok": False,
        "message": "Нет активной подписки или пробный период закончился",
    }
