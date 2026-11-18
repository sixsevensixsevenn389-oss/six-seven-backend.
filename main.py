"""
SIX SEVEN VPN backend + Telegram Stars bot.
Keeps the existing Android API routes: /health, /request-access, /start-trial,
 /start_trial, /activate, /validate.
Python 3.12; python-telegram-bot 21.10.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from telegram import (
    InlineKeyboardButton, InlineKeyboardMarkup, LabeledPrice, Update
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, ContextTypes,
    MessageHandler, PreCheckoutQueryHandler, filters
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("sixseven")

DB_PATH = os.getenv("DB_PATH", "sixseven.sqlite3").strip() or "sixseven.sqlite3"
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
try:
    OWNER_ID = int(os.getenv("ADMIN_TELEGRAM_ID", "0").strip() or "0")
except ValueError:
    OWNER_ID = 0
CHANNEL_ID_RAW = os.getenv("CHANNEL_ID", "").strip()
CHANNEL_ID = CHANNEL_ID_RAW if CHANNEL_ID_RAW else ""
CHANNEL_URL = os.getenv("CHANNEL_URL", "https://t.me/+2zXvPBJZYr0wOTYy").strip()
STAR_RUBLES = 1.5
DEFAULT_DEVICES = 3
app = FastAPI(title="SIX SEVEN VPN API", version="3.0.0")
bot_app: Application | None = None

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        yield conn
    finally:
        conn.close()

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def iso_now() -> str:
    return utcnow().isoformat()

def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def make_key() -> str:
    return "S7-" + "-".join(secrets.token_hex(3).upper() for _ in range(4))

def parse_expiry(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

def is_owner_device(device_id: str) -> bool:
    ids = {x.strip() for x in os.getenv("OWNER_DEVICE_IDS", "").split(",") if x.strip()}
    return device_id in ids

def init_db():
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS requests(
          id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
          note TEXT, status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS licenses(
          id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL,
          expires TEXT, max_devices INTEGER NOT NULL DEFAULT 3,
          revoked INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activations(
          key_hash TEXT NOT NULL, device_id TEXT NOT NULL, created TEXT NOT NULL,
          UNIQUE(key_hash,device_id)
        );
        CREATE TABLE IF NOT EXISTS trial_claims(
          device_id TEXT PRIMARY KEY, started TEXT NOT NULL, expires TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders(
          id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id INTEGER NOT NULL,
          username TEXT, gb INTEGER NOT NULL, days INTEGER NOT NULL,
          servers INTEGER NOT NULL, devices INTEGER NOT NULL,
          price_rub INTEGER NOT NULL, price_stars INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'awaiting_payment',
          telegram_charge_id TEXT, license_id INTEGER, created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS roles(
          tg_id INTEGER PRIMARY KEY, role TEXT NOT NULL, added_by INTEGER NOT NULL,
          created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tariffs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
          gb INTEGER NOT NULL, days INTEGER NOT NULL, servers INTEGER NOT NULL,
          devices INTEGER NOT NULL DEFAULT 3, price_rub INTEGER NOT NULL,
          active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS owner_keys(
          id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL,
          label TEXT, created TEXT NOT NULL
        );
        """)
        # Safe migrations for databases created by earlier versions.
        cols = {r["name"] for r in c.execute("PRAGMA table_info(licenses)")}
        if "source_order" not in cols:
            c.execute("ALTER TABLE licenses ADD COLUMN source_order INTEGER")
    log.info("Database ready: %s", DB_PATH)

def round_price(raw: float) -> int:
    return max(50, int(math.ceil(raw / 50.0) * 50))

def calc_price(gb: int, days: int, servers: int, devices: int = DEFAULT_DEVICES) -> int:
    periods = max(1, math.ceil(days / 30))
    return round_price(gb + 15 * servers * periods + 20 * devices * periods + 60 * periods)

def stars_for_rubles(rub: int) -> int:
    return max(1, math.ceil(rub / STAR_RUBLES))

class DeviceIn(BaseModel):
    device_id: str = Field(min_length=2, max_length=128)
class TrialIn(DeviceIn):
    pass
class ActivateIn(BaseModel):
    key: str = Field(min_length=4, max_length=100)
    device_id: str = Field(min_length=2, max_length=128)
class RequestIn(BaseModel):
    device_id: str = Field(min_length=2, max_length=128)
    note: str = Field(default="Запрос доступа из приложения", max_length=300)

def is_owner(user_id: int) -> bool:
    return bool(OWNER_ID and user_id == OWNER_ID)

def get_role(user_id: int) -> str | None:
    if is_owner(user_id):
        return "owner"
    with db() as c:
        row = c.execute("SELECT role FROM roles WHERE tg_id=?", (user_id,)).fetchone()
    return row["role"] if row else None

def can_manage_keys(user_id: int) -> bool:
    return get_role(user_id) in ("owner", "tech")

def admin_home():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📊 Статистика", callback_data="adm:stats"),
         InlineKeyboardButton("🧾 Заказы", callback_data="adm:orders")],
        [InlineKeyboardButton("🔑 Ключи", callback_data="adm:keys"),
         InlineKeyboardButton("🎟 Тарифы", callback_data="adm:tariffs")],
        [InlineKeyboardButton("👥 Роли", callback_data="adm:roles"),
         InlineKeyboardButton("❔ Помощь", callback_data="adm:help")],
    ])

async def member_ok(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    if not user:
        return False
    if not CHANNEL_ID:
        return False
    try:
        member = await context.bot.get_chat_member(chat_id=CHANNEL_ID, user_id=user.id)
        return member.status in ("member", "administrator", "creator")
    except Exception:
        log.exception("Channel membership check failed; CHANNEL_ID may be wrong")
        return False

async def require_member(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if await member_ok(update, context):
        return True
    msg = update.effective_message
    if not CHANNEL_ID:
        await msg.reply_text(
            "⚙️ Бот ещё не настроен: владелец должен добавить числовой CHANNEL_ID в Render. "
            "После этого проверка подписки заработает."
        )
    else:
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("📢 Подписаться на канал", url=CHANNEL_URL)],
            [InlineKeyboardButton("✅ Я подписался — проверить", callback_data="checksub")],
        ])
        await msg.reply_text(
            "Чтобы пользоваться SIX SEVEN, подпишись на наш Telegram-канал, "
            "затем нажми «Проверить подписку».", reply_markup=kb
        )
    return False

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return
    if is_owner(user.id) or get_role(user.id):
        await update.effective_message.reply_text(
            "💙 SIX SEVEN — панель управления.\nВыбери нужный раздел:",
            reply_markup=admin_home()
        )
        return
    if not await require_member(update, context):
        return
    await update.effective_message.reply_text(
        "💙 Добро пожаловать в SIX SEVEN VPN!\n\n"
        "Собери свой тариф: выбери трафик, срок и количество серверов. "
        "Оплата проходит через Telegram Stars. После оплаты заказ поступит владельцу "
        "на проверку; ключ выдаётся только после его отдельного подтверждения.",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🛒 Собрать тариф", callback_data="buy:start")],
            [InlineKeyboardButton("📦 Мои заказы", callback_data="myorders")],
            [InlineKeyboardButton("🆘 Поддержка", url="https://t.me/Sixevenn_bot")],
        ])
    )

async def whoami(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(f"Ваш Telegram ID: {update.effective_user.id}")

async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not get_role(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Нет доступа.")
        return
    await update.effective_message.reply_text("🛠 SIX SEVEN — управление", reply_markup=admin_home())

async def send_invoice_for_order(query, context, data):
    gb, days, servers = data["gb"], data["days"], data["servers"]
    devices = DEFAULT_DEVICES
    rub = calc_price(gb, days, servers, devices)
    stars = stars_for_rubles(rub)
    with db() as c:
        cur = c.execute(
            """INSERT INTO orders(tg_id,username,gb,days,servers,devices,price_rub,
               price_stars,status,created) VALUES(?,?,?,?,?,?,?,?,'awaiting_payment',?)""",
            (query.from_user.id, query.from_user.username or "", gb, days, servers,
             devices, rub, stars, iso_now())
        )
        oid = cur.lastrowid
    payload = f"sixseven_order_{oid}"
    await context.bot.send_invoice(
        chat_id=query.from_user.id,
        title=f"SIX SEVEN VPN — заказ #{oid}",
        description=f"{gb} ГБ • {days} дней • {servers} сервер(ов) • {devices} устройства. "
                    f"Расчётная цена {rub} ₽.",
        payload=payload,
        provider_token="",
        currency="XTR",
        prices=[LabeledPrice(f"Тариф SIX SEVEN #{oid}", stars)],
    )
    await query.message.reply_text(
        f"🧾 Заказ #{oid} создан: {rub} ₽ = {stars} ⭐.\n"
        "Нажми кнопку оплаты в счёте Telegram. После оплаты заказ появится у владельца."
    )

async def precheckout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.pre_checkout_query
    try:
        oid = int(q.invoice_payload.replace("sixseven_order_", ""))
        with db() as c:
            row = c.execute("SELECT * FROM orders WHERE id=? AND tg_id=?",
                            (oid, q.from_user.id)).fetchone()
        if not row or row["status"] != "awaiting_payment":
            await q.answer(ok=False, error_message="Заказ не найден или уже обработан.")
            return
        if q.currency != "XTR" or q.total_amount != row["price_stars"]:
            await q.answer(ok=False, error_message="Сумма счёта не совпадает с заказом.")
            return
        await q.answer(ok=True)
    except Exception:
        log.exception("Pre-checkout validation failed")
        await q.answer(ok=False, error_message="Не удалось проверить заказ.")

async def successful_payment(update: Update, context: ContextTypes.DEFAULT_TYPE):
    payment = update.effective_message.successful_payment
    try:
        oid = int(payment.invoice_payload.replace("sixseven_order_", ""))
    except Exception:
        await update.effective_message.reply_text("Оплата получена, но номер заказа не распознан. Напиши владельцу.")
        return
    with db() as c:
        row = c.execute("SELECT * FROM orders WHERE id=? AND tg_id=?",
                        (oid, update.effective_user.id)).fetchone()
        if not row:
            await update.effective_message.reply_text("Платёж получен; заказ передан на ручную проверку.")
            return
        c.execute(
            """UPDATE orders SET status='paid_pending_review',telegram_charge_id=?
               WHERE id=? AND status='awaiting_payment'""",
            (payment.telegram_payment_charge_id, oid)
        )
    await update.effective_message.reply_text(
        f"✅ Telegram подтвердил оплату заказа #{oid}.\n"
        "Теперь владелец проверит заказ и отдельно разрешит выдачу ключа."
    )
    if OWNER_ID:
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Подтвердить оплату", callback_data=f"payok:{oid}")],
            [InlineKeyboardButton("🔑 Выдать ключ", callback_data=f"issue:{oid}")],
            [InlineKeyboardButton("❌ Отклонить заказ", callback_data=f"reject:{oid}")],
        ])
        try:
            await context.bot.send_message(
                OWNER_ID,
                f"💳 Оплачен заказ #{oid}\nПокупатель: {update.effective_user.full_name} "
                f"(@{update.effective_user.username or 'нет'})\n"
                f"Тариф: {row['gb']} ГБ, {row['days']} дней, {row['servers']} сервер(ов), "
                f"{row['devices']} устройства\nСумма: {row['price_rub']} ₽ / {row['price_stars']} ⭐\n"
                f"Статус: ожидает подтверждения владельца.",
                reply_markup=kb
            )
        except Exception:
            log.exception("Failed to notify owner for order %s", oid)

async def myorders(update: Update, context: ContextTypes.DEFAULT_TYPE):
    with db() as c:
        rows = c.execute(
            "SELECT id,price_rub,price_stars,status,created FROM orders WHERE tg_id=? ORDER BY id DESC LIMIT 10",
            (update.effective_user.id,)
        ).fetchall()
    if not rows:
        await update.effective_message.reply_text("У тебя пока нет заказов.")
        return
    lines = ["📦 Твои заказы:"]
    for r in rows:
        lines.append(f"#{r['id']} — {r['status']} — {r['price_rub']} ₽ ({r['price_stars']} ⭐)")
    await update.effective_message.reply_text("\n".join(lines))

async def callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    data = q.data or ""
    uid = q.from_user.id
    if data == "checksub":
        if await member_ok(update, context):
            await q.answer("Подписка подтверждена")
            await q.message.reply_text(
                "💙 Подписка подтверждена! Добро пожаловать в SIX SEVEN.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🛒 Собрать тариф", callback_data="buy:start")],
                    [InlineKeyboardButton("📦 Мои заказы", callback_data="myorders")],
                ])
            )
        else:
            await q.answer("Подписка не найдена. Подпишись и попробуй снова.", show_alert=True)
        return
    if data == "buy:start":
        await q.answer()
        if not await member_ok(update, context):
            await q.message.reply_text("Сначала подпишись на канал.", reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📢 Подписаться", url=CHANNEL_URL)],
                [InlineKeyboardButton("Проверить", callback_data="checksub")]
            ]))
            return
        context.user_data["tariff"] = {"gb": 50, "days": 30, "servers": 1}
        await show_builder(q.message, context)
        return
    if data.startswith("set:"):
        await q.answer()
        if not await member_ok(update, context):
            await q.message.reply_text("Сначала подпишись на канал.")
            return
        _, field, val = data.split(":")
        context.user_data.setdefault("tariff", {"gb":50,"days":30,"servers":1})[field] = int(val)
        await show_builder(q.message, context)
        return
    if data == "buy:pay":
        await q.answer()
        if not await member_ok(update, context):
            await q.message.reply_text("Сначала подпишись на канал.")
            return
        try:
            await send_invoice_for_order(q, context, context.user_data["tariff"])
        except Exception:
            log.exception("Invoice creation failed")
            await q.message.reply_text("Не удалось создать счёт. Проверь настройки Telegram Stars и попробуй позже.")
        return
    if data == "myorders":
        await q.answer()
        await myorders(update, context)
        return
    if data.startswith("adm:"):
        await q.answer()
        if not get_role(uid):
            await q.answer("Нет доступа", show_alert=True); return
        section = data.split(":",1)[1]
        if section == "stats":
            with db() as c:
                n_orders = c.execute("SELECT COUNT(*) n FROM orders").fetchone()["n"]
                paid = c.execute("SELECT COUNT(*) n FROM orders WHERE status LIKE 'paid%' OR status='issued'").fetchone()["n"]
                keys = c.execute("SELECT COUNT(*) n FROM licenses").fetchone()["n"]
            msg = f"📊 Статистика\nЗаказов: {n_orders}\nОплачено/в обработке: {paid}\nКлючей: {keys}"
        elif section == "orders":
            with db() as c:
                rows = c.execute("SELECT id,tg_id,price_rub,status FROM orders ORDER BY id DESC LIMIT 12").fetchall()
            msg = "🧾 Заказы:\n" + ("\n".join(f"#{r['id']} • {r['tg_id']} • {r['price_rub']} ₽ • {r['status']}" for r in rows) or "Пока нет.")
        elif section == "keys":
            if not can_manage_keys(uid):
                await q.message.reply_text("⛔ Только владелец или техспециалист может управлять ключами."); return
            with db() as c:
                rows = c.execute("SELECT id,expires,revoked,max_devices FROM licenses ORDER BY id DESC LIMIT 10").fetchall()
            msg = "🔑 Последние ключи:\n" + ("\n".join(f"#{r['id']} • {'отозван' if r['revoked'] else 'активен'} • до {r['expires'] or 'бессрочно'} • устройств {r['max_devices']}" for r in rows) or "Ключей пока нет.")
        elif section == "tariffs":
            msg = "🎟 Тарифы задаются владельцем через команду:\n/tariff Название;ГБ;дни;серверы;цена₽"
        elif section == "roles":
            msg = "👥 Роли (только владелец):\n/role add TELEGRAM_ID junior\n/role add TELEGRAM_ID tech\n/role remove TELEGRAM_ID\n\nМладший админ: просмотр заказов и статистики.\nТехспециалист: управление ключами."
        else:
            msg = "Команды:\n/admin\n/whoami\n/role add|remove ...\n/tariff ...\n/makekey ДНИ [МЕТКА]\n/revoke ID"
        await q.message.reply_text(msg)
        return
    if data.startswith("payok:") or data.startswith("issue:") or data.startswith("reject:"):
        await q.answer()
        if not is_owner(uid):
            await q.answer("Только владелец может подтверждать оплату и выдачу.", show_alert=True); return
        action, oid_s = data.split(":")
        oid = int(oid_s)
        with db() as c:
            row = c.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
            if not row:
                await q.message.reply_text("Заказ не найден."); return
            if action == "payok":
                if row["status"] != "paid_pending_review":
                    await q.message.reply_text("Заказ не ожидает подтверждения оплаты."); return
                c.execute("UPDATE orders SET status='payment_confirmed' WHERE id=?", (oid,))
                msg = f"Оплата заказа #{oid} подтверждена. Теперь можно отдельно выдать ключ."
            elif action == "issue":
                if row["status"] != "payment_confirmed":
                    await q.message.reply_text("Сначала нажми «Подтвердить оплату»."); return
                key = make_key()
                expires = (utcnow() + timedelta(days=row["days"])).isoformat()
                c.execute("INSERT INTO licenses(key_hash,expires,max_devices,revoked,created,source_order) VALUES(?,?,?,0,?,?)",
                          (hash_value(key), expires, row["devices"], iso_now(), oid))
                c.execute("UPDATE orders SET status='issued',license_id=last_insert_rowid() WHERE id=?", (oid,))
                msg = f"🔑 Ключ для заказа #{oid}:\n`{key}`\nСрок: {row['days']} дней • устройств: {row['devices']}"
                try:
                    await context.bot.send_message(row["tg_id"], f"🎉 Твой ключ SIX SEVEN:\n`{key}`\nСрок: {row['days']} дней. Активируй его в приложении.", parse_mode=ParseMode.MARKDOWN)
                except Exception:
                    log.exception("Could not deliver key to customer")
            else:
                if row["status"] == "issued":
                    await q.message.reply_text("Ключ уже выдан; сначала отзови его отдельно."); return
                c.execute("UPDATE orders SET status='rejected' WHERE id=?", (oid,))
                msg = f"Заказ #{oid} отклонён."
        await q.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        return

async def show_builder(message, context):
    t = context.user_data.get("tariff", {"gb":50,"days":30,"servers":1})
    rub = calc_price(t["gb"], t["days"], t["servers"])
    stars = stars_for_rubles(rub)
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("25 ГБ", callback_data="set:gb:25"),
         InlineKeyboardButton("50 ГБ", callback_data="set:gb:50"),
         InlineKeyboardButton("100 ГБ", callback_data="set:gb:100")],
        [InlineKeyboardButton("30 дней", callback_data="set:days:30"),
         InlineKeyboardButton("90 дней", callback_data="set:days:90"),
         InlineKeyboardButton("180 дней", callback_data="set:days:180")],
        [InlineKeyboardButton("1 сервер", callback_data="set:servers:1"),
         InlineKeyboardButton("3 сервера", callback_data="set:servers:3"),
         InlineKeyboardButton("5 серверов", callback_data="set:servers:5")],
        [InlineKeyboardButton(f"💳 Оплатить {stars} ⭐", callback_data="buy:pay")],
    ])
    await message.reply_text(
        f"🛒 Конструктор тарифа SIX SEVEN\n\n"
        f"Трафик: {t['gb']} ГБ\nСрок: {t['days']} дней\nСерверов: {t['servers']}\n"
        f"Устройств: {DEFAULT_DEVICES}\n\n"
        f"Цена: {rub} ₽ = {stars} ⭐\nКурс расчёта: 1 ⭐ = 1,5 ₽.\n"
        "Цена округляется вверх до ближайших 50 ₽.",
        reply_markup=kb
    )

async def role_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Только владелец может назначать роли."); return
    args = context.args
    if len(args) == 3 and args[0] == "add":
        try: target = int(args[1])
        except ValueError:
            await update.effective_message.reply_text("ID должен быть числом."); return
        role = args[2].lower()
        if role not in ("junior", "tech") or target == OWNER_ID:
            await update.effective_message.reply_text("Роль: junior или tech. Владельца менять нельзя."); return
        with db() as c:
            c.execute("INSERT INTO roles(tg_id,role,added_by,created) VALUES(?,?,?,?) ON CONFLICT(tg_id) DO UPDATE SET role=excluded.role,added_by=excluded.added_by",
                      (target, role, OWNER_ID, iso_now()))
        await update.effective_message.reply_text(f"✅ Роль {role} назначена: {target}")
    elif len(args) == 2 and args[0] == "remove":
        try: target = int(args[1])
        except ValueError:
            await update.effective_message.reply_text("ID должен быть числом."); return
        with db() as c: c.execute("DELETE FROM roles WHERE tg_id=? AND tg_id<>?", (target, OWNER_ID))
        await update.effective_message.reply_text(f"Роль удалена для {target}, если она существовала.")
    else:
        await update.effective_message.reply_text("Использование:\n/role add ID junior\n/role add ID tech\n/role remove ID")

async def tariff_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_owner(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Только владелец может создавать тарифы."); return
    raw = " ".join(context.args)
    try:
        title, gb, days, servers, price = [x.strip() for x in raw.split(";")]
        with db() as c:
            c.execute("INSERT INTO tariffs(title,gb,days,servers,devices,price_rub,active) VALUES(?,?,?,?,?,?,1)",
                      (title, int(gb), int(days), int(servers), DEFAULT_DEVICES, int(price)))
        await update.effective_message.reply_text(f"✅ Тариф «{title}» сохранён.")
    except Exception:
        await update.effective_message.reply_text("Формат:\n/tariff Название;ГБ;дни;серверы;цена₽")

async def makekey_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not can_manage_keys(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Нет доступа к управлению ключами."); return
    try:
        days = int(context.args[0]) if context.args else 36500
        label = " ".join(context.args[1:]) or "manual"
        expiry = None if days <= 0 or days >= 36500 else (utcnow()+timedelta(days=days)).isoformat()
        key = make_key()
        with db() as c:
            c.execute("INSERT INTO licenses(key_hash,expires,max_devices,revoked,created) VALUES(?,?,999,0,?)",
                      (hash_value(key), expiry, iso_now()))
            c.execute("INSERT INTO owner_keys(key_hash,label,created) VALUES(?,?,?)",
                      (hash_value(key), label, iso_now()))
        await update.effective_message.reply_text(f"🔑 Создан ключ:\n`{key}`\nСрок: {expiry or 'бессрочно'}\nУстройств: 999",
                                                   parse_mode=ParseMode.MARKDOWN)
    except Exception:
        await update.effective_message.reply_text("Использование: /makekey 30 название (0 = бессрочно)")

async def revoke_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not can_manage_keys(update.effective_user.id):
        await update.effective_message.reply_text("⛔ Нет доступа."); return
    try: lid = int(context.args[0])
    except Exception:
        await update.effective_message.reply_text("Использование: /revoke ID_лицензии"); return
    with db() as c:
        cur = c.execute("UPDATE licenses SET revoked=1 WHERE id=?", (lid,))
    await update.effective_message.reply_text("Ключ отозван." if cur.rowcount else "Ключ не найден.")

async def startup():
    global bot_app
    init_db()
    if not BOT_TOKEN:
        log.warning("No TELEGRAM_BOT_TOKEN: API only.")
        return
    bot_app = Application.builder().token(BOT_TOKEN).build()
    bot_app.add_handler(CommandHandler("start", start))
    bot_app.add_handler(CommandHandler("whoami", whoami))
    bot_app.add_handler(CommandHandler("admin", admin))
    bot_app.add_handler(CommandHandler("role", role_command))
    bot_app.add_handler(CommandHandler("tariff", tariff_command))
    bot_app.add_handler(CommandHandler("makekey", makekey_command))
    bot_app.add_handler(CommandHandler("revoke", revoke_command))
    bot_app.add_handler(PreCheckoutQueryHandler(precheckout))
    bot_app.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment))
    bot_app.add_handler(CallbackQueryHandler(callback))
    await bot_app.initialize()
    await bot_app.start()
    if bot_app.updater:
        await bot_app.updater.start_polling()
    log.info("SIX SEVEN Telegram bot started")

async def shutdown():
    global bot_app
    if bot_app:
        if bot_app.updater and bot_app.updater.running:
            await bot_app.updater.stop()
        if bot_app.running:
            await bot_app.stop()
        await bot_app.shutdown()
        bot_app = None

@app.on_event("startup")
async def on_startup():
    try:
        await startup()
    except Exception:
        log.exception("Bot startup failed; API remains available.")

@app.on_event("shutdown")
async def on_shutdown():
    await shutdown()

@app.get("/")
def root():
    return {"ok": True, "service": "SIX SEVEN VPN API", "version": "3.0.0"}

@app.get("/health")
def health():
    return {"ok": True, "service": "sixseven-license", "version": "3.0.0"}

@app.post("/request-access")
async def request_access(data: RequestIn):
    with db() as c:
        cur = c.execute("INSERT INTO requests(device_id,note,status,created) VALUES(?,?,'pending',?)",
                        (data.device_id, data.note, iso_now()))
    if bot_app and OWNER_ID:
        try:
            await bot_app.bot.send_message(OWNER_ID, f"🆕 Запрос доступа из приложения\nID: {cur.lastrowid}\nУстройство: {data.device_id}\n{data.note}")
        except Exception:
            log.exception("Owner notification failed")
    return {"ok": True, "request_id": cur.lastrowid, "message": "Заявка сохранена"}

@app.post("/start-trial")
@app.post("/start_trial")
def start_trial(data: TrialIn):
    if is_owner_device(data.device_id):
        return {"ok": True, "plan": "developer", "expires": None,
                "message": "Доступ разработчика активен навсегда"}
    started = utcnow()
    expires = started + timedelta(days=7)
    try:
        with db() as c:
            c.execute("INSERT INTO trial_claims(device_id,started,expires) VALUES(?,?,?)",
                      (data.device_id, started.isoformat(), expires.isoformat()))
    except sqlite3.IntegrityError:
        with db() as c:
            row = c.execute("SELECT expires FROM trial_claims WHERE device_id=?", (data.device_id,)).fetchone()
        raise HTTPException(status_code=409, detail={
            "message": "Бесплатный пробный период уже использован на этом устройстве",
            "expires": row["expires"] if row else None
        })
    return {"ok": True, "plan": "trial", "started": started.isoformat(),
            "expires": expires.isoformat(), "days": 7,
            "message": "Пробный доступ активирован на 7 дней"}

@app.post("/activate")
def activate(data: ActivateIn):
    if is_owner_device(data.device_id):
        return {"ok": True, "plan": "developer", "expires": None,
                "max_devices": 999, "message": "Доступ разработчика активен навсегда"}
    kh = hash_value(data.key.strip().upper())
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        lic = c.execute("SELECT * FROM licenses WHERE key_hash=?", (kh,)).fetchone()
        if not lic or lic["revoked"]:
            c.rollback()
            raise HTTPException(status_code=403, detail="Ключ недействителен или отозван")
        expiry = parse_expiry(lic["expires"])
        if lic["expires"] and (not expiry or expiry <= utcnow()):
            c.rollback()
            raise HTTPException(status_code=403, detail="Срок действия ключа истёк")
        existing = c.execute("SELECT 1 FROM activations WHERE key_hash=? AND device_id=?",
                              (kh, data.device_id)).fetchone()
        count = c.execute("SELECT COUNT(*) n FROM activations WHERE key_hash=?", (kh,)).fetchone()["n"]
        if not existing and count >= lic["max_devices"]:
            c.rollback()
            raise HTTPException(status_code=403, detail=f"Достигнут лимит устройств: {lic['max_devices']}")
        c.execute("INSERT OR IGNORE INTO activations(key_hash,device_id,created) VALUES(?,?,?)",
                  (kh, data.device_id, iso_now()))
        c.commit()
    return {"ok": True, "plan": "user", "expires": lic["expires"],
            "max_devices": lic["max_devices"], "message": "Ключ успешно активирован"}

@app.get("/validate")
@app.post("/validate")
async def validate(request: Request, device_id: Optional[str] = None):
    if not device_id:
        try:
            body = await request.json()
            if isinstance(body, dict): device_id = body.get("device_id")
        except Exception: pass
    if not isinstance(device_id, str) or not device_id.strip():
        raise HTTPException(status_code=422, detail="device_id is required")
    device_id = device_id.strip()
    if is_owner_device(device_id):
        return {"ok": True, "plan": "developer", "expires": None}
    now = utcnow()
    with db() as c:
        rows = c.execute(
            "SELECT l.expires,l.revoked FROM activations a JOIN licenses l ON l.key_hash=a.key_hash WHERE a.device_id=? ORDER BY a.rowid DESC",
            (device_id,)
        ).fetchall()
        for row in rows:
            exp = parse_expiry(row["expires"])
            if not row["revoked"] and (row["expires"] is None or (exp and exp > now)):
                return {"ok": True, "plan": "user", "expires": row["expires"]}
        trial = c.execute("SELECT started,expires FROM trial_claims WHERE device_id=?", (device_id,)).fetchone()
    if trial:
        exp = parse_expiry(trial["expires"])
        if exp and exp > now:
            return {"ok": True, "plan": "trial", "started": trial["started"],
                    "expires": trial["expires"], "message": "Пробный доступ активен"}
    return {"ok": False, "message": "Нет активной подписки или пробный период закончился"}
