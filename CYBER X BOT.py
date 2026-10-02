import os
import re
import base64
import socket
import ipaddress
import requests
import whois

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

WELCOME = """
⚡ CYBER X BOT ⚡

[ SYSTEM ONLINE ]

Welcome to Cyber X.
Your cyber utility toolkit.
"""

def valid_domain(domain):
    return bool(re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
        domain.lower().strip()
    ))

def public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [
            InlineKeyboardButton("🌐 IP Lookup", callback_data="ip"),
            InlineKeyboardButton("🔎 DNS Lookup", callback_data="dns"),
        ],
        [
            InlineKeyboardButton("🧾 WHOIS", callback_data="whois"),
            InlineKeyboardButton("🛠 Tools", callback_data="tools"),
        ],
        [
            InlineKeyboardButton("📜 Help", callback_data="help")
        ]
    ]

    await update.message.reply_text(
        WELCOME,
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("""
⚡ CYBER X COMMANDS

/ip <IP>        - IP information
/dns <domain>   - DNS lookup
/whois <domain> - Domain information
/encode <text>  - Base64 encode
/decode <text>  - Base64 decode
/scan <domain>  - Basic security header check
/help           - Show commands
""")

async def ip_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /ip <IP>")
        return

    ip = context.args[0]

    if not public_ip(ip):
        await update.message.reply_text("Enter a valid public IP.")
        return

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=10
        )
        data = response.json()

        if data.get("status") != "success":
            await update.message.reply_text("IP lookup failed.")
            return

        await update.message.reply_text(f"""
🌐 IP INFORMATION

IP: {data.get('query')}
Country: {data.get('country')}
Region: {data.get('regionName')}
City: {data.get('city')}
ZIP: {data.get('zip')}
Timezone: {data.get('timezone')}
ISP: {data.get('isp')}

Note: Location is approximate.
""")
    except requests.RequestException:
        await update.message.reply_text("Network error.")

async def dns_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /dns <domain>")
        return

    domain = context.args[0].strip()

    if not valid_domain(domain):
        await update.message.reply_text("Invalid domain.")
        return

    try:
        addresses = sorted({
            result[4][0]
            for result in socket.getaddrinfo(domain, None)
        })

        await update.message.reply_text(
            "🔎 DNS RESULTS\n\n" +
            f"Domain: {domain}\n\n" +
            "\n".join(addresses)
        )
    except socket.gaierror:
        await update.message.reply_text("DNS lookup failed.")

async def whois_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /whois <domain>")
        return

    domain = context.args[0].strip()

    if not valid_domain(domain):
        await update.message.reply_text("Invalid domain.")
        return

    try:
        info = whois.whois(domain)

        await update.message.reply_text(f"""
🧾 WHOIS RESULTS

Domain: {domain}
Registrar: {info.registrar}
Creation: {info.creation_date}
Expiration: {info.expiration_date}
Name servers: {info.name_servers}
""")
    except Exception:
        await update.message.reply_text("WHOIS lookup failed.")

async def encode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = " ".join(context.args)

    if not text:
        await update.message.reply_text("Usage: /encode <text>")
        return

    encoded = base64.b64encode(text.encode()).decode()
    await update.message.reply_text(f"🔐 Encoded:\n{encoded}")

async def decode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = " ".join(context.args)

    if not text:
        await update.message.reply_text("Usage: /decode <text>")
        return

    try:
        decoded = base64.b64decode(text, validate=True).decode()
        await update.message.reply_text(f"🔓 Decoded:\n{decoded}")
    except Exception:
        await update.message.reply_text("Invalid Base64 text.")

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /scan <domain>")
        return

    domain = context.args[0].strip()

    if not valid_domain(domain):
        await update.message.reply_text("Invalid domain.")
        return

    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(domain, 443)
        }

        if not addresses or not all(public_ip(ip) for ip in addresses):
            await update.message.reply_text("Public domains only.")
            return

        response = requests.get(
            f"https://{domain}",
            timeout=8,
            allow_redirects=False
        )

        headers = response.headers

        checks = {
            "HTTPS": "Enabled",
            "HSTS": "Present" if "Strict-Transport-Security" in headers else "Missing",
            "CSP": "Present" if "Content-Security-Policy" in headers else "Missing",
            "X-Content-Type-Options": "Present" if "