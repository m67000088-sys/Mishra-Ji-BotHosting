# Telegram bot (Python) — ZIP mein bot.py + requirements.txt rakho.
# Token code mein nahi likhte: website par  ⚙️ Env  mein  BOT_TOKEN  add karo.
import os
import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

TOKEN = os.environ["BOT_TOKEN"]


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Hello! Mishra Ji Bot Hosting par chal raha hu 🚀")


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    print("Bot started", flush=True)
    app.run_polling(drop_pending_updates=True)


main()
