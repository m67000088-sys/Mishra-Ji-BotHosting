// Telegram bot (Node.js) — ZIP mein index.js + package.json rakho.
// Token: website par ⚙️ Env mein BOT_TOKEN add karo.
const { Telegraf } = require('telegraf');

const bot = new Telegraf(process.env.BOT_TOKEN);
bot.start((ctx) => ctx.reply('Hello! Mishra Ji Bot Hosting par chal raha hu 🚀'));
bot.launch().then(() => console.log('Bot started'));

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
