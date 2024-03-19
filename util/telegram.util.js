const TelegramBot = require('node-telegram-bot-api');
require('dotenv').config();

const bot = new TelegramBot(process.env.TOKEN_BOT_TELEGRAM, { polling: true });
const groupId = process.env.ID_GROUP_TELEGRAM;

function sendGroupMessageTelegram(payload) {
  const message = formatContent(payload);
  console.log(message)

  bot.sendMessage(groupId, message, { parse_mode: 'Markdown' })
    .then(msg => {
      console.log(`send message telegram`);
    })
    .catch(error => {
      bot.sendMessage(groupId, `❌ Lỗi khi gửi bot telegram =>
      ${error.message}`, { parse_mode: 'Markdown' });
      console.error(`Error sending message: ${error.message}`);
    });
}

function formatContent(payload) {
  if (!payload.name) payload.name = 'name_client';
  if (!payload.content) payload.content = 'content_client';

  return `
📢 New Message

🧑 | \`${payload.name}\`
🗨️ | \`${payload.content}\`
`;
}

module.exports = { sendGroupMessageTelegram };
