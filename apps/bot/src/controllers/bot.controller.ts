import { Telegraf } from 'telegraf';
import { analyzeTextLocal } from '@cybersensei/core';

// Rate Limiter Sederhana di level memori (Cooldown per user)
// Mencegah 1 user spamming ribuan pesan dalam waktu singkat
const userCooldowns = new Map<number, number>();
const COOLDOWN_MS = 2000; // 2 detik cooldown per user

// Pembersihan memori Map secara berkala setiap 1 jam untuk mencegah memory leak
setInterval(() => {
  const now = Date.now();
  for (const [userId, lastTime] of userCooldowns.entries()) {
    if (now - lastTime > 60000) { // Hapus jika sudah tidak aktif > 1 menit
      userCooldowns.delete(userId);
    }
  }
}, 3600000);

export const setupBot = (bot: Telegraf) => {
  bot.start((ctx) => {
    ctx.reply(
      'Halo! Saya adalah agen CyberSensei.\n\n' +
      'Kirimkan pesan teks atau tautan (link) yang mencurigakan, dan saya akan menganalisis apakah itu penipuan (scam/phishing) atau aman.'
    );
  });

  bot.help((ctx) => {
    ctx.reply('Cukup teruskan (forward) atau ketik pesan yang ingin Anda periksa ke chat ini.');
  });

  bot.on('text', async (ctx) => {
    const text = ctx.message.text;
    const userId = ctx.from.id;
    
    // Security & Group Spam Protection
    const isGroup = ctx.chat.type === 'group' || ctx.chat.type === 'supergroup';
    let shouldProcess = !isGroup;

    if (isGroup) {
      // Periksa apakah bot di-mention atau pesan ini adalah balasan ke bot
      const botUsername = ctx.botInfo.username;
      const isMentioned = text.includes(`@${botUsername}`);
      
      // Menggunakan any atau type assertion untuk reply_to_message karena type bawaan telegraf text message mungkin kurang spesifik
      const replyToMsg = (ctx.message as any).reply_to_message;
      const isReplyToBot = replyToMsg?.from?.id === ctx.botInfo.id;
      
      if (isMentioned || isReplyToBot) {
        shouldProcess = true;
      }
    }

    if (!shouldProcess) return;

    const now = Date.now();
    const lastRequestTime = userCooldowns.get(userId) || 0;

    // Security: Spam / Rate Limit Protection
    if (now - lastRequestTime < COOLDOWN_MS) {
      // Abaikan pesan secara diam-diam jika spamming terlalu cepat
      // atau kirim pesan peringatan (opsional)
      return;
    }
    userCooldowns.set(userId, now);

    // Security: Maksimal karakter untuk mencegah Memory exhaustion / ReDoS
    if (text.length > 10000) {
      await ctx.reply('❌ Pesan terlalu panjang. Harap kirim pesan maksimal 10.000 karakter.', { reply_parameters: { message_id: ctx.message.message_id } });
      return;
    }
    
    // Kirim pesan "sedang memproses"
    const processingMsg = await ctx.reply('🔍 Sedang menganalisis pesan Anda...', { reply_parameters: { message_id: ctx.message.message_id } });
    
    try {
      // Analyze text using CyberSensei Core
      const isUrlInput = text.trim().startsWith('http://') || text.trim().startsWith('https://');
      const result = analyzeTextLocal(text, isUrlInput);
      
      // Format response
      let emoji = '✅';
      if (result.verdict === 'BERBAHAYA') emoji = '🚨';
      else if (result.verdict === 'MENCURIGAKAN') emoji = '⚠️';
      
      let replyMessage = `${emoji} <b>Hasil Analisis: ${result.verdict}</b>\n\n`;
      replyMessage += `<b>Skor Bahaya:</b> ${result.dangerScore}/10\n\n`;
      replyMessage += `<b>Penjelasan:</b>\n${result.simpleExplanation}\n\n`;
      
      if (result.redFlags.length > 0) {
        replyMessage += `<b>Tanda Bahaya:</b>\n${result.redFlags.map(f => `- ${f}`).join('\n')}\n\n`;
      }
      
      replyMessage += `<b>Saran Tindakan:</b>\n${result.actionItem}\n\n`;
      replyMessage += `<i>Pelajaran: ${result.microLesson}</i>`;
      
      // Edit message (Telegram HTML format is more resilient against unescaped characters)
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        processingMsg.message_id,
        undefined,
        replyMessage,
        { parse_mode: 'HTML' }
      );
      
    } catch (error) {
      console.error("Error analyzing text:", error);
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        processingMsg.message_id,
        undefined,
        '❌ Maaf, terjadi kesalahan saat menganalisis pesan. Silakan coba lagi nanti.'
      );
    }
  });
};
