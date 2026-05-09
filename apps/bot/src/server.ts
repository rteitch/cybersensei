import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Telegraf } from 'telegraf';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { setupBot } from './controllers/bot.controller.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// Security: Set HTTP response headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
    },
  },
}));

// Security: Rate limiting for the Express API/Webhook
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per `window` (here, per minute)
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Terlalu banyak permintaan dari IP ini, silakan coba lagi nanti.',
});

// Apply rate limiter to all requests
app.use(apiLimiter);

app.use(express.json());

// Initialize Telegram Bot
const botToken = process.env.TELEGRAM_BOT_TOKEN;
if (botToken) {
  const bot = new Telegraf(botToken);
  setupBot(bot);

  // For Cloud Run, standard webhook is often used, but polling is easier to setup initially.
  // Given Cloud Run scales to zero, webhook is strictly required for Telegram bots on Cloud Run
  // if you want it to be fully serverless and reliable. However, for a single container that 
  // runs the web frontend too, we can set webhook if WEBHOOK_DOMAIN is provided.
  
  const webhookDomain = process.env.WEBHOOK_DOMAIN;
  if (webhookDomain) {
    const webhookPath = `/api/telegraf/${bot.secretPathComponent()}`;
    app.use(bot.webhookCallback(webhookPath));
    bot.telegram.setWebhook(`${webhookDomain}${webhookPath}`)
      .then(() => console.log(`Telegram Webhook set on ${webhookDomain}${webhookPath}`))
      .catch((err) => console.error("Failed to set webhook:", err));
  } else {
    // Fallback to polling for local development
    bot.launch()
       .then(() => console.log('Telegram Bot started in polling mode'))
       .catch((err) => console.error("Failed to start bot:", err));
  }

  // Enable graceful stop
  process.once('SIGINT', () => bot.stop('SIGINT'));
  process.once('SIGTERM', () => bot.stop('SIGTERM'));
} else {
  console.warn("TELEGRAM_BOT_TOKEN is not set. Telegram Bot will not start.");
}

// WhatsApp Webhook Mock/Guide (Business API)
app.get('/api/whatsapp/webhook', (req, res) => {
  // Hubungkan ini dengan webhook provider WhatsApp Anda (Meta / Twilio dll)
  // Ini untuk verifikasi token
  const verify_token = process.env.WHATSAPP_VERIFY_TOKEN;
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode && token) {
    if (mode === 'subscribe' && token === verify_token) {
      console.log('WEBHOOK_VERIFIED');
      res.status(200).send(challenge);
    } else {
      res.sendStatus(403);
    }
  } else {
    res.sendStatus(400);
  }
});

app.post('/api/whatsapp/webhook', (req, res) => {
  // Terima dan proses pesan dari WhatsApp
  // Analisis pesan dan balas menggunakan API Provider
  // const body = req.body; 
  // ... Process message similar to Telegram ...
  res.sendStatus(200);
});

// API health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Serve static files from the React (Vite) app
// In the Docker container, we will place the web dist in 'public' relative to this server root
// During local dev, we might not serve it this way, but this ensures it works in Cloud Run
const webDistPath = process.env.NODE_ENV === 'production' 
  ? path.join(__dirname, '..', 'public') // Docker structure
  : path.join(__dirname, '..', '..', '..', 'web', 'dist'); // Local monorepo structure

app.use(express.static(webDistPath));

// Catch-all route to serve index.html for React Router
app.get('*', (req, res) => {
  res.sendFile(path.join(webDistPath, 'index.html'));
});

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Terjadi kesalahan pada server (Internal Server Error)' });
});

app.listen(PORT, () => {
  console.log(`🚀 CyberSensei Server is running on port ${PORT}`);
});
