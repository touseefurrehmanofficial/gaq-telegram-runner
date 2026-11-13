# gaq-telegram-runner

Public, **read-only** Telegram relay for a private trading-research system.

- The operator's PC publishes an **encrypted** status snapshot (AES-256-GCM) to the `status` branch every 5 minutes.
  Only ciphertext is public; the key is a GitHub Actions secret.
- A scheduled workflow decrypts it, answers read-only commands (`/status`, `/report`, `/research`, `/news`, `/alerts`)
  from the single authorised chat, relays alerts the PC could not deliver, and warns if the PC stops publishing.
- There is **no** command that trades, resumes, changes risk or clears an emergency stop, and no path from Telegram
  back to the trading PC.
- Logs print counts only. Secrets: `TELEGRAM_BOT_TOKEN`, `RELAY_KEY`.
