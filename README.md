# NOVA Backend

OAuth token server for the NOVA AI Assistant PWA.

## Stack
- Node.js + Express
- SQLite (better-sqlite3) with AES-256 encrypted token storage
- Google OAuth 2.0 (Calendar + Gmail)

## Deploy to Railway

1. Fork or clone this repo
2. Create a new project on [Railway.app](https://railway.app)
3. Connect this GitHub repo
4. Add environment variables from `.env.example`
5. Railway auto-deploys on every push

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_CLIENT_ID` | Yes | From Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | Yes | From Google Cloud Console |
| `GOOGLE_REDIRECT_URI` | Yes | `https://YOUR_RAILWAY_URL/auth/google/callback` |
| `BACKEND_URL` | Yes | Your Railway public URL |
| `NOVA_APP_URL` | Yes | The NOVA PWA URL |
| `ALLOWED_ORIGINS` | Yes | Comma-separated allowed CORS origins |
| `ENCRYPTION_KEY` | Yes | Long random string for AES-256 encryption |

## API Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /` | None | Health check |
| `POST /api/session` | None | Create/get user session |
| `GET /api/integrations/status` | Session | List connected integrations |
| `GET /auth/google/connect` | Session | Get Google OAuth URL |
| `GET /auth/google/callback` | None | OAuth callback (redirect) |
| `GET /api/google/calendar/today` | Session | Today's calendar events |
| `GET /api/google/calendar/upcoming` | Session | Upcoming events (7 days) |
| `GET /api/google/gmail/inbox` | Session | Inbox / unread emails |
| `GET /api/google/gmail/message/:id` | Session | Full email body |
