# IDS Frontend (React + Vite)

This frontend renders a minimal IDS dashboard backed by the FastAPI service.

## Features

- Live flow table (`/flows`)
- Alerts panel (`/alerts`)
- Summary cards and class distribution chart (`/stats`)

## Configuration

Set the backend base URL with:

```bash
VITE_API_BASE_URL=http://localhost:8000
```

If omitted, the app defaults to `http://localhost:8000`.

## Run

```bash
npm install
npm run dev
```
