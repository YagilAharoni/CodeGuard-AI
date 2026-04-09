# CodeGuardAI Project Guidelines

## Scope And Hierarchy
- This file sets default instructions for the full repository.
- The frontend has additional, higher-priority rules in `my-security-ui/AGENTS.md`.

## Architecture
- Backend API lives in `app.py` (FastAPI, auth, scanning endpoints, provider routing, PDF export).
- Backend helpers live in `utils.py` (PDF generation, text sanitization, file handling helpers).
- Frontend app lives in `my-security-ui/app/` (Next.js App Router).
- Local data stores:
  - `users.db` for auth users.
  - `scan_history.json` for scan history.

## Build And Run
- Backend setup (Windows PowerShell):
  - `python -m venv .venv`
  - `.venv\Scripts\activate`
  - `pip install -r requirements.txt`
- Backend run:
  - `python app.py`
- Frontend setup and run:
  - `cd my-security-ui`
  - `npm install`
  - `npm run dev`

## Validation
- Backend has no formal test suite in this repo; validate by running API endpoints and checking `/docs`.
- Frontend validation commands:
  - `cd my-security-ui`
  - `npm run lint`
  - `npm run build`

## Conventions
- Keep backend changes consistent with existing patterns in `app.py`:
  - Environment-driven configuration (`os.getenv`, `.env` via `load_dotenv`).
  - Clear resource limits (`MAX_*` constants).
  - Defensive request validation and bounded file processing.
  - Route-level rate limits using SlowAPI decorators.
- Keep auth and scan history behavior backward compatible unless migration steps are included.
- Preserve API response shapes used by frontend hooks in `my-security-ui/app/hooks/useScan.ts`.

## Known Pitfalls
- Backend requires an active virtual environment before running commands.
- Backend and frontend use separate terminals and ports (`8000` and `3000` by default).
- Frontend API base URL comes from `NEXT_PUBLIC_API_URL`; default fallback is localhost backend.
- CORS allowlist is controlled via `CORS_ALLOWED_ORIGINS`.
- PDF export uses Latin-1-safe sanitization in `utils.py`; avoid introducing encoding-unsafe output paths.

## Reference Docs
- Setup and day-to-day workflow: `QUICK_START_GUIDE.md`
- Product and feature overview: `README.md`
- Frontend-specific constraints: `my-security-ui/AGENTS.md`