
# AEGIS — Frontend Handoff

## Overview

The AEGIS frontend is a React, TypeScript, and Vite dashboard for interacting with the AEGIS software protection platform.

It provides a user interface for software uploads, protection jobs, security monitoring, and future AI-powered analysis.

## Technology Stack

- React
- TypeScript
- Vite
- CSS
- FastAPI backend integration

## Project Location

`platform/dashboard/`

Main application files:

- `src/App.tsx` — Dashboard pages, React state, and API requests
- `src/style.css` — Dashboard styling
- `src/main.tsx` — React application entry point
- `vite.config.ts` — Development API proxy configuration

## Running the Frontend

From `platform/dashboard/`:

```bash
npm install
npm run dev
```

On Windows PowerShell, use `npm.cmd run dev` if script execution is restricted.

The dashboard normally runs at `http://localhost:5173/`.

## Running the Backend

The AEGIS API is installed in a Python virtual environment.

From the repository root in Ubuntu/WSL:

```bash
source .venv/bin/activate
aegis-api
```

The API normally runs at `http://127.0.0.1:8000`.

## API Integration

The frontend uses these endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/healthz` | Backend health check |
| POST | `/v1/jobs` | Submit a protection job |
| GET | `/v1/jobs/{job_id}` | Retrieve job status |
| GET | `/v1/jobs/{job_id}/report` | Retrieve a completed job report |

The Vite development proxy forwards `/v1` requests to the FastAPI server.

Protection job submissions include:

- The selected LLVM IR `.ll` filename
- Base64-encoded file contents
- A protection policy specifying `llvm-shield`

## Implemented Features

- AEGIS dashboard and navigation
- Software upload interface
- LLVM IR `.ll` file selection and validation
- File name and size display
- Real protection job submission requests
- Backend error handling and notifications
- Session-based tracking of accepted protection jobs
- Job status refresh functionality
- JSON protection report download functionality
- Demo security events and visualizations

## Verified Functionality

- Frontend runs successfully with Vite.
- FastAPI health endpoint returns `status: ok`.
- Vite proxy successfully forwards requests to FastAPI.
- FastAPI receives protection job submissions.
- Unsupported-backend errors are correctly displayed.
- TypeScript and Vite production build complete successfully.

## Pending Integration

### LLVM Shield

The backend currently reports no registered protection adapters.

Submitting a protection job using `llvm-shield` returns `UNSUPPORTED_BACKEND`.

The protection-engine team must register and configure the LLVM Shield adapter before successful protection jobs can be tested.

### Protection Job Statuses and Reports

The frontend contains functions and buttons for retrieving job statuses and reports.

These features still require end-to-end testing with an accepted protection job.

The API does not currently provide an endpoint for listing all jobs. The frontend tracks jobs accepted during the current browser session.

### AI Analysis

AI analysis currently uses demonstration functionality and requires integration with the team's AI backend.

### Other Dashboard Features

Security metrics, licensing information, and decoy activity currently include demonstration data and are not connected to live backend services.

## Production Build

From `platform/dashboard/`:

```bash
npm run build
```

The production build was verified successfully on October 29, 2026.

Vite reported a non-blocking JavaScript bundle-size warning.

## Handoff Status

The core frontend implementation is complete and successfully communicates with the AEGIS API.

Full end-to-end protection testing and additional live dashboard integrations depend on the backend, LLVM Shield, and AI components.
