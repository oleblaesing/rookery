/**
 * index.js — single-asset bundle entry point for rookery's browser code.
 *
 * esbuild bundles this (and everything it imports, including openpgp) into one
 * IIFE asset: static/app.js. The Containerfile js-build stage runs the bundle;
 * base.gohtml loads the result once on every page (`<script src=app.js defer>`).
 *
 * Why one asset instead of per-page scripts:
 *   - One request, one cache entry, one ?v= cache-bust for the whole frontend.
 *   - The openpgp dependency is downloaded once and shared by every page.
 *   - No more remembering to add the right <script> pair to each template.
 *
 * How the single asset serves many pages:
 *   Every page module is a self-contained IIFE that begins with a path guard
 *   (e.g. `if (location.pathname !== '/login') return;`). Importing them all
 *   here runs every guard; only the module whose guard matches the current URL
 *   wires up its behaviour. This keeps the existing "ship as IIFE" style — the
 *   only change to each page module is the guard at the top.
 *
 * Evaluation order matters and is deliberate:
 *   1. expose.js   — sets window.RookeryCrypto before any page module runs.
 *   2. partials.js — sets window.partials and the shell-wide listeners.
 *   3. pages/*     — each guards on location.pathname.
 */

import './expose.js';
import './partials.js';

import './pages/register.js';
import './pages/login.js';
import './pages/compose.js';
import './pages/read.js';
import './pages/settings.js';
import './pages/migrate.js';
