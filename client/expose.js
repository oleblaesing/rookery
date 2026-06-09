/**
 * expose.js — publishes the crypto API on window.RookeryCrypto.
 *
 * This module exists purely for evaluation-order reasons. The bundle (see
 * index.js) imports this module *before* the page modules. ES module imports
 * are evaluated in source order and a module's body runs to completion before
 * the next import is evaluated, so by the time a page module's IIFE runs
 * (which, under `defer`, happens synchronously while document.readyState is
 * already "interactive") window.RookeryCrypto is guaranteed to be set.
 *
 * The page modules continue to read window.RookeryCrypto exactly as they did
 * when crypto.js was a separate <script> — no per-page rewrite needed.
 */

import * as RookeryCrypto from './crypto.js';

window.RookeryCrypto = RookeryCrypto;
