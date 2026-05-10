import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { Readable, Transform } from 'stream';
import express from 'express';
import morgan from 'morgan';
import {
  accountWindowMs,
  buildStickyKey,
  consumeQuota,
  hasQuota,
  parseDurationMs,
  rankWeightedAccounts,
  quotaResetAt,
  quotaResetAtSecondary,
  safeJsonParse,
  sanitizeAccountInput
} from './core.js';
import { createStore } from './sqliteStore.js';
import { createCompatHelpers } from './compatHelpers.js';
import {
  createRiskControlModule,
  normalizeRiskControlMode,
  normalizeRiskControlScopeMode
} from './riskControl.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const jsonConfigPath = process.env.CONFIG_PATH || path.join(rootDir, 'data', 'config.json');
const dbPath = process.env.DB_PATH || path.join(rootDir, 'data', 'gateway.db');
const port = Number(process.env.PORT || 3000);
const adminUser = process.env.ADMIN_USER || 'admin';
const adminPass = process.env.ADMIN_PASS || 'admin123';
const gatewayKeys = (process.env.GATEWAY_KEYS || '')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

const store = createStore(dbPath);
let settings = store.getSettings();
const compat = createCompatHelpers({
  buildUpstreamUrl,
  normalizeBasePath,
  safeJsonParse,
  sanitizeLogText,
  cloneJsonLike,
  canonicalizeJsonLike: (value) => value,
  parseResponsesIncludeFields,
  extractErrorDetail
});
const riskControl = createRiskControlModule({
  store,
  getSettings: () => settings,
  buildUpstreamUrl,
  safeJsonParse,
  sanitizeLogText,
  extractErrorDetail,
  fetchImpl: fetch
});
const requestLogBufferLimit = 2000;
const requestLogPersistLimit = 5000;
const requestLogs = [];
const requestLogClients = new Set();
let requestLogSeq = 0;
let requestLogPersistCounter = 0;
const runtimeDailyStats = {
  dayKey: '',
  requestCount: 0,
  stickyHitCount: 0,
  inputTokens: 0,
  outputTokens: 0,
  cachedTokens: 0,
  totalTokens: 0
};
const stickyCleanupIntervalMs = 30 * 1000;
const adminSessionCleanupIntervalMs = 60 * 1000;
const accountCooldownWindowMs = 45 * 1000;
const accountCooldowns = new Map();
const responsesCompatStrictUnsupported = ['1', 'true', 'yes', 'on'].includes(
  String(process.env.RESPONSES_COMPAT_STRICT_UNSUPPORTED || '').trim().toLowerCase()
);
let lastStickyCleanupMs = 0;
let lastAdminSessionCleanupMs = 0;


function deriveAdminPasswordHash(password, saltHex) {
  return crypto.scryptSync(String(password || ''), Buffer.from(saltHex, 'hex'), 64).toString('hex');
}

function ensureAdminPasswordSeed() {
  settings = store.getSettings();
  if (settings.adminPasswordHash && settings.adminPasswordSalt) {
    return;
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = deriveAdminPasswordHash(adminPass, salt);
  store.updateSettings({
    adminPasswordSalt: salt,
    adminPasswordHash: hash
  });
  settings = store.getSettings();
}

function verifyAdminPassword(password) {
  const salt = String(settings.adminPasswordSalt || '').trim();
  const expected = String(settings.adminPasswordHash || '').trim();
  if (!salt || !expected) {
    return String(password || '') === adminPass;
  }
  const actual = deriveAdminPasswordHash(password, salt);
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}

function safeNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function parseCheckboxLike(value) {
  const normalizeCheckboxToken = (input) => {
    const text = String(input ?? '').trim().toLowerCase();
    if (!text) {
      return false;
    }
    if (['1', 'true', 'yes', 'on', 'enabled'].includes(text)) {
      return true;
    }
    if (['0', 'false', 'no', 'off', 'disabled'].includes(text)) {
      return false;
    }
    return null;
  };

  if (Array.isArray(value)) {
    let resolved = null;
    for (const item of value) {
      const token = normalizeCheckboxToken(item);
      if (token === null) {
        continue;
      }
      resolved = token;
    }
    return resolved === true;
  }
  return normalizeCheckboxToken(value) === true;
}

function parseOptionalRate(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return null;
  }
  const number = Number(text);
  if (!Number.isFinite(number) || number < 0) {
    return null;
  }
  return number;
}

function firstFiniteNumber(values, fallback = 0) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) {
      return number;
    }
  }
  return fallback;
}

function parseCostLimitMinor(limitText, currency) {
  const text = String(limitText ?? '').trim();
  if (!text) {
    return 0;
  }
  const raw = Number(text);
  if (!Number.isFinite(raw) || raw <= 0) {
    return 0;
  }
  const upper = String(currency || 'USD').toUpperCase();
  const factor = upper === 'JPY' ? 1 : 100;
  return Math.round(raw * factor);
}

function formatMinor(value, currency) {
  const upper = String(currency || 'USD').toUpperCase();
  const factor = upper === 'JPY' ? 1 : 100;
  return (safeNumber(value, 0) / factor).toFixed(factor === 1 ? 0 : 2);
}

function splitDuration(ms, defaultUnit = 'hour', defaultValue = 1) {
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const dayMs = 24 * 60 * 60 * 1000;
  const hourMs = 60 * 60 * 1000;
  const minuteMs = 60 * 1000;

  if (!ms || ms <= 0) {
    return { value: defaultValue, unit: defaultUnit };
  }
  if (ms % weekMs === 0) {
    return { value: ms / weekMs, unit: 'week' };
  }
  if (ms % dayMs === 0) {
    return { value: ms / dayMs, unit: 'day' };
  }
  if (ms % hourMs === 0) {
    return { value: ms / hourMs, unit: 'hour' };
  }
  return { value: Math.max(Math.round(ms / minuteMs), 1), unit: 'minute' };
}

function readCookies(req) {
  const raw = req.headers.cookie || '';
  const map = {};
  for (const part of raw.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (!key) {
      continue;
    }
    map[key] = decodeURIComponent(rest.join('='));
  }
  return map;
}

function createAdminSession() {
  const token = crypto.randomBytes(24).toString('hex');
  store.setAdminSession(token, Date.now() + settings.sessionTtlMs);
  return token;
}

function cleanupAdminSessions(force = false) {
  const now = Date.now();
  if (!force && now - lastAdminSessionCleanupMs < adminSessionCleanupIntervalMs) {
    return;
  }
  lastAdminSessionCleanupMs = now;
  store.cleanupExpiredAdminSessions(now);
}

function adminOnly(req, res, next) {
  const cookies = readCookies(req);
  const token = cookies.admin_session || '';
  const session = store.getAdminSession(token, Date.now());
  if (!session) {
    store.deleteAdminSession(token);
    return res.redirect('/admin/login');
  }
  store.setAdminSession(token, Date.now() + settings.sessionTtlMs);
  return next();
}

function cleanupStickyBindings(force = false) {
  const now = Date.now();
  if (!force && now - lastStickyCleanupMs < stickyCleanupIntervalMs) {
    return;
  }
  lastStickyCleanupMs = now;
  store.cleanupExpiredStickyBindings(now);
}

function cloneJsonLike(value, fallback = null) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return fallback;
  }
}

function parseResponsesIncludeFields(include) {
  if (!Array.isArray(include)) {
    return [];
  }
  return include
    .map((item) => String(item || '').trim())
    .filter(Boolean);
}

function wantsResponsesReasoningSummary(body) {
  if (!body || typeof body !== 'object') {
    return '';
  }
  const reasoning = body.reasoning;
  if (!reasoning || typeof reasoning !== 'object') {
    return '';
  }
  const summary = typeof reasoning.summary === 'string' ? reasoning.summary.trim() : '';
  const legacy = typeof reasoning.generate_summary === 'string' ? reasoning.generate_summary.trim() : '';
  return summary || legacy;
}

function detectResponsesCompatUnsupportedFields(body) {
  if (!body || typeof body !== 'object') {
    return [];
  }
  const unsupported = new Set();
  const includeFields = parseResponsesIncludeFields(body.include);
  const supportedIncludeFields = new Set([
    'message.output_text.logprobs'
  ]);
  if (Object.prototype.hasOwnProperty.call(body, 'include') && !Array.isArray(body.include)) {
    unsupported.add('include(invalid)');
  }
  for (const field of includeFields) {
    if (!supportedIncludeFields.has(field)) {
      unsupported.add(`include.${field}`);
    }
  }
  if (body.background === true) {
    unsupported.add('background');
  }
  if (
    body.reasoning &&
    typeof body.reasoning === 'object' &&
    Object.prototype.hasOwnProperty.call(body.reasoning, 'summary')
  ) {
    // Supported by Responses API, but may not be supported by every upstream when we convert to chat completions.
    // We treat it as best-effort and do not fail the request.
  }
  if (Object.prototype.hasOwnProperty.call(body, 'max_tool_calls') && Number.isFinite(Number(body.max_tool_calls))) {
    const maxToolCalls = Math.floor(Number(body.max_tool_calls));
    if (maxToolCalls > 0) {
      unsupported.add('max_tool_calls(>0)');
    }
  }
  return Array.from(unsupported);
}

function getCooldown(accountId, nowMs = Date.now()) {
  const key = String(accountId || '').trim();
  if (!key) {
    return null;
  }
  const cooldown = accountCooldowns.get(key);
  if (!cooldown) {
    return null;
  }
  if (cooldown.expiresAt <= nowMs) {
    accountCooldowns.delete(key);
    return null;
  }
  return cooldown;
}

function setAccountCooldown(accountId, reason, windowMs = accountCooldownWindowMs) {
  const key = String(accountId || '').trim();
  if (!key) {
    return;
  }
  const ttl = Number.isFinite(windowMs) && windowMs > 0 ? Math.floor(windowMs) : accountCooldownWindowMs;
  accountCooldowns.set(key, {
    reason: sanitizeLogText(reason, 160) || 'cooldown',
    expiresAt: Date.now() + ttl
  });
}

function sanitizeLogText(input, limit = 500) {
  const text = String(input ?? '').trim();
  if (!text) {
    return '';
  }
  return text.slice(0, limit);
}

function extractErrorDetail(payload, fallbackText = '') {
  if (payload && typeof payload === 'object') {
    const candidates = [
      payload.error?.message,
      payload.error?.detail,
      payload.error?.type,
      payload.detail,
      payload.message
    ];
    for (const candidate of candidates) {
      const normalized = sanitizeLogText(candidate);
      if (normalized) {
        return normalized;
      }
    }
  }
  return sanitizeLogText(fallbackText);
}

function shouldLogGatewayRequest(req) {
  const method = String(req?.method || '').toUpperCase();
  const path = String(req?.path || '');
  if (!path.startsWith('/v1/')) {
    return false;
  }
  if (path === '/v1/messages/count_tokens') {
    return false;
  }
  if (path === '/v1/models' || path.startsWith('/v1/models/')) {
    return false;
  }
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return false;
  }
  return true;
}

function normalizeProviderName(provider) {
  return String(provider || 'openai').trim().toLowerCase() === 'anthropic' ? 'anthropic' : 'openai';
}

function classifyUpstreamRetry(statusCode, payload, fallbackText = '') {
  const status = Number(statusCode) || 0;
  const detail = extractErrorDetail(payload, fallbackText).toLowerCase();
  const type = String(payload?.error?.type || payload?.type || '').toLowerCase();
  const code = String(payload?.error?.code || payload?.code || '').toLowerCase();

  const overloadSignals = [
    'rate limit',
    'rate_limit',
    'too many requests',
    'overloaded',
    'capacity',
    'resource exhausted',
    'model is currently overloaded',
    'temporarily unavailable'
  ];
  const hasOverloadSignal = overloadSignals.some((item) => (
    detail.includes(item) || type.includes(item) || code.includes(item)
  ));
  if (status === 502 || status === 503 || status === 504 || status === 529) {
    return { shouldRetry: true, reason: sanitizeLogText(extractErrorDetail(payload, fallbackText), 180) || `upstream ${status}` };
  }
  if (status === 429 && hasOverloadSignal) {
    return { shouldRetry: true, reason: sanitizeLogText(extractErrorDetail(payload, fallbackText), 180) || `upstream ${status}` };
  }
  return { shouldRetry: false, reason: '' };
}

function publishRequestLog(entry) {
  try {
    store.appendRequestLog(entry);
    requestLogPersistCounter += 1;
    if (requestLogPersistCounter % 40 === 0) {
      store.trimRequestLogs(requestLogPersistLimit);
    }
  } catch (error) {
    console.warn('[request-log] persist failed:', error?.message || error);
  }

  requestLogs.push(entry);
  if (requestLogs.length > requestLogBufferLimit) {
    requestLogs.splice(0, requestLogs.length - requestLogBufferLimit);
  }
  const payload = `data: ${JSON.stringify(entry)}\n\n`;
  for (const client of requestLogClients) {
    try {
      if (client.writableEnded || client.destroyed) {
        requestLogClients.delete(client);
        continue;
      }
      const ok = client.write(payload);
      if (!ok) {
        requestLogClients.delete(client);
        client.end();
      }
    } catch {
      requestLogClients.delete(client);
    }
  }
  updateRuntimeDailyStats(entry);
}

function resetRuntimeDailyStats() {
  runtimeDailyStats.dayKey = '';
  runtimeDailyStats.requestCount = 0;
  runtimeDailyStats.stickyHitCount = 0;
  runtimeDailyStats.inputTokens = 0;
  runtimeDailyStats.outputTokens = 0;
  runtimeDailyStats.cachedTokens = 0;
  runtimeDailyStats.totalTokens = 0;
}

function hydrateRequestLogsFromStore() {
  requestLogs.splice(0, requestLogs.length);
  resetRuntimeDailyStats();

  const persisted = store.listRecentRequestLogs(requestLogBufferLimit).reverse();
  for (const entry of persisted) {
    requestLogs.push(entry);
    updateRuntimeDailyStats(entry);
  }

  store.trimRequestLogs(requestLogPersistLimit);
}

function currentLocalDayKey(now = new Date()) {
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function ensureRuntimeDailyStats(now = new Date()) {
  const key = currentLocalDayKey(now);
  if (runtimeDailyStats.dayKey === key) {
    return;
  }
  runtimeDailyStats.dayKey = key;
  runtimeDailyStats.requestCount = 0;
  runtimeDailyStats.stickyHitCount = 0;
  runtimeDailyStats.inputTokens = 0;
  runtimeDailyStats.outputTokens = 0;
  runtimeDailyStats.cachedTokens = 0;
  runtimeDailyStats.totalTokens = 0;
}

function updateRuntimeDailyStats(entry) {
  const at = entry?.at ? new Date(entry.at) : new Date();
  const now = Number.isNaN(at.getTime()) ? new Date() : at;
  ensureRuntimeDailyStats(now);
  runtimeDailyStats.requestCount += 1;
  runtimeDailyStats.stickyHitCount += entry?.stickyHit ? 1 : 0;
  runtimeDailyStats.inputTokens += Math.max(Number(entry?.inputTokens) || 0, 0);
  runtimeDailyStats.outputTokens += Math.max(Number(entry?.outputTokens) || 0, 0);
  runtimeDailyStats.cachedTokens += Math.max(Number(entry?.cachedTokens) || 0, 0);
  runtimeDailyStats.totalTokens += Math.max(Number(entry?.tokens) || 0, 0);
}

function checkGatewayAuth(req, res) {
  const header = req.headers.authorization || '';
  const bearerToken = header.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : '';
  const xApiKeyToken = String(req.headers['x-api-key'] || '').trim();
  const candidates = [...new Set([bearerToken, xApiKeyToken].filter(Boolean))];

  if (!candidates.length) {
    const error = 'Unauthorized gateway token';
    res.status(401).json({ error });
    return { ok: false, groupKey: '', error };
  }

  for (const token of candidates) {
    const dbKey = store.getAccessKeyByToken(token);
    if (dbKey) {
      if (!dbKey.enabled) {
        const error = 'Access key disabled';
        res.status(403).json({ error });
        return { ok: false, groupKey: '', error };
      }
      if (dbKey.groupId && !dbKey.groupEnabled) {
        const error = 'Bound group is disabled';
        res.status(403).json({ error });
        return { ok: false, groupKey: '', groupId: '', error };
      }
      store.touchAccessKey(dbKey.id, new Date().toISOString());
      return {
        ok: true,
        groupKey: dbKey.groupKey || '',
        groupId: dbKey.groupId || '',
        accessKeyId: dbKey.id
      };
    }

    if (gatewayKeys.length && gatewayKeys.includes(token)) {
      return { ok: true, groupKey: '', groupId: '', accessKeyId: '' };
    }
  }

  const error = 'Unauthorized gateway token';
  res.status(401).json({ error });
  return { ok: false, groupKey: '', groupId: '', error };
}

function maskKey(value = '') {
  if (!value) {
    return '';
  }
  if (value.length <= 10) {
    return `${value.slice(0, 3)}***`;
  }
  return `${value.slice(0, 6)}***${value.slice(-4)}`;
}

function getModelUsage(usageObject) {
  const usage = usageObject && typeof usageObject === 'object' ? usageObject : {};
  const input = firstFiniteNumber([
    usage.input_tokens,
    usage.prompt_tokens
  ], 0);
  const output = firstFiniteNumber([
    usage.output_tokens,
    usage.completion_tokens
  ], 0);
  const cacheRead = firstFiniteNumber([
    usage.cache_read_input_tokens,
    usage.input_tokens_details?.cache_read_input_tokens,
    usage.input_tokens_details?.cached_tokens,
    usage.prompt_tokens_details?.cached_tokens
  ], 0);
  let cacheWrite = firstFiniteNumber([
    usage.cache_creation_input_tokens,
    usage.input_tokens_details?.cache_creation_input_tokens,
    usage.input_tokens_details?.cache_creation_tokens,
    usage.prompt_tokens_details?.cache_creation_tokens
  ], 0);
  if (!cacheWrite && usage.cache_creation && typeof usage.cache_creation === 'object') {
    const cacheCreationParts = Object.values(usage.cache_creation)
      .map((value) => Number(value))
      .filter((value) => Number.isFinite(value));
    if (cacheCreationParts.length) {
      cacheWrite = cacheCreationParts.reduce((sum, value) => sum + value, 0);
    }
  }
  const explicitTotal = Number(usage.total_tokens);
  const total = Number.isFinite(explicitTotal)
    ? explicitTotal
    : (input + output);
  const reasoning = firstFiniteNumber([
    usage.output_tokens_details?.reasoning_tokens,
    usage.completion_tokens_details?.reasoning_tokens,
    usage.reasoning_tokens
  ], 0);
  return {
    input,
    output,
    total,
    cached: cacheRead,
    cacheRead,
    cacheWrite,
    reasoning
  };
}

function findUsageObjectDeep(input, depth = 0) {
  if (!input || typeof input !== 'object' || depth > 6) {
    return null;
  }
  if (
    Object.prototype.hasOwnProperty.call(input, 'input_tokens') ||
    Object.prototype.hasOwnProperty.call(input, 'output_tokens') ||
    Object.prototype.hasOwnProperty.call(input, 'total_tokens')
  ) {
    return input;
  }

  if (Array.isArray(input)) {
    for (const item of input) {
      const found = findUsageObjectDeep(item, depth + 1);
      if (found) {
        return found;
      }
    }
    return null;
  }

  for (const value of Object.values(input)) {
    const found = findUsageObjectDeep(value, depth + 1);
    if (found) {
      return found;
    }
  }
  return null;
}

function extractUsageFromPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }
  const direct = payload.response?.usage || payload.usage || payload.data?.usage;
  if (direct && typeof direct === 'object') {
    return getModelUsage(direct);
  }
  const deep = findUsageObjectDeep(payload);
  return deep ? getModelUsage(deep) : null;
}

function normalizeStickyPart(value) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  return text
    .replace(/\s+/g, '-')
    .replace(/[^a-zA-Z0-9._:-]/g, '')
    .slice(0, 160);
}

function normalizeBasePath(pathname) {
  const normalized = String(pathname || '').trim();
  if (!normalized || normalized === '/') {
    return '';
  }
  return normalized.endsWith('/') ? normalized.slice(0, -1) : normalized;
}

function resolveUpstreamPath(basePathname, requestPathname) {
  const basePath = normalizeBasePath(basePathname);
  const requestPath = String(requestPathname || '/').trim() || '/';
  if (!basePath) {
    return requestPath;
  }
  if (requestPath === '/v1' || requestPath.startsWith('/v1/')) {
    const tail = requestPath.slice('/v1'.length);
    return `${basePath}${tail}`;
  }
  if (requestPath.startsWith('/')) {
    return `${basePath}${requestPath}`;
  }
  return `${basePath}/${requestPath}`;
}

function buildUpstreamUrl(baseUrl, requestUrl) {
  const base = new URL(String(baseUrl || '').trim());
  const incoming = new URL(String(requestUrl || '/'), 'http://gateway.local');
  const target = new URL(base.origin);
  target.pathname = resolveUpstreamPath(base.pathname, incoming.pathname);
  target.search = incoming.search;
  return target;
}

const {
  buildResponsesCompatTargetUrl,
  normalizeServiceBaseUrl,
  extractSessionRoutingId,
  extractPreviousResponseId,
  extractCodexTurnState,
  extractResponseContinuationIdFromPayload,
  buildResponseContinuationStickyKey,
  isLikelyCodexRequest,
  buildDeterministicRoutingBody,
  buildCodexTurnStateStickyKey,
  buildCodexAffinityStickyKey,
  convertAnthropicMessagesRequestToChatRequest,
  convertChatCompletionToAnthropicResponsePayload,
  convertResponsesRequestToChatRequest,
  convertChatCompletionToResponsesPayload,
  createChatCompletionsToResponsesSseTransform,
  createChatCompletionsToAnthropicSseTransform,
  createStreamUsageObserver,
  isStreamingRequest,
  ensureStringContent
} = compat;

function extractPromptCacheKey(jsonBody) {
  if (!jsonBody || typeof jsonBody !== 'object') {
    return '';
  }
  const candidates = [
    jsonBody.prompt_cache_key,
    jsonBody.metadata?.prompt_cache_key,
    jsonBody.conversation_id,
    jsonBody.conversationId,
    jsonBody.metadata?.conversation_id,
    jsonBody.metadata?.conversationId
  ];
  for (const value of candidates) {
    const key = String(value || '').trim();
    if (key) {
      return key;
    }
  }
  return '';
}

function buildPromptCacheStickyKey({ provider, model, promptCacheKey }) {
  const key = String(promptCacheKey || '').trim();
  if (!key) {
    return '';
  }
  const providerPart = normalizeStickyPart(provider) || 'openai';
  const modelPart = normalizeStickyPart(model) || '-';
  const digest = crypto.createHash('sha256').update(key).digest('hex');
  return `prompt-cache:${providerPart}:${modelPart}:${digest}`;
}

function bindResponseContinuationSticky(account, responseId, ttlMs = 0) {
  const stickyKey = buildResponseContinuationStickyKey(responseId);
  const accountId = String(account?.id || '').trim();
  if (!stickyKey || !accountId) {
    return;
  }
  const expiresAt = Date.now() + Math.max(Math.floor(Number(ttlMs) || 0), 60 * 1000);
  store.setStickyBinding(stickyKey, accountId, expiresAt);
}
function computeCostMinor(usage, priceRow, currency) {
  if (!priceRow) {
    return 0;
  }
  const curr = String(currency || priceRow.currency || 'USD').toUpperCase();
  const factor = curr === 'JPY' ? 1 : 100;
  const inputRate = safeNumber(priceRow.inputPerMillion, 0);
  const outputRate = safeNumber(priceRow.outputPerMillion, 0);
  const cacheReadRate = safeNumber(priceRow.cacheReadPerMillion, 0);
  const cacheWriteRate = safeNumber(priceRow.cacheWritePerMillion, 0);

  const inputTokens = Math.max(safeNumber(usage.input, 0), 0);
  const outputTokens = Math.max(safeNumber(usage.output, 0), 0);
  const cacheReadTokens = Math.max(firstFiniteNumber([usage.cacheRead, usage.cached], 0), 0);
  const cacheWriteTokens = Math.max(safeNumber(usage.cacheWrite, 0), 0);
  const totalTokens = Math.max(safeNumber(usage.total, inputTokens + outputTokens + cacheReadTokens + cacheWriteTokens), 0);
  const hasSeparateCacheBreakdown = (
    cacheWriteTokens > 0 ||
    totalTokens > (inputTokens + outputTokens)
  );
  const billableInput = hasSeparateCacheBreakdown
    ? inputTokens
    : Math.max(inputTokens - cacheReadTokens, 0);
  const inputCost = (billableInput / 1_000_000) * inputRate;
  const cachedCost = (cacheReadTokens / 1_000_000) * cacheReadRate;
  const cacheWriteCost = (cacheWriteTokens / 1_000_000) * cacheWriteRate;
  const outputCost = (outputTokens / 1_000_000) * outputRate;
  const totalCost = inputCost + cachedCost + cacheWriteCost + outputCost;

  return Math.max(Math.round(totalCost * factor), 0);
}

function quotaResetAtFromRow(quota) {
  if (!quota.windowMs || !quota.windowStartMs) {
    return '';
  }
  return new Date(quota.windowStartMs + quota.windowMs).toISOString();
}

function canAccountServeModel(accountId, upstreamModel, accountModelIndex = null) {
  if (!upstreamModel) {
    return true;
  }
  if (accountModelIndex && accountModelIndex.has(accountId)) {
    const modelSet = accountModelIndex.get(accountId);
    if (!modelSet || modelSet.size === 0) {
      return true;
    }
    return modelSet.has(upstreamModel);
  }
  const models = store.listAccountModels(accountId);
  if (!models.length) {
    return true;
  }
  return models.some((item) => item.modelName === upstreamModel);
}

function parseModelNamesInput(text) {
  if (!text) {
    return [];
  }
  return String(text)
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function generateAccessToken() {
  return `ak_${crypto.randomBytes(24).toString('base64url')}`;
}

function tryReserveAccountQuota(account, nowMs) {
  const snapshot = {
    windowStartMs: account.stats.windowStartMs,
    windowStartMs2: account.stats.windowStartMs2,
    usedRequests: account.stats.usedRequests,
    usedRequests2: account.stats.usedRequests2,
    totalRequests: account.stats.totalRequests,
    lastUsedAt: account.stats.lastUsedAt
  };
  if (!hasQuota(account, nowMs)) {
    return { ok: false };
  }
  consumeQuota(account, nowMs);
  store.updateAccountStats(account.id, account.stats);
  return { ok: true, snapshot };
}

function releaseAccountQuotaReservation(account, snapshot) {
  account.stats.windowStartMs = snapshot.windowStartMs;
  account.stats.windowStartMs2 = snapshot.windowStartMs2;
  account.stats.usedRequests = snapshot.usedRequests;
  account.stats.usedRequests2 = snapshot.usedRequests2;
  account.stats.totalRequests = snapshot.totalRequests;
  account.stats.lastUsedAt = snapshot.lastUsedAt;
  store.updateAccountStats(account.id, account.stats);
}

function selectAccount({
  stickyKey,
  seed,
  requestModel,
  upstreamModel,
  requestProvider = '',
  groupKey,
  excludeAccountIds = new Set(),
  reserveQuota = true,
  enforceQuota = true
}) {
  cleanupStickyBindings();

  const now = Date.now();
  const excluded = excludeAccountIds instanceof Set
    ? excludeAccountIds
    : new Set(Array.isArray(excludeAccountIds) ? excludeAccountIds : []);
  const scopedAccounts = groupKey
    ? store.listAccountsByGroupKey(groupKey)
    : store.listAccounts();
  const accountModelIndex = upstreamModel
    ? store.listAccountModelsForAccounts(scopedAccounts.map((item) => item.id))
    : null;
  const filteredAccounts = scopedAccounts
    .filter((item) => item.enabled && item.apiKey)
    .filter((item) => !requestProvider || (item.provider || 'openai') === requestProvider)
    .filter((item) => canAccountServeModel(item.id, upstreamModel, accountModelIndex))
    .filter((item) => !excluded.has(item.id));
  const allAccounts = filteredAccounts.filter((item) => !getCooldown(item.id, now));
  const candidateAccounts = allAccounts.length ? allAccounts : filteredAccounts;

  if (!candidateAccounts.length) {
    if (groupKey) {
      return { error: `Group key "${groupKey}" has no usable accounts` };
    }
    if (requestProvider) {
      return { error: `No enabled ${requestProvider} account can serve this request` };
    }
    return { error: 'No enabled account can serve this model' };
  }

  const availableByQuota = [];
  for (const account of candidateAccounts) {
    if (!enforceQuota) {
      availableByQuota.push(account);
      continue;
    }
    const beforeWindowStart = account.stats.windowStartMs;
    const beforeWindowStart2 = account.stats.windowStartMs2;
    const beforeUsedRequests = account.stats.usedRequests;
    const beforeUsedRequests2 = account.stats.usedRequests2;
    if (!hasQuota(account, now)) {
      if (
        account.stats.windowStartMs !== beforeWindowStart ||
        account.stats.windowStartMs2 !== beforeWindowStart2 ||
        account.stats.usedRequests !== beforeUsedRequests ||
        account.stats.usedRequests2 !== beforeUsedRequests2
      ) {
        store.updateAccountStats(account.id, account.stats);
      }
      continue;
    }
    if (
      account.stats.windowStartMs !== beforeWindowStart ||
      account.stats.windowStartMs2 !== beforeWindowStart2 ||
      account.stats.usedRequests !== beforeUsedRequests ||
      account.stats.usedRequests2 !== beforeUsedRequests2
    ) {
      store.updateAccountStats(account.id, account.stats);
    }
    let modelQuota = store.getModelQuota(account.id, requestModel);
    if (modelQuota) {
      if (!modelQuota.windowStartMs) {
        store.resetModelQuotaUsage(account.id, requestModel, now);
        modelQuota = {
          ...modelQuota,
          windowStartMs: now,
          usedRequests: 0,
          usedTokens: 0,
          usedCostMinor: 0
        };
      } else if (modelQuota.windowMs > 0 && now - modelQuota.windowStartMs >= modelQuota.windowMs) {
        store.resetModelQuotaUsage(account.id, requestModel, now);
        modelQuota = {
          ...modelQuota,
          windowStartMs: now,
          usedRequests: 0,
          usedTokens: 0,
          usedCostMinor: 0
        };
      }
      if (modelQuota.requestLimit > 0 && modelQuota.usedRequests >= modelQuota.requestLimit) {
        continue;
      }
      if (modelQuota.costLimitMinor > 0 && modelQuota.usedCostMinor >= modelQuota.costLimitMinor) {
        continue;
      }
      if (modelQuota.tokenLimit > 0 && modelQuota.usedTokens >= modelQuota.tokenLimit) {
        continue;
      }
    }
    availableByQuota.push(account);
  }

  if (!availableByQuota.length) {
    return { error: 'No account has remaining model/account quota' };
  }

  const tryReserve = (account, reserveQuota = true) => {
    if (!reserveQuota) {
      return {
        account,
        reservation: null
      };
    }
    const accountReserve = tryReserveAccountQuota(account, now);
    if (!accountReserve.ok) {
      return null;
    }
    const modelReserve = store.reserveModelQuota(account.id, requestModel, now);
    if (!modelReserve.allowed) {
      releaseAccountQuotaReservation(account, accountReserve.snapshot);
      return null;
    }
    return {
      account,
      reservation: {
        accountSnapshot: accountReserve.snapshot,
        modelName: requestModel
      }
    };
  };

  if (stickyKey) {
    const existing = store.getStickyBinding(stickyKey, now);
    if (existing) {
      const stickyAccount = availableByQuota.find((item) => item.id === existing.accountId);
      if (stickyAccount) {
        const reserved = tryReserve(stickyAccount, reserveQuota);
        if (reserved) {
          return {
            account: stickyAccount,
            stickyHit: true,
            reservation: reserved.reservation
          };
        }
      }
    }
  }

  const rankedCandidates = rankWeightedAccounts(availableByQuota, seed);
  for (const chosen of rankedCandidates) {
    const reserved = tryReserve(chosen, reserveQuota);
    if (reserved) {
      return {
        account: chosen,
        stickyHit: false,
        reservation: reserved.reservation
      };
    }
  }

  return { error: 'No account could reserve quota' };
}

async function migrateJsonConfigIfNeeded() {
  const existingAccounts = store.listAccounts();
  if (existingAccounts.length > 0) {
    return;
  }

  try {
    const text = await fs.readFile(jsonConfigPath, 'utf8');
    const parsed = JSON.parse(text);

    const nextSettings = {};
    if (parsed?.settings?.globalStickyWindowMs) {
      nextSettings.globalStickyWindowMs = parsed.settings.globalStickyWindowMs;
    }
    if (parsed?.settings?.defaultBaseUrl) {
      nextSettings.defaultBaseUrl = parsed.settings.defaultBaseUrl;
    }
    if (parsed?.settings?.sessionTtlMs) {
      nextSettings.sessionTtlMs = parsed.settings.sessionTtlMs;
    }
    if (Object.keys(nextSettings).length > 0) {
      store.updateSettings(nextSettings);
    }
    settings = store.getSettings();

    if (Array.isArray(parsed?.accounts)) {
      for (const raw of parsed.accounts) {
        const name = String(raw?.name || '').trim();
        const apiKey = String(raw?.apiKey || '').trim();
        if (!name || !apiKey) {
          continue;
        }
        store.createAccount({
          id: raw.id || crypto.randomUUID(),
          name,
          provider: String(raw.provider || 'openai').trim().toLowerCase() === 'anthropic' ? 'anthropic' : 'openai',
          forceResponsesCompat: raw.forceResponsesCompat === true,
          apiKey,
          baseUrl: String(raw.baseUrl || settings.defaultBaseUrl).trim().replace(/\/$/, ''),
          enabled: raw.enabled !== false,
          weight: Number.isFinite(raw.weight) && raw.weight > 0 ? Math.floor(raw.weight) : 1,
          quotaLimit: Number.isFinite(raw.quotaLimit) && raw.quotaLimit > 0 ? Math.floor(raw.quotaLimit) : 0,
          quotaWindowMs: Number.isFinite(raw.quotaWindowMs) && raw.quotaWindowMs > 0 ? Math.floor(raw.quotaWindowMs) : 0,
          quotaLimit2: Number.isFinite(raw.quotaLimit2) && raw.quotaLimit2 > 0 ? Math.floor(raw.quotaLimit2) : 0,
          quotaWindowMs2: Number.isFinite(raw.quotaWindowMs2) && raw.quotaWindowMs2 > 0 ? Math.floor(raw.quotaWindowMs2) : 0,
          stickyWindowMs: Number.isFinite(raw.stickyWindowMs) && raw.stickyWindowMs > 0 ? Math.floor(raw.stickyWindowMs) : 0,
          stats: {
            windowStartMs: Number.isFinite(raw?.stats?.windowStartMs) ? raw.stats.windowStartMs : Date.now(),
            windowStartMs2: Number.isFinite(raw?.stats?.windowStartMs2) ? raw.stats.windowStartMs2 : Date.now(),
            usedRequests: Number.isFinite(raw?.stats?.usedRequests) ? raw.stats.usedRequests : 0,
            usedRequests2: Number.isFinite(raw?.stats?.usedRequests2) ? raw.stats.usedRequests2 : 0,
            totalRequests: Number.isFinite(raw?.stats?.totalRequests) ? raw.stats.totalRequests : 0,
            lastUsedAt: raw?.stats?.lastUsedAt || ''
          }
        });
      }
    }
  } catch {
    return;
  } finally {
    settings = store.getSettings();
  }
}

async function syncModelsFromUpstream(account) {
  const url = buildUpstreamUrl(account.baseUrl, '/v1/models');
  const provider = normalizeProviderName(account.provider);
  const headers = {
    Accept: 'application/json',
    'Accept-Encoding': 'identity',
    'User-Agent': 'responses-gateway/1.0 (+model-sync)'
  };
  if (provider === 'anthropic') {
    headers['x-api-key'] = account.apiKey;
    headers['anthropic-version'] = '2023-06-01';
  } else {
    headers.Authorization = `Bearer ${account.apiKey}`;
  }
  const response = await fetch(url, {
    method: 'GET',
    headers
  });
  if (!response.ok) {
    const text = await response.text();
    const compact = String(text || '').replace(/\s+/g, ' ').trim();
    const looksLikeVercelCheckpoint = (
      response.status === 429 &&
      (compact.includes('Vercel Security Checkpoint') || compact.toLowerCase().includes('security checkpoint'))
    );
    if (looksLikeVercelCheckpoint) {
      throw new Error(`status=429 blocked by Vercel Security Checkpoint at ${account.baseUrl} (anti-bot). 请关闭“创建后自动拉取模型”，改为手动添加模型，或换可直连的 /v1/models 上游。`);
    }
    throw new Error(`status=${response.status} body=${compact.slice(0, 220)}`);
  }
  const contentType = String(response.headers.get('content-type') || '').toLowerCase();
  if (!contentType.includes('application/json')) {
    const text = await response.text();
    const compact = String(text || '').replace(/\s+/g, ' ').trim();
    throw new Error(`invalid /v1/models response content-type=${contentType || '-'} body=${compact.slice(0, 220)}`);
  }
  const body = await response.json();
  const modelSet = new Set();
  const pushModel = (value) => {
    const normalized = String(value || '').trim();
    if (normalized) {
      modelSet.add(normalized);
    }
  };

  if (Array.isArray(body?.data)) {
    for (const item of body.data) {
      if (item && typeof item === 'object') {
        pushModel(item.id);
        pushModel(item.model);
        pushModel(item.name);
      } else {
        pushModel(item);
      }
    }
  }

  if (Array.isArray(body?.models)) {
    for (const item of body.models) {
      if (item && typeof item === 'object') {
        pushModel(item.id);
        pushModel(item.model);
        pushModel(item.name);
      } else {
        pushModel(item);
      }
    }
  }

  if (body?.models && typeof body.models === 'object' && !Array.isArray(body.models)) {
    for (const [modelName] of Object.entries(body.models)) {
      pushModel(modelName);
    }
  }

  const models = [...modelSet];
  store.syncRemoteModels(account.id, models);
  return models.length;
}

async function syncModelPricesFromModelsDev(providerId = 'openai', currency = 'USD') {
  const response = await fetch('https://models.dev/api.json');
  if (!response.ok) {
    throw new Error(`models.dev status=${response.status}`);
  }
  const payload = await response.json();
  const provider = payload?.[providerId];
  if (!provider || typeof provider !== 'object') {
    throw new Error(`provider "${providerId}" not found`);
  }

  const modelsObject = provider.models || {};
  const prices = [];
  for (const [modelName, modelData] of Object.entries(modelsObject)) {
    const cost = modelData?.cost || {};
    prices.push({
      modelName,
      inputPerMillion: Number(cost.input),
      outputPerMillion: Number(cost.output),
      cacheReadPerMillion: Number(cost.cache_read),
      cacheWritePerMillion: Number(cost.cache_write)
    });
  }
  store.upsertModelPrices(providerId, prices, String(currency || 'USD').toUpperCase());
  return prices.length;
}

function getPromptCacheConfigForGroupKey(groupKey) {
  const key = String(groupKey || '').trim();
  if (!key) {
    return null;
  }
  const group = store.getGroupByKey(key);
  if (!group || group.enabled !== true || group.cacheEnabled !== true) {
    return null;
  }
  const baseUrl = normalizeServiceBaseUrl(group.cacheBaseUrl);
  if (!baseUrl) {
    return null;
  }
  return {
    groupId: group.id,
    groupName: group.name,
    groupKey: group.groupKey,
    baseUrl,
    authToken: String(group.cacheAuthToken || '').trim()
  };
}

function isPromptCacheCandidateRequest(req) {
  const method = String(req.method || '').toUpperCase();
  const path = String(req.path || '');
  if (method !== 'POST') {
    return false;
  }
  return (
    path === '/v1/chat/completions' ||
    path === '/v1/responses' ||
    path === '/v1/responses/compact' ||
    path === '/v1/messages'
  );
}

function getPromptCacheTargetUrl(baseUrl) {
  return buildUpstreamUrl(baseUrl, '/v1/chat/completions');
}

function mapPromptCacheStats(rawStats) {
  const stats = rawStats && typeof rawStats === 'object' ? rawStats : {};
  const hits = firstFiniteNumber([
    stats.hits,
    stats.cache_hits,
    stats.cacheHits,
    stats.hit_count
  ], 0);
  const misses = firstFiniteNumber([
    stats.misses,
    stats.cache_misses,
    stats.cacheMisses,
    stats.miss_count
  ], 0);
  const total = Math.max(hits + misses, 0);
  const hitRate = total > 0 ? (hits / total) : 0;
  return {
    hits,
    misses,
    total,
    hitRate,
    raw: stats
  };
}

async function fetchPromptCacheGroupRuntime(group) {
  const baseUrl = normalizeServiceBaseUrl(group.cacheBaseUrl);
  const authToken = String(group.cacheAuthToken || '').trim();
  if (!group.cacheEnabled || !baseUrl) {
    return {
      groupId: group.id,
      groupName: group.name,
      groupKey: group.groupKey,
      enabled: group.cacheEnabled === true,
      baseUrl,
      healthy: false,
      healthDetail: group.cacheEnabled ? 'Invalid cache base URL' : 'Disabled',
      stats: mapPromptCacheStats({})
    };
  }

  const headers = {
    Accept: 'application/json',
    'Accept-Encoding': 'identity'
  };
  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  let healthy = false;
  let healthDetail = '';
  let stats = mapPromptCacheStats({});
  try {
    const healthUrl = buildUpstreamUrl(baseUrl, '/health');
    const healthResp = await fetch(healthUrl, { method: 'GET', headers });
    healthy = healthResp.ok;
    if (!healthResp.ok) {
      healthDetail = `health status ${healthResp.status}`;
    }
  } catch (error) {
    healthy = false;
    healthDetail = error?.message || 'health check failed';
  }

  try {
    const statsUrl = buildUpstreamUrl(baseUrl, '/v1/stats');
    const statsResp = await fetch(statsUrl, { method: 'GET', headers });
    if (statsResp.ok) {
      const payload = await statsResp.json();
      stats = mapPromptCacheStats(payload);
    } else if (!healthDetail) {
      healthDetail = `stats status ${statsResp.status}`;
    }
  } catch (error) {
    if (!healthDetail) {
      healthDetail = error?.message || 'stats fetch failed';
    }
  }

  return {
    groupId: group.id,
    groupName: group.name,
    groupKey: group.groupKey,
    enabled: group.cacheEnabled === true,
    baseUrl,
    healthy,
    healthDetail,
    stats
  };
}

await migrateJsonConfigIfNeeded();
ensureAdminPasswordSeed();
hydrateRequestLogsFromStore();

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(rootDir, 'views'));
app.use('/public', express.static(path.join(rootDir, 'public')));
app.use(morgan('tiny'));

app.get('/', (req, res) => {
  res.redirect('/admin');
});

app.use('/admin', express.urlencoded({ extended: false }));

app.get('/admin/login', (req, res) => {
  cleanupAdminSessions();
  res.render('login', { error: req.query.error || '' });
});

app.post('/admin/login', (req, res) => {
  cleanupAdminSessions();
  if (req.body.username !== adminUser || !verifyAdminPassword(req.body.password || '')) {
    return res.redirect('/admin/login?error=Invalid+credentials');
  }
  const token = createAdminSession();
  res.setHeader('Set-Cookie', `admin_session=${token}; Path=/; HttpOnly; SameSite=Lax`);
  return res.redirect('/admin');
});

app.post('/admin/logout', (req, res) => {
  const cookies = readCookies(req);
  const token = cookies.admin_session || '';
  store.deleteAdminSession(token);
  res.setHeader('Set-Cookie', 'admin_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax');
  res.redirect('/admin/login');
});

function adminNoticeRedirect(req, res, message, fallbackPath = '/admin/accounts') {
  let targetPath = fallbackPath;
  const referer = req.get('referer') || '';
  if (referer) {
    try {
      const url = new URL(referer, `http://${req.headers.host || '127.0.0.1'}`);
      if (url.pathname.startsWith('/admin')) {
        targetPath = `${url.pathname}${url.search}`;
      }
    } catch {
      targetPath = fallbackPath;
    }
  }
  const glue = targetPath.includes('?') ? '&' : '?';
  return res.redirect(`${targetPath}${glue}notice=${encodeURIComponent(message)}`);
}

function buildAdminStats(accounts) {
  cleanupStickyBindings();
  ensureRuntimeDailyStats(new Date());
  const todayInputTokens = runtimeDailyStats.inputTokens;
  const todayOutputTokens = runtimeDailyStats.outputTokens;
  const todayCachedTokens = runtimeDailyStats.cachedTokens;
  const todayTotalTokens = runtimeDailyStats.totalTokens;
  const cacheHitRate = todayInputTokens > 0
    ? (todayCachedTokens / todayInputTokens)
    : 0;
  const stickyHitRate = runtimeDailyStats.requestCount > 0
    ? (runtimeDailyStats.stickyHitCount / runtimeDailyStats.requestCount)
    : 0;
  return {
    accountCount: accounts.length,
    activeCount: accounts.filter((item) => item.enabled).length,
    stickyCount: store.countActiveStickyBindings(Date.now()),
    todayInputTokens,
    todayOutputTokens,
    todayCachedTokens,
    todayTotalTokens,
    cacheHitRate,
    stickyHitRate
  };
}

function buildHourBucketKey(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    return '';
  }
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hour = String(date.getHours()).padStart(2, '0');
  return `${year}-${month}-${day} ${hour}`;
}

function buildRecentHourSlots(count = 24) {
  const slots = [];
  const now = new Date();
  now.setMinutes(0, 0, 0);
  const length = Math.max(Math.floor(Number(count) || 24), 1);
  for (let offset = length - 1; offset >= 0; offset -= 1) {
    const time = new Date(now.getTime() - (offset * 60 * 60 * 1000));
    slots.push({
      key: buildHourBucketKey(time),
      label: `${String(time.getHours()).padStart(2, '0')}:00`
    });
  }
  return slots;
}

function percentileFromSorted(values, percentile) {
  if (!Array.isArray(values) || values.length === 0) {
    return 0;
  }
  const p = Math.min(Math.max(Number(percentile) || 0, 0), 100);
  if (values.length === 1) {
    return values[0];
  }
  const index = (p / 100) * (values.length - 1);
  const lowerIndex = Math.floor(index);
  const upperIndex = Math.ceil(index);
  if (lowerIndex === upperIndex) {
    return values[lowerIndex];
  }
  const ratio = index - lowerIndex;
  return values[lowerIndex] + ((values[upperIndex] - values[lowerIndex]) * ratio);
}

function buildAdminDashboardData(accounts) {
  ensureRuntimeDailyStats(new Date());
  const slots = buildRecentHourSlots(24);
  const hourlyMap = new Map();
  for (const slot of slots) {
    hourlyMap.set(slot.key, {
      requests: 0,
      inputTokens: 0,
      outputTokens: 0,
      cachedTokens: 0
    });
  }

  const last24hStartMs = Date.now() - (24 * 60 * 60 * 1000);
  const providerMap = new Map();
  const statusMap = new Map([
    ['2xx', 0],
    ['4xx', 0],
    ['5xx', 0],
    ['other', 0]
  ]);
  const modelMap = new Map();

  const todayKey = currentLocalDayKey(new Date());
  let todayRequests = 0;
  let todaySuccess = 0;
  let todayCostMinor = 0;
  const todayLatencies = [];

  for (const entry of requestLogs) {
    const date = new Date(entry.at || '');
    if (Number.isNaN(date.getTime())) {
      continue;
    }

    const statusCode = Number(entry.statusCode) || 0;
    const requestTokens = Math.max(Number(entry.tokens) || 0, 0);
    const inputTokens = Math.max(Number(entry.inputTokens) || 0, 0);
    const outputTokens = Math.max(Number(entry.outputTokens) || 0, 0);
    const cachedTokens = Math.max(Number(entry.cachedTokens) || 0, 0);
    const durationMs = Math.max(Number(entry.durationMs) || 0, 0);
    const costMinor = Math.max(Number(entry.costMinor) || 0, 0);

    const entryDay = currentLocalDayKey(date);
    if (entryDay === todayKey) {
      todayRequests += 1;
      if (statusCode >= 200 && statusCode < 300) {
        todaySuccess += 1;
      }
      todayCostMinor += costMinor;
      todayLatencies.push(durationMs);
    }

    if (date.getTime() >= last24hStartMs) {
      const hourKey = buildHourBucketKey(date);
      const hourBucket = hourlyMap.get(hourKey);
      if (hourBucket) {
        hourBucket.requests += 1;
        hourBucket.inputTokens += inputTokens;
        hourBucket.outputTokens += outputTokens;
        hourBucket.cachedTokens += cachedTokens;
      }

      const provider = String(entry.provider || 'unknown').trim().toLowerCase() || 'unknown';
      providerMap.set(provider, (providerMap.get(provider) || 0) + 1);

      const model = String(entry.model || '').trim();
      if (model && model !== '-') {
        const existing = modelMap.get(model) || {
          model,
          requests: 0,
          tokens: 0,
          costMinor: 0
        };
        existing.requests += 1;
        existing.tokens += requestTokens;
        existing.costMinor += costMinor;
        modelMap.set(model, existing);
      }

      if (statusCode >= 200 && statusCode < 300) {
        statusMap.set('2xx', (statusMap.get('2xx') || 0) + 1);
      } else if (statusCode >= 400 && statusCode < 500) {
        statusMap.set('4xx', (statusMap.get('4xx') || 0) + 1);
      } else if (statusCode >= 500) {
        statusMap.set('5xx', (statusMap.get('5xx') || 0) + 1);
      } else {
        statusMap.set('other', (statusMap.get('other') || 0) + 1);
      }
    }
  }

  const sortedLatencies = todayLatencies.slice().sort((left, right) => left - right);
  const p95LatencyMs = Math.round(percentileFromSorted(sortedLatencies, 95));
  const avgLatencyMs = sortedLatencies.length
    ? Math.round(sortedLatencies.reduce((sum, value) => sum + value, 0) / sortedLatencies.length)
    : 0;

  const currency = String(settings.defaultCurrency || 'USD').toUpperCase();
  const factor = currency === 'JPY' ? 1 : 100;
  const todayCostMajor = Number((todayCostMinor / factor).toFixed(factor === 1 ? 0 : 2));
  const successRate = todayRequests > 0 ? (todaySuccess / todayRequests) : 0;

  const hourlySeries = slots.map((slot) => hourlyMap.get(slot.key) || {
    requests: 0,
    inputTokens: 0,
    outputTokens: 0,
    cachedTokens: 0
  });

  const modelTopList = Array.from(modelMap.values())
    .sort((left, right) => right.tokens - left.tokens)
    .slice(0, 10)
    .map((item) => ({
      model: item.model,
      requests: item.requests,
      tokens: item.tokens,
      costMinor: item.costMinor,
      cost: Number((item.costMinor / factor).toFixed(factor === 1 ? 0 : 2))
    }));

  const providerSeries = Array.from(providerMap.entries())
    .sort((left, right) => right[1] - left[1])
    .map(([name, value]) => ({ name, value }));

  const statusSeries = [
    { name: '2xx', value: statusMap.get('2xx') || 0 },
    { name: '4xx', value: statusMap.get('4xx') || 0 },
    { name: '5xx', value: statusMap.get('5xx') || 0 },
    { name: 'other', value: statusMap.get('other') || 0 }
  ];

  const groups = store.listGroups();
  const accessKeys = store.listAccessKeys();
  const groupCount = groups.filter((item) => item.enabled).length;
  const accessKeyCount = accessKeys.filter((item) => item.enabled).length;
  const activeAccountCount = accounts.filter((item) => item.enabled).length;

  return {
    cards: {
      todayRequests: runtimeDailyStats.requestCount,
      todayInputTokens: runtimeDailyStats.inputTokens,
      todayOutputTokens: runtimeDailyStats.outputTokens,
      todayCachedTokens: runtimeDailyStats.cachedTokens,
      todayTotalTokens: runtimeDailyStats.totalTokens,
      todayCost: todayCostMajor,
      currency,
      successRate,
      avgLatencyMs,
      p95LatencyMs,
      groupCount,
      accessKeyCount,
      activeAccountCount
    },
    charts: {
      hourLabels: slots.map((slot) => slot.label),
      requestSeries: hourlySeries.map((item) => item.requests),
      inputTokenSeries: hourlySeries.map((item) => item.inputTokens),
      outputTokenSeries: hourlySeries.map((item) => item.outputTokens),
      cachedTokenSeries: hourlySeries.map((item) => item.cachedTokens),
      providerSeries,
      statusSeries,
      modelNames: modelTopList.map((item) => item.model),
      modelTokenSeries: modelTopList.map((item) => item.tokens)
    },
    topModels: modelTopList
  };
}

function loadAccountPageData() {
  cleanupStickyBindings();
  settings = store.getSettings();
  const groups = store.listGroups();
  const membershipsByAccount = new Map();
  for (const group of groups) {
    const members = store.listGroupMembers(group.id);
    for (const member of members) {
      const current = membershipsByAccount.get(member.accountId) || [];
      current.push({
        groupId: group.id,
        groupName: group.name,
        groupKey: group.groupKey,
        weight: member.weight
      });
      membershipsByAccount.set(member.accountId, current);
    }
  }

  const accounts = store.listAccounts().map((account) => {
    const modelQuotas = store.listModelQuotas(account.id).map((quota) => ({
      ...quota,
      resetAt: quotaResetAtFromRow(quota),
      windowDuration: splitDuration(quota.windowMs, 'hour', 5),
      costLimitMajor: formatMinor(quota.costLimitMinor, quota.currency),
      usedCostMajor: formatMinor(quota.usedCostMinor, quota.currency),
      hasCostLimit: quota.costLimitMinor > 0
    }));
    return {
      ...account,
      provider: account.provider || 'openai',
      providerLabel: (account.provider || 'openai') === 'anthropic' ? 'Claude' : 'OpenAI',
      memberships: membershipsByAccount.get(account.id) || [],
      maskedKey: maskKey(account.apiKey),
      quotaResetAt: quotaResetAt(account),
      quotaResetAt2: quotaResetAtSecondary(account),
      stickyMinutes: account.stickyWindowMs > 0 ? Math.floor(account.stickyWindowMs / 60000) : 0,
      quotaDuration: splitDuration(account.quotaWindowMs, 'hour', 5),
      quotaDuration2: splitDuration(account.quotaWindowMs2, 'week', 1),
      models: store.listAccountModels(account.id),
      modelQuotas
    };
  });
  return { accounts, settings, groups };
}

app.get('/admin', adminOnly, (req, res) => {
  return res.redirect('/admin/home');
});

app.get('/admin/home', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  const stats = buildAdminStats(accounts);
  const dashboard = buildAdminDashboardData(accounts);
  res.render('admin-home', {
    activePage: 'home',
    settings,
    stats,
    dashboard,
    notice: req.query.notice || ''
  });
});

app.get('/admin/accounts', adminOnly, (req, res) => {
  const { accounts, groups } = loadAccountPageData();
  res.render('admin-accounts', {
    activePage: 'accounts',
    accounts,
    groups,
    settings,
    stats: buildAdminStats(accounts),
    notice: req.query.notice || ''
  });
});

app.get('/admin/settings', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  const stickyDuration = splitDuration(settings.globalStickyWindowMs, 'hour', 6);
  const sessionDuration = splitDuration(settings.sessionTtlMs, 'day', 1);

  res.render('admin-settings', {
    activePage: 'settings',
    settings,
    stats: buildAdminStats(accounts),
    stickyDuration,
    sessionDuration,
    notice: req.query.notice || ''
  });
});

app.get('/admin/mappings', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  res.render('admin-mappings', {
    activePage: 'mappings',
    settings,
    mappings: store.listModelMappings(),
    stats: buildAdminStats(accounts),
    notice: req.query.notice || ''
  });
});

app.get('/admin/pricing', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  const provider = String(req.query.provider || 'openai').trim().toLowerCase() || 'openai';
  res.render('admin-pricing', {
    activePage: 'pricing',
    settings,
    provider,
    prices: store.listModelPrices(provider).slice(0, 500),
    stats: buildAdminStats(accounts),
    notice: req.query.notice || ''
  });
});

app.get('/admin/groups', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  const groups = store.listGroups().map((group) => ({
    ...group,
    members: store.listGroupMembers(group.id)
  }));
  res.render('admin-groups', {
    activePage: 'groups',
    settings,
    accounts,
    groups,
    stats: buildAdminStats(accounts),
    notice: req.query.notice || ''
  });
});

app.get('/admin/keys', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  const groups = store.listGroups().filter((group) => group.enabled);
  const accessKeys = store.listAccessKeys().map((item) => ({
    ...item,
    maskedToken: maskKey(item.token)
  }));
  res.render('admin-keys', {
    activePage: 'keys',
    settings,
    groups,
    accessKeys,
    stats: buildAdminStats(accounts),
    notice: req.query.notice || '',
    freshToken: req.query.freshToken || ''
  });
});

app.get('/admin/logs', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  res.render('admin-logs', {
    activePage: 'logs',
    settings,
    stats: buildAdminStats(accounts),
    logs: requestLogs.slice(-120).reverse(),
    notice: req.query.notice || ''
  });
});

app.get('/admin/cache', adminOnly, async (req, res) => {
  const { accounts } = loadAccountPageData();
  const groups = store.listGroups();
  const cacheGroups = groups.filter((group) => group.cacheEnabled === true);
  const runtimes = [];
  for (const group of cacheGroups) {
    // eslint-disable-next-line no-await-in-loop
    runtimes.push(await fetchPromptCacheGroupRuntime(group));
  }
  const totalHits = runtimes.reduce((sum, item) => sum + item.stats.hits, 0);
  const totalMisses = runtimes.reduce((sum, item) => sum + item.stats.misses, 0);
  const totalRequests = totalHits + totalMisses;
  const totalHitRate = totalRequests > 0 ? (totalHits / totalRequests) : 0;
  const cacheRuntimeCharts = {
    groupNames: runtimes.map((item) => item.groupName || item.groupKey || '-'),
    groupHitRates: runtimes.map((item) => Number(((item.stats.hitRate || 0) * 100).toFixed(2))),
    groupHits: runtimes.map((item) => Math.max(Number(item.stats.hits || 0), 0)),
    groupMisses: runtimes.map((item) => Math.max(Number(item.stats.misses || 0), 0)),
    healthSeries: [
      {
        name: '健康',
        value: runtimes.filter((item) => item.healthy).length
      },
      {
        name: '异常',
        value: runtimes.filter((item) => !item.healthy).length
      }
    ],
    requestSeries: [
      { name: '命中', value: totalHits },
      { name: '未命中', value: totalMisses }
    ]
  };
  res.render('admin-cache', {
    activePage: 'cache',
    settings,
    stats: buildAdminStats(accounts),
    notice: req.query.notice || '',
    runtimes,
    charts: cacheRuntimeCharts,
    summary: {
      enabledGroups: cacheGroups.length,
      totalHits,
      totalMisses,
      totalRequests,
      totalHitRate
    }
  });
});

app.get('/admin/risk-control', adminOnly, (req, res) => {
  const { accounts } = loadAccountPageData();
  const groups = store.listGroups();
  const riskCfg = riskControl.buildConfig();
  const summary = riskControl.getSummary();
  const logs = store.listRecentRiskControlLogs(160);
  const groupIdSet = new Set(groups.map((group) => String(group.id || '').trim()).filter(Boolean));
  const groupKeyToId = new Map(
    groups
      .map((group) => [String(group.groupKey || '').trim(), String(group.id || '').trim()])
      .filter(([groupKey, groupId]) => groupKey && groupId)
  );
  const selectedGroupIds = [];
  for (const raw of Array.from(riskCfg.groupIds || [])) {
    const value = String(raw || '').trim();
    if (!value) {
      continue;
    }
    if (groupIdSet.has(value)) {
      selectedGroupIds.push(value);
      continue;
    }
    const mappedId = groupKeyToId.get(value);
    if (mappedId) {
      selectedGroupIds.push(mappedId);
    }
  }
  res.render('admin-risk-control', {
    activePage: 'risk-control',
    settings,
    stats: buildAdminStats(accounts),
    notice: req.query.notice || '',
    groups,
    riskCfg,
    summary,
    logs,
    selectedGroupIds
  });
});

app.get('/admin/logs/stream', adminOnly, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  res.write(': connected\n\n');

  requestLogClients.add(res);
  const keepalive = setInterval(() => {
    res.write(': keepalive\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(keepalive);
    requestLogClients.delete(res);
  });
});

app.post('/admin/risk-control/settings', adminOnly, (req, res) => {
  const currentSettings = store.getSettings();
  const hasOwn = (key) => Object.prototype.hasOwnProperty.call(req.body || {}, key);
  const currentBool = (key, fallback = false) => {
    if (!Object.prototype.hasOwnProperty.call(currentSettings, key)) {
      return fallback;
    }
    return parseCheckboxLike(currentSettings[key]);
  };
  const pickCheckbox = (key, fallback = false) => {
    if (!hasOwn(key)) {
      return fallback;
    }
    return parseCheckboxLike(req.body[key]);
  };
  const pickWhenMissing = (key, fallback) => {
    if (!hasOwn(key)) {
      return String(fallback || '').trim();
    }
    return String(req.body[key] || '').trim();
  };
  const pickApiKey = (key, fallback) => {
    if (!hasOwn(key)) {
      return String(fallback || '').trim();
    }
    const value = String(req.body[key] || '').trim();
    return value || String(fallback || '').trim();
  };
  const pickNumberWhenMissing = (key, fallback) => {
    if (!hasOwn(key)) {
      return safeNumber(fallback, 0);
    }
    return safeNumber(req.body[key], safeNumber(fallback, 0));
  };

  const hasGroupSelectionField = hasOwn('riskControlGroupIds_present') || hasOwn('riskControlGroupIds');
  const shouldClearGroupSelection = parseCheckboxLike(req.body.riskControlGroupIdsClear);
  const selectedGroupIds = Array.isArray(req.body.riskControlGroupIds)
    ? req.body.riskControlGroupIds
    : (req.body.riskControlGroupIds ? [req.body.riskControlGroupIds] : []);
  const groups = store.listGroups();
  const groupIdSet = new Set(groups.map((group) => String(group.id || '').trim()).filter(Boolean));
  const groupKeyToId = new Map(
    groups
      .map((group) => [String(group.groupKey || '').trim(), String(group.id || '').trim()])
      .filter(([groupKey, groupId]) => groupKey && groupId)
  );
  const normalizedGroupIds = [...new Set(
    selectedGroupIds
      .map((item) => String(item || '').trim())
      .map((value) => {
        if (!value) {
          return '';
        }
        if (groupIdSet.has(value)) {
          return value;
        }
        return groupKeyToId.get(value) || '';
      })
      .filter(Boolean)
  )];

  const nextSettings = {
    riskControlEnabled: pickCheckbox('riskControlEnabled', currentBool('riskControlEnabled', false)) ? '1' : '0',
    riskControlMode: hasOwn('riskControlMode')
      ? normalizeRiskControlMode(req.body.riskControlMode)
      : normalizeRiskControlMode(currentSettings.riskControlMode),
    riskControlScopeMode: hasOwn('riskControlScopeMode')
      ? normalizeRiskControlScopeMode(req.body.riskControlScopeMode)
      : normalizeRiskControlScopeMode(currentSettings.riskControlScopeMode),
    riskControlGroupIds: shouldClearGroupSelection
      ? normalizedGroupIds.join(',')
      : (
        hasGroupSelectionField
          ? normalizedGroupIds.join(',')
          : String(currentSettings.riskControlGroupIds || '')
      ),
    riskControlSampleRate: String(Math.max(Math.min(Math.floor(pickNumberWhenMissing('riskControlSampleRate', currentSettings.riskControlSampleRate ?? 100)), 100), 0)),
    riskControlQueueSize: String(Math.max(Math.min(Math.floor(pickNumberWhenMissing('riskControlQueueSize', currentSettings.riskControlQueueSize ?? 2000)), 50000), 50)),
    riskControlWorkerConcurrency: String(Math.max(Math.min(Math.floor(pickNumberWhenMissing('riskControlWorkerConcurrency', currentSettings.riskControlWorkerConcurrency ?? 2)), 12), 1)),
    riskControlRetentionDays: String(Math.max(Math.min(Math.floor(pickNumberWhenMissing('riskControlRetentionDays', currentSettings.riskControlRetentionDays ?? 30)), 3650), 1)),
    riskControlBlockMessage: pickWhenMissing('riskControlBlockMessage', currentSettings.riskControlBlockMessage || '内容审查命中风险规则，请调整输入后重试') || '内容审查命中风险规则，请调整输入后重试',
    riskControlL1Enabled: pickCheckbox('riskControlL1Enabled', currentBool('riskControlL1Enabled', true)) ? '1' : '0',
    riskControlL1BaseUrl: pickWhenMissing('riskControlL1BaseUrl', currentSettings.riskControlL1BaseUrl || 'https://api.openai.com') || 'https://api.openai.com',
    riskControlL1ApiKey: pickApiKey('riskControlL1ApiKey', currentSettings.riskControlL1ApiKey || ''),
    riskControlL1Model: pickWhenMissing('riskControlL1Model', currentSettings.riskControlL1Model || 'omni-moderation-latest') || 'omni-moderation-latest',
    riskControlL1Threshold: String(Math.min(Math.max(pickNumberWhenMissing('riskControlL1Threshold', currentSettings.riskControlL1Threshold ?? 0.7), 0), 1)),
    riskControlL1TimeoutMs: String(Math.max(Math.min(Math.floor(pickNumberWhenMissing('riskControlL1TimeoutMs', currentSettings.riskControlL1TimeoutMs ?? 5000)), 30000), 500)),
    riskControlL2Enabled: pickCheckbox('riskControlL2Enabled', currentBool('riskControlL2Enabled', false)) ? '1' : '0',
    riskControlL2BaseUrl: pickWhenMissing('riskControlL2BaseUrl', currentSettings.riskControlL2BaseUrl || 'https://api.openai.com') || 'https://api.openai.com',
    riskControlL2ApiKey: pickApiKey('riskControlL2ApiKey', currentSettings.riskControlL2ApiKey || ''),
    riskControlL2Model: pickWhenMissing('riskControlL2Model', currentSettings.riskControlL2Model || 'gpt-4.1-mini') || 'gpt-4.1-mini',
    riskControlL2Prompt: pickWhenMissing('riskControlL2Prompt', currentSettings.riskControlL2Prompt || ''),
    riskControlL2Temperature: String(Math.min(Math.max(pickNumberWhenMissing('riskControlL2Temperature', currentSettings.riskControlL2Temperature ?? 0), 0), 2)),
    riskControlL2MaxTokens: String(Math.max(Math.min(Math.floor(pickNumberWhenMissing('riskControlL2MaxTokens', currentSettings.riskControlL2MaxTokens ?? 200)), 4096), 16)),
    riskControlL2TimeoutMs: String(Math.max(Math.min(Math.floor(pickNumberWhenMissing('riskControlL2TimeoutMs', currentSettings.riskControlL2TimeoutMs ?? 12000)), 60000), 500))
  };

  store.updateSettings(nextSettings);
  settings = store.getSettings();
  riskControl.trimHistoryIfNeeded();
  return adminNoticeRedirect(req, res, '审查网关设置已保存', '/admin/risk-control');
});

app.post('/admin/settings', adminOnly, (req, res) => {
  const stickyMs = parseDurationMs(req.body.globalStickyValue, req.body.globalStickyUnit);
  const sessionMs = parseDurationMs(req.body.sessionTtlValue, req.body.sessionTtlUnit);
  const defaultCurrency = String(req.body.defaultCurrency || '').trim().toUpperCase();

  const nextSettings = {};
  if (stickyMs > 0) {
    nextSettings.globalStickyWindowMs = stickyMs;
  }
  if (sessionMs > 0) {
    nextSettings.sessionTtlMs = sessionMs;
  }
  const nextBaseUrl = String(req.body.defaultBaseUrl || '').trim().replace(/\/$/, '');
  if (nextBaseUrl) {
    nextSettings.defaultBaseUrl = nextBaseUrl;
  }
  if (defaultCurrency) {
    nextSettings.defaultCurrency = defaultCurrency;
  }

  if (Object.keys(nextSettings).length > 0) {
    store.updateSettings(nextSettings);
    settings = store.getSettings();
  }
  return adminNoticeRedirect(req, res, 'Settings updated', '/admin/settings');
});

app.post('/admin/settings/password', adminOnly, (req, res) => {
  settings = store.getSettings();
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  const confirmPassword = String(req.body.confirmPassword || '');

  if (!verifyAdminPassword(currentPassword)) {
    return adminNoticeRedirect(req, res, 'Current password incorrect', '/admin/settings');
  }
  if (newPassword.length < 8) {
    return adminNoticeRedirect(req, res, 'New password must be at least 8 chars', '/admin/settings');
  }
  if (newPassword !== confirmPassword) {
    return adminNoticeRedirect(req, res, 'Password confirmation mismatch', '/admin/settings');
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = deriveAdminPasswordHash(newPassword, salt);
  store.updateSettings({
    adminPasswordSalt: salt,
    adminPasswordHash: hash
  });
  settings = store.getSettings();
  return adminNoticeRedirect(req, res, 'Admin password updated', '/admin/settings');
});

app.post('/admin/accounts', adminOnly, async (req, res) => {
  settings = store.getSettings();
  const payload = sanitizeAccountInput(req.body, settings.defaultBaseUrl);
  if (!payload.name || !payload.apiKey) {
    return adminNoticeRedirect(req, res, 'Name and API key required');
  }

  const accountId = crypto.randomUUID();
  store.createAccount({
    id: accountId,
    ...payload,
    stats: {
      windowStartMs: Date.now(),
      windowStartMs2: Date.now(),
      usedRequests: 0,
      usedRequests2: 0,
      totalRequests: 0,
      lastUsedAt: ''
    }
  });

  const customModels = parseModelNamesInput(req.body.customModels);
  for (const modelName of customModels) {
    store.addAccountModel(accountId, modelName, 'custom');
  }

  const shouldSyncModels = parseCheckboxLike(req.body.syncModelsAfterCreate);
  const groupId = String(req.body.groupId || '').trim();
  const groupWeight = Math.max(Math.floor(safeNumber(req.body.groupWeight, 1)), 1);
  if (groupId) {
    const group = store.getGroupById(groupId);
    if (group) {
      store.upsertGroupMember(group.id, accountId, groupWeight);
    }
  }
  if (shouldSyncModels) {
    try {
      await syncModelsFromUpstream({
        id: accountId,
        provider: payload.provider,
        apiKey: payload.apiKey,
        baseUrl: payload.baseUrl
      });
    } catch (error) {
      return adminNoticeRedirect(req, res, `Account created, model sync failed: ${error.message}`);
    }
  }
  return adminNoticeRedirect(req, res, 'Account created');
});

app.post('/admin/accounts/:id/update', adminOnly, (req, res) => {
  const existing = store.getAccountById(req.params.id);
  if (!existing) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  settings = store.getSettings();
  const payload = sanitizeAccountInput(req.body, settings.defaultBaseUrl);
  if (!payload.name) {
    return adminNoticeRedirect(req, res, 'Name required');
  }
  const keepApiKey = !String(payload.apiKey || '').trim();
  if (!keepApiKey && !payload.apiKey) {
    return adminNoticeRedirect(req, res, 'API key required');
  }
  store.updateAccount(req.params.id, payload, { keepApiKey });
  return adminNoticeRedirect(req, res, 'Account updated');
});

app.post('/admin/accounts/:id/reset', adminOnly, (req, res) => {
  const existing = store.getAccountById(req.params.id);
  if (!existing) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  store.resetAccountQuota(req.params.id, Date.now());
  return adminNoticeRedirect(req, res, 'Account quota reset');
});

app.post('/admin/accounts/:id/delete', adminOnly, (req, res) => {
  const existing = store.getAccountById(req.params.id);
  if (!existing) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  store.deleteAccount(req.params.id);
  store.clearStickyBindingsByAccount(req.params.id);
  return adminNoticeRedirect(req, res, 'Account deleted');
});

app.post('/admin/accounts/:id/copy', adminOnly, (req, res) => {
  const source = store.getAccountById(req.params.id);
  if (!source) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }

  const copyId = crypto.randomUUID();
  const copyName = `${source.name}-copy-${Date.now().toString().slice(-6)}`;
  store.createAccount({
    id: copyId,
    name: copyName,
    provider: source.provider || 'openai',
    forceResponsesCompat: source.forceResponsesCompat === true,
    apiKey: source.apiKey,
    baseUrl: source.baseUrl,
    enabled: source.enabled,
    weight: source.weight,
    quotaLimit: source.quotaLimit,
    quotaWindowMs: source.quotaWindowMs,
    quotaLimit2: source.quotaLimit2 || 0,
    quotaWindowMs2: source.quotaWindowMs2 || 0,
    stickyWindowMs: source.stickyWindowMs,
    stats: {
      windowStartMs: Date.now(),
      windowStartMs2: Date.now(),
      usedRequests: 0,
      usedRequests2: 0,
      totalRequests: 0,
      lastUsedAt: ''
    }
  });

  const sourceModels = store.listAccountModels(source.id);
  for (const item of sourceModels) {
    store.addAccountModel(copyId, item.modelName, item.source || 'custom');
  }

  const sourceQuotas = store.listModelQuotas(source.id);
  for (const quota of sourceQuotas) {
    store.upsertModelQuota(copyId, quota.modelName, {
      requestLimit: quota.requestLimit,
      tokenLimit: quota.tokenLimit,
      windowMs: quota.windowMs,
      costLimitMinor: quota.costLimitMinor,
      currency: quota.currency
    });
    store.resetModelQuotaUsage(copyId, quota.modelName, Date.now());
  }

  return adminNoticeRedirect(req, res, `Account copied: ${copyName}`);
});

app.post('/admin/accounts/:id/models/sync', adminOnly, async (req, res) => {
  const account = store.getAccountById(req.params.id);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  try {
    const count = await syncModelsFromUpstream(account);
    return adminNoticeRedirect(req, res, `Synced ${count} models for ${account.name}`);
  } catch (error) {
    return adminNoticeRedirect(req, res, `Model sync failed: ${error.message}`);
  }
});

app.post('/admin/accounts/:id/models/add', adminOnly, (req, res) => {
  const account = store.getAccountById(req.params.id);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  const modelName = String(req.body.modelName || '').trim();
  if (!modelName) {
    return adminNoticeRedirect(req, res, 'Model name required');
  }
  store.addAccountModel(account.id, modelName, 'custom');
  return adminNoticeRedirect(req, res, 'Custom model added');
});

app.post('/admin/accounts/:id/models/replace', adminOnly, (req, res) => {
  const account = store.getAccountById(req.params.id);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  const modelNames = parseModelNamesInput(req.body.modelNamesText);
  store.replaceAccountModels(account.id, modelNames, 'custom');
  return adminNoticeRedirect(req, res, `Model list saved (${modelNames.length})`);
});

app.post('/admin/accounts/:id/models/delete', adminOnly, (req, res) => {
  const account = store.getAccountById(req.params.id);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  const modelName = String(req.body.modelName || '').trim();
  if (!modelName) {
    return adminNoticeRedirect(req, res, 'Model name required');
  }
  store.removeAccountModel(account.id, modelName);
  return adminNoticeRedirect(req, res, 'Model removed');
});

app.post('/admin/accounts/:id/quotas/upsert', adminOnly, (req, res) => {
  const account = store.getAccountById(req.params.id);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }

  settings = store.getSettings();
  const modelName = String(req.body.modelName || '').trim();
  const requestLimit = Math.max(Math.floor(safeNumber(req.body.requestLimit, 0)), 0);
  const tokenLimit = Math.max(Math.floor(safeNumber(req.body.tokenLimit, 0)), 0);
  const windowMs = parseDurationMs(req.body.windowValue, req.body.windowUnit);
  const currency = String(req.body.currency || settings.defaultCurrency || 'USD').trim().toUpperCase();
  const costLimitMinor = parseCostLimitMinor(req.body.costLimit, currency);

  if (!modelName) {
    return adminNoticeRedirect(req, res, 'Model name required for quota');
  }

  store.upsertModelQuota(account.id, modelName, {
    requestLimit,
    tokenLimit,
    windowMs,
    costLimitMinor,
    currency
  });

  return adminNoticeRedirect(req, res, 'Model quota saved');
});

app.post('/admin/accounts/:id/quotas/delete', adminOnly, (req, res) => {
  const account = store.getAccountById(req.params.id);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  const modelName = String(req.body.modelName || '').trim();
  if (!modelName) {
    return adminNoticeRedirect(req, res, 'Model name required');
  }
  store.deleteModelQuota(account.id, modelName);
  return adminNoticeRedirect(req, res, 'Model quota deleted');
});

app.post('/admin/accounts/:id/quotas/reset', adminOnly, (req, res) => {
  const account = store.getAccountById(req.params.id);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found');
  }
  const modelName = String(req.body.modelName || '').trim();
  if (!modelName) {
    return adminNoticeRedirect(req, res, 'Model name required');
  }
  store.resetModelQuotaUsage(account.id, modelName, Date.now());
  return adminNoticeRedirect(req, res, 'Model quota usage reset');
});

app.post('/admin/mappings/upsert', adminOnly, (req, res) => {
  const sourceModel = String(req.body.sourceModel || '').trim();
  const targetModel = String(req.body.targetModel || '').trim();
  if (!sourceModel || !targetModel) {
    return adminNoticeRedirect(req, res, 'Source and target model required', '/admin/mappings');
  }
  store.upsertModelMapping(sourceModel, targetModel, true);
  return adminNoticeRedirect(req, res, 'Model mapping saved', '/admin/mappings');
});

app.post('/admin/mappings/delete', adminOnly, (req, res) => {
  const sourceModel = String(req.body.sourceModel || '').trim();
  if (!sourceModel) {
    return adminNoticeRedirect(req, res, 'Source model required', '/admin/mappings');
  }
  store.deleteModelMapping(sourceModel);
  return adminNoticeRedirect(req, res, 'Model mapping deleted', '/admin/mappings');
});

app.post('/admin/prices/sync', adminOnly, async (req, res) => {
  const provider = String(req.body.provider || 'openai').trim().toLowerCase() || 'openai';
  const currency = String(req.body.currency || 'USD').trim().toUpperCase();
  try {
    const count = await syncModelPricesFromModelsDev(provider, currency);
    return adminNoticeRedirect(req, res, `Synced ${count} prices from models.dev`, `/admin/pricing?provider=${encodeURIComponent(provider)}`);
  } catch (error) {
    return adminNoticeRedirect(req, res, `Price sync failed: ${error.message}`, `/admin/pricing?provider=${encodeURIComponent(provider)}`);
  }
});

app.post('/admin/prices/upsert', adminOnly, (req, res) => {
  settings = store.getSettings();
  const provider = String(req.body.provider || 'openai').trim().toLowerCase() || 'openai';
  const modelName = String(req.body.modelName || '').trim();
  const currency = String(req.body.currency || settings.defaultCurrency || 'USD').trim().toUpperCase() || 'USD';
  if (!modelName) {
    return adminNoticeRedirect(req, res, 'Model name required', `/admin/pricing?provider=${encodeURIComponent(provider)}`);
  }
  const inputPerMillion = parseOptionalRate(req.body.inputPerMillion);
  const outputPerMillion = parseOptionalRate(req.body.outputPerMillion);
  const cacheReadPerMillion = parseOptionalRate(req.body.cacheReadPerMillion);
  const cacheWritePerMillion = parseOptionalRate(req.body.cacheWritePerMillion);
  store.upsertModelPrices(provider, [{
    modelName,
    inputPerMillion,
    outputPerMillion,
    cacheReadPerMillion,
    cacheWritePerMillion
  }], currency);
  return adminNoticeRedirect(req, res, `Price saved: ${provider}/${modelName}`, `/admin/pricing?provider=${encodeURIComponent(provider)}`);
});

app.post('/admin/prices/delete', adminOnly, (req, res) => {
  const provider = String(req.body.provider || 'openai').trim().toLowerCase() || 'openai';
  const modelName = String(req.body.modelName || '').trim();
  if (!modelName) {
    return adminNoticeRedirect(req, res, 'Model name required', `/admin/pricing?provider=${encodeURIComponent(provider)}`);
  }
  store.deleteModelPrice(provider, modelName);
  return adminNoticeRedirect(req, res, `Price deleted: ${provider}/${modelName}`, `/admin/pricing?provider=${encodeURIComponent(provider)}`);
});

app.post('/admin/groups', adminOnly, (req, res) => {
  const name = String(req.body.name || '').trim();
  const groupKey = String(req.body.groupKey || '').trim();
  const description = String(req.body.description || '').trim();
  const cacheEnabled = parseCheckboxLike(req.body.cacheEnabled);
  const cacheBaseUrl = normalizeServiceBaseUrl(req.body.cacheBaseUrl || '');
  const cacheAuthToken = String(req.body.cacheAuthToken || '').trim();
  if (!name || !groupKey) {
    return adminNoticeRedirect(req, res, 'Group name and group key required', '/admin/groups');
  }
  if (store.getGroupByKey(groupKey)) {
    return adminNoticeRedirect(req, res, 'Group key already exists', '/admin/groups');
  }
  if (cacheEnabled && !cacheBaseUrl) {
    return adminNoticeRedirect(req, res, 'Cache enabled but cache base URL is invalid', '/admin/groups');
  }
  store.createGroup({
    id: crypto.randomUUID(),
    name,
    groupKey,
    description,
    cacheEnabled,
    cacheBaseUrl,
    cacheAuthToken,
    enabled: parseCheckboxLike(req.body.enabled),
    createdAt: new Date().toISOString()
  });
  return adminNoticeRedirect(req, res, 'Group created', '/admin/groups');
});

app.post('/admin/groups/:id/update', adminOnly, (req, res) => {
  const group = store.getGroupById(req.params.id);
  if (!group) {
    return adminNoticeRedirect(req, res, 'Group not found', '/admin/groups');
  }
  const name = String(req.body.name || '').trim();
  const groupKey = String(req.body.groupKey || '').trim();
  const description = String(req.body.description || '').trim();
  const cacheEnabled = parseCheckboxLike(req.body.cacheEnabled);
  const cacheBaseUrl = normalizeServiceBaseUrl(req.body.cacheBaseUrl || '');
  const cacheAuthToken = String(req.body.cacheAuthToken || '').trim();
  if (!name || !groupKey) {
    return adminNoticeRedirect(req, res, 'Group name and group key required', '/admin/groups');
  }
  const keyOwner = store.getGroupByKey(groupKey);
  if (keyOwner && keyOwner.id !== group.id) {
    return adminNoticeRedirect(req, res, 'Group key already exists', '/admin/groups');
  }
  if (cacheEnabled && !cacheBaseUrl) {
    return adminNoticeRedirect(req, res, 'Cache enabled but cache base URL is invalid', '/admin/groups');
  }
  store.updateGroup(group.id, {
    name,
    groupKey,
    description,
    cacheEnabled,
    cacheBaseUrl,
    cacheAuthToken,
    enabled: parseCheckboxLike(req.body.enabled)
  });
  return adminNoticeRedirect(req, res, 'Group updated', '/admin/groups');
});

app.post('/admin/groups/:id/delete', adminOnly, (req, res) => {
  const group = store.getGroupById(req.params.id);
  if (!group) {
    return adminNoticeRedirect(req, res, 'Group not found', '/admin/groups');
  }
  store.deleteGroup(group.id);
  return adminNoticeRedirect(req, res, 'Group deleted', '/admin/groups');
});

app.post('/admin/groups/:id/members/upsert', adminOnly, (req, res) => {
  const group = store.getGroupById(req.params.id);
  if (!group) {
    return adminNoticeRedirect(req, res, 'Group not found', '/admin/groups');
  }
  const accountId = String(req.body.accountId || '').trim();
  const account = store.getAccountById(accountId);
  if (!account) {
    return adminNoticeRedirect(req, res, 'Account not found', '/admin/groups');
  }
  const weight = Math.max(Math.floor(safeNumber(req.body.weight, 1)), 1);
  store.upsertGroupMember(group.id, account.id, weight);
  return adminNoticeRedirect(req, res, 'Group member saved', '/admin/groups');
});

app.post('/admin/groups/:id/members/delete', adminOnly, (req, res) => {
  const group = store.getGroupById(req.params.id);
  if (!group) {
    return adminNoticeRedirect(req, res, 'Group not found', '/admin/groups');
  }
  const accountId = String(req.body.accountId || '').trim();
  if (!accountId) {
    return adminNoticeRedirect(req, res, 'Account required', '/admin/groups');
  }
  store.removeGroupMember(group.id, accountId);
  return adminNoticeRedirect(req, res, 'Group member removed', '/admin/groups');
});

app.post('/admin/keys', adminOnly, (req, res) => {
  const name = String(req.body.name || '').trim();
  const groupId = String(req.body.groupId || '').trim();
  if (!name) {
    return adminNoticeRedirect(req, res, 'Key name required', '/admin/keys');
  }
  if (groupId) {
    const group = store.getGroupById(groupId);
    if (!group) {
      return adminNoticeRedirect(req, res, 'Group not found', '/admin/keys');
    }
  }
  const token = generateAccessToken();
  store.createAccessKey({
    id: crypto.randomUUID(),
    name,
    token,
    groupId: groupId || null,
    enabled: true,
    createdAt: new Date().toISOString()
  });
  return res.redirect(`/admin/keys?notice=${encodeURIComponent('Access key created')}&freshToken=${encodeURIComponent(token)}`);
});

app.post('/admin/keys/:id/update', adminOnly, (req, res) => {
  const keys = store.listAccessKeys();
  const key = keys.find((item) => item.id === req.params.id);
  if (!key) {
    return adminNoticeRedirect(req, res, 'Access key not found', '/admin/keys');
  }
  const name = String(req.body.name || '').trim();
  const groupId = String(req.body.groupId || '').trim();
  if (!name) {
    return adminNoticeRedirect(req, res, 'Key name required', '/admin/keys');
  }
  if (groupId) {
    const group = store.getGroupById(groupId);
    if (!group) {
      return adminNoticeRedirect(req, res, 'Group not found', '/admin/keys');
    }
  }
  store.updateAccessKey(key.id, {
    name,
    groupId: groupId || null,
    enabled: parseCheckboxLike(req.body.enabled)
  });
  return adminNoticeRedirect(req, res, 'Access key updated', '/admin/keys');
});

app.post('/admin/keys/:id/delete', adminOnly, (req, res) => {
  store.deleteAccessKey(req.params.id);
  return adminNoticeRedirect(req, res, 'Access key deleted', '/admin/keys');
});

app.use('/v1', express.raw({ type: '*/*', limit: '20mb' }));

app.all('/v1/*', async (req, res) => {
  const startedAtMs = Date.now();
  const shouldLogRequest = shouldLogGatewayRequest(req);
  const logState = {
    provider: '',
    accountName: '',
    model: '',
    mappedModel: '',
    groupKey: '',
    accessKeyId: ''
  };
  let logWritten = false;
  const logCurrency = String(settings.defaultCurrency || 'USD').toUpperCase();
  const writeRequestLog = ({
    statusCode,
    tokens = 0,
    inputTokens = 0,
    outputTokens = 0,
    cachedTokens = 0,
    costMinor = 0,
    errorDetail = '',
    compatUnsupported = '',
    attempts = 1,
    switches = 0,
    retryReason = '',
    stickyHit = false
  }) => {
    if (!shouldLogRequest) {
      return;
    }
    if (logWritten) {
      return;
    }
    logWritten = true;
    publishRequestLog({
      id: `${Date.now()}-${(++requestLogSeq).toString(36)}-${crypto.randomBytes(3).toString('hex')}`,
      at: new Date().toISOString(),
      method: req.method,
      path: req.path,
      endpoint: `${req.method} ${req.originalUrl || req.path}`,
      provider: logState.provider || 'unknown',
      account: logState.accountName || '-',
      model: logState.mappedModel || logState.model || '-',
      requestModel: logState.model || '-',
      groupKey: logState.groupKey || '-',
      accessKeyId: logState.accessKeyId || '-',
      statusCode: Number(statusCode) || 0,
      tokens: Math.max(Number(tokens) || 0, 0),
      inputTokens: Math.max(Number(inputTokens) || 0, 0),
      outputTokens: Math.max(Number(outputTokens) || 0, 0),
      cachedTokens: Math.max(Number(cachedTokens) || 0, 0),
      costMinor: Math.max(Number(costMinor) || 0, 0),
      currency: logCurrency,
      durationMs: Math.max(Date.now() - startedAtMs, 0),
      error: sanitizeLogText(errorDetail),
      compatUnsupported: sanitizeLogText(compatUnsupported, 240),
      attempts: Math.max(Number(attempts) || 1, 1),
      switches: Math.max(Number(switches) || 0, 0),
      retryReason: sanitizeLogText(retryReason, 180),
      stickyHit: stickyHit === true
    });
  };

  const authResult = checkGatewayAuth(req, res);
  if (!authResult.ok) {
    writeRequestLog({
      statusCode: res.statusCode || 401,
      errorDetail: authResult.error || 'Unauthorized gateway token'
    });
    return;
  }
  settings = store.getSettings();

  const isResponsesPath = req.path === '/v1/responses' || req.path.startsWith('/v1/responses/');
  const isResponsesCreate = req.method === 'POST' && req.path === '/v1/responses';
  const isResponsesCompact = req.method === 'POST' && req.path === '/v1/responses/compact';
  const isChatCompletionsCreate = req.method === 'POST' && req.path === '/v1/chat/completions';
  const isResponsesSessionRequest = isResponsesCreate || isResponsesCompact;
  const isAnthropicMessagesCreate = req.method === 'POST' && req.path === '/v1/messages';
  const isAnthropicCountTokens = req.method === 'POST' && req.path === '/v1/messages/count_tokens';
  const rawBuffer = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const contentTypeHeader = String(req.headers['content-type'] || '').toLowerCase();
  const shouldParseRequestJson = (
    rawBuffer.length > 0 &&
    (
      contentTypeHeader.includes('application/json') ||
      contentTypeHeader.includes('+json') ||
      isResponsesCreate ||
      isResponsesCompact ||
      isAnthropicMessagesCreate ||
      isAnthropicCountTokens
    )
  );
  const rawText = shouldParseRequestJson ? rawBuffer.toString('utf8') : '';
  const jsonBody = shouldParseRequestJson ? safeJsonParse(rawText) : null;
  const isBillableRequest = isResponsesSessionRequest || isAnthropicMessagesCreate;
  const hasAnthropicHint = (
    String(req.headers['anthropic-version'] || '').trim() !== '' ||
    String(req.headers['anthropic-beta'] || '').trim() !== '' ||
    String(req.headers['user-agent'] || '').toLowerCase().includes('claude')
  );
  const isAnthropicStyleRequest = req.path.startsWith('/v1/messages') || (req.path === '/v1/models' && hasAnthropicHint);
  const requestProvider = isResponsesPath
    ? 'openai'
    : (isAnthropicMessagesCreate || isAnthropicCountTokens || isAnthropicStyleRequest ? 'anthropic' : '');
  const requestedStream = isStreamingRequest({
    supportsStreamField: isResponsesCreate || isAnthropicMessagesCreate,
    jsonBody,
    req
  });
  const requestGroupKey = authResult.groupKey || '';
  logState.provider = requestProvider || 'openai';
  logState.groupKey = requestGroupKey;
  logState.accessKeyId = authResult.accessKeyId || '';

  let requestModel = '';
  let upstreamModel = '';
  let bodyChanged = false;
  const hasModelField = (
    (isResponsesSessionRequest || isChatCompletionsCreate || isAnthropicMessagesCreate || isAnthropicCountTokens) &&
    jsonBody &&
    typeof jsonBody === 'object'
  );
  if (hasModelField) {
    requestModel = String(jsonBody.model || '').trim();
    upstreamModel = requestModel ? store.resolveMappedModel(requestModel) : '';
    if (upstreamModel && upstreamModel !== requestModel) {
      jsonBody.model = upstreamModel;
      bodyChanged = true;
    }
    if (isResponsesCreate && Object.prototype.hasOwnProperty.call(jsonBody, 'group_key')) {
      delete jsonBody.group_key;
      bodyChanged = true;
    }
  }
  logState.model = requestModel;
  logState.mappedModel = upstreamModel;

  let outgoingBody = rawBuffer;
  if (isChatCompletionsCreate && jsonBody && typeof jsonBody === 'object' && jsonBody.stream === true) {
    const streamOptions = (
      jsonBody.stream_options && typeof jsonBody.stream_options === 'object'
        ? { ...jsonBody.stream_options }
        : {}
    );
    if (!Object.prototype.hasOwnProperty.call(streamOptions, 'include_usage')) {
      streamOptions.include_usage = true;
      jsonBody.stream_options = streamOptions;
      bodyChanged = true;
    }
  }
  if (hasModelField && bodyChanged) {
    outgoingBody = Buffer.from(JSON.stringify(jsonBody), 'utf8');
  }
  const responsesCompatSourceBody = jsonBody;
  const responsesCompatChatBody = isResponsesSessionRequest ? convertResponsesRequestToChatRequest(responsesCompatSourceBody) : null;
  const responsesCompatUnsupportedFields = isResponsesSessionRequest
    ? detectResponsesCompatUnsupportedFields(jsonBody)
    : [];
  const responsesCompatReasoningSummaryMode = isResponsesSessionRequest
    ? wantsResponsesReasoningSummary(jsonBody)
    : '';

  const promptCacheConfig = getPromptCacheConfigForGroupKey(requestGroupKey);
  const canUsePromptCache = Boolean(promptCacheConfig && isPromptCacheCandidateRequest(req));
  let promptCacheBypassReason = '';
  if (canUsePromptCache) {
    let cacheChatBody = null;
    let cacheResponseMode = '';
    if (isChatCompletionsCreate) {
      cacheChatBody = jsonBody && typeof jsonBody === 'object' ? cloneJsonLike(jsonBody, null) : null;
      cacheResponseMode = 'chat';
    } else if (isResponsesSessionRequest) {
      cacheChatBody = responsesCompatChatBody ? cloneJsonLike(responsesCompatChatBody, null) : null;
      cacheResponseMode = isResponsesCompact ? 'responses_compact' : 'responses';
    } else if (isAnthropicMessagesCreate) {
      cacheChatBody = convertAnthropicMessagesRequestToChatRequest(jsonBody);
      cacheResponseMode = 'anthropic';
    }

    if (cacheChatBody && cacheChatBody.model) {
      if (upstreamModel && upstreamModel !== cacheChatBody.model) {
        cacheChatBody.model = upstreamModel;
      }
      const promptCacheTargetUrl = getPromptCacheTargetUrl(promptCacheConfig.baseUrl);
      const promptCacheHeaders = {
        accept: requestedStream ? 'text/event-stream' : 'application/json',
        'accept-encoding': 'identity',
        'content-type': 'application/json',
        'user-agent': 'responses-gateway/1.0 (+prompt-cache)'
      };
      if (promptCacheConfig.authToken) {
        promptCacheHeaders.authorization = `Bearer ${promptCacheConfig.authToken}`;
      }
      const promptCacheBodyBuffer = Buffer.from(JSON.stringify(cacheChatBody), 'utf8');
      try {
        let cacheUpstream = await fetch(promptCacheTargetUrl, {
          method: 'POST',
          headers: promptCacheHeaders,
          body: promptCacheBodyBuffer,
          duplex: 'half',
          redirect: 'manual'
        });

        logState.provider = 'promptcache';
        logState.accountName = `promptcache:${promptCacheConfig.groupName}`;

        res.status(cacheUpstream.status);
        cacheUpstream.headers.forEach((value, key) => {
          const lower = key.toLowerCase();
          if (
            lower === 'transfer-encoding' ||
            lower === 'content-encoding' ||
            lower === 'content-length' ||
            lower === 'connection' ||
            lower === 'keep-alive'
          ) {
            return;
          }
          res.setHeader(key, value);
        });
        res.setHeader('x-gateway-cache-proxy', 'promptcache');
        res.setHeader('x-gateway-account', `promptcache:${promptCacheConfig.groupName}`);
        res.setHeader('x-gateway-sticky-hit', 'false');
        if (requestModel && upstreamModel && requestModel !== upstreamModel) {
          res.setHeader('x-gateway-model-mapped', `${requestModel}->${upstreamModel}`);
        }

        const contentType = String(cacheUpstream.headers.get('content-type') || '').toLowerCase();
        const streamLikeContentType = (
          contentType.includes('text/event-stream') ||
          contentType.includes('application/x-ndjson') ||
          contentType.includes('application/stream+json')
        );
        const shouldPipeStream = streamLikeContentType || (requestedStream && cacheUpstream.ok);

        if (!shouldPipeStream) {
          const responseBuffer = Buffer.from(await cacheUpstream.arrayBuffer());
          const responseText = responseBuffer.toString('utf8');
          const payload = safeJsonParse(responseText);
          const usage = payload ? extractUsageFromPayload(payload) : null;
          const outputTokens = usage?.output || 0;
          const inputTokens = usage?.input || 0;
          const cachedTokens = usage?.cached || 0;
          const totalTokens = usage?.total || (inputTokens + outputTokens);

          let outgoingResponseBuffer = responseBuffer;
          if (cacheUpstream.ok && payload && typeof payload === 'object') {
            if (cacheResponseMode === 'responses') {
              const compatPayload = convertChatCompletionToResponsesPayload(payload, {
                includeReasoningSummary: Boolean(responsesCompatReasoningSummaryMode)
              });
              outgoingResponseBuffer = Buffer.from(JSON.stringify(compatPayload), 'utf8');
              res.setHeader('content-type', 'application/json; charset=utf-8');
            } else if (cacheResponseMode === 'responses_compact') {
              const compatPayload = convertChatCompletionToResponsesPayload(payload, {
                includeReasoningSummary: Boolean(responsesCompatReasoningSummaryMode)
              });
              outgoingResponseBuffer = Buffer.from(JSON.stringify({ output: compatPayload.output || [] }), 'utf8');
              res.setHeader('content-type', 'application/json; charset=utf-8');
            } else if (cacheResponseMode === 'anthropic') {
              const anthropicPayload = convertChatCompletionToAnthropicResponsePayload(payload, requestModel || upstreamModel || '');
              outgoingResponseBuffer = Buffer.from(JSON.stringify(anthropicPayload), 'utf8');
              res.setHeader('content-type', 'application/json; charset=utf-8');
            }
          }
          writeRequestLog({
            statusCode: cacheUpstream.status,
            tokens: totalTokens,
            inputTokens,
            outputTokens,
            cachedTokens,
            costMinor: 0,
            errorDetail: cacheUpstream.ok ? '' : extractErrorDetail(payload, responseText)
          });
          res.setHeader('content-length', String(outgoingResponseBuffer.byteLength));
          res.end(outgoingResponseBuffer);
          return;
        }

        if (!cacheUpstream.body) {
          writeRequestLog({
            statusCode: cacheUpstream.status,
            errorDetail: `PromptCache returned empty body (${cacheUpstream.status})`
          });
          res.end();
          return;
        }

        const sourceStream = Readable.fromWeb(cacheUpstream.body);
        let outgoingStream = sourceStream;
        if (cacheResponseMode === 'responses') {
          const compatResponseId = generateCompatResponseId();
          const compatTransform = createChatCompletionsToResponsesSseTransform({
            responseId: compatResponseId,
            model: upstreamModel || requestModel || '',
            includeReasoningSummary: Boolean(responsesCompatReasoningSummaryMode)
          });
          res.setHeader('content-type', 'text/event-stream; charset=utf-8');
          res.setHeader('cache-control', 'no-cache, no-transform');
          outgoingStream = sourceStream.pipe(compatTransform.transformer);
        } else if (cacheResponseMode === 'responses_compact') {
          const compatResponseId = generateCompatResponseId();
          const compatTransform = createChatCompletionsToResponsesSseTransform({
            responseId: compatResponseId,
            model: upstreamModel || requestModel || '',
            includeReasoningSummary: Boolean(responsesCompatReasoningSummaryMode)
          });
          res.setHeader('content-type', 'text/event-stream; charset=utf-8');
          res.setHeader('cache-control', 'no-cache, no-transform');
          outgoingStream = sourceStream.pipe(compatTransform.transformer);
        } else if (cacheResponseMode === 'anthropic') {
          const anthropicTransform = createChatCompletionsToAnthropicSseTransform({
            messageId: `msg_${crypto.randomUUID()}`,
            model: requestModel || upstreamModel || ''
          });
          res.setHeader('content-type', 'text/event-stream; charset=utf-8');
          res.setHeader('cache-control', 'no-cache, no-transform');
          outgoingStream = sourceStream.pipe(anthropicTransform.transformer);
        }

        let streamUsage = null;
        let streamErrorDetail = '';
        let usageFlushed = false;
        const usageObserver = createStreamUsageObserver(
          String(res.getHeader('content-type') || cacheUpstream.headers.get('content-type') || '').toLowerCase(),
          {
            onPayload: (payload) => {
              if (!streamErrorDetail && payload && typeof payload === 'object') {
                streamErrorDetail = extractErrorDetail(payload, '');
              }
            },
            onUsage: (usage) => {
              if (!usage) {
                return;
              }
              if (!streamUsage || usage.total >= streamUsage.total) {
                streamUsage = usage;
              }
            }
          }
        );
        const flushStreamUsage = () => {
          if (usageFlushed) {
            return;
          }
          usageFlushed = true;
          writeRequestLog({
            statusCode: cacheUpstream.status,
            tokens: streamUsage?.total || 0,
            inputTokens: streamUsage?.input || 0,
            outputTokens: streamUsage?.output || 0,
            cachedTokens: streamUsage?.cached || 0,
            costMinor: 0,
            errorDetail: cacheUpstream.ok ? '' : streamErrorDetail
          });
        };
        usageObserver.on('end', flushStreamUsage);
        res.once('finish', flushStreamUsage);
        res.flushHeaders();
        outgoingStream.pipe(usageObserver).pipe(res);
        return;
      } catch (error) {
        promptCacheBypassReason = sanitizeLogText(
          `PromptCache bypass: ${error?.message || 'unknown error'}`,
          220
        );
      }
    }
  }

  let stickyKey = '';
  let stickySeed = crypto.randomUUID();
  if ((isResponsesSessionRequest || isAnthropicMessagesCreate) && jsonBody && typeof jsonBody === 'object') {
    const sessionRoutingId = extractSessionRoutingId(req, jsonBody);
    const previousResponseId = isResponsesSessionRequest ? extractPreviousResponseId(jsonBody) : '';
    if (isResponsesSessionRequest) {
      const codexTurnState = extractCodexTurnState(req, jsonBody);
      const codexTurnStickyKey = buildCodexTurnStateStickyKey({
        provider: requestProvider || 'openai',
        model: requestModel || upstreamModel || '',
        turnState: codexTurnState
      });
      const previousResponseStickyKey = buildResponseContinuationStickyKey(previousResponseId);
      const promptCacheKey = extractPromptCacheKey(jsonBody);
      const promptCacheStickyKey = buildPromptCacheStickyKey({
        provider: requestProvider || 'openai',
        model: requestModel || upstreamModel || '',
        promptCacheKey
      });
      const codexAffinityStickyKey = (!codexTurnStickyKey && !sessionRoutingId && !promptCacheStickyKey && isLikelyCodexRequest(req, jsonBody))
        ? buildCodexAffinityStickyKey({
          provider: requestProvider || 'openai',
          model: requestModel || upstreamModel || '',
          accessKeyId: authResult.accessKeyId || '',
          req,
          jsonBody
        })
        : '';
      stickyKey = codexTurnStickyKey
        ? codexTurnStickyKey
        : (previousResponseStickyKey
          ? previousResponseStickyKey
          : (sessionRoutingId
            ? `session:${requestProvider || 'openai'}:${sessionRoutingId}`
            : (promptCacheStickyKey || codexAffinityStickyKey || buildStickyKey(req.method, req.path, buildDeterministicRoutingBody(jsonBody), req.query))));
    } else if (sessionRoutingId) {
      stickyKey = `session:${requestProvider || 'anthropic'}:${sessionRoutingId}`;
    }
    const bucketMs = Math.max(settings.globalStickyWindowMs || 0, 60 * 1000);
    const bucket = Math.floor(Date.now() / bucketMs);
    stickySeed = stickyKey ? `${stickyKey}:${bucket}` : crypto.randomUUID();
  }

  let selection = selectAccount({
    stickyKey,
    seed: stickySeed,
    requestModel: requestModel || upstreamModel || '',
    upstreamModel: upstreamModel || requestModel || '',
    requestProvider,
    groupKey: requestGroupKey,
    reserveQuota: isBillableRequest,
    enforceQuota: isBillableRequest
  });
  if (selection.error || !selection.account) {
    writeRequestLog({
      statusCode: 429,
      errorDetail: (
        promptCacheBypassReason
          ? `${selection.error || 'No account available'} | ${promptCacheBypassReason}`
          : (selection.error || 'No account available')
      )
    });
    res.status(429).json({ error: selection.error || 'No account available' });
    return;
  }

  let account = selection.account;
  const quotaModel = requestModel || upstreamModel || '';
  const maxAttemptCount = 3;
  let attemptCount = 1;
  let switchCount = 0;
  let lastRetryReason = promptCacheBypassReason;
  let activeCompatUnsupportedFields = [];
  const excludedAccounts = new Set();
  const writeAttemptLog = (payload) => {
    const compatUnsupported = activeCompatUnsupportedFields.length
      ? activeCompatUnsupportedFields.join(',')
      : '';
    writeRequestLog({
      ...payload,
      compatUnsupported,
      attempts: attemptCount,
      switches: switchCount,
      retryReason: lastRetryReason,
      stickyHit: selection?.stickyHit === true
    });
  };

  const releaseReservation = (currentSelection = selection, currentAccount = account) => {
    if (currentSelection?.reservation?.modelName) {
      store.releaseModelQuotaReservation(currentAccount.id, currentSelection.reservation.modelName);
    }
    if (currentSelection?.reservation?.accountSnapshot) {
      releaseAccountQuotaReservation(currentAccount, currentSelection.reservation.accountSnapshot);
    }
  };
  logState.accountName = account.name;
  const shouldForceResponsesCompat = (selectedAccount) => {
    if (!isResponsesSessionRequest) {
      return false;
    }
    if (normalizeProviderName(selectedAccount.provider) !== 'openai') {
      return false;
    }
    return selectedAccount.forceResponsesCompat === true;
  };
	  const resolveRequestForAccount = (selectedAccount) => {
	    const forceCompat = shouldForceResponsesCompat(selectedAccount);
	    if (!forceCompat) {
	      return {
	        targetUrl: buildUpstreamUrl(selectedAccount.baseUrl, req.originalUrl),
	        body: outgoingBody,
	        forceCompat: false,
	        compatUnsupportedFields: [],
	        compatReasoningSummaryMode: ''
	      };
	    }
	    if (!responsesCompatChatBody) {
	      throw new Error('Responses compatibility mode requires valid JSON request body');
	    }
    if (responsesCompatStrictUnsupported && responsesCompatUnsupportedFields.length) {
      throw new Error(`Responses compatibility mode unsupported fields: ${responsesCompatUnsupportedFields.join(', ')}`);
    }
    const compatBody = { ...responsesCompatChatBody };
    if (isResponsesCompact) {
      compatBody.stream = false;
      if (Object.prototype.hasOwnProperty.call(compatBody, 'stream_options')) {
        delete compatBody.stream_options;
      }
	    }
	    const compatBodyBuffer = Buffer.from(JSON.stringify(compatBody), 'utf8');
	    return {
	      targetUrl: buildResponsesCompatTargetUrl(selectedAccount.baseUrl, req.originalUrl),
	      body: compatBodyBuffer,
	      forceCompat: true,
	      compatUnsupportedFields: [...responsesCompatUnsupportedFields],
	      compatReasoningSummaryMode: responsesCompatReasoningSummaryMode
	    };
	  };
  const bindRequestSticky = () => {
    if (!stickyKey) {
      return;
    }
    const stickyMs = accountWindowMs(account, settings.globalStickyWindowMs);
    store.setStickyBinding(stickyKey, account.id, Date.now() + Math.max(stickyMs, 60 * 1000));
  };

  const bindResponseSticky = (responseId) => {
    if (!isResponsesSessionRequest || !responseId) {
      return;
    }
    const stickyMs = accountWindowMs(account, settings.globalStickyWindowMs);
    bindResponseContinuationSticky(account, responseId, stickyMs);
  };

  if (jsonBody && typeof jsonBody === 'object') {
    const riskResult = await riskControl.applyIfNeeded({
      req,
      res,
      jsonBody,
      requestProvider: requestProvider || normalizeProviderName(account.provider),
      requestModel: requestModel || upstreamModel || '',
      authResult,
      selectedAccountName: account.name
    });
    if (riskResult?.blocked) {
      releaseReservation(selection, account);
      writeAttemptLog({
        statusCode: 403,
        errorDetail: 'Blocked by risk control'
      });
      return;
    }
  }

  const buildRequestInit = (selectedAccount, requestBody) => {
    const selectedProvider = normalizeProviderName(selectedAccount.provider);
    const headers = { ...req.headers };
    delete headers.host;
    delete headers['content-length'];
    delete headers['accept-encoding'];
    if (selectedProvider === 'anthropic') {
      delete headers.authorization;
      headers['x-api-key'] = selectedAccount.apiKey;
      if (!headers['anthropic-version']) {
        headers['anthropic-version'] = '2023-06-01';
      }
    } else {
      delete headers['x-api-key'];
      headers.authorization = `Bearer ${selectedAccount.apiKey}`;
    }
    headers['accept-encoding'] = 'identity';
    headers['x-pool-account'] = selectedAccount.name;
    if (Buffer.isBuffer(requestBody) && requestBody !== rawBuffer) {
      headers['content-length'] = String(requestBody.byteLength);
    }
    const init = {
      method: req.method,
      headers,
      redirect: 'manual'
    };
    if (!['GET', 'HEAD'].includes(req.method) && Buffer.isBuffer(requestBody) && requestBody.length) {
      init.body = requestBody;
      init.duplex = 'half';
    }
    return init;
  };

  const applyUpstreamHeaders = (
    upstream,
    selectedAccount,
    selectedSelection,
    forceResponsesCompat = false,
    compatUnsupportedFields = []
  ) => {
    res.status(upstream.status);
    upstream.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (
        lower === 'transfer-encoding' ||
        lower === 'content-encoding' ||
        lower === 'content-length' ||
        lower === 'connection' ||
        lower === 'keep-alive'
      ) {
        return;
      }
      res.setHeader(key, value);
    });
    res.setHeader('x-gateway-account', selectedAccount.name);
    res.setHeader('x-gateway-sticky-hit', String(selectedSelection.stickyHit));
    res.setHeader('x-gateway-responses-compat', forceResponsesCompat ? '1' : '0');
    if (forceResponsesCompat && compatUnsupportedFields.length) {
      res.setHeader('x-gateway-responses-compat-unsupported', compatUnsupportedFields.join(','));
    }
    if (requestModel && upstreamModel && requestModel !== upstreamModel) {
      res.setHeader('x-gateway-model-mapped', `${requestModel}->${upstreamModel}`);
    }
    if (promptCacheBypassReason) {
      res.setHeader('x-gateway-cache-proxy', 'bypass');
      res.setHeader('x-gateway-cache-bypass', promptCacheBypassReason);
    }
  };

	  try {
	    let upstream = null;
	    let usedResponsesCompat = false;
	    let compatReasoningSummaryMode = '';
	    while (attemptCount <= maxAttemptCount) {
      if (shouldForceResponsesCompat(account)) {
        activeCompatUnsupportedFields = [...responsesCompatUnsupportedFields];
      } else {
        activeCompatUnsupportedFields = [];
      }
	      const requestSpec = resolveRequestForAccount(account);
	      compatReasoningSummaryMode = String(requestSpec.compatReasoningSummaryMode || '').trim();
	      const requestInit = buildRequestInit(account, requestSpec.body);
	      upstream = await fetch(requestSpec.targetUrl, requestInit);
	      usedResponsesCompat = requestSpec.forceCompat;
	      activeCompatUnsupportedFields = requestSpec.compatUnsupportedFields || [];
	      if (upstream.ok) {
	        break;
	      }

      const errorBuffer = Buffer.from(await upstream.arrayBuffer());
      const errorText = errorBuffer.toString('utf8');
      const errorPayload = safeJsonParse(errorText);
      const retry = classifyUpstreamRetry(upstream.status, errorPayload, errorText);
      const canRetry = retry.shouldRetry && attemptCount < maxAttemptCount;

      if (!canRetry) {
        releaseReservation(selection, account);
        applyUpstreamHeaders(upstream, account, selection, usedResponsesCompat, activeCompatUnsupportedFields);
        writeAttemptLog({
          statusCode: upstream.status,
          errorDetail: extractErrorDetail(errorPayload, errorText)
        });
        res.setHeader('content-length', String(errorBuffer.byteLength));
        res.end(errorBuffer);
        return;
      }

      lastRetryReason = retry.reason || `upstream ${upstream.status}`;
      setAccountCooldown(account.id, lastRetryReason);
      releaseReservation(selection, account);
      excludedAccounts.add(account.id);

      const nextSelection = selectAccount({
        stickyKey,
        seed: `${stickySeed}:retry:${attemptCount}`,
        requestModel: requestModel || upstreamModel || '',
        upstreamModel: upstreamModel || requestModel || '',
        requestProvider,
        groupKey: requestGroupKey,
        excludeAccountIds: excludedAccounts,
        reserveQuota: isBillableRequest,
        enforceQuota: isBillableRequest
      });
      if (nextSelection.error || !nextSelection.account) {
        applyUpstreamHeaders(upstream, account, selection, usedResponsesCompat, activeCompatUnsupportedFields);
        writeAttemptLog({
          statusCode: upstream.status,
          errorDetail: `${extractErrorDetail(errorPayload, errorText)} | switch-failed: ${nextSelection.error || 'no backup account'}`
        });
        res.setHeader('content-length', String(errorBuffer.byteLength));
        res.end(errorBuffer);
        return;
      }

      switchCount += 1;
      attemptCount += 1;
      selection = nextSelection;
      account = selection.account;
      logState.accountName = account.name;
    }
    if (!upstream) {
      throw new Error('Upstream request failed without response');
    }
    if (upstream.ok) {
      bindRequestSticky();
    }

    applyUpstreamHeaders(upstream, account, selection, usedResponsesCompat, activeCompatUnsupportedFields);

    const contentType = String(upstream.headers.get('content-type') || '').toLowerCase();
    const streamLikeContentType = (
      contentType.includes('text/event-stream') ||
      contentType.includes('application/x-ndjson') ||
      contentType.includes('application/stream+json')
    );
    const shouldPipeStream = streamLikeContentType || (requestedStream && upstream.ok);

    if (!shouldPipeStream && contentType.includes('application/json')) {
      const responseBuffer = Buffer.from(await upstream.arrayBuffer());
      const shouldParsePayload = isBillableRequest || isResponsesSessionRequest || !upstream.ok;
      const responseText = shouldParsePayload ? responseBuffer.toString('utf8') : '';
      const payload = shouldParsePayload ? safeJsonParse(responseText) : null;
      let compatPayload = null;
      let outgoingResponseBuffer = responseBuffer;
	      if (upstream.ok && isResponsesCreate && usedResponsesCompat && payload && typeof payload === 'object') {
	        compatPayload = convertChatCompletionToResponsesPayload(payload, {
	          includeReasoningSummary: Boolean(compatReasoningSummaryMode)
	        });
	        outgoingResponseBuffer = Buffer.from(JSON.stringify(compatPayload), 'utf8');
	        res.setHeader('content-type', 'application/json; charset=utf-8');
	      } else if (upstream.ok && isResponsesCompact && usedResponsesCompat && payload && typeof payload === 'object') {
	        const compactCompatPayload = convertChatCompletionToResponsesPayload(payload, {
	          includeReasoningSummary: Boolean(compatReasoningSummaryMode)
	        });
	        compatPayload = compactCompatPayload;
	        outgoingResponseBuffer = Buffer.from(JSON.stringify({ output: compactCompatPayload.output || [] }), 'utf8');
	        res.setHeader('content-type', 'application/json; charset=utf-8');
	      }
      let responseTokens = 0;
      let responseInputTokens = 0;
      let responseOutputTokens = 0;
      let responseCachedTokens = 0;
      let responseCostMinor = 0;
      const usageSourcePayload = compatPayload || payload;
      const responseContinuationId = upstream.ok && isResponsesSessionRequest && usageSourcePayload
        ? extractResponseContinuationIdFromPayload(usageSourcePayload)
        : '';
      if (upstream.ok && isBillableRequest && usageSourcePayload && quotaModel) {
        const usage = extractUsageFromPayload(usageSourcePayload);
        if (usage) {
          responseTokens = usage.total;
          responseInputTokens = usage.input;
          responseOutputTokens = usage.output;
          responseCachedTokens = usage.cached;
          const accountProvider = normalizeProviderName(account.provider);
          const price = store.getModelPrice(accountProvider, upstreamModel || requestModel);
          const costMinor = computeCostMinor(usage, price, settings.defaultCurrency);
          responseCostMinor = costMinor;
          store.addModelQuotaUsage(account.id, quotaModel, {
            tokens: usage.total,
            costMinor
          });
        }
      }
      if (!upstream.ok) {
        releaseReservation();
      }
      writeAttemptLog({
        statusCode: upstream.status,
        tokens: responseTokens,
        inputTokens: responseInputTokens,
        outputTokens: responseOutputTokens,
        cachedTokens: responseCachedTokens,
        costMinor: responseCostMinor,
        errorDetail: upstream.ok ? '' : extractErrorDetail(payload, responseText)
      });
      if (responseContinuationId) {
        bindResponseSticky(responseContinuationId);
      }
      res.setHeader('content-length', String(outgoingResponseBuffer.byteLength));
      res.end(outgoingResponseBuffer);
      return;
    }

    if (!upstream.ok) {
      releaseReservation();
    }

    if (!upstream.body) {
      writeAttemptLog({
        statusCode: upstream.status,
        errorDetail: upstream.ok ? '' : `Upstream returned empty body (${upstream.status})`
      });
      res.end();
      return;
    }
    if (!shouldPipeStream) {
      if (!upstream.ok) {
        const responseBuffer = Buffer.from(await upstream.arrayBuffer());
        const responseText = responseBuffer.toString('utf8');
        const payload = safeJsonParse(responseText);
        writeAttemptLog({
          statusCode: upstream.status,
          errorDetail: extractErrorDetail(payload, responseText)
        });
        res.setHeader('content-length', String(responseBuffer.byteLength));
        res.end(responseBuffer);
        return;
      }
      const upstreamReadable = Readable.fromWeb(upstream.body);
      res.once('finish', () => {
        writeAttemptLog({
          statusCode: upstream.status,
          errorDetail: upstream.ok ? '' : `Upstream non-JSON error (${upstream.status})`
        });
      });
      upstreamReadable.pipe(res);
      return;
    }

    const upstreamReadable = Readable.fromWeb(upstream.body);

	    if (upstream.ok && isResponsesCreate && usedResponsesCompat) {
	      const compatResponseId = generateCompatResponseId();
	      const compatTransform = createChatCompletionsToResponsesSseTransform({
	        responseId: compatResponseId,
	        model: upstreamModel || requestModel || '',
	        includeReasoningSummary: Boolean(compatReasoningSummaryMode)
	      });

      let usageFlushed = false;
      const flushCompatUsage = () => {
        if (usageFlushed) {
          return;
        }
        usageFlushed = true;
        const compatUsage = compatTransform.getUsage();
        const usage = compatUsage ? getModelUsage(compatUsage) : null;
        if (isBillableRequest && upstream.ok && quotaModel && usage) {
          const accountProvider = normalizeProviderName(account.provider);
          const price = store.getModelPrice(accountProvider, upstreamModel || requestModel);
          const costMinor = computeCostMinor(usage, price, settings.defaultCurrency);
          store.addModelQuotaUsage(account.id, quotaModel, {
            tokens: usage.total,
            costMinor
          });
          writeAttemptLog({
            statusCode: upstream.status,
            tokens: usage.total,
            inputTokens: usage.input,
            outputTokens: usage.output,
            cachedTokens: usage.cached,
            costMinor
          });
        } else {
          writeAttemptLog({
            statusCode: upstream.status,
            tokens: usage?.total || 0,
            inputTokens: usage?.input || 0,
            outputTokens: usage?.output || 0,
            cachedTokens: usage?.cached || 0,
            costMinor: 0
          });
        }
        bindResponseSticky(compatResponseId);
      };

      compatTransform.transformer.on('end', flushCompatUsage);
      res.once('finish', flushCompatUsage);
      res.setHeader('content-type', 'text/event-stream; charset=utf-8');
      res.setHeader('cache-control', 'no-cache, no-transform');
      res.flushHeaders();
      upstreamReadable.pipe(compatTransform.transformer).pipe(res);
      return;
    }

    let streamUsage = null;
    let streamErrorDetail = '';
    let streamResponseContinuationId = '';
    let usageFlushed = false;
    const usageObserver = createStreamUsageObserver(contentType, {
      onPayload: (payload) => {
        if (!streamErrorDetail && payload && typeof payload === 'object') {
          streamErrorDetail = extractErrorDetail(payload, '');
        }
      },
      onResponseId: (responseId) => {
        if (!streamResponseContinuationId) {
          streamResponseContinuationId = responseId;
        }
      },
      onUsage: (usage) => {
        if (!usage) {
          return;
        }
        if (!streamUsage || usage.total >= streamUsage.total) {
          streamUsage = usage;
        }
      }
    });

    const flushStreamUsage = () => {
      if (usageFlushed) {
        return;
      }
      usageFlushed = true;
      if (isBillableRequest && upstream.ok && quotaModel && streamUsage) {
        const accountProvider = normalizeProviderName(account.provider);
        const price = store.getModelPrice(accountProvider, upstreamModel || requestModel);
        const costMinor = computeCostMinor(streamUsage, price, settings.defaultCurrency);
        store.addModelQuotaUsage(account.id, quotaModel, {
          tokens: streamUsage.total,
          costMinor
        });
        writeAttemptLog({
          statusCode: upstream.status,
          tokens: streamUsage.total,
          inputTokens: streamUsage.input,
          outputTokens: streamUsage.output,
          cachedTokens: streamUsage.cached,
          costMinor,
          errorDetail: upstream.ok ? '' : streamErrorDetail
        });
        if (upstream.ok) {
          bindResponseSticky(streamResponseContinuationId);
        }
        return;
      }
      writeAttemptLog({
        statusCode: upstream.status,
        tokens: streamUsage?.total || 0,
        inputTokens: streamUsage?.input || 0,
        outputTokens: streamUsage?.output || 0,
        cachedTokens: streamUsage?.cached || 0,
        costMinor: 0,
        errorDetail: upstream.ok ? '' : streamErrorDetail
      });
      if (upstream.ok) {
        bindResponseSticky(streamResponseContinuationId);
      }
    };

    usageObserver.on('end', flushStreamUsage);
    res.once('finish', flushStreamUsage);

    res.flushHeaders();
    upstreamReadable.pipe(usageObserver).pipe(res);
  } catch (error) {
    releaseReservation();
    const detail = error?.message || 'upstream fetch failed';
    const badRequest = (
      detail.includes('requires valid JSON request body') ||
      detail.includes('unsupported fields')
    );
    if (badRequest && shouldForceResponsesCompat(account) && activeCompatUnsupportedFields.length) {
      res.setHeader('x-gateway-responses-compat', '1');
      res.setHeader('x-gateway-responses-compat-unsupported', activeCompatUnsupportedFields.join(','));
    }
    if (!badRequest) {
      setAccountCooldown(account.id, detail);
    }
    writeAttemptLog({
      statusCode: badRequest ? 400 : 502,
      errorDetail: detail
    });
    res.status(badRequest ? 400 : 502).json({
      error: badRequest ? 'Bad request' : 'Upstream request failed',
      detail
    });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

const server = app.listen(port, '0.0.0.0', () => {
  console.log(`Gateway listening on http://127.0.0.1:${port}`);
  console.log(`Admin panel: http://127.0.0.1:${port}/admin/login`);
  console.log(`SQLite DB: ${dbPath}`);
});

process.on('SIGINT', () => {
  server.close(() => {
    store.close();
    process.exit(0);
  });
});
