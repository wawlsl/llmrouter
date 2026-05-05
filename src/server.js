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
const requestLogBufferLimit = 300;
const requestLogs = [];
const requestLogClients = new Set();
let requestLogSeq = 0;
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
        return { ok: false, groupKey: '', error };
      }
      store.touchAccessKey(dbKey.id, new Date().toISOString());
      return { ok: true, groupKey: dbKey.groupKey || '', accessKeyId: dbKey.id };
    }

    if (gatewayKeys.length && gatewayKeys.includes(token)) {
      return { ok: true, groupKey: '', accessKeyId: '' };
    }
  }

  const error = 'Unauthorized gateway token';
  res.status(401).json({ error });
  return { ok: false, groupKey: '', error };
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

function buildResponsesCompatTargetUrl(baseUrl, requestUrl) {
  const incoming = new URL(String(requestUrl || '/v1/responses'), 'http://gateway.local');
  if (incoming.pathname === '/v1/responses' || incoming.pathname === '/v1/responses/compact') {
    incoming.pathname = '/v1/chat/completions';
  } else if (incoming.pathname.endsWith('/v1/responses') || incoming.pathname.endsWith('/v1/responses/compact')) {
    incoming.pathname = incoming.pathname.replace(/\/v1\/responses(?:\/compact)?$/, '/v1/chat/completions');
  }
  return buildUpstreamUrl(baseUrl, `${incoming.pathname}${incoming.search}`);
}

function normalizeServiceBaseUrl(value) {
  const text = String(value || '').trim();
  if (!text) {
    return '';
  }
  try {
    const parsed = new URL(text);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return '';
    }
    return `${parsed.origin}${normalizeBasePath(parsed.pathname)}`;
  } catch {
    return '';
  }
}

function convertAnthropicToolsToChatTools(tools) {
  if (!Array.isArray(tools)) {
    return [];
  }
  const converted = [];
  for (const item of tools) {
    if (!item || typeof item !== 'object') {
      continue;
    }
    const name = String(item.name || '').trim();
    if (!name) {
      continue;
    }
    converted.push({
      type: 'function',
      function: {
        name,
        description: String(item.description || '').trim(),
        parameters: item.input_schema && typeof item.input_schema === 'object'
          ? cloneJsonLike(item.input_schema, {})
          : { type: 'object', properties: {} }
      }
    });
  }
  return converted;
}

function convertAnthropicToolChoiceToChatToolChoice(toolChoice) {
  if (!toolChoice) {
    return 'auto';
  }
  if (typeof toolChoice === 'string') {
    const normalized = toolChoice.trim().toLowerCase();
    if (normalized === 'none') {
      return 'none';
    }
    if (normalized === 'auto' || normalized === 'any') {
      return 'auto';
    }
    return 'auto';
  }
  if (typeof toolChoice === 'object') {
    const type = String(toolChoice.type || '').trim().toLowerCase();
    if (type === 'none') {
      return 'none';
    }
    if (type === 'auto' || type === 'any') {
      return 'auto';
    }
    if (type === 'tool' && toolChoice.name) {
      return {
        type: 'function',
        function: {
          name: String(toolChoice.name).trim()
        }
      };
    }
  }
  return 'auto';
}

function convertAnthropicMessagesRequestToChatRequest(body) {
  if (!body || typeof body !== 'object') {
    return null;
  }
  const model = String(body.model || '').trim();
  if (!model) {
    return null;
  }
  const messages = [];
  const system = body.system;
  if (typeof system === 'string' && system.trim()) {
    messages.push({ role: 'system', content: system.trim() });
  } else if (Array.isArray(system)) {
    const parts = system
      .map((item) => {
        if (typeof item === 'string') {
          return item;
        }
        if (item && typeof item === 'object' && item.type === 'text') {
          return String(item.text || '');
        }
        return '';
      })
      .filter(Boolean);
    if (parts.length) {
      messages.push({ role: 'system', content: parts.join('\n') });
    }
  }

  const sourceMessages = Array.isArray(body.messages) ? body.messages : [];
  for (const rawMessage of sourceMessages) {
    if (!rawMessage || typeof rawMessage !== 'object') {
      continue;
    }
    const role = String(rawMessage.role || '').trim().toLowerCase();
    if (role !== 'user' && role !== 'assistant') {
      continue;
    }
    const contentBlocks = Array.isArray(rawMessage.content)
      ? rawMessage.content
      : [{ type: 'text', text: String(rawMessage.content || '') }];
    const textParts = [];
    const assistantToolCalls = [];
    const toolResultMessages = [];

    for (const block of contentBlocks) {
      if (!block || typeof block !== 'object') {
        continue;
      }
      const type = String(block.type || '').trim().toLowerCase();
      if (type === 'text') {
        const text = String(block.text || '').trim();
        if (text) {
          textParts.push(text);
        }
        continue;
      }
      if (role === 'assistant' && type === 'tool_use') {
        const name = String(block.name || '').trim();
        if (!name) {
          continue;
        }
        const callId = String(block.id || `call_${crypto.randomUUID()}`).trim();
        assistantToolCalls.push({
          id: callId,
          type: 'function',
          function: {
            name,
            arguments: normalizeToolCallArguments(block.input)
          }
        });
        continue;
      }
      if (role === 'user' && type === 'tool_result') {
        const toolCallId = String(block.tool_use_id || block.id || '').trim();
        if (!toolCallId) {
          continue;
        }
        let resultText = '';
        if (typeof block.content === 'string') {
          resultText = block.content;
        } else if (Array.isArray(block.content)) {
          resultText = block.content
            .map((item) => (item && typeof item === 'object' ? String(item.text || '') : String(item || '')))
            .filter(Boolean)
            .join('\n');
        } else if (Object.prototype.hasOwnProperty.call(block, 'content')) {
          resultText = normalizeToolCallArguments(block.content);
        }
        toolResultMessages.push({
          role: 'tool',
          tool_call_id: toolCallId,
          content: resultText || ''
        });
      }
    }

    if (role === 'assistant') {
      const assistantMessage = {
        role: 'assistant',
        content: textParts.join('\n')
      };
      if (assistantToolCalls.length) {
        assistantMessage.tool_calls = assistantToolCalls;
      }
      messages.push(assistantMessage);
    } else {
      messages.push({
        role: 'user',
        content: textParts.join('\n')
      });
    }
    for (const toolMessage of toolResultMessages) {
      messages.push(toolMessage);
    }
  }

  if (!messages.length) {
    messages.push({ role: 'user', content: '' });
  }

  const chatBody = {
    model,
    messages
  };

  if (Object.prototype.hasOwnProperty.call(body, 'stream')) {
    chatBody.stream = body.stream === true;
  }
  if (chatBody.stream === true) {
    chatBody.stream_options = { include_usage: true };
  }
  if (Object.prototype.hasOwnProperty.call(body, 'temperature') && Number.isFinite(Number(body.temperature))) {
    chatBody.temperature = Number(body.temperature);
  }
  if (Object.prototype.hasOwnProperty.call(body, 'top_p') && Number.isFinite(Number(body.top_p))) {
    chatBody.top_p = Number(body.top_p);
  }
  if (Object.prototype.hasOwnProperty.call(body, 'max_tokens') && Number.isFinite(Number(body.max_tokens))) {
    const maxTokens = Math.floor(Number(body.max_tokens));
    if (maxTokens > 0) {
      chatBody.max_tokens = maxTokens;
    }
  }
  const tools = convertAnthropicToolsToChatTools(body.tools);
  if (tools.length) {
    chatBody.tools = tools;
    chatBody.tool_choice = convertAnthropicToolChoiceToChatToolChoice(body.tool_choice);
  }

  return chatBody;
}

function mapFinishReasonToAnthropicStopReason(finishReason) {
  const normalized = String(finishReason || '').trim().toLowerCase();
  if (normalized === 'tool_calls' || normalized === 'function_call') {
    return 'tool_use';
  }
  if (normalized === 'length') {
    return 'max_tokens';
  }
  if (normalized === 'content_filter') {
    return 'content_filter';
  }
  return 'end_turn';
}

function convertChatCompletionToAnthropicResponsePayload(chatPayload, requestModel = '') {
  const choices = Array.isArray(chatPayload?.choices) ? chatPayload.choices : [];
  const choice = choices[0] || {};
  const message = choice.message && typeof choice.message === 'object' ? choice.message : {};
  const finishReason = mapFinishReasonToAnthropicStopReason(choice.finish_reason);
  const content = [];
  const textContent = ensureStringContent(message.content || '');
  if (textContent) {
    content.push({
      type: 'text',
      text: textContent
    });
  }
  if (Array.isArray(message.tool_calls)) {
    for (const toolCall of message.tool_calls) {
      const name = String(toolCall?.function?.name || '').trim();
      if (!name) {
        continue;
      }
      let input = {};
      try {
        const parsed = safeJsonParse(String(toolCall?.function?.arguments || '').trim());
        input = parsed && typeof parsed === 'object' ? parsed : {};
      } catch {
        input = {};
      }
      content.push({
        type: 'tool_use',
        id: String(toolCall.id || `toolu_${crypto.randomUUID()}`).trim(),
        name,
        input
      });
    }
  }
  const usage = getModelUsage(chatPayload?.usage || {});
  return {
    id: String(chatPayload?.id || `msg_${crypto.randomUUID()}`),
    type: 'message',
    role: 'assistant',
    model: String(chatPayload?.model || requestModel || ''),
    content,
    stop_reason: finishReason,
    stop_sequence: null,
    usage: {
      input_tokens: usage.input,
      output_tokens: usage.output
    }
  };
}

function extractSessionRoutingId(req, jsonBody) {
  const headers = req?.headers || {};
  const byHeader = [
    headers['session_id'],
    headers['x-session-id'],
    headers['session-id'],
    headers['x-claude-session-id']
  ];
  for (const value of byHeader) {
    const normalized = normalizeStickyPart(value);
    if (normalized) {
      return normalized;
    }
  }

  if (!jsonBody || typeof jsonBody !== 'object') {
    return '';
  }
  const byBody = [
    jsonBody.session_id,
    jsonBody.sessionId,
    jsonBody.conversation_id,
    jsonBody.conversationId,
    jsonBody.metadata?.session_id,
    jsonBody.metadata?.sessionId
  ];
  for (const value of byBody) {
    const normalized = normalizeStickyPart(value);
    if (normalized) {
      return normalized;
    }
  }
  return '';
}

function extractPreviousResponseId(jsonBody) {
  if (!jsonBody || typeof jsonBody !== 'object') {
    return '';
  }
  const candidates = [
    jsonBody.previous_response_id,
    jsonBody.previousResponseId,
    jsonBody.metadata?.previous_response_id,
    jsonBody.metadata?.previousResponseId
  ];
  for (const value of candidates) {
    const normalized = normalizeStickyPart(value);
    if (normalized) {
      return normalized;
    }
  }
  return '';
}

function extractCodexTurnState(req, jsonBody) {
  const headers = req?.headers || {};
  const candidates = [
    headers['x-codex-turn-state'],
    jsonBody?.client_metadata?.['x-codex-turn-state'],
    jsonBody?.client_metadata?.codex_turn_state
  ];
  for (const value of candidates) {
    const text = String(value || '').trim();
    if (text) {
      return text;
    }
  }
  return '';
}

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

function extractResponseContinuationIdFromPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return '';
  }
  const candidates = [
    payload.response?.id,
    payload.response?.response?.id,
    payload.response_id,
    payload.responseId,
    payload.id
  ];
  for (const value of candidates) {
    const normalized = normalizeStickyPart(value);
    if (normalized) {
      return normalized;
    }
  }
  return '';
}

function buildResponseContinuationStickyKey(responseId) {
  const normalized = normalizeStickyPart(responseId);
  if (!normalized) {
    return '';
  }
  return `response:${normalized}`;
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

function isLikelyCodexRequest(req, jsonBody) {
  const headers = req?.headers || {};
  const userAgent = String(headers['user-agent'] || '').toLowerCase();
  if (userAgent.includes('codex')) {
    return true;
  }
  if (headers['x-codex-installation-id'] || headers['x-codex-turn-state']) {
    return true;
  }
  const promptCacheKey = extractPromptCacheKey(jsonBody);
  if (promptCacheKey) {
    return true;
  }
  if (jsonBody && typeof jsonBody === 'object') {
    const clientMetadata = jsonBody.client_metadata;
    if (clientMetadata && typeof clientMetadata === 'object') {
      const installationId = clientMetadata['x-codex-installation-id'] || clientMetadata.codex_installation_id;
      if (String(installationId || '').trim()) {
        return true;
      }
    }
  }
  return false;
}

function buildDeterministicRoutingBody(input, depth = 0) {
  if (depth > 10) {
    return null;
  }
  if (input === null || input === undefined) {
    return input;
  }
  if (typeof input !== 'object') {
    return input;
  }
  if (Array.isArray(input)) {
    return input.map((item) => buildDeterministicRoutingBody(item, depth + 1));
  }

  const skipTopLevelKeys = new Set([
    'stream',
    'stream_options',
    'user',
    'service_tier',
    'safety_identifier',
    'store',
    'background',
    'metadata',
    'client_metadata',
    'previous_response_id',
    'previousResponseId',
    'session_id',
    'sessionId',
    'conversation_id',
    'conversationId',
    'prompt_cache_key',
    'promptCacheKey'
  ]);
  const skipNestedKeys = new Set([
    'request_id',
    'requestId',
    'trace_id',
    'traceId',
    'timestamp',
    'ts',
    'nonce'
  ]);

  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (depth === 0 && skipTopLevelKeys.has(key)) {
      continue;
    }
    if (skipNestedKeys.has(key)) {
      continue;
    }
    output[key] = buildDeterministicRoutingBody(value, depth + 1);
  }
  return output;
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

function buildCodexTurnStateStickyKey({ provider, model, turnState }) {
  const token = String(turnState || '').trim();
  if (!token) {
    return '';
  }
  const providerPart = normalizeStickyPart(provider) || 'openai';
  const modelPart = normalizeStickyPart(model) || '-';
  const digest = crypto.createHash('sha256').update(token).digest('hex');
  return `codex-turn:${providerPart}:${modelPart}:${digest}`;
}

function buildCodexAffinityStickyKey({ provider, model, accessKeyId, req, jsonBody }) {
  const headers = req?.headers || {};
  const clientMetadata = (jsonBody && typeof jsonBody === 'object' && jsonBody.client_metadata && typeof jsonBody.client_metadata === 'object')
    ? jsonBody.client_metadata
    : null;
  const installationId = normalizeStickyPart(
    headers['x-codex-installation-id']
    || clientMetadata?.['x-codex-installation-id']
    || clientMetadata?.codex_installation_id
  );
  const windowId = normalizeStickyPart(
    headers['x-codex-window-id']
    || clientMetadata?.['x-codex-window-id']
    || clientMetadata?.codex_window_id
  );
  const parentThreadId = normalizeStickyPart(
    headers['x-codex-parent-thread-id']
    || clientMetadata?.['x-codex-parent-thread-id']
    || clientMetadata?.codex_parent_thread_id
  );
  const subagent = normalizeStickyPart(
    headers['x-openai-subagent']
    || clientMetadata?.['x-openai-subagent']
    || clientMetadata?.openai_subagent
  );
  const providerPart = normalizeStickyPart(provider) || 'openai';
  const modelPart = normalizeStickyPart(model) || '-';
  const accessPart = normalizeStickyPart(accessKeyId) || 'global';
  const fingerprintInput = [
    installationId || '-',
    windowId || '-',
    parentThreadId || '-',
    subagent || '-',
    String(headers['user-agent'] || '').toLowerCase()
  ].join('|');
  const fingerprint = crypto.createHash('sha256').update(fingerprintInput).digest('hex').slice(0, 24);
  return `codex-affinity:${providerPart}:${modelPart}:${accessPart}:${fingerprint}`;
}

function ensureStringContent(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function normalizeToolCallArguments(value) {
  if (typeof value === 'string') {
    return value;
  }
  if (value === null || value === undefined) {
    return '{}';
  }
  try {
    return JSON.stringify(value);
  } catch {
    return '{}';
  }
}

function extractChatDeltaText(content) {
  if (typeof content === 'string') {
    return content;
  }
  if (!Array.isArray(content)) {
    return '';
  }
  return content
    .map((part) => {
      if (!part || typeof part !== 'object') {
        return '';
      }
      if (typeof part.text === 'string') {
        return part.text;
      }
      if (typeof part.content === 'string') {
        return part.content;
      }
      if (typeof part.delta === 'string') {
        return part.delta;
      }
      return '';
    })
    .filter(Boolean)
    .join('');
}

function extractToolOutputText(output) {
  if (typeof output === 'string') {
    return output;
  }
  if (output === null || output === undefined) {
    return '';
  }
  if (Array.isArray(output)) {
    return output
      .map((item) => extractToolOutputText(item))
      .filter(Boolean)
      .join('\n');
  }
  if (typeof output === 'object') {
    if (typeof output.output_text === 'string') {
      return output.output_text;
    }
    if (typeof output.text === 'string') {
      return output.text;
    }
    if (typeof output.body === 'string') {
      return output.body;
    }
    if (Array.isArray(output.body)) {
      return output.body
        .map((item) => ensureStringContent(item?.text || item?.output_text || item?.content || ''))
        .filter(Boolean)
        .join('\n');
    }
    if (Array.isArray(output.content)) {
      return output.content
        .map((item) => ensureStringContent(item?.text || item?.output_text || item?.content || ''))
        .filter(Boolean)
        .join('\n');
    }
  }
  return ensureStringContent(output);
}

function encodeCustomToolInputAsFunctionArguments(input) {
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed) {
      return '{}';
    }
    const parsed = safeJsonParse(trimmed);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return JSON.stringify(parsed);
    }
    return JSON.stringify({ input: trimmed });
  }
  if (input === null || input === undefined) {
    return '{}';
  }
  if (typeof input === 'object') {
    try {
      return JSON.stringify(input);
    } catch {
      return JSON.stringify({ input: ensureStringContent(input) });
    }
  }
  return JSON.stringify({ input: ensureStringContent(input) });
}

function buildNamespacedToolName(namespace, name) {
  const inner = String(name || '').trim();
  if (!inner) {
    return '';
  }
  const ns = String(namespace || '').trim();
  if (!ns) {
    return inner;
  }
  return `${ns}__${inner}`;
}

function defaultCompatFunctionParameters() {
  return {
    type: 'object',
    properties: {},
    additionalProperties: true
  };
}

function convertResponsesToolToChatFunction(tool, namespaceName = '') {
  if (!tool || typeof tool !== 'object') {
    return null;
  }
  const source = (tool.function && typeof tool.function === 'object') ? tool.function : tool;
  const innerName = String(source.name || '').trim();
  if (!innerName) {
    return null;
  }
  const name = buildNamespacedToolName(namespaceName, innerName);
  const description = ensureStringContent(source.description || '').trim();
  const parameters = (source.parameters && typeof source.parameters === 'object' && !Array.isArray(source.parameters))
    ? source.parameters
    : defaultCompatFunctionParameters();
  const strictValue = source.strict ?? tool.strict;
  const functionSpec = {
    name,
    parameters
  };
  if (description) {
    functionSpec.description = description;
  }
  if (typeof strictValue === 'boolean') {
    functionSpec.strict = strictValue;
  }
  return {
    type: 'function',
    function: functionSpec
  };
}

function convertResponsesToolsToChatTools(tools) {
  if (!Array.isArray(tools) || !tools.length) {
    return [];
  }
  const converted = [];
  const seenNames = new Set();

  const addFunctionTool = (candidate) => {
    if (!candidate || typeof candidate !== 'object') {
      return;
    }
    const name = String(candidate?.function?.name || '').trim();
    if (!name || seenNames.has(name)) {
      return;
    }
    seenNames.add(name);
    converted.push(candidate);
  };

  for (const tool of tools) {
    if (!tool || typeof tool !== 'object') {
      continue;
    }
    const type = String(tool.type || '').trim();
    if (type === 'function') {
      addFunctionTool(convertResponsesToolToChatFunction(tool));
      continue;
    }
    if (type === 'namespace') {
      const namespaceName = String(tool.name || '').trim();
      const namespaceTools = Array.isArray(tool.tools) ? tool.tools : [];
      for (const namespaceTool of namespaceTools) {
        addFunctionTool(convertResponsesToolToChatFunction(namespaceTool, namespaceName));
      }
      continue;
    }
    if (type === 'custom') {
      const name = String(tool.name || '').trim();
      if (!name) {
        continue;
      }
      const description = ensureStringContent(tool.description || '').trim()
        || `Custom tool "${name}" converted for chat completions compatibility.`;
      addFunctionTool({
        type: 'function',
        function: {
          name,
          description,
          parameters: {
            type: 'object',
            properties: {
              input: {
                type: 'string',
                description: 'Raw tool input'
              }
            },
            required: ['input'],
            additionalProperties: true
          }
        }
      });
    }
  }

  return converted;
}

function convertResponsesToolChoiceToChatToolChoice(toolChoice, chatTools = []) {
  if (typeof toolChoice === 'string') {
    return toolChoice;
  }
  if (!toolChoice || typeof toolChoice !== 'object') {
    return 'auto';
  }
  const enabledNames = new Set(
    chatTools
      .map((item) => String(item?.function?.name || '').trim())
      .filter(Boolean)
  );
  const explicitName = buildNamespacedToolName(
    toolChoice?.function?.namespace ?? toolChoice?.namespace,
    toolChoice?.function?.name ?? toolChoice?.name
  );
  if (explicitName) {
    if (!enabledNames.has(explicitName)) {
      return 'auto';
    }
    return {
      type: 'function',
      function: { name: explicitName }
    };
  }
  const normalizedType = String(toolChoice.type || '').trim().toLowerCase();
  if (normalizedType === 'required') {
    return enabledNames.size > 0 ? 'required' : 'auto';
  }
  if (normalizedType === 'none') {
    return 'none';
  }
  return 'auto';
}

function convertResponsesTextFormatToChatResponseFormat(format) {
  if (!format || typeof format !== 'object') {
    return null;
  }
  const type = String(format.type || '').trim().toLowerCase();
  if (!type) {
    return null;
  }
  if (type === 'json_object') {
    return { type: 'json_object' };
  }
  if (type === 'json_schema') {
    const schemaNode = format.json_schema && typeof format.json_schema === 'object'
      ? format.json_schema
      : format;
    const name = String(schemaNode.name || format.name || 'structured_output').trim() || 'structured_output';
    const schema = schemaNode.schema && typeof schemaNode.schema === 'object'
      ? schemaNode.schema
      : null;
    if (!schema) {
      return { type: 'json_object' };
    }
    const jsonSchema = {
      name,
      schema
    };
    if (typeof schemaNode.strict === 'boolean') {
      jsonSchema.strict = schemaNode.strict;
    }
    if (typeof schemaNode.description === 'string' && schemaNode.description.trim()) {
      jsonSchema.description = schemaNode.description.trim();
    }
    return {
      type: 'json_schema',
      json_schema: jsonSchema
    };
  }
  return null;
}

function normalizeChatResponseFormat(format) {
  if (!format || typeof format !== 'object') {
    return null;
  }
  const type = String(format.type || '').trim().toLowerCase();
  if (type === 'json_object') {
    return { type: 'json_object' };
  }
  if (type === 'json_schema') {
    const schemaNode = format.json_schema && typeof format.json_schema === 'object'
      ? format.json_schema
      : format;
    const name = String(schemaNode.name || format.name || 'structured_output').trim() || 'structured_output';
    const schema = schemaNode.schema && typeof schemaNode.schema === 'object'
      ? schemaNode.schema
      : null;
    if (!schema) {
      return { type: 'json_object' };
    }
    const jsonSchema = {
      name,
      schema
    };
    if (typeof schemaNode.strict === 'boolean') {
      jsonSchema.strict = schemaNode.strict;
    }
    if (typeof schemaNode.description === 'string' && schemaNode.description.trim()) {
      jsonSchema.description = schemaNode.description.trim();
    }
    return {
      type: 'json_schema',
      json_schema: jsonSchema
    };
  }
  return null;
}

function convertResponsesContentToChatContent(content, role = 'user') {
  if (typeof content === 'string') {
    return content;
  }
  if (!Array.isArray(content)) {
    return ensureStringContent(content);
  }

  const richParts = [];
  const textParts = [];
  for (const rawPart of content) {
    if (!rawPart || typeof rawPart !== 'object') {
      continue;
    }
    const partType = String(rawPart.type || '').trim();
    if (partType === 'input_text' || partType === 'output_text' || partType === 'text') {
      const text = ensureStringContent(rawPart.text || '');
      if (text) {
        textParts.push(text);
        richParts.push({ type: 'text', text });
      }
      continue;
    }
    if (partType === 'input_image') {
      const imageUrl = typeof rawPart.image_url === 'string'
        ? rawPart.image_url
        : ensureStringContent(rawPart.image_url?.url || rawPart.url || '');
      if (imageUrl) {
        richParts.push({
          type: 'image_url',
          image_url: { url: imageUrl }
        });
      }
      continue;
    }
    if (partType === 'input_audio' && rawPart.input_audio) {
      richParts.push({
        type: 'input_audio',
        input_audio: rawPart.input_audio
      });
      continue;
    }
    if (partType === 'input_file' && rawPart.file) {
      richParts.push({
        type: 'file',
        file: rawPart.file
      });
      continue;
    }
    if (partType === 'refusal' && typeof rawPart.refusal === 'string') {
      richParts.push({
        type: 'text',
        text: rawPart.refusal
      });
      textParts.push(rawPart.refusal);
      continue;
    }
    if (typeof rawPart.text === 'string' && rawPart.text) {
      textParts.push(rawPart.text);
      richParts.push({ type: 'text', text: rawPart.text });
      continue;
    }
    const fallbackText = ensureStringContent(rawPart?.text || rawPart?.content || '').trim();
    if (fallbackText) {
      textParts.push(fallbackText);
      richParts.push({ type: 'text', text: fallbackText });
    }
  }

  if (!richParts.length) {
    return '';
  }
  const hasNonText = richParts.some((part) => part.type !== 'text');
  if (!hasNonText) {
    if (role === 'assistant') {
      return textParts.join('');
    }
    return textParts.join('\n');
  }
  return richParts;
}

function convertResponsesInputToChatMessages(input) {
  const messages = [];
  const items = Array.isArray(input) ? input : [input];

  for (const item of items) {
    if (typeof item === 'string') {
      if (item.trim()) {
        messages.push({ role: 'user', content: item });
      }
      continue;
    }
    if (!item || typeof item !== 'object') {
      continue;
    }

    if (item.type === 'function_call_output' || item.type === 'custom_tool_call_output') {
      const toolCallId = String(item.call_id || item.tool_call_id || '').trim();
      if (!toolCallId) {
        continue;
      }
      messages.push({
        role: 'tool',
        tool_call_id: toolCallId,
        content: extractToolOutputText(item.output)
      });
      continue;
    }

    if (item.type === 'reasoning') {
      const summaries = Array.isArray(item.summary) ? item.summary : [];
      const summaryText = summaries
        .map((part) => ensureStringContent(part?.text || ''))
        .join('\n')
        .trim();
      if (summaryText) {
        messages.push({ role: 'assistant', content: summaryText });
      }
      continue;
    }

    if (item.type === 'function_call' || item.type === 'custom_tool_call') {
      const functionName = buildNamespacedToolName(item.namespace, item.name);
      const toolCallId = String(item.call_id || item.id || '').trim() || `call_${crypto.randomUUID()}`;
      if (!functionName) {
        continue;
      }
      const functionArguments = item.type === 'custom_tool_call'
        ? encodeCustomToolInputAsFunctionArguments(item.input)
        : normalizeToolCallArguments(item.arguments);
      messages.push({
        role: 'assistant',
        content: '',
        tool_calls: [{
          id: toolCallId,
          type: 'function',
          function: {
            name: functionName,
            arguments: functionArguments
          }
        }]
      });
      continue;
    }

    if (item.type === 'input_image') {
      const imageUrl = typeof item.image_url === 'string'
        ? item.image_url
        : ensureStringContent(item.image_url?.url || item.url || '');
      if (imageUrl) {
        messages.push({
          role: 'user',
          content: [{
            type: 'image_url',
            image_url: { url: imageUrl }
          }]
        });
      }
      continue;
    }
    if (item.type === 'input_audio' && item.input_audio) {
      messages.push({
        role: 'user',
        content: [{
          type: 'input_audio',
          input_audio: item.input_audio
        }]
      });
      continue;
    }
    if (item.type === 'input_file' && item.file) {
      messages.push({
        role: 'user',
        content: [{
          type: 'file',
          file: item.file
        }]
      });
      continue;
    }

    if (item.type === 'message' || item.role) {
      const roleRaw = String(item.role || 'user').trim().toLowerCase();
      let role = (
        roleRaw === 'assistant' ||
        roleRaw === 'system' ||
        roleRaw === 'developer' ||
        roleRaw === 'tool'
      )
        ? roleRaw
        : 'user';
      // Many OpenAI-compatible upstreams don't understand "developer" yet.
      if (role === 'developer') {
        role = 'system';
      }
      const content = convertResponsesContentToChatContent(item.content, role);
      const message = {
        role,
        content: content || ''
      };
      if (role === 'tool') {
        const toolCallId = String(item.call_id || item.tool_call_id || '').trim();
        if (toolCallId) {
          message.tool_call_id = toolCallId;
        }
      }
      messages.push(message);
      continue;
    }

    if (item.type === 'input_text' && item.text) {
      messages.push({ role: 'user', content: ensureStringContent(item.text) });
      continue;
    }
    if (item.type === 'output_text' && item.text) {
      messages.push({ role: 'assistant', content: ensureStringContent(item.text) });
    }
  }

  return messages;
}

function convertResponsesRequestToChatRequest(body) {
  if (!body || typeof body !== 'object') {
    return null;
  }
  const model = String(body.model || '').trim();
  if (!model) {
    return null;
  }
  const messages = [];
  const rawInstructions = body.instructions;
  if (typeof rawInstructions === 'string') {
    const instructions = rawInstructions.trim();
    if (instructions) {
      messages.push({ role: 'system', content: instructions });
    }
  } else if (Array.isArray(rawInstructions)) {
    const instructionsContent = convertResponsesContentToChatContent(rawInstructions, 'system');
    if (instructionsContent) {
      messages.push({ role: 'system', content: instructionsContent });
    }
  } else if (rawInstructions && typeof rawInstructions === 'object') {
    const instructionsContent = convertResponsesContentToChatContent(rawInstructions, 'system');
    if (instructionsContent) {
      messages.push({ role: 'system', content: instructionsContent });
    }
  }
  const inputMessages = convertResponsesInputToChatMessages(body.input);
  messages.push(...inputMessages);
  if (!messages.length) {
    messages.push({ role: 'user', content: '' });
  }

  const chatBody = {
    model,
    messages
  };

  if (Object.prototype.hasOwnProperty.call(body, 'stream')) {
    chatBody.stream = body.stream === true;
  }
  if (chatBody.stream === true) {
    const streamOptions = {};
    if (body.stream_options && typeof body.stream_options === 'object') {
      if (Object.prototype.hasOwnProperty.call(body.stream_options, 'include_usage')) {
        streamOptions.include_usage = body.stream_options.include_usage === true;
      }
      if (Object.prototype.hasOwnProperty.call(body.stream_options, 'include_obfuscation')) {
        streamOptions.include_obfuscation = body.stream_options.include_obfuscation === true;
      }
    }
    if (!Object.prototype.hasOwnProperty.call(streamOptions, 'include_usage')) {
      streamOptions.include_usage = true;
    }
    chatBody.stream_options = streamOptions;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'temperature') && Number.isFinite(Number(body.temperature))) {
    chatBody.temperature = Number(body.temperature);
  }
  if (Object.prototype.hasOwnProperty.call(body, 'top_p') && Number.isFinite(Number(body.top_p))) {
    chatBody.top_p = Number(body.top_p);
  }
  if (Object.prototype.hasOwnProperty.call(body, 'presence_penalty') && Number.isFinite(Number(body.presence_penalty))) {
    chatBody.presence_penalty = Number(body.presence_penalty);
  }
  if (Object.prototype.hasOwnProperty.call(body, 'frequency_penalty') && Number.isFinite(Number(body.frequency_penalty))) {
    chatBody.frequency_penalty = Number(body.frequency_penalty);
  }
  if (Object.prototype.hasOwnProperty.call(body, 'parallel_tool_calls')) {
    chatBody.parallel_tool_calls = body.parallel_tool_calls === true;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'stop')) {
    if (typeof body.stop === 'string' || Array.isArray(body.stop)) {
      chatBody.stop = body.stop;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'user')) {
    const userValue = String(body.user || '').trim();
    if (userValue) {
      chatBody.user = userValue;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'metadata') && body.metadata && typeof body.metadata === 'object') {
    const metadata = cloneJsonLike(body.metadata, null);
    if (metadata && typeof metadata === 'object') {
      chatBody.metadata = metadata;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'service_tier')) {
    const tier = String(body.service_tier || '').trim();
    if (tier) {
      chatBody.service_tier = tier;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'store')) {
    chatBody.store = body.store === true;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'prompt_cache_key')) {
    const cacheKey = String(body.prompt_cache_key || '').trim();
    if (cacheKey) {
      chatBody.prompt_cache_key = cacheKey;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'prompt_cache_retention')) {
    const cacheRetention = cloneJsonLike(body.prompt_cache_retention, null);
    if (cacheRetention && typeof cacheRetention === 'object') {
      chatBody.prompt_cache_retention = cacheRetention;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'safety_identifier')) {
    const safetyIdentifier = String(body.safety_identifier || '').trim();
    if (safetyIdentifier) {
      chatBody.safety_identifier = safetyIdentifier;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'reasoning_effort')) {
    const effort = String(body.reasoning_effort || '').trim();
    if (effort) {
      chatBody.reasoning_effort = effort;
    }
  }
  if (
    !Object.prototype.hasOwnProperty.call(chatBody, 'reasoning_effort') &&
    body.reasoning &&
    typeof body.reasoning === 'object' &&
    body.reasoning.effort
  ) {
    const effort = String(body.reasoning.effort || '').trim();
    if (effort) {
      chatBody.reasoning_effort = effort;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'response_format') && body.response_format && typeof body.response_format === 'object') {
    const explicitFormat = normalizeChatResponseFormat(body.response_format);
    if (explicitFormat) {
      chatBody.response_format = explicitFormat;
    }
  }
  const compatTools = convertResponsesToolsToChatTools(body.tools);
  if (compatTools.length) {
    chatBody.tools = compatTools;
  } else {
    delete chatBody.tools;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'tool_choice')) {
    chatBody.tool_choice = convertResponsesToolChoiceToChatToolChoice(body.tool_choice, compatTools);
  }
  if (Object.prototype.hasOwnProperty.call(body, 'max_tool_calls') && Number.isFinite(Number(body.max_tool_calls))) {
    const maxToolCalls = Math.floor(Number(body.max_tool_calls));
    if (maxToolCalls <= 0) {
      chatBody.tool_choice = 'none';
    }
  }

  if (!Object.prototype.hasOwnProperty.call(chatBody, 'response_format')) {
    const mappedFormat = convertResponsesTextFormatToChatResponseFormat(body?.text?.format);
    if (mappedFormat) {
      chatBody.response_format = mappedFormat;
    }
  }
  if (Object.prototype.hasOwnProperty.call(body, 'max_output_tokens') && !Object.prototype.hasOwnProperty.call(chatBody, 'max_tokens')) {
    const maxTokens = Number(body.max_output_tokens);
    if (Number.isFinite(maxTokens) && maxTokens > 0) {
      const normalized = Math.floor(maxTokens);
      chatBody.max_tokens = normalized;
      if (!Object.prototype.hasOwnProperty.call(chatBody, 'max_completion_tokens')) {
        chatBody.max_completion_tokens = normalized;
      }
    }
  }
  const includeFields = parseResponsesIncludeFields(body.include);
  const wantsLogprobsFromInclude = includeFields.includes('message.output_text.logprobs');
  const topLogprobsRaw = Number(body.top_logprobs);
  const hasTopLogprobs = Number.isFinite(topLogprobsRaw) && topLogprobsRaw > 0;
  if (Object.prototype.hasOwnProperty.call(body, 'logprobs')) {
    chatBody.logprobs = body.logprobs === true;
  }
  if (wantsLogprobsFromInclude || hasTopLogprobs) {
    chatBody.logprobs = true;
  }
  if (hasTopLogprobs) {
    chatBody.top_logprobs = Math.floor(topLogprobsRaw);
  }

  return chatBody;
}

function buildResponsesUsageFromChatUsage(usage) {
  if (!usage || typeof usage !== 'object') {
    return null;
  }
  const metrics = getModelUsage(usage);
  const usagePayload = {
    input_tokens: metrics.input,
    output_tokens: metrics.output,
    total_tokens: metrics.total,
    // Some OpenAI-compatible dashboards still expect Chat Completions field names.
    prompt_tokens: metrics.input,
    completion_tokens: metrics.output,
    input_tokens_details: {
      cached_tokens: metrics.cacheRead
    },
    output_tokens_details: {
      reasoning_tokens: metrics.reasoning
    }
  };
  usagePayload.prompt_tokens_details = { ...usagePayload.input_tokens_details };
  usagePayload.completion_tokens_details = { ...usagePayload.output_tokens_details };
  if (metrics.cacheRead > 0) {
    usagePayload.input_tokens_details.cache_read_input_tokens = metrics.cacheRead;
    usagePayload.cache_read_input_tokens = metrics.cacheRead;
    usagePayload.prompt_tokens_details.cache_read_input_tokens = metrics.cacheRead;
  }
  if (metrics.cacheWrite > 0) {
    usagePayload.input_tokens_details.cache_creation_input_tokens = metrics.cacheWrite;
    usagePayload.cache_creation_input_tokens = metrics.cacheWrite;
    usagePayload.prompt_tokens_details.cache_creation_input_tokens = metrics.cacheWrite;
  }
  return usagePayload;
}

function generateCompatResponseId(chatId = '') {
  const normalized = String(chatId || '').trim();
  if (normalized.startsWith('resp_')) {
    return normalized;
  }
  const suffix = normalized || crypto.randomBytes(8).toString('hex');
  return `resp_${suffix}`;
}

function extractReasoningDelta(delta = {}) {
  const chunks = [];
  let lastChunk = '';
  const append = (value) => {
    if (typeof value === 'string' && value) {
      if (value === lastChunk) {
        return;
      }
      chunks.push(value);
      lastChunk = value;
    }
  };
  const appendFromCollection = (value) => {
    if (!value) {
      return;
    }
    if (typeof value === 'string') {
      append(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        appendFromCollection(item);
      }
      return;
    }
    if (typeof value === 'object') {
      const localSeen = new Set();
      const appendLocal = (text) => {
        if (typeof text !== 'string' || !text || localSeen.has(text)) {
          return;
        }
        localSeen.add(text);
        append(text);
      };
      appendLocal(value.delta);
      appendLocal(value.text);
      appendLocal(value.summary_text);
      appendLocal(value.content);
      if (Array.isArray(value.summary)) {
        appendFromCollection(value.summary);
      }
      if (Array.isArray(value.content)) {
        appendFromCollection(value.content);
      }
    }
  };

  appendFromCollection(delta.reasoning_content);
  appendFromCollection(delta.reasoning);
  return chunks.join('');
}

function convertChatCompletionToResponsesPayload(
  chatPayload,
  { includeReasoningSummary = false } = {}
) {
  const now = Math.floor(Date.now() / 1000);
  const choices = Array.isArray(chatPayload?.choices) ? chatPayload.choices : [];
  const output = [];
  let incompleteReason = '';

  for (let choiceIndex = 0; choiceIndex < choices.length; choiceIndex += 1) {
    const choice = choices[choiceIndex] || {};
    const message = choice?.message || {};
    let reasoningSummaryText = '';
    if (includeReasoningSummary) {
      reasoningSummaryText = extractReasoningDelta(message);
    }
    let contentText = '';
    if (typeof message?.content === 'string') {
      contentText = message.content;
    } else if (Array.isArray(message?.content)) {
      contentText = message.content
        .map((part) => ensureStringContent(part?.text || part?.content || ''))
        .filter(Boolean)
        .join('');
    } else {
      contentText = ensureStringContent(message?.content || '');
    }
    const finishReason = String(choice?.finish_reason || '').trim();
    if (!incompleteReason && (finishReason === 'length' || finishReason === 'content_filter')) {
      incompleteReason = finishReason;
    }

    if (includeReasoningSummary && reasoningSummaryText) {
      output.push({
        type: 'reasoning',
        id: `rs_${crypto.randomUUID()}`,
        summary: [{
          type: 'summary_text',
          text: reasoningSummaryText
        }]
      });
    }

    if (contentText) {
      const outputText = {
        type: 'output_text',
        text: contentText,
        annotations: []
      };
      if (choice?.logprobs && typeof choice.logprobs === 'object' && Array.isArray(choice.logprobs.content)) {
        outputText.logprobs = choice.logprobs.content;
      }
      output.push({
        type: 'message',
        id: `msg_${choiceIndex}_${crypto.randomUUID()}`,
        role: 'assistant',
        status: 'completed',
        content: [outputText]
      });
    }

    if (Array.isArray(message.tool_calls) && message.tool_calls.length > 0) {
      for (const toolCall of message.tool_calls) {
        const callName = String(toolCall?.function?.name || '').trim();
        if (!callName) {
          continue;
        }
        output.push({
          type: 'function_call',
          id: String(toolCall.id || '').trim() || `fc_${choiceIndex}_${crypto.randomUUID()}`,
          call_id: String(toolCall.id || '').trim() || `call_${choiceIndex}_${crypto.randomUUID()}`,
          name: callName,
          arguments: normalizeToolCallArguments(toolCall?.function?.arguments),
          status: 'completed'
        });
      }
    }
  }

  if (!output.length) {
    output.push({
      type: 'message',
      id: `msg_${crypto.randomUUID()}`,
      role: 'assistant',
      status: 'completed',
      content: [{
        type: 'output_text',
        text: '',
        annotations: []
      }]
    });
  }

  const responsePayload = {
    id: generateCompatResponseId(chatPayload?.id),
    object: 'response',
    created_at: safeNumber(chatPayload?.created, now),
    status: 'completed',
    model: chatPayload?.model || '',
    output,
    usage: buildResponsesUsageFromChatUsage(chatPayload?.usage)
  };
  if (incompleteReason) {
    responsePayload.status = 'incomplete';
    responsePayload.incomplete_details = { reason: incompleteReason };
  }
  return responsePayload;
}

function createResponsesCompatStreamParser(
  { responseId, model, includeReasoningSummary = false } = {}
) {
  const rid = generateCompatResponseId(responseId);
  const createdAt = Math.floor(Date.now() / 1000);
  let started = false;
  let finished = false;
  let usage = null;
  let completedResponse = null;
  let nextOutputIndex = 0;
  let finalFinishReason = '';
  let sequenceNumber = 0;
  const choiceStates = new Map();
  const choiceOrder = [];

  const allocateOutputIndex = () => {
    const current = nextOutputIndex;
    nextOutputIndex += 1;
    return current;
  };
  const emit = (payload) => {
    // OpenAI Responses streaming uses a monotonically increasing sequence number starting at 0.
    const seq = sequenceNumber;
    sequenceNumber += 1;
    return `data: ${JSON.stringify({ ...payload, sequence_number: seq })}\n\n`;
  };

	  const maybeStart = () => {
	    if (started) {
	      return '';
	    }
	    started = true;
    return emit({
      type: 'response.created',
      response: {
        id: rid,
        object: 'response',
        created_at: createdAt,
        status: 'in_progress',
        model: model || ''
      }
    });
  };

  const getChoiceState = (choiceIndex) => {
    const normalizedIndex = Number.isFinite(choiceIndex) ? Math.max(0, Math.floor(choiceIndex)) : 0;
    if (choiceStates.has(normalizedIndex)) {
      return choiceStates.get(normalizedIndex);
    }
    const state = {
      index: normalizedIndex,
      reasoningBuffer: '',
      textBuffer: '',
      toolCalls: [],
      emittedReasoningItemAdded: false,
      emittedReasoningSummaryPartAdded: false,
      emittedTextItemAdded: false,
      emittedContentPartAdded: false,
      finished: false,
      reasoningItemId: `rs_${crypto.randomUUID()}`,
      reasoningOutputIndex: null,
      messageItemId: `msg_${crypto.randomUUID()}`,
      messageOutputIndex: null
    };
    choiceStates.set(normalizedIndex, state);
    choiceOrder.push(normalizedIndex);
    return state;
  };

  const ensureReasoningOutputIndex = (state) => {
    if (state.reasoningOutputIndex === null) {
      state.reasoningOutputIndex = allocateOutputIndex();
    }
    return state.reasoningOutputIndex;
  };
  const ensureMessageOutputIndex = (state) => {
    if (state.messageOutputIndex === null) {
      state.messageOutputIndex = allocateOutputIndex();
    }
    return state.messageOutputIndex;
  };
  const ensureToolOutputIndex = (tool) => {
    if (!Number.isFinite(tool.outputIndex)) {
      tool.outputIndex = allocateOutputIndex();
    }
    return tool.outputIndex;
  };
  const ensureToolIdentifiers = (tool) => {
    if (!tool.id) {
      tool.id = `fc_${crypto.randomUUID()}`;
    }
    if (!tool.call_id) {
      tool.call_id = `call_${crypto.randomUUID()}`;
    }
  };

  const pushChoiceOutput = (state, indexedOutput) => {
    if (includeReasoningSummary && state.reasoningBuffer) {
      indexedOutput.push({
        index: ensureReasoningOutputIndex(state),
        item: {
          type: 'reasoning',
          id: state.reasoningItemId,
          status: 'completed',
          summary: [{
            type: 'summary_text',
            text: state.reasoningBuffer
          }]
        }
      });
    }
    if (state.textBuffer) {
      indexedOutput.push({
        index: ensureMessageOutputIndex(state),
        item: {
          type: 'message',
          id: state.messageItemId,
          role: 'assistant',
          status: 'completed',
          content: [{
            type: 'output_text',
            text: state.textBuffer,
            annotations: []
          }]
        }
      });
    }
    for (const tool of state.toolCalls) {
      ensureToolIdentifiers(tool);
      indexedOutput.push({
        index: ensureToolOutputIndex(tool),
        item: {
          type: 'function_call',
          id: tool.id,
          call_id: tool.call_id,
          name: tool.name,
          arguments: tool.arguments,
          status: 'completed'
        }
      });
    }
  }

  const toResponsesOutput = () => {
    const indexedOutput = [];
    for (const choiceIndex of choiceOrder) {
      const state = choiceStates.get(choiceIndex);
      if (!state) {
        continue;
      }
      pushChoiceOutput(state, indexedOutput);
    }
    if (!indexedOutput.length) {
      const fallbackChoice = getChoiceState(0);
      indexedOutput.push({
        index: ensureMessageOutputIndex(fallbackChoice),
        item: {
          type: 'message',
          id: fallbackChoice.messageItemId,
          role: 'assistant',
          status: 'completed',
          content: [{
            type: 'output_text',
            text: '',
            annotations: []
          }]
        }
      });
    }
    indexedOutput.sort((left, right) => left.index - right.index);
    return indexedOutput.map((entry) => entry.item);
  };

  const finish = () => {
    if (finished) {
      return '';
    }
    finished = true;
    const parts = [];
    for (const choiceIndex of choiceOrder) {
      const state = choiceStates.get(choiceIndex);
      if (!state) {
        continue;
      }
      if (includeReasoningSummary && state.reasoningBuffer) {
        const outputIndex = ensureReasoningOutputIndex(state);
        if (!state.emittedReasoningItemAdded) {
          state.emittedReasoningItemAdded = true;
          parts.push(emit({
            type: 'response.output_item.added',
            output_index: outputIndex,
            item: {
              type: 'reasoning',
              id: state.reasoningItemId,
              status: 'in_progress',
              summary: []
            }
          }));
        }
        if (!state.emittedReasoningSummaryPartAdded) {
          state.emittedReasoningSummaryPartAdded = true;
          parts.push(emit({
            type: 'response.reasoning_summary_part.added',
            item_id: state.reasoningItemId,
            output_index: outputIndex,
            summary_index: 0,
            part: {
              type: 'summary_text',
              text: ''
            }
          }));
        }
        parts.push(emit({
          type: 'response.reasoning_summary_text.done',
          item_id: state.reasoningItemId,
          output_index: outputIndex,
          summary_index: 0,
          text: state.reasoningBuffer
        }));
        parts.push(emit({
          type: 'response.reasoning_summary_part.done',
          item_id: state.reasoningItemId,
          output_index: outputIndex,
          summary_index: 0,
          part: {
            type: 'summary_text',
            text: state.reasoningBuffer
          }
        }));
        parts.push(emit({
          type: 'response.output_item.done',
          output_index: outputIndex,
          item: {
            type: 'reasoning',
            id: state.reasoningItemId,
            status: 'completed',
            summary: [{
              type: 'summary_text',
              text: state.reasoningBuffer
            }]
          }
        }));
      }
      if (state.textBuffer && !state.emittedTextItemAdded) {
        state.emittedTextItemAdded = true;
        const outputIndex = ensureMessageOutputIndex(state);
        parts.push(emit({
          type: 'response.output_item.added',
          output_index: outputIndex,
          item: {
            type: 'message',
            id: state.messageItemId,
            role: 'assistant',
            status: 'in_progress',
            content: []
          }
        }));
      }
      if (state.textBuffer && !state.emittedContentPartAdded) {
        state.emittedContentPartAdded = true;
        const outputIndex = ensureMessageOutputIndex(state);
        parts.push(emit({
          type: 'response.content_part.added',
          item_id: state.messageItemId,
          output_index: outputIndex,
          content_index: 0,
          part: {
            type: 'output_text',
            text: '',
            annotations: []
          }
        }));
      }
      if (state.textBuffer) {
        const outputIndex = ensureMessageOutputIndex(state);
        parts.push(emit({
          type: 'response.output_text.done',
          item_id: state.messageItemId,
          output_index: outputIndex,
          content_index: 0,
          text: state.textBuffer
        }));
        parts.push(emit({
          type: 'response.content_part.done',
          item_id: state.messageItemId,
          output_index: outputIndex,
          content_index: 0,
          part: {
            type: 'output_text',
            text: state.textBuffer,
            annotations: []
          }
        }));
        parts.push(emit({
          type: 'response.output_item.done',
          output_index: outputIndex,
          item: {
            type: 'message',
            id: state.messageItemId,
            role: 'assistant',
            status: 'completed',
            content: [{
              type: 'output_text',
              text: state.textBuffer,
              annotations: []
            }]
          }
        }));
      }
      if (state.toolCalls.length) {
        for (const tool of state.toolCalls) {
          ensureToolIdentifiers(tool);
          const outputIndex = ensureToolOutputIndex(tool);
          parts.push(emit({
            type: 'response.function_call_arguments.done',
            item_id: tool.id,
            output_index: outputIndex,
            arguments: tool.arguments
          }));
          parts.push(emit({
            type: 'response.output_item.done',
            output_index: outputIndex,
            item: {
              type: 'function_call',
              id: tool.id,
              call_id: tool.call_id,
              name: tool.name,
              arguments: tool.arguments,
              status: 'completed'
            }
          }));
        }
      }
    }
    const responsePayload = {
      id: rid,
      object: 'response',
      created_at: createdAt,
      status: 'completed',
      model: model || '',
      output: toResponsesOutput(),
      usage: buildResponsesUsageFromChatUsage(usage)
    };
    if (finalFinishReason === 'length' || finalFinishReason === 'content_filter') {
      responsePayload.status = 'incomplete';
      responsePayload.incomplete_details = { reason: finalFinishReason };
    }
    completedResponse = responsePayload;
    parts.push(emit({
      type: 'response.completed',
      response: responsePayload
    }));
    parts.push('data: [DONE]\n\n');
    return parts.join('');
  };

  const consumeChunk = (chunk) => {
    if (!chunk || typeof chunk !== 'object') {
      return '';
    }
    const parts = [];
    parts.push(maybeStart());
    if (chunk.model && !model) {
      model = String(chunk.model || '');
    }
    if (chunk.usage && typeof chunk.usage === 'object') {
      usage = chunk.usage;
    }

    const choices = Array.isArray(chunk.choices) ? chunk.choices : [];
    for (const choice of choices) {
      const choiceIndex = Number.isFinite(choice?.index) ? choice.index : 0;
      const state = getChoiceState(choiceIndex);
      const delta = choice?.delta || {};
      if (includeReasoningSummary) {
        const reasoningDelta = extractReasoningDelta(delta);
        if (reasoningDelta) {
          const outputIndex = ensureReasoningOutputIndex(state);
          if (!state.emittedReasoningItemAdded) {
            state.emittedReasoningItemAdded = true;
            parts.push(emit({
              type: 'response.output_item.added',
              output_index: outputIndex,
              item: {
                type: 'reasoning',
                id: state.reasoningItemId,
                status: 'in_progress',
                summary: []
              }
            }));
          }
          if (!state.emittedReasoningSummaryPartAdded) {
            state.emittedReasoningSummaryPartAdded = true;
            parts.push(emit({
              type: 'response.reasoning_summary_part.added',
              item_id: state.reasoningItemId,
              output_index: outputIndex,
              summary_index: 0,
              part: {
                type: 'summary_text',
                text: ''
              }
            }));
          }
          state.reasoningBuffer += reasoningDelta;
          parts.push(emit({
            type: 'response.reasoning_summary_text.delta',
            item_id: state.reasoningItemId,
            output_index: outputIndex,
            summary_index: 0,
            delta: reasoningDelta
          }));
        }
      }

      const deltaText = extractChatDeltaText(delta.content) || ensureStringContent(delta.content || '');
      if (deltaText) {
        const outputIndex = ensureMessageOutputIndex(state);
        if (!state.emittedTextItemAdded) {
          state.emittedTextItemAdded = true;
          parts.push(emit({
            type: 'response.output_item.added',
            output_index: outputIndex,
            item: {
              type: 'message',
              id: state.messageItemId,
              role: 'assistant',
              status: 'in_progress',
              content: []
            }
          }));
        }
        if (!state.emittedContentPartAdded) {
          state.emittedContentPartAdded = true;
          parts.push(emit({
            type: 'response.content_part.added',
            item_id: state.messageItemId,
            output_index: outputIndex,
            content_index: 0,
            part: {
              type: 'output_text',
              text: '',
              annotations: []
            }
          }));
        }
        state.textBuffer += deltaText;
        parts.push(emit({
          type: 'response.output_text.delta',
          item_id: state.messageItemId,
          output_index: outputIndex,
          content_index: 0,
          delta: deltaText
        }));
      }

      if (Array.isArray(delta.tool_calls)) {
        for (const toolCallDelta of delta.tool_calls) {
          const index = Number.isFinite(toolCallDelta?.index) ? toolCallDelta.index : state.toolCalls.length;
          while (state.toolCalls.length <= index) {
            state.toolCalls.push({
              id: '',
              call_id: '',
              name: '',
              arguments: '',
              outputIndex: null,
              emittedAdded: false
            });
          }
          const target = state.toolCalls[index];
          if (toolCallDelta?.id && !target.emittedAdded) {
            target.id = String(toolCallDelta.id);
            target.call_id = String(toolCallDelta.id);
          }
          if (toolCallDelta?.function?.name) {
            target.name = String(toolCallDelta.function.name);
          }
          ensureToolIdentifiers(target);
          const outputIndex = ensureToolOutputIndex(target);
          if (!target.emittedAdded) {
            target.emittedAdded = true;
            parts.push(emit({
              type: 'response.output_item.added',
              output_index: outputIndex,
              item: {
                type: 'function_call',
                id: target.id,
                call_id: target.call_id,
                name: target.name,
                arguments: '',
                status: 'in_progress'
              }
            }));
          }
          if (typeof toolCallDelta?.function?.arguments === 'string') {
            target.arguments += toolCallDelta.function.arguments;
            parts.push(emit({
              type: 'response.function_call_arguments.delta',
              item_id: target.id,
              output_index: outputIndex,
              delta: toolCallDelta.function.arguments
            }));
          }
        }
      }

      const finishReason = String(choice?.finish_reason || '').trim();
      if (finishReason) {
        if (finishReason === 'length' || finishReason === 'content_filter') {
          finalFinishReason = finishReason;
        } else if (!finalFinishReason) {
          finalFinishReason = finishReason;
        }
        state.finished = true;
      }
    }

    return parts.join('');
  };

  return {
    consumeChunk,
    finish,
    getUsage: () => buildResponsesUsageFromChatUsage(usage),
    getCompletedResponse: () => completedResponse
  };
}

function createChatCompletionsToResponsesSseTransform(
  { responseId, model, includeReasoningSummary = false } = {}
) {
  const parser = createResponsesCompatStreamParser({
    responseId,
    model,
    includeReasoningSummary
  });
  let buffer = '';
  let currentDataLines = [];

  const flushData = (push) => {
    if (!currentDataLines.length) {
      return;
    }
    const payloadText = currentDataLines.join('\n').trim();
    currentDataLines = [];
    if (!payloadText) {
      return;
    }
    if (payloadText === '[DONE]') {
      push(parser.finish());
      return;
    }
    const payload = safeJsonParse(payloadText);
    if (!payload) {
      return;
    }
    push(parser.consumeChunk(payload));
  };

  const transformer = new Transform({
    transform(chunk, _encoding, callback) {
      buffer += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk || '');
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? '';
      for (const line of lines) {
        if (line === '') {
          flushData((eventPayload) => {
            if (eventPayload) {
              this.push(eventPayload);
            }
          });
          continue;
        }
        if (line.startsWith('data:')) {
          currentDataLines.push(line.slice(5).trimStart());
        }
      }
      callback();
    },
    flush(callback) {
      if (buffer) {
        if (buffer.startsWith('data:')) {
          currentDataLines.push(buffer.slice(5).trimStart());
        }
        buffer = '';
      }
      flushData((eventPayload) => {
        if (eventPayload) {
          this.push(eventPayload);
        }
      });
      const tail = parser.finish();
      if (tail) {
        this.push(tail);
      }
      callback();
    }
  });

  return {
    transformer,
    getUsage: () => parser.getUsage(),
    getCompletedResponse: () => parser.getCompletedResponse()
  };
}

function createStreamUsageObserver(contentType, { onUsage, onPayload, onResponseId } = {}) {
  const lower = String(contentType || '').toLowerCase();
  const isSse = lower.includes('text/event-stream');
  let buffer = '';
  let eventDataLines = [];

  const maybeCaptureUsage = (text) => {
    const trimmed = String(text || '').trim();
    if (!trimmed || trimmed === '[DONE]') {
      return;
    }
    const payload = safeJsonParse(trimmed);
    if (!payload) {
      return;
    }
    if (typeof onPayload === 'function') {
      onPayload(payload);
    }
    const responseId = extractResponseContinuationIdFromPayload(payload);
    if (responseId && typeof onResponseId === 'function') {
      onResponseId(responseId);
    }
    const usage = extractUsageFromPayload(payload);
    if (usage && typeof onUsage === 'function') {
      onUsage(usage);
    }
  };

  const consumeSseLine = (line) => {
    if (line === '') {
      if (eventDataLines.length) {
        maybeCaptureUsage(eventDataLines.join('\n'));
      }
      eventDataLines = [];
      return;
    }
    if (line.startsWith('data:')) {
      eventDataLines.push(line.slice(5).trimStart());
    }
  };

  return new Transform({
    transform(chunk, _encoding, callback) {
      const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk || '');
      buffer += text;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() ?? '';

      if (isSse) {
        for (const line of lines) {
          consumeSseLine(line);
        }
      } else {
        for (const line of lines) {
          maybeCaptureUsage(line);
        }
      }

      callback(null, chunk);
    },
    flush(callback) {
      if (isSse) {
        if (buffer) {
          consumeSseLine(buffer);
        }
        if (eventDataLines.length) {
          maybeCaptureUsage(eventDataLines.join('\n'));
        }
      } else if (buffer) {
        maybeCaptureUsage(buffer);
      }
      callback();
    }
  });
}

function isStreamingRequest({ supportsStreamField, jsonBody, req }) {
  if (!supportsStreamField) {
    return false;
  }
  if (jsonBody && typeof jsonBody === 'object' && jsonBody.stream === true) {
    return true;
  }
  const accept = String(req.headers.accept || '').toLowerCase();
  return accept.includes('text/event-stream');
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
  return res.redirect('/admin/accounts');
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
  res.render('admin-cache', {
    activePage: 'cache',
    settings,
    stats: buildAdminStats(accounts),
    notice: req.query.notice || '',
    runtimes,
    summary: {
      enabledGroups: cacheGroups.length,
      totalHits,
      totalMisses,
      totalRequests,
      totalHitRate
    }
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

  const shouldSyncModels = req.body.syncModelsAfterCreate === 'on';
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
  const cacheEnabled = req.body.cacheEnabled === 'on';
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
    enabled: req.body.enabled === 'on',
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
  const cacheEnabled = req.body.cacheEnabled === 'on';
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
    enabled: req.body.enabled === 'on'
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
    enabled: req.body.enabled === 'on'
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
      id: `${Date.now()}-${(++requestLogSeq).toString(36)}`,
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
      if (cacheChatBody && cacheChatBody.stream === true) {
        // First checkpoint: only non-stream Claude caching path.
        cacheChatBody = null;
      }
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
        writeRequestLog({
          statusCode: 502,
          errorDetail: `PromptCache proxy failed: ${error?.message || 'unknown error'}`
        });
        res.status(502).json({
          error: 'PromptCache proxy failed',
          detail: error?.message || 'unknown error'
        });
        return;
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
      errorDetail: selection.error || 'No account available'
    });
    res.status(429).json({ error: selection.error || 'No account available' });
    return;
  }

  let account = selection.account;
  const quotaModel = requestModel || upstreamModel || '';
  const maxAttemptCount = 3;
  let attemptCount = 1;
  let switchCount = 0;
  let lastRetryReason = '';
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
