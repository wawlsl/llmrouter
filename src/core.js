import crypto from 'crypto';

const durationUnits = {
  minute: 60 * 1000,
  hour: 60 * 60 * 1000,
  day: 24 * 60 * 60 * 1000,
  week: 7 * 24 * 60 * 60 * 1000
};

export function parseDurationMs(value, unit) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) {
    return 0;
  }
  const unitMs = durationUnits[unit] ?? 0;
  if (!unitMs) {
    return 0;
  }
  return Math.round(number * unitMs);
}

function canonicalize(input) {
  if (input === null || typeof input !== 'object') {
    return input;
  }
  if (Array.isArray(input)) {
    return input.map(canonicalize);
  }
  const sorted = {};
  for (const key of Object.keys(input).sort()) {
    sorted[key] = canonicalize(input[key]);
  }
  return sorted;
}

export function buildStickyKey(method, path, bodyObject, queryObject) {
  const normalized = {
    method: method.toUpperCase(),
    path,
    query: canonicalize(queryObject ?? {}),
    body: canonicalize(bodyObject ?? {})
  };
  const text = JSON.stringify(normalized);
  return crypto.createHash('sha256').update(text).digest('hex');
}

function ensureQuotaWindow(account, nowMs, tier) {
  const windowMs = tier === 1 ? account.quotaWindowMs : account.quotaWindowMs2;
  const startKey = tier === 1 ? 'windowStartMs' : 'windowStartMs2';
  const usedKey = tier === 1 ? 'usedRequests' : 'usedRequests2';
  if (!account.stats[startKey]) {
    account.stats[startKey] = nowMs;
    return;
  }
  if (!windowMs || windowMs <= 0) {
    return;
  }
  if (nowMs - account.stats[startKey] >= windowMs) {
    account.stats[startKey] = nowMs;
    account.stats[usedKey] = 0;
  }
}

export function hasQuota(account, nowMs) {
  ensureQuotaWindow(account, nowMs, 1);
  ensureQuotaWindow(account, nowMs, 2);
  const primaryOk = !account.quotaLimit || account.quotaLimit <= 0
    ? true
    : account.stats.usedRequests < account.quotaLimit;
  const secondaryOk = !account.quotaLimit2 || account.quotaLimit2 <= 0
    ? true
    : (account.stats.usedRequests2 || 0) < account.quotaLimit2;
  return primaryOk && secondaryOk;
}

export function consumeQuota(account, nowMs) {
  ensureQuotaWindow(account, nowMs, 1);
  ensureQuotaWindow(account, nowMs, 2);
  account.stats.usedRequests += 1;
  account.stats.usedRequests2 = (account.stats.usedRequests2 || 0) + 1;
  account.stats.totalRequests += 1;
  account.stats.lastUsedAt = new Date(nowMs).toISOString();
}

export function quotaResetAt(account) {
  if (!account.quotaWindowMs || !account.stats.windowStartMs) {
    return '';
  }
  return new Date(account.stats.windowStartMs + account.quotaWindowMs).toISOString();
}

export function quotaResetAtSecondary(account) {
  if (!account.quotaWindowMs2 || !account.stats.windowStartMs2) {
    return '';
  }
  return new Date(account.stats.windowStartMs2 + account.quotaWindowMs2).toISOString();
}

export function accountWindowMs(account, fallbackWindowMs) {
  if (account.stickyWindowMs && account.stickyWindowMs > 0) {
    return account.stickyWindowMs;
  }
  return fallbackWindowMs;
}

function weightedScore(account, normalizedSeed) {
  const weight = Number.isFinite(account.weight) ? Math.max(1, Math.floor(account.weight)) : 1;
  const key = `${normalizedSeed}:${account.id || account.name || ''}`;
  const hash = crypto.createHash('sha256').update(key).digest();
  const raw = hash.readUInt32BE(0) * 2 ** 21 + (hash.readUInt32BE(4) >>> 11);
  const uniform = (raw + 1) / (2 ** 53 + 1);
  return -Math.log(uniform) / weight;
}

export function rankWeightedAccounts(accounts, seed = '') {
  if (!Array.isArray(accounts) || !accounts.length) {
    return [];
  }

  const normalizedSeed = String(seed || crypto.randomUUID());
  return [...accounts]
    .map((account) => ({ account, score: weightedScore(account, normalizedSeed) }))
    .sort((left, right) => left.score - right.score)
    .map((item) => item.account);
}

export function pickWeightedAccount(accounts, seed = '') {
  const ranked = rankWeightedAccounts(accounts, seed);
  return ranked[0] || null;
}

export function sanitizeAccountInput(body, fallbackBaseUrl) {
  const quotaLimitRaw = Number(body.quotaLimit);
  const quotaLimit2Raw = Number(body.quotaLimit2);
  const weightRaw = Number(body.weight);
  const stickyWindowMinutesRaw = Number(body.stickyWindowMinutes);

  const providerRaw = String(body.provider || 'openai').trim().toLowerCase();
  const provider = providerRaw === 'anthropic' ? 'anthropic' : 'openai';
  const forceResponsesCompat = (
    body.forceResponsesCompat === 'on' ||
    body.forceResponsesCompat === true ||
    body.forceResponsesCompat === 1 ||
    body.forceResponsesCompat === '1'
  );

  return {
    name: (body.name ?? '').trim(),
    provider,
    apiKey: (body.apiKey ?? '').trim(),
    baseUrl: (body.baseUrl ?? fallbackBaseUrl ?? 'https://api.openai.com').trim().replace(/\/$/, ''),
    enabled: body.enabled === 'on' || body.enabled === true,
    weight: Number.isFinite(weightRaw) && weightRaw > 0 ? Math.floor(weightRaw) : 1,
    quotaLimit: Number.isFinite(quotaLimitRaw) && quotaLimitRaw > 0 ? Math.floor(quotaLimitRaw) : 0,
    quotaWindowMs: parseDurationMs(body.quotaWindowValue, body.quotaWindowUnit),
    quotaLimit2: Number.isFinite(quotaLimit2Raw) && quotaLimit2Raw > 0 ? Math.floor(quotaLimit2Raw) : 0,
    quotaWindowMs2: parseDurationMs(body.quotaWindowValue2, body.quotaWindowUnit2),
    stickyWindowMs: Number.isFinite(stickyWindowMinutesRaw) && stickyWindowMinutesRaw > 0
      ? Math.floor(stickyWindowMinutesRaw * 60 * 1000)
      : 0,
    forceResponsesCompat
  };
}

export function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
