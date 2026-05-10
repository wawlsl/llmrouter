import crypto from 'crypto';

function parseBooleanLike(value, fallback = false) {
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) {
    return fallback;
  }
  return ['1', 'true', 'yes', 'on', 'enabled'].includes(text);
}

function asFiniteNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

export function normalizeRiskControlMode(value) {
  const text = String(value || '').trim().toLowerCase();
  if (text === 'pre_block' || text === 'preblock') {
    return 'pre_block';
  }
  if (text === 'off' || text === 'disabled') {
    return 'off';
  }
  return 'observe';
}

export function normalizeRiskControlScopeMode(value) {
  const text = String(value || '').trim().toLowerCase();
  if (text === 'selected' || text === 'group_selected' || text === 'groups') {
    return 'selected';
  }
  return 'all';
}

function parseRiskControlGroupIdSet(raw) {
  const text = String(raw || '').trim();
  if (!text) {
    return new Set();
  }
  return new Set(
    text
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
  );
}

function normalizeWhitespace(text) {
  return String(text || '').replace(/\s+/g, ' ').trim();
}

function maybePushText(parts, value) {
  const text = normalizeWhitespace(value);
  if (!text) {
    return;
  }
  if (text.startsWith('<system-reminder>')) {
    return;
  }
  parts.push(text);
}

function collectContentText(value, parts, depth = 0) {
  if (depth > 8 || value === null || value === undefined) {
    return;
  }
  if (typeof value === 'string') {
    maybePushText(parts, value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectContentText(item, parts, depth + 1);
    }
    return;
  }
  if (typeof value !== 'object') {
    return;
  }
  if (Object.prototype.hasOwnProperty.call(value, 'text')) {
    maybePushText(parts, value.text);
  }
  if (Object.prototype.hasOwnProperty.call(value, 'content')) {
    collectContentText(value.content, parts, depth + 1);
  }
  if (Object.prototype.hasOwnProperty.call(value, 'input_text')) {
    collectContentText(value.input_text, parts, depth + 1);
  }
}

function extractLastUserTextFromMessages(messages) {
  if (!Array.isArray(messages)) {
    return '';
  }
  let last = '';
  for (const message of messages) {
    if (!message || typeof message !== 'object') {
      continue;
    }
    const role = String(message.role || '').trim().toLowerCase();
    if (role !== 'user') {
      continue;
    }
    const parts = [];
    collectContentText(message.content, parts);
    const joined = normalizeWhitespace(parts.join('\n'));
    if (joined) {
      last = joined;
    }
  }
  return last;
}

function extractLastUserTextFromResponsesInput(input) {
  if (typeof input === 'string') {
    return normalizeWhitespace(input);
  }
  if (!Array.isArray(input)) {
    return '';
  }
  let last = '';
  for (const item of input) {
    if (!item || typeof item !== 'object') {
      continue;
    }
    const role = String(item.role || '').trim().toLowerCase();
    if (role && role !== 'user') {
      continue;
    }
    const parts = [];
    if (Object.prototype.hasOwnProperty.call(item, 'content')) {
      collectContentText(item.content, parts);
    }
    if (Object.prototype.hasOwnProperty.call(item, 'text')) {
      collectContentText(item.text, parts);
    }
    if (Object.prototype.hasOwnProperty.call(item, 'input_text')) {
      collectContentText(item.input_text, parts);
    }
    const joined = normalizeWhitespace(parts.join('\n'));
    if (joined) {
      last = joined;
    }
  }
  return last;
}

function extractLastUserTextFromGemini(contents) {
  if (!Array.isArray(contents)) {
    return '';
  }
  let last = '';
  for (const item of contents) {
    if (!item || typeof item !== 'object') {
      continue;
    }
    const role = String(item.role || '').trim().toLowerCase();
    if (role && role !== 'user') {
      continue;
    }
    const parts = [];
    const p = Array.isArray(item.parts) ? item.parts : [];
    for (const part of p) {
      if (part && typeof part === 'object' && Object.prototype.hasOwnProperty.call(part, 'text')) {
        maybePushText(parts, part.text);
      }
    }
    const joined = normalizeWhitespace(parts.join('\n'));
    if (joined) {
      last = joined;
    }
  }
  return last;
}

function extractRiskControlText(req, jsonBody) {
  const path = String(req?.path || '');
  if (!jsonBody || typeof jsonBody !== 'object') {
    return '';
  }
  if (path.startsWith('/v1/messages')) {
    return extractLastUserTextFromMessages(jsonBody.messages);
  }
  if (path.startsWith('/v1/chat/completions')) {
    return extractLastUserTextFromMessages(jsonBody.messages);
  }
  if (path.startsWith('/v1/responses')) {
    return extractLastUserTextFromResponsesInput(jsonBody.input);
  }
  if (path.includes('/gemini') || Array.isArray(jsonBody.contents)) {
    return extractLastUserTextFromGemini(jsonBody.contents);
  }
  return (
    extractLastUserTextFromResponsesInput(jsonBody.input)
    || extractLastUserTextFromMessages(jsonBody.messages)
    || extractLastUserTextFromGemini(jsonBody.contents)
    || normalizeWhitespace(String(jsonBody.prompt || ''))
  );
}

function buildRiskInputHash(pathname, text) {
  const hash = crypto.createHash('sha256');
  hash.update(String(pathname || ''));
  hash.update('\n');
  hash.update(String(text || ''));
  return hash.digest('hex');
}

function textExcerpt(text, limit = 240) {
  const normalized = normalizeWhitespace(text);
  if (normalized.length <= limit) {
    return normalized;
  }
  return `${normalized.slice(0, limit)}...`;
}

function shouldApplyRiskControl(req) {
  if (req.method !== 'POST') {
    return false;
  }
  return (
    req.path === '/v1/responses'
    || req.path === '/v1/responses/compact'
    || req.path === '/v1/chat/completions'
    || req.path === '/v1/messages'
  );
}

function sampleByHash(hashHex, sampleRate) {
  if (sampleRate >= 100) {
    return true;
  }
  if (sampleRate <= 0) {
    return false;
  }
  const prefix = String(hashHex || '').slice(0, 8);
  const value = Number.parseInt(prefix, 16);
  if (!Number.isFinite(value)) {
    return Math.random() * 100 < sampleRate;
  }
  return (value % 100) < sampleRate;
}

function normalizeModerationScores(value, output = {}, prefix = '') {
  if (!value || typeof value !== 'object') {
    return output;
  }
  for (const [key, child] of Object.entries(value)) {
    const nextKey = prefix ? `${prefix}/${key}` : key;
    if (typeof child === 'number' && Number.isFinite(child)) {
      output[nextKey] = child;
      continue;
    }
    if (child && typeof child === 'object') {
      normalizeModerationScores(child, output, nextKey);
    }
  }
  return output;
}

function evaluateModerationResult(payload, threshold = 0.7) {
  const results = Array.isArray(payload?.results) ? payload.results : [];
  const first = results[0] && typeof results[0] === 'object' ? results[0] : {};
  const flatScores = normalizeModerationScores(first.category_scores || {}, {});
  const flaggedByProvider = first.flagged === true;
  let bestCategory = '';
  let bestScore = 0;
  for (const [category, score] of Object.entries(flatScores)) {
    if (score > bestScore) {
      bestScore = score;
      bestCategory = category;
    }
  }
  return {
    flagged: flaggedByProvider || bestScore >= threshold,
    score: bestScore,
    category: bestCategory
  };
}

export function createRiskControlModule({
  store,
  getSettings,
  buildUpstreamUrl,
  safeJsonParse,
  sanitizeLogText,
  extractErrorDetail,
  fetchImpl = fetch
}) {
  const tasks = [];
  let activeWorkers = 0;
  let dropCount = 0;
  let processedCount = 0;

  function buildConfig() {
    const current = getSettings() || {};
    const mode = normalizeRiskControlMode(current.riskControlMode);
    const scopeMode = normalizeRiskControlScopeMode(current.riskControlScopeMode);
    const groupIds = parseRiskControlGroupIdSet(current.riskControlGroupIds);
    const enabled = parseBooleanLike(current.riskControlEnabled, false) && mode !== 'off';
    const sampleRateRaw = Math.floor(asFiniteNumber(current.riskControlSampleRate, 100));
    const sampleRate = Math.min(Math.max(sampleRateRaw, 0), 100);
    const l1TimeoutMs = Math.min(Math.max(Math.floor(asFiniteNumber(current.riskControlL1TimeoutMs, 5000)), 500), 30000);
    const l2TimeoutMs = Math.min(Math.max(Math.floor(asFiniteNumber(current.riskControlL2TimeoutMs, 12000)), 500), 60000);
    const queueSize = Math.min(Math.max(Math.floor(asFiniteNumber(current.riskControlQueueSize, 2000)), 50), 50000);
    const workerConcurrency = Math.min(Math.max(Math.floor(asFiniteNumber(current.riskControlWorkerConcurrency, 2)), 1), 12);
    const l1Threshold = Math.min(Math.max(asFiniteNumber(current.riskControlL1Threshold, 0.7), 0), 1);
    const l2Temperature = Math.min(Math.max(asFiniteNumber(current.riskControlL2Temperature, 0), 0), 2);
    const l2MaxTokens = Math.min(Math.max(Math.floor(asFiniteNumber(current.riskControlL2MaxTokens, 200)), 16), 4096);
    const retentionDays = Math.min(Math.max(Math.floor(asFiniteNumber(current.riskControlRetentionDays, 30)), 1), 3650);

    return {
      enabled,
      mode,
      scopeMode,
      groupIds,
      sampleRate,
      queueSize,
      workerConcurrency,
      l1: {
        enabled: parseBooleanLike(current.riskControlL1Enabled, true),
        baseUrl: String(current.riskControlL1BaseUrl || 'https://api.openai.com').trim(),
        apiKey: String(current.riskControlL1ApiKey || '').trim(),
        model: String(current.riskControlL1Model || 'omni-moderation-latest').trim(),
        threshold: l1Threshold,
        timeoutMs: l1TimeoutMs
      },
      l2: {
        enabled: parseBooleanLike(current.riskControlL2Enabled, false),
        baseUrl: String(current.riskControlL2BaseUrl || 'https://api.openai.com').trim(),
        apiKey: String(current.riskControlL2ApiKey || '').trim(),
        model: String(current.riskControlL2Model || 'gpt-4.1-mini').trim(),
        prompt: String(current.riskControlL2Prompt || '').trim(),
        temperature: l2Temperature,
        maxTokens: l2MaxTokens,
        timeoutMs: l2TimeoutMs
      },
      blockMessage: String(current.riskControlBlockMessage || '内容审查命中风险规则，请调整输入后重试').trim(),
      retentionDays
    };
  }

  function isEnabledForGroup(authResult = {}, cfg = null) {
    const riskCfg = cfg || buildConfig();
    if (!riskCfg.enabled) {
      return false;
    }
    if (riskCfg.scopeMode !== 'selected') {
      return true;
    }
    const groupId = String(authResult.groupId || '').trim();
    if (groupId) {
      return riskCfg.groupIds.has(groupId);
    }
    const groupKey = String(authResult.groupKey || '').trim();
    if (!groupKey) {
      return false;
    }
    return riskCfg.groupIds.has(groupKey);
  }

  function appendLog(entry) {
    store.appendRiskControlLog({
      id: crypto.randomUUID(),
      at: new Date().toISOString(),
      requestId: entry.requestId || '',
      groupKey: entry.contextInfo?.groupKey || '',
      accessKeyId: entry.contextInfo?.accessKeyId || '',
      provider: entry.contextInfo?.provider || '',
      path: entry.contextInfo?.path || '',
      model: entry.contextInfo?.model || '',
      account: entry.contextInfo?.account || '',
      mode: entry.mode || 'observe',
      action: entry.action || 'allow',
      blocked: entry.blocked === true,
      sampled: entry.sampled !== false,
      inputHash: entry.inputHash || '',
      excerpt: textExcerpt(entry.text || '', 260),
      l1Flagged: entry.l1?.flagged === true,
      l1Score: entry.l1?.score || 0,
      l1Category: entry.l1?.category || '',
      l1Error: entry.l1?.error || '',
      l1LatencyMs: entry.l1?.latencyMs || 0,
      l2Flagged: entry.l2?.flagged === true,
      l2Score: entry.l2?.score || 0,
      l2Reason: entry.l2?.reason || '',
      l2Raw: entry.l2?.raw || '',
      l2Error: entry.l2?.error || '',
      l2LatencyMs: entry.l2?.latencyMs || 0,
      finalReason: entry.finalReason || '',
      statusCode: entry.statusCode || 0
    });
  }

  async function runL1Moderation(text, cfg) {
    if (!cfg.l1.enabled || !cfg.l1.baseUrl || !cfg.l1.apiKey || !cfg.l1.model) {
      return { enabled: false, flagged: false, score: 0, category: '', latencyMs: 0, error: '' };
    }
    const started = Date.now();
    try {
      const target = buildUpstreamUrl(cfg.l1.baseUrl, '/v1/moderations');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort('l1-timeout'), cfg.l1.timeoutMs);
      const response = await fetchImpl(target, {
        method: 'POST',
        headers: { authorization: `Bearer ${cfg.l1.apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ model: cfg.l1.model, input: text }),
        signal: controller.signal
      });
      clearTimeout(timer);
      const payload = safeJsonParse(await response.text());
      if (!response.ok) {
        return {
          enabled: true,
          flagged: false,
          score: 0,
          category: '',
          latencyMs: Date.now() - started,
          error: extractErrorDetail(payload, `L1 moderation error ${response.status}`)
        };
      }
      const result = evaluateModerationResult(payload, cfg.l1.threshold);
      return {
        enabled: true,
        flagged: result.flagged,
        score: result.score,
        category: result.category,
        latencyMs: Date.now() - started,
        error: ''
      };
    } catch (error) {
      return {
        enabled: true,
        flagged: false,
        score: 0,
        category: '',
        latencyMs: Date.now() - started,
        error: sanitizeLogText(error?.message || 'L1 moderation failed', 300)
      };
    }
  }

  function parseL2Json(text) {
    const direct = safeJsonParse(text);
    if (direct && typeof direct === 'object') {
      return direct;
    }
    const match = String(text || '').match(/\{[\s\S]*\}/);
    if (!match) {
      return null;
    }
    const nested = safeJsonParse(match[0]);
    return nested && typeof nested === 'object' ? nested : null;
  }

  async function runL2Review(text, contextInfo, cfg) {
    if (!cfg.l2.enabled || !cfg.l2.baseUrl || !cfg.l2.apiKey || !cfg.l2.model || !cfg.l2.prompt) {
      return { enabled: false, flagged: false, score: 0, reason: '', raw: '', latencyMs: 0, error: '' };
    }
    const started = Date.now();
    try {
      const target = buildUpstreamUrl(cfg.l2.baseUrl, '/v1/chat/completions');
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort('l2-timeout'), cfg.l2.timeoutMs);
      const userText = [
        `path=${contextInfo.path}`,
        `provider=${contextInfo.provider}`,
        `model=${contextInfo.model}`,
        `group_key=${contextInfo.groupKey}`,
        '-----',
        text
      ].join('\n');
      const response = await fetchImpl(target, {
        method: 'POST',
        headers: { authorization: `Bearer ${cfg.l2.apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          model: cfg.l2.model,
          temperature: cfg.l2.temperature,
          max_tokens: cfg.l2.maxTokens,
          messages: [
            { role: 'system', content: cfg.l2.prompt },
            { role: 'user', content: userText }
          ]
        }),
        signal: controller.signal
      });
      clearTimeout(timer);
      const responseText = await response.text();
      const payload = safeJsonParse(responseText);
      if (!response.ok) {
        return {
          enabled: true,
          flagged: false,
          score: 0,
          reason: '',
          raw: sanitizeLogText(responseText, 1200),
          latencyMs: Date.now() - started,
          error: extractErrorDetail(payload, `L2 review error ${response.status}`)
        };
      }
      const content = String(payload?.choices?.[0]?.message?.content || payload?.output_text || '');
      const parsed = parseL2Json(content);
      const riskRaw = String(parsed?.risk || parsed?.decision || '').trim().toLowerCase();
      const reason = String(parsed?.reason || parsed?.message || '').trim();
      const score = Math.min(Math.max(asFiniteNumber(parsed?.score, 0), 0), 1);
      return {
        enabled: true,
        flagged: riskRaw === 'block' || riskRaw === 'deny' || riskRaw === 'reject',
        score,
        reason: sanitizeLogText(reason, 400),
        raw: sanitizeLogText(content, 1200),
        latencyMs: Date.now() - started,
        error: ''
      };
    } catch (error) {
      return {
        enabled: true,
        flagged: false,
        score: 0,
        reason: '',
        raw: '',
        latencyMs: Date.now() - started,
        error: sanitizeLogText(error?.message || 'L2 review failed', 300)
      };
    }
  }

  function trimHistoryIfNeeded() {
    const cfg = buildConfig();
    const approxMaxRows = Math.max(cfg.retentionDays * 5000, 10000);
    store.trimRiskControlLogs(approxMaxRows);
  }

  async function runSyncAndMaybeBlock(task, cfg) {
    const l1 = await runL1Moderation(task.text, cfg);
    const l2 = await runL2Review(task.text, task.contextInfo, cfg);
    const blocked = cfg.mode === 'pre_block' && (l1.flagged || l2.flagged);
    appendLog({
      requestId: task.requestId,
      contextInfo: task.contextInfo,
      mode: cfg.mode,
      action: blocked ? 'block' : (l1.flagged || l2.flagged ? 'flag' : 'allow'),
      blocked,
      sampled: true,
      inputHash: task.inputHash,
      text: task.text,
      l1,
      l2,
      finalReason: blocked ? (l2.reason || `${l1.category}:${l1.score.toFixed(3)}`) : '',
      statusCode: blocked ? 403 : 200
    });
    return {
      blocked,
      message: blocked ? (cfg.blockMessage || '内容审查命中风险规则，请调整输入后重试') : ''
    };
  }

  function schedule(task) {
    const cfg = buildConfig();
    if (!cfg.enabled) {
      return { ok: false, reason: 'disabled' };
    }
    if (tasks.length >= cfg.queueSize) {
      dropCount += 1;
      return { ok: false, reason: 'queue_full' };
    }
    tasks.push(task);
    void processQueue();
    return { ok: true, reason: 'enqueued' };
  }

  async function processQueue() {
    const cfg = buildConfig();
    while (activeWorkers < cfg.workerConcurrency && tasks.length > 0) {
      const nextTask = tasks.shift();
      if (!nextTask) {
        break;
      }
      activeWorkers += 1;
      (async () => {
        try {
          const l1 = await runL1Moderation(nextTask.text, cfg);
          const l2 = await runL2Review(nextTask.text, nextTask.contextInfo, cfg);
          const blocked = cfg.mode === 'pre_block' && (l1.flagged || l2.flagged);
          appendLog({
            requestId: nextTask.requestId,
            contextInfo: nextTask.contextInfo,
            mode: cfg.mode,
            action: blocked ? 'block' : (l1.flagged || l2.flagged ? 'flag' : 'allow'),
            blocked,
            sampled: true,
            inputHash: nextTask.inputHash,
            text: nextTask.text,
            l1,
            l2,
            finalReason: blocked ? (l2.reason || `${l1.category}:${l1.score.toFixed(3)}`) : '',
            statusCode: blocked ? 403 : 200
          });
          processedCount += 1;
          if (processedCount % 50 === 0) {
            trimHistoryIfNeeded();
          }
        } catch {
          // keep gateway path unaffected
        } finally {
          activeWorkers = Math.max(activeWorkers - 1, 0);
          void processQueue();
        }
      })();
    }
  }

  function getSummary() {
    return {
      queueSize: tasks.length,
      workerActive: activeWorkers,
      dropped: dropCount,
      processed: processedCount
    };
  }

  async function applyIfNeeded({
    req,
    res,
    jsonBody,
    requestProvider,
    requestModel,
    authResult,
    selectedAccountName = ''
  }) {
    if (!shouldApplyRiskControl(req)) {
      return { blocked: false };
    }
    const cfg = buildConfig();
    if (!isEnabledForGroup(authResult, cfg)) {
      return { blocked: false };
    }
    const text = extractRiskControlText(req, jsonBody);
    if (!text) {
      return { blocked: false };
    }

    const inputHash = buildRiskInputHash(req.path, text);
    const sampled = sampleByHash(inputHash, cfg.sampleRate);
    const contextInfo = {
      provider: requestProvider || '',
      path: req.path,
      model: requestModel || '',
      groupKey: authResult.groupKey || '',
      accessKeyId: authResult.accessKeyId || '',
      account: selectedAccountName || ''
    };
    const task = {
      requestId: crypto.randomUUID(),
      text,
      inputHash,
      contextInfo
    };

    if (!sampled) {
      appendLog({
        requestId: task.requestId,
        contextInfo,
        mode: cfg.mode,
        action: 'skip_sample',
        blocked: false,
        sampled: false,
        inputHash: task.inputHash,
        text: task.text,
        finalReason: `sample_rate=${cfg.sampleRate}`,
        statusCode: 204
      });
      return { blocked: false };
    }

    if (cfg.mode === 'pre_block') {
      const result = await runSyncAndMaybeBlock(task, cfg);
      if (result.blocked) {
        res.status(403).json({
          error: {
            message: result.message,
            type: 'content_policy_violation',
            code: 'risk_control_blocked'
          }
        });
        return { blocked: true };
      }
      return { blocked: false };
    }

    const queued = schedule(task);
    if (!queued.ok) {
      appendLog({
        requestId: task.requestId,
        contextInfo,
        mode: cfg.mode,
        action: queued.reason === 'queue_full' ? 'queue_drop' : 'skip',
        blocked: false,
        sampled: true,
        inputHash: task.inputHash,
        text: task.text,
        finalReason: queued.reason,
        statusCode: queued.reason === 'queue_full' ? 503 : 204
      });
    }
    return { blocked: false };
  }

  return {
    buildConfig,
    getSummary,
    trimHistoryIfNeeded,
    applyIfNeeded
  };
}
