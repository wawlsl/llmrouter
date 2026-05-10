import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

function loadDatabaseDriver() {
  try {
    const BetterSqlite3 = require('better-sqlite3');
    return {
      name: 'better-sqlite3',
      Database: BetterSqlite3
    };
  } catch (error) {
    if (error?.code !== 'MODULE_NOT_FOUND') {
      throw error;
    }
  }

  try {
    const builtin = require('node:sqlite');
    if (builtin?.DatabaseSync) {
      return {
        name: 'node:sqlite',
        Database: builtin.DatabaseSync
      };
    }
  } catch (error) {
    if (error?.code !== 'ERR_UNKNOWN_BUILTIN_MODULE' && error?.code !== 'MODULE_NOT_FOUND') {
      throw error;
    }
  }

  throw new Error(
    'No SQLite driver available. Install better-sqlite3 (recommended for Node 20), or use Node 24+ with node:sqlite.'
  );
}

const sqliteDriver = loadDatabaseDriver();

const defaultSettings = {
  globalStickyWindowMs: 6 * 60 * 60 * 1000,
  defaultBaseUrl: 'https://api.openai.com',
  sessionTtlMs: 24 * 60 * 60 * 1000,
  defaultCurrency: 'USD',
  debugAutoMode: 'off',
  riskControlEnabled: 'off',
  riskControlScopeMode: 'all',
  riskControlGroupIds: '',
  riskControlMode: 'observe',
  riskControlSampleRate: '100',
  riskControlL1Enabled: '1',
  riskControlL1BaseUrl: 'https://api.openai.com',
  riskControlL1Model: 'omni-moderation-latest',
  riskControlL1ApiKey: '',
  riskControlL1Threshold: '0.70',
  riskControlL1TimeoutMs: '5000',
  riskControlL2Enabled: '0',
  riskControlL2BaseUrl: 'https://api.openai.com',
  riskControlL2Model: 'gpt-4.1-mini',
  riskControlL2ApiKey: '',
  riskControlL2Prompt: 'You are a strict safety reviewer. Return JSON only: {\"risk\":\"allow|block\",\"reason\":\"...\",\"score\":0.0}.',
  riskControlL2Temperature: '0',
  riskControlL2MaxTokens: '200',
  riskControlL2TimeoutMs: '12000',
  riskControlQueueSize: '2000',
  riskControlWorkerConcurrency: '2',
  riskControlBlockMessage: '内容审查命中风险规则，请调整输入后重试',
  riskControlRetentionDays: '30'
};

export const DEFAULT_RISK_CONTROL_L2_PROMPT = defaultSettings.riskControlL2Prompt;

const numericSettings = new Set([
  'globalStickyWindowMs',
  'sessionTtlMs'
]);

function ensureDirectoryFor(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function toAccount(row) {
  return {
    id: row.id,
    name: row.name,
    provider: row.provider || 'openai',
    forceResponsesCompat: row.force_responses_compat === 1,
    apiKey: row.api_key,
    baseUrl: row.base_url,
    enabled: row.enabled === 1,
    weight: row.weight,
    quotaLimit: row.quota_limit,
    quotaWindowMs: row.quota_window_ms,
    quotaLimit2: row.quota_limit_2,
    quotaWindowMs2: row.quota_window_ms_2,
    stickyWindowMs: row.sticky_window_ms,
    stats: {
      windowStartMs: row.window_start_ms,
      windowStartMs2: row.window_start_ms_2,
      usedRequests: row.used_requests,
      usedRequests2: row.used_requests_2,
      totalRequests: row.total_requests,
      lastUsedAt: row.last_used_at
    }
  };
}

function toQuota(row) {
  return {
    accountId: row.account_id,
    modelName: row.model_name,
    requestLimit: row.request_limit,
    usedRequests: row.used_requests,
    windowMs: row.window_ms,
    windowStartMs: row.window_start_ms,
    tokenLimit: row.token_limit,
    usedTokens: row.used_tokens,
    costLimitMinor: row.cost_limit_minor,
    usedCostMinor: row.used_cost_minor,
    currency: row.currency
  };
}

function safeModelName(name) {
  return String(name ?? '').trim();
}

export function createStore(dbPath) {
  ensureDirectoryFor(dbPath);
  const db = new sqliteDriver.Database(dbPath);

  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA synchronous = NORMAL;');
  db.exec('PRAGMA busy_timeout = 5000;');
  db.exec('PRAGMA foreign_keys = ON;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT 'openai',
      force_responses_compat INTEGER NOT NULL DEFAULT 0,
      api_key TEXT NOT NULL,
      base_url TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      weight INTEGER NOT NULL DEFAULT 1,
      quota_limit INTEGER NOT NULL DEFAULT 0,
      quota_window_ms INTEGER NOT NULL DEFAULT 0,
      quota_limit_2 INTEGER NOT NULL DEFAULT 0,
      quota_window_ms_2 INTEGER NOT NULL DEFAULT 0,
      sticky_window_ms INTEGER NOT NULL DEFAULT 0,
      window_start_ms INTEGER NOT NULL DEFAULT 0,
      window_start_ms_2 INTEGER NOT NULL DEFAULT 0,
      used_requests INTEGER NOT NULL DEFAULT 0,
      used_requests_2 INTEGER NOT NULL DEFAULT 0,
      total_requests INTEGER NOT NULL DEFAULT 0,
      last_used_at TEXT NOT NULL DEFAULT ''
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS account_models (
      account_id TEXT NOT NULL,
      model_name TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'custom',
      created_at TEXT NOT NULL DEFAULT '',
      PRIMARY KEY (account_id, model_name),
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS model_mappings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_model TEXT NOT NULL UNIQUE,
      target_model TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS account_model_quotas (
      account_id TEXT NOT NULL,
      model_name TEXT NOT NULL,
      request_limit INTEGER NOT NULL DEFAULT 0,
      used_requests INTEGER NOT NULL DEFAULT 0,
      window_ms INTEGER NOT NULL DEFAULT 0,
      window_start_ms INTEGER NOT NULL DEFAULT 0,
      token_limit INTEGER NOT NULL DEFAULT 0,
      used_tokens INTEGER NOT NULL DEFAULT 0,
      cost_limit_minor INTEGER NOT NULL DEFAULT 0,
      used_cost_minor INTEGER NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'USD',
      PRIMARY KEY (account_id, model_name),
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS model_prices (
      provider TEXT NOT NULL,
      model_name TEXT NOT NULL,
      input_per_million REAL,
      output_per_million REAL,
      cache_read_per_million REAL,
      cache_write_per_million REAL,
      currency TEXT NOT NULL DEFAULT 'USD',
      updated_at TEXT NOT NULL,
      PRIMARY KEY (provider, model_name)
    );
  `);

	  db.exec(`
	    CREATE TABLE IF NOT EXISTS pool_groups (
	      id TEXT PRIMARY KEY,
	      name TEXT NOT NULL,
	      group_key TEXT NOT NULL UNIQUE,
	      description TEXT NOT NULL DEFAULT '',
	      enabled INTEGER NOT NULL DEFAULT 1,
	      created_at TEXT NOT NULL
	    );
	  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS group_members (
      group_id TEXT NOT NULL,
      account_id TEXT NOT NULL,
      weight INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (group_id, account_id),
      FOREIGN KEY (group_id) REFERENCES pool_groups(id) ON DELETE CASCADE,
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS access_keys (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      token TEXT NOT NULL UNIQUE,
      group_id TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      last_used_at TEXT NOT NULL DEFAULT '',
      FOREIGN KEY (group_id) REFERENCES pool_groups(id) ON DELETE SET NULL
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS sticky_bindings (
      sticky_key TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      token TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS request_logs (
      id TEXT PRIMARY KEY,
      at TEXT NOT NULL,
      method TEXT NOT NULL DEFAULT '',
      path TEXT NOT NULL DEFAULT '',
      endpoint TEXT NOT NULL DEFAULT '',
      provider TEXT NOT NULL DEFAULT 'unknown',
      account TEXT NOT NULL DEFAULT '-',
      model TEXT NOT NULL DEFAULT '-',
      request_model TEXT NOT NULL DEFAULT '-',
      group_key TEXT NOT NULL DEFAULT '-',
      access_key_id TEXT NOT NULL DEFAULT '-',
      status_code INTEGER NOT NULL DEFAULT 0,
      tokens INTEGER NOT NULL DEFAULT 0,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      cached_tokens INTEGER NOT NULL DEFAULT 0,
      gateway_cache TEXT NOT NULL DEFAULT '',
      upstream_cache TEXT NOT NULL DEFAULT '',
      cache_layer TEXT NOT NULL DEFAULT '',
      cost_minor INTEGER NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'USD',
      duration_ms INTEGER NOT NULL DEFAULT 0,
      error TEXT NOT NULL DEFAULT '',
      debug_info TEXT NOT NULL DEFAULT '',
      compat_unsupported TEXT NOT NULL DEFAULT '',
      attempts INTEGER NOT NULL DEFAULT 1,
      switches INTEGER NOT NULL DEFAULT 0,
      retry_reason TEXT NOT NULL DEFAULT '',
      sticky_hit INTEGER NOT NULL DEFAULT 0
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS risk_control_logs (
      id TEXT PRIMARY KEY,
      at TEXT NOT NULL,
      request_id TEXT NOT NULL DEFAULT '',
      group_key TEXT NOT NULL DEFAULT '',
      access_key_id TEXT NOT NULL DEFAULT '',
      provider TEXT NOT NULL DEFAULT '',
      path TEXT NOT NULL DEFAULT '',
      model TEXT NOT NULL DEFAULT '',
      account TEXT NOT NULL DEFAULT '',
      mode TEXT NOT NULL DEFAULT 'observe',
      action TEXT NOT NULL DEFAULT 'allow',
      blocked INTEGER NOT NULL DEFAULT 0,
      sampled INTEGER NOT NULL DEFAULT 1,
      input_hash TEXT NOT NULL DEFAULT '',
      excerpt TEXT NOT NULL DEFAULT '',
      l1_flagged INTEGER NOT NULL DEFAULT 0,
      l1_score REAL NOT NULL DEFAULT 0,
      l1_category TEXT NOT NULL DEFAULT '',
      l1_error TEXT NOT NULL DEFAULT '',
      l1_latency_ms INTEGER NOT NULL DEFAULT 0,
      l2_flagged INTEGER NOT NULL DEFAULT 0,
      l2_score REAL NOT NULL DEFAULT 0,
      l2_reason TEXT NOT NULL DEFAULT '',
      l2_raw TEXT NOT NULL DEFAULT '',
      l2_error TEXT NOT NULL DEFAULT '',
      l2_latency_ms INTEGER NOT NULL DEFAULT 0,
      final_reason TEXT NOT NULL DEFAULT '',
      status_code INTEGER NOT NULL DEFAULT 0
    );
  `);

  db.exec('CREATE INDEX IF NOT EXISTS idx_accounts_enabled ON accounts(enabled);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_account_models_account ON account_models(account_id);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_quotas_account ON account_model_quotas(account_id);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_prices_provider ON model_prices(provider);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_groups_group_key ON pool_groups(group_key);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_access_keys_group ON access_keys(group_id);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_sticky_expires ON sticky_bindings(expires_at);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_request_logs_at ON request_logs(at DESC);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_risk_control_logs_at ON risk_control_logs(at DESC);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_risk_control_logs_action_at ON risk_control_logs(action, at DESC);');
  db.exec('CREATE INDEX IF NOT EXISTS idx_risk_control_logs_group_at ON risk_control_logs(group_key, at DESC);');

  function ensureColumn(tableName, columnName, definitionSql) {
    const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
    const exists = columns.some((row) => row.name === columnName);
    if (!exists) {
      db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${definitionSql};`);
    }
  }

  ensureColumn('accounts', 'quota_limit_2', 'quota_limit_2 INTEGER NOT NULL DEFAULT 0');
  ensureColumn('accounts', 'quota_window_ms_2', 'quota_window_ms_2 INTEGER NOT NULL DEFAULT 0');
  ensureColumn('accounts', 'window_start_ms_2', 'window_start_ms_2 INTEGER NOT NULL DEFAULT 0');
  ensureColumn('accounts', 'used_requests_2', 'used_requests_2 INTEGER NOT NULL DEFAULT 0');
  ensureColumn('accounts', 'provider', "provider TEXT NOT NULL DEFAULT 'openai'");
  ensureColumn('accounts', 'force_responses_compat', 'force_responses_compat INTEGER NOT NULL DEFAULT 0');
  ensureColumn('request_logs', 'gateway_cache', "gateway_cache TEXT NOT NULL DEFAULT ''");
  ensureColumn('request_logs', 'upstream_cache', "upstream_cache TEXT NOT NULL DEFAULT ''");
  ensureColumn('request_logs', 'cache_layer', "cache_layer TEXT NOT NULL DEFAULT ''");
  ensureColumn('request_logs', 'debug_info', "debug_info TEXT NOT NULL DEFAULT ''");

  const upsertSettingStmt = db.prepare(`
    INSERT INTO settings(key, value) VALUES (?, ?)
    ON CONFLICT(key) DO NOTHING
  `);
  const setSettingStmt = db.prepare(`
    INSERT INTO settings(key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `);
  const settingsStmt = db.prepare('SELECT key, value FROM settings');

  const listAccountsStmt = db.prepare(`
    SELECT
      id, name, provider, force_responses_compat, api_key, base_url, enabled, weight, quota_limit, quota_window_ms,
      quota_limit_2, quota_window_ms_2, sticky_window_ms, window_start_ms, window_start_ms_2,
      used_requests, used_requests_2, total_requests, last_used_at
    FROM accounts
    ORDER BY rowid ASC
  `);
  const insertAccountStmt = db.prepare(`
    INSERT INTO accounts (
      id, name, provider, force_responses_compat, api_key, base_url, enabled, weight, quota_limit, quota_window_ms,
      quota_limit_2, quota_window_ms_2, sticky_window_ms, window_start_ms, window_start_ms_2,
      used_requests, used_requests_2, total_requests, last_used_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const updateAccountStmt = db.prepare(`
    UPDATE accounts
    SET
      name = ?,
      provider = ?,
      force_responses_compat = ?,
      api_key = ?,
      base_url = ?,
      enabled = ?,
      weight = ?,
      quota_limit = ?,
      quota_window_ms = ?,
      quota_limit_2 = ?,
      quota_window_ms_2 = ?,
      sticky_window_ms = ?
    WHERE id = ?
  `);
  const updateStatsStmt = db.prepare(`
    UPDATE accounts
    SET
      window_start_ms = ?,
      window_start_ms_2 = ?,
      used_requests = ?,
      used_requests_2 = ?,
      total_requests = ?,
      last_used_at = ?
    WHERE id = ?
  `);
  const resetQuotaStmt = db.prepare(`
    UPDATE accounts
    SET window_start_ms = ?, window_start_ms_2 = ?, used_requests = 0, used_requests_2 = 0
    WHERE id = ?
  `);
  const deleteAccountStmt = db.prepare('DELETE FROM accounts WHERE id = ?');
  const accountByIdStmt = db.prepare(`
    SELECT
      id, name, provider, force_responses_compat, api_key, base_url, enabled, weight, quota_limit, quota_window_ms,
      quota_limit_2, quota_window_ms_2, sticky_window_ms, window_start_ms, window_start_ms_2,
      used_requests, used_requests_2, total_requests, last_used_at
    FROM accounts
    WHERE id = ?
  `);

  const listAccountModelsStmt = db.prepare(`
    SELECT model_name, source, created_at
    FROM account_models
    WHERE account_id = ?
    ORDER BY model_name ASC
  `);
  const accountModelsByIdsStmtCache = new Map();
  const upsertAccountModelStmt = db.prepare(`
    INSERT INTO account_models(account_id, model_name, source, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(account_id, model_name) DO UPDATE SET
      source = excluded.source,
      created_at = excluded.created_at
  `);
  const deleteAccountModelStmt = db.prepare(`
    DELETE FROM account_models
    WHERE account_id = ? AND model_name = ?
  `);
  const deleteAllAccountModelsStmt = db.prepare(`
    DELETE FROM account_models
    WHERE account_id = ?
  `);
  const clearRemoteModelsStmt = db.prepare(`
    DELETE FROM account_models
    WHERE account_id = ? AND source = 'remote'
  `);

  const listMappingsStmt = db.prepare(`
    SELECT id, source_model, target_model, enabled
    FROM model_mappings
    ORDER BY source_model ASC
  `);
  const upsertMappingStmt = db.prepare(`
    INSERT INTO model_mappings(source_model, target_model, enabled)
    VALUES (?, ?, ?)
    ON CONFLICT(source_model) DO UPDATE SET
      target_model = excluded.target_model,
      enabled = excluded.enabled
  `);
  const deleteMappingStmt = db.prepare('DELETE FROM model_mappings WHERE source_model = ?');
  const findMappingStmt = db.prepare(`
    SELECT source_model, target_model, enabled
    FROM model_mappings
    WHERE source_model = ?
  `);

  const listQuotasStmt = db.prepare(`
    SELECT
      account_id, model_name, request_limit, used_requests, window_ms, window_start_ms,
      token_limit, used_tokens, cost_limit_minor, used_cost_minor, currency
    FROM account_model_quotas
    WHERE account_id = ?
    ORDER BY model_name ASC
  `);
  const quotaByKeyStmt = db.prepare(`
    SELECT
      account_id, model_name, request_limit, used_requests, window_ms, window_start_ms,
      token_limit, used_tokens, cost_limit_minor, used_cost_minor, currency
    FROM account_model_quotas
    WHERE account_id = ? AND model_name = ?
  `);
  const upsertQuotaStmt = db.prepare(`
    INSERT INTO account_model_quotas(
      account_id, model_name, request_limit, used_requests, window_ms, window_start_ms,
      token_limit, used_tokens, cost_limit_minor, used_cost_minor, currency
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(account_id, model_name) DO UPDATE SET
      request_limit = excluded.request_limit,
      window_ms = excluded.window_ms,
      token_limit = excluded.token_limit,
      cost_limit_minor = excluded.cost_limit_minor,
      currency = excluded.currency
  `);
  const resetQuotaUsageStmt = db.prepare(`
    UPDATE account_model_quotas
    SET
      window_start_ms = ?,
      used_requests = 0,
      used_tokens = 0,
      used_cost_minor = 0
    WHERE account_id = ? AND model_name = ?
  `);
  const updateQuotaUsageStmt = db.prepare(`
    UPDATE account_model_quotas
    SET
      window_start_ms = ?,
      used_requests = ?,
      used_tokens = ?,
      used_cost_minor = ?
    WHERE account_id = ? AND model_name = ?
  `);
  const deleteQuotaStmt = db.prepare(`
    DELETE FROM account_model_quotas
    WHERE account_id = ? AND model_name = ?
  `);

  const listPricesStmt = db.prepare(`
    SELECT
      provider, model_name, input_per_million, output_per_million, cache_read_per_million,
      cache_write_per_million, currency, updated_at
    FROM model_prices
    WHERE provider = ?
    ORDER BY model_name ASC
  `);
  const upsertPriceStmt = db.prepare(`
    INSERT INTO model_prices(
      provider, model_name, input_per_million, output_per_million, cache_read_per_million,
      cache_write_per_million, currency, updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(provider, model_name) DO UPDATE SET
      input_per_million = excluded.input_per_million,
      output_per_million = excluded.output_per_million,
      cache_read_per_million = excluded.cache_read_per_million,
      cache_write_per_million = excluded.cache_write_per_million,
      currency = excluded.currency,
      updated_at = excluded.updated_at
  `);
  const findPriceStmt = db.prepare(`
    SELECT
      provider, model_name, input_per_million, output_per_million, cache_read_per_million,
      cache_write_per_million, currency, updated_at
    FROM model_prices
    WHERE provider = ? AND model_name = ?
  `);
  const deletePriceStmt = db.prepare(`
    DELETE FROM model_prices
    WHERE provider = ? AND model_name = ?
  `);

	  const listGroupsStmt = db.prepare(`
	    SELECT
	      id, name, group_key, description,
	      enabled, created_at
	    FROM pool_groups
	    ORDER BY created_at DESC
	  `);
	  const groupByIdStmt = db.prepare(`
	    SELECT
	      id, name, group_key, description,
	      enabled, created_at
	    FROM pool_groups
	    WHERE id = ?
	  `);
	  const groupByKeyStmt = db.prepare(`
	    SELECT
	      id, name, group_key, description,
	      enabled, created_at
	    FROM pool_groups
	    WHERE group_key = ?
	  `);
	  const insertGroupStmt = db.prepare(`
	    INSERT INTO pool_groups(
	      id, name, group_key, description,
	      enabled, created_at
	    )
	    VALUES (?, ?, ?, ?, ?, ?)
	  `);
	  const updateGroupStmt = db.prepare(`
	    UPDATE pool_groups
	    SET
	      name = ?,
	      group_key = ?,
	      description = ?,
	      enabled = ?
	    WHERE id = ?
	  `);
  const deleteGroupStmt = db.prepare('DELETE FROM pool_groups WHERE id = ?');

  const listGroupMembersStmt = db.prepare(`
    SELECT
      gm.group_id,
      gm.account_id,
      gm.weight,
      a.name AS account_name,
      a.enabled AS account_enabled
    FROM group_members gm
    JOIN accounts a ON a.id = gm.account_id
    WHERE gm.group_id = ?
    ORDER BY a.name ASC
  `);
  const upsertGroupMemberStmt = db.prepare(`
    INSERT INTO group_members(group_id, account_id, weight)
    VALUES (?, ?, ?)
    ON CONFLICT(group_id, account_id) DO UPDATE SET
      weight = excluded.weight
  `);
  const deleteGroupMemberStmt = db.prepare(`
    DELETE FROM group_members
    WHERE group_id = ? AND account_id = ?
  `);
  const listAccountsForGroupStmt = db.prepare(`
    SELECT
      a.id, a.name, a.provider, a.force_responses_compat, a.api_key, a.base_url, a.enabled, gm.weight,
      a.quota_limit, a.quota_window_ms, a.quota_limit_2, a.quota_window_ms_2,
      a.sticky_window_ms, a.window_start_ms, a.window_start_ms_2,
      a.used_requests, a.used_requests_2, a.total_requests, a.last_used_at
    FROM group_members gm
    JOIN pool_groups g ON g.id = gm.group_id
    JOIN accounts a ON a.id = gm.account_id
    WHERE g.group_key = ? AND g.enabled = 1
    ORDER BY a.name ASC
  `);

  const listAccessKeysStmt = db.prepare(`
    SELECT
      ak.id,
      ak.name,
      ak.token,
      ak.group_id,
      ak.enabled,
      ak.created_at,
      ak.last_used_at,
      g.name AS group_name,
      g.group_key AS group_key
    FROM access_keys ak
    LEFT JOIN pool_groups g ON g.id = ak.group_id
    ORDER BY ak.created_at DESC
  `);
  const insertAccessKeyStmt = db.prepare(`
    INSERT INTO access_keys(id, name, token, group_id, enabled, created_at, last_used_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const updateAccessKeyStmt = db.prepare(`
    UPDATE access_keys
    SET name = ?, group_id = ?, enabled = ?
    WHERE id = ?
  `);
  const deleteAccessKeyStmt = db.prepare('DELETE FROM access_keys WHERE id = ?');
  const accessKeyByTokenStmt = db.prepare(`
    SELECT
      ak.id,
      ak.name,
      ak.token,
      ak.group_id,
      ak.enabled,
      ak.created_at,
      ak.last_used_at,
      g.name AS group_name,
      g.group_key AS group_key,
      g.enabled AS group_enabled
    FROM access_keys ak
    LEFT JOIN pool_groups g ON g.id = ak.group_id
    WHERE ak.token = ?
  `);
  const updateAccessKeyLastUsedStmt = db.prepare(`
    UPDATE access_keys
    SET last_used_at = ?
    WHERE id = ?
  `);

  const stickyByKeyStmt = db.prepare(`
    SELECT sticky_key, account_id, expires_at
    FROM sticky_bindings
    WHERE sticky_key = ?
  `);
  const upsertStickyStmt = db.prepare(`
    INSERT INTO sticky_bindings(sticky_key, account_id, expires_at)
    VALUES (?, ?, ?)
    ON CONFLICT(sticky_key) DO UPDATE SET
      account_id = excluded.account_id,
      expires_at = excluded.expires_at
  `);
  const deleteStickyByKeyStmt = db.prepare('DELETE FROM sticky_bindings WHERE sticky_key = ?');
  const deleteStickyByAccountStmt = db.prepare('DELETE FROM sticky_bindings WHERE account_id = ?');
  const deleteExpiredStickyStmt = db.prepare('DELETE FROM sticky_bindings WHERE expires_at <= ?');
  const countActiveStickyStmt = db.prepare('SELECT COUNT(*) AS total FROM sticky_bindings WHERE expires_at > ?');

  const adminSessionByTokenStmt = db.prepare(`
    SELECT token, expires_at
    FROM admin_sessions
    WHERE token = ?
  `);
  const upsertAdminSessionStmt = db.prepare(`
    INSERT INTO admin_sessions(token, expires_at)
    VALUES (?, ?)
    ON CONFLICT(token) DO UPDATE SET
      expires_at = excluded.expires_at
  `);
  const deleteAdminSessionStmt = db.prepare('DELETE FROM admin_sessions WHERE token = ?');
  const deleteExpiredAdminSessionStmt = db.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?');

  const insertRequestLogStmt = db.prepare(`
    INSERT INTO request_logs(
      id, at, method, path, endpoint, provider, account, model, request_model,
      group_key, access_key_id, status_code, tokens, input_tokens, output_tokens,
      cached_tokens, gateway_cache, upstream_cache, cache_layer, cost_minor, currency, duration_ms,
      error, debug_info, compat_unsupported, attempts, switches, retry_reason, sticky_hit
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const listRecentRequestLogsStmt = db.prepare(`
    SELECT
      id,
      at,
      method,
      path,
      endpoint,
      provider,
      account,
      model,
      request_model,
      group_key,
      access_key_id,
      status_code,
      tokens,
      input_tokens,
      output_tokens,
      cached_tokens,
      gateway_cache,
      upstream_cache,
      cache_layer,
      cost_minor,
      currency,
      duration_ms,
      error,
      debug_info,
      compat_unsupported,
      attempts,
      switches,
      retry_reason,
      sticky_hit
    FROM request_logs
    ORDER BY at DESC, id DESC
    LIMIT ?
  `);
  const trimRequestLogsStmt = db.prepare(`
    DELETE FROM request_logs
    WHERE id IN (
      SELECT id FROM request_logs
      ORDER BY at DESC, id DESC
      LIMIT -1 OFFSET ?
    )
  `);
  const insertRiskControlLogStmt = db.prepare(`
    INSERT INTO risk_control_logs(
      id, at, request_id, group_key, access_key_id, provider, path, model, account,
      mode, action, blocked, sampled, input_hash, excerpt, l1_flagged, l1_score, l1_category,
      l1_error, l1_latency_ms, l2_flagged, l2_score, l2_reason, l2_raw, l2_error, l2_latency_ms,
      final_reason, status_code
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const listRecentRiskControlLogsStmt = db.prepare(`
    SELECT
      id, at, request_id, group_key, access_key_id, provider, path, model, account,
      mode, action, blocked, sampled, input_hash, excerpt, l1_flagged, l1_score, l1_category,
      l1_error, l1_latency_ms, l2_flagged, l2_score, l2_reason, l2_raw, l2_error, l2_latency_ms,
      final_reason, status_code
    FROM risk_control_logs
    ORDER BY at DESC, id DESC
    LIMIT ?
  `);
  const trimRiskControlLogsStmt = db.prepare(`
    DELETE FROM risk_control_logs
    WHERE id IN (
      SELECT id FROM risk_control_logs
      ORDER BY at DESC, id DESC
      LIMIT -1 OFFSET ?
    )
  `);

  for (const [key, value] of Object.entries(defaultSettings)) {
    upsertSettingStmt.run(key, String(value));
  }

  function runInTransaction(callback) {
    db.exec('BEGIN IMMEDIATE');
    try {
      callback();
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  function getSettings() {
    const rows = settingsStmt.all();
    const settings = { ...defaultSettings };
    for (const row of rows) {
      if (numericSettings.has(row.key)) {
        const number = Number(row.value);
        if (Number.isFinite(number) && number > 0) {
          settings[row.key] = number;
        }
      } else {
        settings[row.key] = row.value;
      }
    }
    return settings;
  }

  function updateSettings(partialSettings) {
    const entries = Object.entries(partialSettings);
    runInTransaction(() => {
      for (const [key, value] of entries) {
        setSettingStmt.run(key, String(value));
      }
    });
  }

  function listAccounts() {
    return listAccountsStmt.all().map(toAccount);
  }

  function getAccountById(id) {
    const row = accountByIdStmt.get(id);
    return row ? toAccount(row) : null;
  }

  function createAccount(account) {
    insertAccountStmt.run(
      account.id,
      account.name,
      account.provider || 'openai',
      account.forceResponsesCompat ? 1 : 0,
      account.apiKey,
      account.baseUrl,
      account.enabled ? 1 : 0,
      account.weight,
      account.quotaLimit,
      account.quotaWindowMs,
      account.quotaLimit2 || 0,
      account.quotaWindowMs2 || 0,
      account.stickyWindowMs,
      account.stats.windowStartMs,
      account.stats.windowStartMs2 || 0,
      account.stats.usedRequests,
      account.stats.usedRequests2 || 0,
      account.stats.totalRequests,
      account.stats.lastUsedAt
    );
  }

  function updateAccount(id, account, { keepApiKey } = { keepApiKey: false }) {
    const nextApiKey = keepApiKey ? getAccountById(id)?.apiKey : account.apiKey;
    updateAccountStmt.run(
      account.name,
      account.provider || 'openai',
      account.forceResponsesCompat ? 1 : 0,
      nextApiKey || '',
      account.baseUrl,
      account.enabled ? 1 : 0,
      account.weight,
      account.quotaLimit,
      account.quotaWindowMs,
      account.quotaLimit2 || 0,
      account.quotaWindowMs2 || 0,
      account.stickyWindowMs,
      id
    );
  }

  function updateAccountStats(accountId, stats) {
    updateStatsStmt.run(
      stats.windowStartMs,
      stats.windowStartMs2 || 0,
      stats.usedRequests,
      stats.usedRequests2 || 0,
      stats.totalRequests,
      stats.lastUsedAt || '',
      accountId
    );
  }

  function resetAccountQuota(id, nowMs) {
    resetQuotaStmt.run(nowMs, nowMs, id);
  }

  function deleteAccount(id) {
    deleteAccountStmt.run(id);
  }

  function listAccountModels(accountId) {
    return listAccountModelsStmt.all(accountId).map((row) => ({
      modelName: row.model_name,
      source: row.source,
      createdAt: row.created_at
    }));
  }

  function listAccountModelsForAccounts(accountIds = []) {
    const ids = [...new Set((accountIds || []).map((item) => String(item || '').trim()).filter(Boolean))];
    if (!ids.length) {
      return new Map();
    }

    const count = ids.length;
    let stmt = accountModelsByIdsStmtCache.get(count);
    if (!stmt) {
      const placeholders = new Array(count).fill('?').join(', ');
      stmt = db.prepare(`
        SELECT account_id, model_name
        FROM account_models
        WHERE account_id IN (${placeholders})
      `);
      accountModelsByIdsStmtCache.set(count, stmt);
    }

    const rows = stmt.all(...ids);
    const index = new Map();
    for (const id of ids) {
      index.set(id, new Set());
    }
    for (const row of rows) {
      if (!index.has(row.account_id)) {
        index.set(row.account_id, new Set());
      }
      index.get(row.account_id).add(row.model_name);
    }
    return index;
  }

  function addAccountModel(accountId, modelName, source = 'custom') {
    const normalized = safeModelName(modelName);
    if (!normalized) {
      return;
    }
    upsertAccountModelStmt.run(accountId, normalized, source, new Date().toISOString());
  }

  function removeAccountModel(accountId, modelName) {
    const normalized = safeModelName(modelName);
    if (!normalized) {
      return;
    }
    deleteAccountModelStmt.run(accountId, normalized);
  }

  function syncRemoteModels(accountId, modelNames) {
    const normalized = [...new Set(modelNames.map(safeModelName).filter(Boolean))];
    runInTransaction(() => {
      clearRemoteModelsStmt.run(accountId);
      for (const modelName of normalized) {
        upsertAccountModelStmt.run(accountId, modelName, 'remote', new Date().toISOString());
      }
    });
  }

  function replaceAccountModels(accountId, modelNames, source = 'custom') {
    const normalized = [...new Set((modelNames || []).map(safeModelName).filter(Boolean))];
    runInTransaction(() => {
      deleteAllAccountModelsStmt.run(accountId);
      for (const modelName of normalized) {
        upsertAccountModelStmt.run(accountId, modelName, source, new Date().toISOString());
      }
    });
  }

  function listModelMappings() {
    return listMappingsStmt.all().map((row) => ({
      id: row.id,
      sourceModel: row.source_model,
      targetModel: row.target_model,
      enabled: row.enabled === 1
    }));
  }

  function upsertModelMapping(sourceModel, targetModel, enabled = true) {
    const source = safeModelName(sourceModel);
    const target = safeModelName(targetModel);
    if (!source || !target) {
      return;
    }
    upsertMappingStmt.run(source, target, enabled ? 1 : 0);
  }

  function deleteModelMapping(sourceModel) {
    const source = safeModelName(sourceModel);
    if (!source) {
      return;
    }
    deleteMappingStmt.run(source);
  }

  function resolveMappedModel(sourceModel) {
    const source = safeModelName(sourceModel);
    if (!source) {
      return '';
    }
    const row = findMappingStmt.get(source);
    if (!row || row.enabled !== 1 || !row.target_model) {
      return source;
    }
    return row.target_model;
  }

  function listModelQuotas(accountId) {
    return listQuotasStmt.all(accountId).map(toQuota);
  }

  function getModelQuota(accountId, modelName) {
    const normalized = safeModelName(modelName);
    if (!normalized) {
      return null;
    }
    const row = quotaByKeyStmt.get(accountId, normalized);
    return row ? toQuota(row) : null;
  }

  function upsertModelQuota(accountId, modelName, quota) {
    const normalized = safeModelName(modelName);
    if (!normalized) {
      return;
    }
    const existing = getModelQuota(accountId, normalized);
    upsertQuotaStmt.run(
      accountId,
      normalized,
      quota.requestLimit || 0,
      existing?.usedRequests || 0,
      quota.windowMs || 0,
      existing?.windowStartMs || Date.now(),
      quota.tokenLimit || 0,
      existing?.usedTokens || 0,
      quota.costLimitMinor || 0,
      existing?.usedCostMinor || 0,
      quota.currency || 'USD'
    );
  }

  function deleteModelQuota(accountId, modelName) {
    const normalized = safeModelName(modelName);
    if (!normalized) {
      return;
    }
    deleteQuotaStmt.run(accountId, normalized);
  }

  function resetModelQuotaUsage(accountId, modelName, nowMs) {
    const normalized = safeModelName(modelName);
    if (!normalized) {
      return;
    }
    resetQuotaUsageStmt.run(nowMs, accountId, normalized);
  }

  function reserveModelQuota(accountId, modelName, nowMs) {
    const normalized = safeModelName(modelName);
    if (!normalized) {
      return { allowed: true, quota: null };
    }
    const quota = getModelQuota(accountId, normalized);
    if (!quota) {
      return { allowed: true, quota: null };
    }

    if (!quota.windowStartMs) {
      quota.windowStartMs = nowMs;
    }
    if (quota.windowMs > 0 && nowMs - quota.windowStartMs >= quota.windowMs) {
      quota.windowStartMs = nowMs;
      quota.usedRequests = 0;
      quota.usedTokens = 0;
      quota.usedCostMinor = 0;
      updateQuotaUsageStmt.run(
        quota.windowStartMs,
        quota.usedRequests,
        quota.usedTokens,
        quota.usedCostMinor,
        accountId,
        normalized
      );
    }

    if (quota.requestLimit > 0 && quota.usedRequests >= quota.requestLimit) {
      return { allowed: false, quota };
    }

    quota.usedRequests += 1;
    updateQuotaUsageStmt.run(
      quota.windowStartMs,
      quota.usedRequests,
      quota.usedTokens,
      quota.usedCostMinor,
      accountId,
      normalized
    );
    return { allowed: true, quota };
  }

  function releaseModelQuotaReservation(accountId, modelName) {
    const quota = getModelQuota(accountId, modelName);
    if (!quota) {
      return;
    }
    const usedRequests = Math.max(quota.usedRequests - 1, 0);
    updateQuotaUsageStmt.run(
      quota.windowStartMs || Date.now(),
      usedRequests,
      quota.usedTokens,
      quota.usedCostMinor,
      accountId,
      quota.modelName
    );
  }

  function addModelQuotaUsage(accountId, modelName, usage = {}) {
    const quota = getModelQuota(accountId, modelName);
    if (!quota) {
      return;
    }
    const tokensDelta = Math.max(Number(usage.tokens || 0), 0);
    const costDelta = Math.max(Number(usage.costMinor || 0), 0);

    const nextTokens = quota.usedTokens + tokensDelta;
    const nextCostMinor = quota.usedCostMinor + costDelta;
    updateQuotaUsageStmt.run(
      quota.windowStartMs || Date.now(),
      quota.usedRequests,
      nextTokens,
      nextCostMinor,
      accountId,
      quota.modelName
    );
  }

  function listModelPrices(provider = 'openai') {
    return listPricesStmt.all(provider).map((row) => ({
      provider: row.provider,
      modelName: row.model_name,
      inputPerMillion: row.input_per_million,
      outputPerMillion: row.output_per_million,
      cacheReadPerMillion: row.cache_read_per_million,
      cacheWritePerMillion: row.cache_write_per_million,
      currency: row.currency,
      updatedAt: row.updated_at
    }));
  }

  function getModelPrice(provider, modelName) {
    const model = safeModelName(modelName);
    if (!model) {
      return null;
    }
    const row = findPriceStmt.get(provider, model);
    if (!row) {
      return null;
    }
    return {
      provider: row.provider,
      modelName: row.model_name,
      inputPerMillion: row.input_per_million,
      outputPerMillion: row.output_per_million,
      cacheReadPerMillion: row.cache_read_per_million,
      cacheWritePerMillion: row.cache_write_per_million,
      currency: row.currency,
      updatedAt: row.updated_at
    };
  }

  function upsertModelPrices(provider, prices, currency = 'USD') {
    const now = new Date().toISOString();
    runInTransaction(() => {
      for (const item of prices) {
        const modelName = safeModelName(item.modelName);
        if (!modelName) {
          continue;
        }
        upsertPriceStmt.run(
          provider,
          modelName,
          Number.isFinite(item.inputPerMillion) ? item.inputPerMillion : null,
          Number.isFinite(item.outputPerMillion) ? item.outputPerMillion : null,
          Number.isFinite(item.cacheReadPerMillion) ? item.cacheReadPerMillion : null,
          Number.isFinite(item.cacheWritePerMillion) ? item.cacheWritePerMillion : null,
          currency,
          now
        );
      }
    });
  }

  function deleteModelPrice(provider, modelName) {
    const providerName = String(provider || '').trim().toLowerCase();
    const normalized = safeModelName(modelName);
    if (!providerName || !normalized) {
      return;
    }
    deletePriceStmt.run(providerName, normalized);
  }

  function close() {
    db.close();
  }

  function listAccessKeys() {
    return listAccessKeysStmt.all().map((row) => ({
      id: row.id,
      name: row.name,
      token: row.token,
      groupId: row.group_id,
      groupName: row.group_name || '',
      groupKey: row.group_key || '',
      enabled: row.enabled === 1,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at
    }));
  }

  function createAccessKey(accessKey) {
    insertAccessKeyStmt.run(
      accessKey.id,
      accessKey.name,
      accessKey.token,
      accessKey.groupId || null,
      accessKey.enabled ? 1 : 0,
      accessKey.createdAt || new Date().toISOString(),
      accessKey.lastUsedAt || ''
    );
  }

  function updateAccessKey(accessKeyId, accessKey) {
    updateAccessKeyStmt.run(
      accessKey.name,
      accessKey.groupId || null,
      accessKey.enabled ? 1 : 0,
      accessKeyId
    );
  }

  function deleteAccessKey(accessKeyId) {
    deleteAccessKeyStmt.run(accessKeyId);
  }

  function getAccessKeyByToken(token) {
    const row = accessKeyByTokenStmt.get(token);
    if (!row) {
      return null;
    }
    return {
      id: row.id,
      name: row.name,
      token: row.token,
      groupId: row.group_id || '',
      groupName: row.group_name || '',
      groupKey: row.group_key || '',
      groupEnabled: row.group_enabled === 1,
      enabled: row.enabled === 1,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at
    };
  }

  function touchAccessKey(accessKeyId, nowIso) {
    updateAccessKeyLastUsedStmt.run(nowIso || new Date().toISOString(), accessKeyId);
  }

  function getStickyBinding(stickyKey, nowMs = Date.now()) {
    const key = String(stickyKey || '').trim();
    if (!key) {
      return null;
    }
    const row = stickyByKeyStmt.get(key);
    if (!row) {
      return null;
    }
    if (row.expires_at <= nowMs) {
      deleteStickyByKeyStmt.run(key);
      return null;
    }
    return {
      stickyKey: row.sticky_key,
      accountId: row.account_id,
      expiresAt: row.expires_at
    };
  }

  function setStickyBinding(stickyKey, accountId, expiresAt) {
    const key = String(stickyKey || '').trim();
    const account = String(accountId || '').trim();
    const expires = Number(expiresAt);
    if (!key || !account || !Number.isFinite(expires) || expires <= 0) {
      return;
    }
    upsertStickyStmt.run(key, account, Math.floor(expires));
  }

  function clearStickyBinding(stickyKey) {
    const key = String(stickyKey || '').trim();
    if (!key) {
      return;
    }
    deleteStickyByKeyStmt.run(key);
  }

  function clearStickyBindingsByAccount(accountId) {
    const account = String(accountId || '').trim();
    if (!account) {
      return;
    }
    deleteStickyByAccountStmt.run(account);
  }

  function cleanupExpiredStickyBindings(nowMs = Date.now()) {
    deleteExpiredStickyStmt.run(Math.floor(nowMs));
  }

  function countActiveStickyBindings(nowMs = Date.now()) {
    const row = countActiveStickyStmt.get(Math.floor(nowMs));
    return Number(row?.total || 0);
  }

  function getAdminSession(token, nowMs = Date.now()) {
    const sessionToken = String(token || '').trim();
    if (!sessionToken) {
      return null;
    }
    const row = adminSessionByTokenStmt.get(sessionToken);
    if (!row) {
      return null;
    }
    if (row.expires_at <= nowMs) {
      deleteAdminSessionStmt.run(sessionToken);
      return null;
    }
    return {
      token: row.token,
      expiresAt: row.expires_at
    };
  }

  function setAdminSession(token, expiresAt) {
    const sessionToken = String(token || '').trim();
    const expires = Number(expiresAt);
    if (!sessionToken || !Number.isFinite(expires) || expires <= 0) {
      return;
    }
    upsertAdminSessionStmt.run(sessionToken, Math.floor(expires));
  }

  function deleteAdminSession(token) {
    const sessionToken = String(token || '').trim();
    if (!sessionToken) {
      return;
    }
    deleteAdminSessionStmt.run(sessionToken);
  }

  function cleanupExpiredAdminSessions(nowMs = Date.now()) {
    deleteExpiredAdminSessionStmt.run(Math.floor(nowMs));
  }

  function appendRequestLog(entry) {
    insertRequestLogStmt.run(
      entry.id,
      entry.at,
      entry.method || '',
      entry.path || '',
      entry.endpoint || '',
      entry.provider || 'unknown',
      entry.account || '-',
      entry.model || '-',
      entry.requestModel || '-',
      entry.groupKey || '-',
      entry.accessKeyId || '-',
      Number(entry.statusCode) || 0,
      Number(entry.tokens) || 0,
      Number(entry.inputTokens) || 0,
      Number(entry.outputTokens) || 0,
      Number(entry.cachedTokens) || 0,
      entry.gatewayCache || '',
      entry.upstreamCache || '',
      entry.cacheLayer || '',
      Number(entry.costMinor) || 0,
      entry.currency || 'USD',
      Number(entry.durationMs) || 0,
      entry.error || '',
      entry.debugInfo || '',
      entry.compatUnsupported || '',
      Number(entry.attempts) || 1,
      Number(entry.switches) || 0,
      entry.retryReason || '',
      entry.stickyHit ? 1 : 0
    );
  }

  function listRecentRequestLogs(limit = 120) {
    const safeLimit = Math.max(Math.floor(Number(limit) || 120), 1);
    return listRecentRequestLogsStmt.all(safeLimit).map((row) => ({
      id: row.id,
      at: row.at,
      method: row.method,
      path: row.path,
      endpoint: row.endpoint,
      provider: row.provider,
      account: row.account,
      model: row.model,
      requestModel: row.request_model,
      groupKey: row.group_key,
      accessKeyId: row.access_key_id,
      statusCode: row.status_code,
      tokens: row.tokens,
      inputTokens: row.input_tokens,
      outputTokens: row.output_tokens,
      cachedTokens: row.cached_tokens,
      gatewayCache: row.gateway_cache,
      upstreamCache: row.upstream_cache,
      cacheLayer: row.cache_layer,
      costMinor: row.cost_minor,
      currency: row.currency,
      durationMs: row.duration_ms,
      error: row.error,
      debugInfo: row.debug_info || '',
      compatUnsupported: row.compat_unsupported,
      attempts: row.attempts,
      switches: row.switches,
      retryReason: row.retry_reason,
      stickyHit: row.sticky_hit === 1
    }));
  }

  function trimRequestLogs(maxRows = 2000) {
    const safeMax = Math.max(Math.floor(Number(maxRows) || 2000), 1);
    trimRequestLogsStmt.run(safeMax);
  }

  function appendRiskControlLog(entry) {
    insertRiskControlLogStmt.run(
      entry.id,
      entry.at,
      entry.requestId || '',
      entry.groupKey || '',
      entry.accessKeyId || '',
      entry.provider || '',
      entry.path || '',
      entry.model || '',
      entry.account || '',
      entry.mode || 'observe',
      entry.action || 'allow',
      entry.blocked ? 1 : 0,
      entry.sampled === false ? 0 : 1,
      entry.inputHash || '',
      entry.excerpt || '',
      entry.l1Flagged ? 1 : 0,
      Number(entry.l1Score) || 0,
      entry.l1Category || '',
      entry.l1Error || '',
      Number(entry.l1LatencyMs) || 0,
      entry.l2Flagged ? 1 : 0,
      Number(entry.l2Score) || 0,
      entry.l2Reason || '',
      entry.l2Raw || '',
      entry.l2Error || '',
      Number(entry.l2LatencyMs) || 0,
      entry.finalReason || '',
      Number(entry.statusCode) || 0
    );
  }

  function listRecentRiskControlLogs(limit = 120) {
    const safeLimit = Math.max(Math.floor(Number(limit) || 120), 1);
    return listRecentRiskControlLogsStmt.all(safeLimit).map((row) => ({
      id: row.id,
      at: row.at,
      requestId: row.request_id,
      groupKey: row.group_key,
      accessKeyId: row.access_key_id,
      provider: row.provider,
      path: row.path,
      model: row.model,
      account: row.account,
      mode: row.mode,
      action: row.action,
      blocked: row.blocked === 1,
      sampled: row.sampled === 1,
      inputHash: row.input_hash,
      excerpt: row.excerpt,
      l1Flagged: row.l1_flagged === 1,
      l1Score: Number(row.l1_score) || 0,
      l1Category: row.l1_category,
      l1Error: row.l1_error,
      l1LatencyMs: row.l1_latency_ms,
      l2Flagged: row.l2_flagged === 1,
      l2Score: Number(row.l2_score) || 0,
      l2Reason: row.l2_reason,
      l2Raw: row.l2_raw,
      l2Error: row.l2_error,
      l2LatencyMs: row.l2_latency_ms,
      finalReason: row.final_reason,
      statusCode: row.status_code
    }));
  }

  function trimRiskControlLogs(maxRows = 5000) {
    const safeMax = Math.max(Math.floor(Number(maxRows) || 5000), 1);
    trimRiskControlLogsStmt.run(safeMax);
  }

	function listGroups() {
	  return listGroupsStmt.all().map((row) => ({
	    id: row.id,
	    name: row.name,
	    groupKey: row.group_key,
	    description: row.description,
	    enabled: row.enabled === 1,
	    createdAt: row.created_at
	  }));
	}

	function getGroupById(groupId) {
    const row = groupByIdStmt.get(groupId);
    if (!row) {
      return null;
    }
	  return {
	    id: row.id,
	    name: row.name,
	    groupKey: row.group_key,
	    description: row.description,
	    enabled: row.enabled === 1,
	    createdAt: row.created_at
	  };
	}

	function getGroupByKey(groupKey) {
    const key = safeModelName(groupKey);
    if (!key) {
      return null;
    }
    const row = groupByKeyStmt.get(key);
    if (!row) {
      return null;
    }
	  return {
	    id: row.id,
	    name: row.name,
	    groupKey: row.group_key,
	    description: row.description,
	    enabled: row.enabled === 1,
	    createdAt: row.created_at
	  };
	}

	function createGroup(group) {
	  insertGroupStmt.run(
	    group.id,
	    group.name,
	    group.groupKey,
	    group.description || '',
	    group.enabled ? 1 : 0,
	    group.createdAt || new Date().toISOString()
	  );
	}

	function updateGroup(groupId, group) {
	  updateGroupStmt.run(
	    group.name,
	    group.groupKey,
	    group.description || '',
	    group.enabled ? 1 : 0,
	    groupId
	  );
	}

  function deleteGroup(groupId) {
    deleteGroupStmt.run(groupId);
  }

  function listGroupMembers(groupId) {
    return listGroupMembersStmt.all(groupId).map((row) => ({
      groupId: row.group_id,
      accountId: row.account_id,
      accountName: row.account_name,
      accountEnabled: row.account_enabled === 1,
      weight: row.weight
    }));
  }

  function upsertGroupMember(groupId, accountId, weight = 1) {
    const safeWeight = Number.isFinite(weight) && weight > 0 ? Math.floor(weight) : 1;
    upsertGroupMemberStmt.run(groupId, accountId, safeWeight);
  }

  function removeGroupMember(groupId, accountId) {
    deleteGroupMemberStmt.run(groupId, accountId);
  }

  function listAccountsByGroupKey(groupKey) {
    const key = safeModelName(groupKey);
    if (!key) {
      return [];
    }
    return listAccountsForGroupStmt.all(key).map(toAccount);
  }

  return {
    getSettings,
    updateSettings,
    listAccounts,
    getAccountById,
    createAccount,
    updateAccount,
    updateAccountStats,
    resetAccountQuota,
    deleteAccount,
    listAccountModels,
    listAccountModelsForAccounts,
    addAccountModel,
    removeAccountModel,
    syncRemoteModels,
    replaceAccountModels,
    listModelMappings,
    upsertModelMapping,
    deleteModelMapping,
    resolveMappedModel,
    listModelQuotas,
    getModelQuota,
    upsertModelQuota,
    deleteModelQuota,
    resetModelQuotaUsage,
    reserveModelQuota,
    releaseModelQuotaReservation,
    addModelQuotaUsage,
    listModelPrices,
    getModelPrice,
    upsertModelPrices,
    deleteModelPrice,
    listGroups,
    getGroupById,
    getGroupByKey,
    createGroup,
    updateGroup,
    deleteGroup,
    listGroupMembers,
    upsertGroupMember,
    removeGroupMember,
    listAccountsByGroupKey,
    listAccessKeys,
    createAccessKey,
    updateAccessKey,
    deleteAccessKey,
    getAccessKeyByToken,
    touchAccessKey,
    getStickyBinding,
    setStickyBinding,
    clearStickyBinding,
    clearStickyBindingsByAccount,
    cleanupExpiredStickyBindings,
    countActiveStickyBindings,
    getAdminSession,
    setAdminSession,
    deleteAdminSession,
    cleanupExpiredAdminSessions,
    appendRequestLog,
    listRecentRequestLogs,
    trimRequestLogs,
    appendRiskControlLog,
    listRecentRiskControlLogs,
    trimRiskControlLogs,
    close
  };
}
