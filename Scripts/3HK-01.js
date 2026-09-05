/**
 * ================================================================
 * Surge / Loon 双平台智能出站模式切换脚本（带WIFI白名单最后一版）  v2.5
 * 目标版本：Surge iOS 5.22.0 (Build 3831) / Loon 3.5.1 (987)
 * ================================================================
 * v2.5 变更：
 *  P1  平台抽象层 Platform：运行时识别 Surge / Loon，网络信息、模式切换、HTTP timeout 单位各走一套实现
 *  P2  Loon：$httpClient.timeout 为毫秒（Surge 为秒）；网络信息来自 $config.getConfig() 仅有 ssid，
 *      无接口名/网关/IP → kind 只能按 ssid 有无区分 wifi/cell，指纹恒为弱指纹策略（缩短 TTL、不作 direct fallback）
 *  P3  Loon 可读真实运行模式 running_model：切换前校对，lastMode 漂移问题在 Loon 上彻底解决
 *  P4  模式映射：内部 direct/rule/proxy ↔ Surge "direct"/"rule"/"global-proxy" ↔ Loon 0/1/2
 *  P5  Surge JSC 引擎无 clearTimeout，改用 safeClearTimeout；两平台 setter 返回 false 时视为失败
 *  P6  Surge iOS 蜂窝指纹优先使用 $network['cellular-data'].carrier（跨基站稳定）
 *  P7  探针强制直连：Surge $httpClient policy=DIRECT / Loon node=DIRECT，判定回路从根上消除；
 *      探针结果携带 ip，冲突日志打印双方 IP 便于诊断
 *
 * v2.4 变更（对照第三轮审阅 18 条）：
 *  R1  缓存命中但 liveness 显示出口变化且指向 direct → 不再直接切换/写缓存，转入完整路径交叉验证
 *  R2  探针健康度只对"真实失败"记账：截短超时、未就绪时的 NET_ERR、ABORT 不计；budget<1500 直接 NO_BUDGET
 *  R3  FINISHED 后 probe 不 resolve、不落账；$done 后无任何写盘
 *  R4  token 写盘失败 → ERROR 并降级为内存 token（单实例模式），不再静默瘫痪
 *  R5  软让步改为"先等待再写入 token"，给旧实例完成 switchMode 的窗口
 *  R6  fetchLoc 暴露 all（全部结果），交叉验证优先复用竞速败者，避免重复请求
 *  R7  SSID/BSSID 皆空的弱指纹拼入 gw+子网+v6 前缀，TTL 缩短，且不允许 fallback 到 direct 缓存
 *  R8  lastModeKind：bootstrap 与 fresh 跳过均按链路类型判断
 *  R9  蜂窝 v6 前缀缩至 2 段；LRU 淘汰优先同 kind；蜂窝缓存仅可作为 rule 方向依据
 *  R10 头注释修正：DIRECT 规则仅在 rule 模式生效，proxy 模式下脚本不可用；WHITELIST_MODE=proxy 告警
 *  R11 readJSON 拒绝非对象 JSON 并自愈
 *  R12 仅对 TIMEOUT/NET_ERR/NO_RESP 重试；确定性失败不重试
 *  R13 Budget.READY_POLL 与决策最低需求对齐；validateConfig 校验预算充足性
 *  R14 lastAppliedMode 驱动 changed / 通知，避免 bootstrap 后重复通知
 *  R15 switchMode 单次 mutate 完成判定与写入
 *  R16 probeStats 清理失效探针；成功率改 EWMA
 *  R17 finally 前短暂等待在飞请求并输出 pending 数
 *  R18 双探针专用策略：健康度只用于统计/日志，不再把探针排除出竞速或交叉验证；
 *      新增 SINGLE_SOURCE_POLICY 决定第二探针不可用时对 direct 的处理
 *
 * ---------------------------------------------------------------
 * 部署前置条件（必读）：
 *
 * 1) 探针请求已由脚本强制直连（PROBE_FORCE_DIRECT：Surge policy=DIRECT / Loon node=DIRECT），
 *    不再依赖 [Rule] 配置，也不受当前出站模式影响（含 proxy/全局模式）。
 *    仍建议在 [Rule] 顶部保留以下规则作为双保险（例如关闭 PROBE_FORCE_DIRECT 时）：
 *      DOMAIN-SUFFIX,cloudflare-cn.com,DIRECT
 *      DOMAIN-SUFFIX,ip.sb,DIRECT
 *    诊断：若日志出现「交叉冲突 A=HK(ip1) vs B=CN(ip2)」且两 IP 明显不同，说明有探针走了代理。
 *
 * 2) 脚本超时必须显式放大，并通过 argument 把同一数值告知脚本（两处相邻，改时一并修改）；
 *    脚本会据此把 DEADLINE_MS 自动收紧到 timeout−10s。未提供 argument 时按 60s 处理并输出 WARN。
 *    Surge 5.22 [Script]（建议同时挂 engine-started，解决 Surge 冷启动后首次不触发 network-changed 的问题）：
 *      smart-route = type=event,event-name=network-changed,script-path=smart-route.js,timeout=60,argument=timeout=60
 *      smart-route-boot = type=event,event-name=engine-started,script-path=smart-route.js,timeout=60,argument=timeout=60
 *    Loon 3.5.1(983+) [Script]（新语法；timeout 默认 300，显式写 60 与 argument 对齐）：
 *      network-changed then script("smart-route.js", "timeout=60") with tag="智能路由", timeout=60
 *    Loon 3.5.0 / 3.5.1(≤982) [Script]（旧语法；脚本 JS 代码本身无版本要求，两种写法均可）：
 *      network-changed script-path=smart-route.js,tag=智能路由,timeout=60,argument="timeout=60",enable=true
 *    差异：新语法下同一事件会执行所有已启用的 network-changed 脚本，旧语法只执行第一条。
 *    Loon 的 DIRECT 规则写法：DOMAIN-SUFFIX,cloudflare-cn.com,DIRECT / DOMAIN-SUFFIX,ip.sb,DIRECT（与 Surge 相同）
 *
 * 3) 授予 Surge / Loon「精确定位」权限，否则 SSID 不可读，Wi-Fi 指纹退化（脚本会 WARN 并缩短缓存 TTL）。
 *    Loon 下即使有权限也只有 ssid（无 bssid/网关/IP），白名单请只用 SSID 规则。
 *
 * 4) 平台 API 事实：
 *    Surge: $httpClient timeout 单位「秒」；$network.v4/v6 仅 primaryAddress/primaryInterface/primaryRouter；
 *           $surge.setOutboundMode 无 getter；$persistentStore.write 失败返回 false
 *    Surge: setOutboundMode 合法值 "direct" | "rule" | "global-proxy"（不是 "proxy"）；所有 $surge setter 返回 Boolean；
 *           默认 engine=auto，JSC 下无 clearTimeout；$network 在 iOS 另有 cellular-data{carrier,radio}
 *    Loon:  $httpClient timeout 单位「毫秒」（默认 5000）；$config.getConfig() 返回 JSON 字符串，含 running_model(0 直连/1 分流/2 全局)
 *           与 ssid；$config.setRunningModel(n)；$argument 省略时为 null
 * ================================================================
 */

'use strict';

const CONFIG = {
  LOG_LEVEL: 'INFO',
  USE_EMOJI: true,
  PROFILE: true,
  NOTIFY_ON_SWITCH: false,
  NOTIFY_MIN_INTERVAL_MS: 60000,

  WIFI_WHITELIST_SSID: [/^NTJGJT-AC5[1-9]U$/, 'Metropark', 'HMetropark'],
  WIFI_WHITELIST_BSSID: [],
  WHITELIST_MODE: 'direct',

  RULE_LOCS: ['CN'],

  // 双探针配置。两者并发竞速，首个成功者给出判定；切向 direct 时必须由另一探针交叉验证。
  PROBES: [
    { name: 'CF',   url: 'https://www.cloudflare-cn.com/cdn-cgi/trace', parser: 'trace' },
    { name: 'IPSB', url: 'https://api.ip.sb/geoip',                     parser: 'json'  }
  ],
  PROBE_UNHEALTHY_AFTER: 5,          // 连续失败 N 次标记为 down（仅日志/统计，双探针下不排除该探针）
  PROBE_UNHEALTHY_TTL_MS: 600000,
  /**
   * 第二探针不可用（超时/被拒/解析失败）时对 direct 判定的处理：
   *  'deny'    —— 拒绝切 direct，保持现状（默认，最安全）
   *  'confirm' —— 允许同一探针间隔 SINGLE_SOURCE_GAP_MS 再次返回相同非 CN 地区后切 direct。
   *              仅能防偶发抖动，不能防该探针的系统性误判；仅在 api.ip.sb 在你的网络下长期不可达时启用。
   */
  SINGLE_SOURCE_POLICY: 'deny',
  SINGLE_SOURCE_GAP_MS: 1500,
  PROBE_MIN_BUDGET_MS: 1500,         // R2 低于此预算的探测注定超时，不发起
  PROBE_FORCE_DIRECT: true,          // P7 探针请求强制直连（Surge policy / Loon node = DIRECT），不再依赖 [Rule]

  DEADLINE_MS: 40000,
  DEFAULT_SCRIPT_TIMEOUT_MS: 60000,  // 仅当 [Script] 未提供 argument=timeout=N 时使用

  BOOT_DELAY_MS: 800,
  BOOT_YIELD_MS: 1500,
  ACTIVE_INSTANCE_MS: 20000,
  WIFI_BUFFER_MS: 1200,
  WIRED_BUFFER_MS: 600,
  CELLULAR_BUFFER_MS: 3500,
  READY_POLL_MAX: 4,
  READY_POLL_BASE_MS: 350,
  READY_POLL_CAP_MS: 1500,

  PROBE_TIMEOUT_MS: 4000,
  LIVENESS_TIMEOUT_MS: 2500,
  MAX_RETRIES: 1,
  RETRY_BASE_MS: 600,

  RECHECK_DELAY_WIFI_MS: 4000,
  RECHECK_DELAY_CELLULAR_MS: 7000,

  CACHE_TTL_WIFI_MS: 12 * 3600000,
  CACHE_TTL_CELLULAR_MS: 2 * 3600000,
  CACHE_TTL_WEAK_MS: 2 * 3600000,    // R7 弱指纹
  MAX_CACHE_COUNT: 24,

  MODE_REASSERT_MS: 60000,
  PROBE_STATS_ALPHA: 0.3,
  PENDING_DRAIN_MS: 300              // R17 结束前等待在飞请求的最长时间
};

// ==================== 环境注入 ====================
const Env = {
  http:    () => (typeof $httpClient !== 'undefined' ? $httpClient : null),
  store:   () => (typeof $persistentStore !== 'undefined' ? $persistentStore : null),
  notify:  () => (typeof $notification !== 'undefined' ? $notification : null),
  done:    (v) => { if (typeof $done === 'function') $done(v); },
  argument: () => (typeof $argument !== 'undefined' ? String($argument || '') : '')
};

// ==================== 平台抽象层（P1）====================
const LOON_MODEL = { direct: 0, rule: 1, proxy: 2 };
const LOON_MODEL_NAME = ['direct', 'rule', 'proxy'];

const Platform = (() => {
  const isLoon = typeof $loon !== 'undefined' || (typeof $config !== 'undefined' && $config && typeof $config.setRunningModel === 'function');
  const isSurge = !isLoon && typeof $surge !== 'undefined';

  if (isLoon) {
    const cfg = () => {
      try { const c = $config.getConfig(); return (typeof c === 'string' ? JSON.parse(c) : c) || {}; }
      catch (e) { return {}; }
    };
    return {
      name: 'Loon',
      /** Loon $httpClient.timeout 单位为毫秒 */
      httpTimeout: ms => Math.max(500, Math.round(ms)),
      /** Loon 用 node 字段指定出站（内置 DIRECT） */
      directRequestFields: () => ({ node: 'DIRECT' }),
      /** Loon 只暴露 ssid；无接口名/网关/IP */
      rawNetwork: () => {
        const c = cfg();
        return { ssid: c.ssid || '', bssid: c.bssid || '', loonOnly: true };
      },
      canSetMode: () => typeof $config !== 'undefined' && typeof $config.setRunningModel === 'function',
      /** P3：Loon 可读真实运行模式 */
      getMode: () => {
        const m = cfg().running_model;
        return LOON_MODEL_NAME[m] || null;
      },
      setMode: mode => { const ok = $config.setRunningModel(LOON_MODEL[mode]); if (ok === false) throw new Error('setRunningModel 返回 false'); }
    };
  }
  return {
    name: isSurge ? 'Surge' : 'Unknown',
    /** Surge $httpClient.timeout 单位为秒 */
    httpTimeout: ms => Math.max(1, Math.ceil(ms / 1000)),
    /** Surge 用 policy 字段指定出站（内置 DIRECT） */
    directRequestFields: () => ({ policy: 'DIRECT' }),
    rawNetwork: () => {
      const n = typeof $network !== 'undefined' ? ($network || {}) : {};
      const v4 = n.v4 || {}, v6 = n.v6 || {}, wifi = n.wifi || {};
      return {
        ssid: wifi.ssid || '', bssid: wifi.bssid || '',
        iface: v4.primaryInterface || v6.primaryInterface || '',
        gw: v4.primaryRouter || v6.primaryRouter || '',
        addr4: v4.primaryAddress || '', addr6: v6.primaryAddress || '',
        carrier: (n['cellular-data'] && n['cellular-data'].carrier) || '',   // iOS 专有
        radio: (n['cellular-data'] && n['cellular-data'].radio) || ''
      };
    },
    canSetMode: () => typeof $surge !== 'undefined' && $surge && typeof $surge.setOutboundMode === 'function',
    getMode: () => null,                                             // Surge 无 getter
    /** Surge 的全局代理模式字符串是 'global-proxy'，脚本内部统一用 'proxy' */
    setMode: mode => { const ok = $surge.setOutboundMode(mode === 'proxy' ? 'global-proxy' : mode); if (ok === false) throw new Error('setOutboundMode 返回 false'); }
  };
})();

/** 解析 [Script] argument="k=v&k2=v2" 或 "k=v,k2=v2" */
function parseArgument() {
  const out = {};
  Env.argument().split(/[&,;]/).forEach(kv => {
    const i = kv.indexOf('=');
    if (i > 0) out[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  });
  return out;
}

// ==================== 运行期上下文 ====================
const KEY_TOKEN = 'smart_route_token_v25';
const KEY_STATE = 'smart_route_state_v25';
const TOKEN = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const T0 = Date.now();
let FINISHED = false;
let TOKEN_LOCAL_ONLY = false;         // R4
let PENDING_REQUESTS = 0;             // R17

const LOG_LEVELS = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
const EMOJI_RE = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}\u{200D}]/gu;
const elapsed = () => Date.now() - T0;
/** Surge JSC 引擎无 clearTimeout（仅 WebView 有）；finish 已有 settled 守卫，清不掉也无副作用 */
const safeClearTimeout = t => { if (typeof clearTimeout === 'function') clearTimeout(t); };

function log(level, msg) {
  if (FINISHED) return;
  const lv = LOG_LEVELS[level];
  const min = LOG_LEVELS[CONFIG.LOG_LEVEL] !== undefined ? LOG_LEVELS[CONFIG.LOG_LEVEL] : 1;
  if (lv === undefined || lv < min) return;
  const text = CONFIG.USE_EMOJI ? msg : String(msg).replace(EMOJI_RE, '');
  console.log(`[SR ${TOKEN}] [${level}] [+${elapsed()}ms] ${text}`);
}

// ==================== 时间预算 ====================
const budgetLeft = () => CONFIG.DEADLINE_MS - elapsed();
const outOfBudget = (reserve = 0) => budgetLeft() <= reserve;
const sleep = ms => new Promise(r => setTimeout(r, Math.max(0, Math.min(ms, Math.max(0, budgetLeft())))));

const Budget = {
  PROBE_ONCE:  () => CONFIG.PROBE_TIMEOUT_MS + 800,
  PROBE_RETRY: () => CONFIG.PROBE_TIMEOUT_MS + 1500,
  LIVENESS:    () => CONFIG.LIVENESS_TIMEOUT_MS + 1000,
  DECIDE_MIN:  () => Budget.LIVENESS() + Budget.PROBE_ONCE() + 500,   // R13 决策最低需求
  READY_POLL:  () => Budget.DECIDE_MIN()
};

async function withBudget(label, reserve, factory, fallback) {
  if (outOfBudget(reserve)) {
    log('WARN', `[Budget] ${label} 需 ${reserve}ms，剩余 ${Math.max(0, budgetLeft())}ms，跳过`);
    return fallback;
  }
  return factory();
}

// ==================== 存储 ====================
function readJSON(key) {
  const ps = Env.store();
  if (!ps) return {};
  let v;
  try { v = JSON.parse(ps.read(key) || '{}'); }
  catch (e) { v = null; }
  if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  log('WARN', `${key} 内容非法（非对象），已重置`);                 // R11
  try { ps.write('{}', key); } catch (_) {}
  return {};
}
function writeJSON(key, obj) {
  if (FINISHED) return false;                                        // R3
  const ps = Env.store();
  if (!ps) return false;
  try {
    const ok = ps.write(JSON.stringify(obj), key);
    if (ok === false) { log('ERROR', `${key} 写入失败（write 返回 false）`); return false; }
    return true;
  } catch (e) { log('ERROR', `${key} 写入异常: ${e}`); return false; }
}
const State = {
  read: () => readJSON(KEY_STATE),
  mutate(fn) {
    const s = readJSON(KEY_STATE);
    const patch = fn(s) || {};
    if (!Object.keys(patch).length) return s;
    const next = Object.assign(s, patch);
    writeJSON(KEY_STATE, next);
    return next;
  }
};

// ==================== Token（R4 写失败降级；R5 先让步再接管）====================
const Token = {
  async register() {
    const prev = readJSON(KEY_TOKEN);
    const age = Date.now() - (prev.ts || 0);
    if (prev.active && age < CONFIG.ACTIVE_INSTANCE_MS) {
      log('DEBUG', `检测到活跃实例 ${prev.active}（${age}ms），让步 ${CONFIG.BOOT_YIELD_MS}ms`);
      await sleep(CONFIG.BOOT_YIELD_MS);
      const again = readJSON(KEY_TOKEN);
      log('DEBUG', again.active ? `让步结束，接管 ${again.active}` : '让步期间旧实例已自然结束');
    } else if (prev.active) {
      log('DEBUG', `抢占僵尸 token ${prev.active}（${age}ms）`);
    }
    if (!Env.store()) { TOKEN_LOCAL_ONLY = true; log('WARN', '无持久化存储，token 降级为内存模式'); return; }
    if (!writeJSON(KEY_TOKEN, { active: TOKEN, ts: Date.now() })) {
      TOKEN_LOCAL_ONLY = true;
      log('ERROR', 'token 写入失败，降级为单实例模式（无法防并发）');
    }
  },
  isLatest() { return TOKEN_LOCAL_ONLY || readJSON(KEY_TOKEN).active === TOKEN; },
  release() {
    if (TOKEN_LOCAL_ONLY) return;
    if (readJSON(KEY_TOKEN).active === TOKEN) writeJSON(KEY_TOKEN, { active: '', ts: 0 });
  }
};

// ==================== 网络信息 ====================
function getNetworkInfo() {
  const raw = Platform.rawNetwork();
  const ssid = raw.ssid || '';
  const bssid = (raw.bssid || '').toLowerCase();

  if (raw.loonOnly) {
    // P2：Loon 无接口名/网关/IP。有 ssid → wifi；无 ssid → 无法区分蜂窝与无权限 Wi-Fi，按 cell 处理（更保守：
    // cell 缓存不作 direct fallback、TTL 2h），并输出 WARN 提示授权。
    const isWifi = !!ssid;
    const kind = isWifi ? 'wifi' : 'cell';
    return {
      iface: 'n/a', ssid, bssid, gw: '', kind, isWifi, isCellular: !isWifi, isWired: false,
      isReady: true,                                                 // Loon 无 IP 字段，视为就绪
      weak: !isWifi,
      loonAmbiguous: !isWifi,                                        // 标记"可能是无权限 Wi-Fi"
      fingerprint: isWifi ? `wifi|${ssid}|${bssid || 'loon'}` : 'cell|loon|unknown'
    };
  }

  const iface = raw.iface || 'none';
  const gw = raw.gw || '';
  const addr4 = raw.addr4 || '';
  const addr6 = raw.addr6 || '';
  const v6Prefix = addr6 ? addr6.split(':').slice(0, 4).join(':') : '';
  const v6Carrier = addr6 ? addr6.split(':').slice(0, 2).join(':') : '';  // R9 运营商级前缀
  const subnet4 = addr4 ? addr4.split('.').slice(0, 3).join('.') : '';

  const isCellular = /^pdp_ip\d*$/i.test(iface);
  const isWifi = !isCellular && (/^en0$/i.test(iface) || !!ssid);
  const isWired = !isCellular && !isWifi && iface !== 'none';
  const kind = isCellular ? 'cell' : isWifi ? 'wifi' : isWired ? 'wired' : 'none';
  const isReady = !!(addr4 || addr6);
  const weak = !isCellular && !ssid && !bssid;                       // R7 弱指纹

  const fingerprint = isCellular
    ? `cell|${raw.carrier || iface}|${v6Carrier || 'nov6'}`                    // 运营商名优先，跨基站稳定
    : weak
      ? `${kind}|?|${gw || '-'}/${subnet4 || '-'}/${v6Prefix || 'nov6'}`
      : `${kind}|${ssid || '?'}|${bssid || gw || subnet4 || iface}`;

  return { iface, ssid, bssid, gw, kind, isWifi, isCellular, isWired, isReady, weak, loonAmbiguous: false, fingerprint, carrier: raw.carrier || '', radio: raw.radio || '' };
}

function inWhitelist(net) {
  if (!net.isWifi) return false;
  if (net.bssid && CONFIG.WIFI_WHITELIST_BSSID.some(x => String(x).toLowerCase() === net.bssid)) return true;
  const s = net.ssid;
  return !!s && CONFIG.WIFI_WHITELIST_SSID.some(r => (r && typeof r.test === 'function' ? r.test(s) : r === s));
}

// ==================== 地区码 ====================
const INVALID_LOC = new Set(['XX', 'T1', 'ZZ', 'A1', 'A2', 'O1', 'EU', 'AP']);
function normLoc(raw) {
  const l = String(raw || '').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(l) && !INVALID_LOC.has(l) ? l : null;
}
const modeForLoc = loc => (CONFIG.RULE_LOCS.includes(loc) ? 'rule' : 'direct');

/** 解析器返回 { loc, ip }；loc 为 null 表示解析失败。ip 仅用于诊断日志 */
const PARSERS = {
  trace: body => {
    const t = String(body || '');
    return { loc: normLoc((t.match(/^loc=(\S+)\s*$/m) || [])[1]), ip: (t.match(/^ip=(\S+)\s*$/m) || [])[1] || '' };
  },
  json: body => {
    try { const j = JSON.parse(body || '{}'); return { loc: normLoc(j.country_code || j.countryCode), ip: j.ip || '' }; }
    catch (e) { return { loc: null, ip: '' }; }
  }
};
const bodyBrief = b => String(b || '').replace(/\s+/g, ' ').slice(0, 80) || '<empty>';

// ==================== 配置自检 ====================
function validateConfig() {
  const VALID_MODES = ['direct', 'rule', 'proxy'];
  if (!VALID_MODES.includes(CONFIG.WHITELIST_MODE)) {
    log('WARN', `WHITELIST_MODE="${CONFIG.WHITELIST_MODE}" 非法，回落 rule`);
    CONFIG.WHITELIST_MODE = 'rule';
  }
  if (CONFIG.WHITELIST_MODE === 'proxy') log('WARN', 'WHITELIST_MODE=proxy：该 SSID 上的任何探测结论均不可信（proxy 模式不评估规则）');   // R10
  // B 方案：脚本 timeout 从 [Script] argument=timeout=N 读取（秒），缺省回落 DEFAULT_SCRIPT_TIMEOUT_MS
  const arg = parseArgument();
  let timeoutMs = CONFIG.DEFAULT_SCRIPT_TIMEOUT_MS;
  if (arg.timeout !== undefined) {
    const sec = Number(arg.timeout);
    if (Number.isFinite(sec) && sec >= 15) timeoutMs = sec * 1000;
    else log('WARN', `argument timeout="${arg.timeout}" 非法（需 ≥15 的秒数），按 ${timeoutMs / 1000}s 处理`);
  } else {
    log('WARN', `[Script] 未提供 argument=timeout=N，按 ${timeoutMs / 1000}s 处理；请确保与实际 timeout= 一致`);
  }
  CONFIG.SCRIPT_TIMEOUT_MS = timeoutMs;
  const maxDeadline = timeoutMs - 10000;
  if (CONFIG.DEADLINE_MS > maxDeadline) {
    log('WARN', `DEADLINE_MS=${CONFIG.DEADLINE_MS} > timeout−10s(${maxDeadline})，已收紧`);
    CONFIG.DEADLINE_MS = maxDeadline;
  }
  const seen = new Set();
  CONFIG.PROBES = (Array.isArray(CONFIG.PROBES) ? CONFIG.PROBES : []).filter(p => {
    const ok = p && p.url && p.name && PARSERS[p.parser] && !seen.has(p.url);
    if (!ok) log('WARN', `探针 ${p && p.name} 配置非法或 url 重复，已忽略`);
    if (p) seen.add(p.url);
    return ok;
  });
  if (!CONFIG.PROBES.length) log('ERROR', 'PROBES 为空，脚本无法工作');
  else if (CONFIG.PROBES.length < 2) log('WARN', '有效探针少于 2 个，切向 direct 的交叉验证无法进行（脚本会拒绝切 direct）');
  if (!['deny', 'confirm'].includes(CONFIG.SINGLE_SOURCE_POLICY)) { log('WARN', `SINGLE_SOURCE_POLICY="${CONFIG.SINGLE_SOURCE_POLICY}" 非法，回落 deny`); CONFIG.SINGLE_SOURCE_POLICY = 'deny'; }
  if (CONFIG.SINGLE_SOURCE_POLICY === 'confirm') log('WARN', 'SINGLE_SOURCE_POLICY=confirm：第二探针不可用时将以同源二次确认放行 direct，安全性低于双源验证');
  CONFIG.RULE_LOCS = (CONFIG.RULE_LOCS || []).map(s => String(s).toUpperCase()).filter(s => /^[A-Z]{2}$/.test(s));
  if (!CONFIG.RULE_LOCS.length) { log('WARN', 'RULE_LOCS 为空或非法，回落 ["CN"]'); CONFIG.RULE_LOCS = ['CN']; }

  // R13 预算充足性
  const minNeeded = CONFIG.BOOT_DELAY_MS + CONFIG.BOOT_YIELD_MS + CONFIG.CELLULAR_BUFFER_MS + Budget.READY_POLL();
  if (CONFIG.DEADLINE_MS < minNeeded) log('WARN', `DEADLINE_MS=${CONFIG.DEADLINE_MS} 不足以完成一次决策（至少需 ${minNeeded}ms）`);

  const down = CONFIG.PROBES.filter(p => !ProbeStats.isHealthy(p.name)).map(p => p.name);
  log('INFO', `平台=${Platform.name} 配置: probes=${CONFIG.PROBES.map(p => p.name).join('/')}${down.length ? `(${down.join(',')} 持续失败中)` : ''} policy=${CONFIG.SINGLE_SOURCE_POLICY} ruleLocs=${CONFIG.RULE_LOCS.join(',')} whitelist=${CONFIG.WIFI_WHITELIST_SSID.length}ssid+${CONFIG.WIFI_WHITELIST_BSSID.length}bssid deadline=${CONFIG.DEADLINE_MS}ms timeout=${CONFIG.SCRIPT_TIMEOUT_MS / 1000}s`);
}

// ==================== 探针统计（R2 仅真实失败记账；R16 EWMA 成功率 + 清理）====================
const ENV_FAIL = new Set(['NO_BUDGET', 'ABORT', 'NO_HTTP', 'NO_PROBE']);
const ProbeStats = {
  _get(s) { return s.probeStats || {}; },
  isHealthy(name) {
    const h = this._get(State.read())[name];
    return !h || !h.downUntil || Date.now() > h.downUntil;
  },
  /** @param r 探针结果；r.truncated = 超时被预算截短；r.envReady = 调用时链路是否已有 IP */
  report(r) {
    if (FINISHED) return;                                            // R3
    if (!r.ok) {
      if (ENV_FAIL.has(r.reason)) return;
      if (r.reason === 'TIMEOUT' && r.truncated) return;             // 预算截短的超时不算探针的错
      if (r.reason === 'NET_ERR' && r.envReady === false) return;    // 无 IP 时的失败不算
    }
    const a = CONFIG.PROBE_STATS_ALPHA;
    const valid = new Set(CONFIG.PROBES.map(p => p.name));
    State.mutate(s => {
      const all = this._get(s);
      for (const k in all) if (!valid.has(k)) delete all[k];         // R16 清理失效探针
      const h = all[r.name] || { fails: 0, downUntil: 0, ewmaMs: 0, okRate: 1 };
      h.okRate = +(h.okRate * (1 - a) + (r.ok ? 1 : 0) * a).toFixed(3);
      if (r.ok) {
        h.fails = 0; h.downUntil = 0;
        h.ewmaMs = h.ewmaMs ? Math.round(h.ewmaMs * (1 - a) + r.latency * a) : r.latency;
      } else {
        h.fails++;
        h.lastReason = r.reason;
        if (h.fails >= CONFIG.PROBE_UNHEALTHY_AFTER) {
          h.downUntil = Date.now() + CONFIG.PROBE_UNHEALTHY_TTL_MS;
          h.fails = 0;
          log('WARN', `探针 ${r.name} 连续 ${CONFIG.PROBE_UNHEALTHY_AFTER} 次失败(${r.reason})；若长期如此且需要 direct，可考虑 SINGLE_SOURCE_POLICY=confirm`);
        }
      }
      all[r.name] = h;
      return { probeStats: all };
    });
  },
  summary() {
    const all = this._get(State.read());
    return Object.keys(all).map(k => {
      const h = all[k];
      return `${k}:${h.ewmaMs || '-'}ms/${Math.round((h.okRate || 0) * 100)}%${h.downUntil && Date.now() < h.downUntil ? '(down)' : ''}`;
    }).join(' ');
  }
};

// ==================== 探针 ====================
const withCacheBuster = url => url + (url.includes('?') ? '&' : '?') + 't=' + Date.now();

function probe(p, timeoutMs, ctx = {}) {
  return new Promise(resolve => {
    const start = Date.now();
    let settled = false;
    PENDING_REQUESTS++;
    const finish = out => {
      if (settled) return;
      settled = true;
      safeClearTimeout(timer);
      PENDING_REQUESTS--;
      out.name = p.name;
      out.latency = Date.now() - start;
      out.truncated = timeoutMs < CONFIG.PROBE_TIMEOUT_MS;
      out.envReady = ctx.ready;
      if (FINISHED) return;                                          // R3 不 resolve、不落账
      if (CONFIG.PROFILE) log('DEBUG', `[Probe] ${p.name} ${out.ok ? out.loc + (out.ip ? ' ' + out.ip : '') : out.reason} ${out.latency}ms`);
      resolve(out);
    };
    const timer = setTimeout(() => finish({ ok: false, reason: 'TIMEOUT' }), timeoutMs);
    const http = Env.http();
    if (!http) return finish({ ok: false, reason: 'NO_HTTP' });
    try {
      http.get({
        url: withCacheBuster(p.url),
        headers: {
          'Cache-Control': 'no-cache',
          'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
        },
        timeout: Platform.httpTimeout(timeoutMs),                   // P2 单位按平台换算
        ...(CONFIG.PROBE_FORCE_DIRECT ? Platform.directRequestFields() : {})   // P7 强制直连
      }, (error, response, body) => {
        if (FINISHED) return finish({ ok: false, reason: 'ABORT' });
        if (error) return finish({ ok: false, reason: 'NET_ERR' });
        if (!response) return finish({ ok: false, reason: 'NO_RESP' });
        if (response.status >= 400) {
          if (response.status === 403 || response.status === 429) log('WARN', `[Probe] ${p.name} 被拒绝 HTTP ${response.status}`);
          return finish({ ok: false, reason: `HTTP_${response.status}` });
        }
        const parsed = (PARSERS[p.parser] && PARSERS[p.parser](body)) || { loc: null, ip: '' };
        if (parsed.loc) return finish({ ok: true, loc: parsed.loc, ip: parsed.ip });
        log('DEBUG', `[Probe] ${p.name} 解析失败 body="${bodyBrief(body)}"`);
        return finish({ ok: false, reason: 'PARSE_FAIL' });
      });
    } catch (e) { finish({ ok: false, reason: 'THROW' }); }
  });
}

/**
 * 并发探针，首个成功即 resolve；成功结果对象附带 .all（全部结果数组的 Promise，R6）。
 * @param {object} ctx  { ready: boolean }
 */
function fetchLoc(timeoutMs = CONFIG.PROBE_TIMEOUT_MS, probes = CONFIG.PROBES, ctx = {}) {
  const budget = Math.min(timeoutMs, budgetLeft() - 300);
  if (budget < CONFIG.PROBE_MIN_BUDGET_MS) return Promise.resolve({ ok: false, reason: 'NO_BUDGET', reasons: ['NO_BUDGET'] });   // R2
  const list = probes;                                                 // R18 双探针下不按健康度过滤：两者都必须参与
  if (!list.length) return Promise.resolve({ ok: false, reason: 'NO_PROBE', reasons: ['NO_PROBE'] });
  const runs = list.map(p => probe(p, budget, ctx).then(r => { ProbeStats.report(r); return r; }));
  const all = Promise.all(runs);
  const first = new Promise(resolve => {
    let pending = runs.length, done = false;
    const reasons = [];
    runs.forEach(run => run.then(r => {
      if (done) return;
      if (r.ok) { done = true; r.all = all; return resolve(r); }          // 结果对象携带 all，供交叉验证复用败者
      reasons.push(r.reason);
      if (--pending === 0) { done = true; resolve({ ok: false, reason: 'ALL_FAILED', reasons }); }
    }));
  });
  return first;
}

const RETRYABLE = /TIMEOUT|NET_ERR|NO_RESP/;                          // R12
async function fetchLocWithRetry(ctx, maxRetries = CONFIG.MAX_RETRIES) {
  let last = { ok: false, reason: 'NONE' };
  for (let i = 0; i <= maxRetries; i++) {
    last = await fetchLoc(CONFIG.PROBE_TIMEOUT_MS, CONFIG.PROBES, ctx);
    if (last.ok || last.reason === 'NO_BUDGET' || !Token.isLatest()) return last;
    const retryable = RETRYABLE.test((last.reasons || [last.reason]).join(','));
    if (!retryable) { log('DEBUG', `失败原因 ${(last.reasons || []).join('/')} 不可重试`); break; }
    if (i < maxRetries && !outOfBudget(Budget.PROBE_RETRY())) {
      const d = CONFIG.RETRY_BASE_MS * Math.pow(2, i);
      log('WARN', `探针失败(${(last.reasons || []).join('/')})，${d}ms 后重试`);
      await sleep(d);
    } else break;
  }
  return Object.assign({ ok: false }, last, { reason: 'EXHAUSTED', last: last.reason });
}

// ==================== 缓存（R7 弱指纹 TTL；R9 同 kind 淘汰）====================
function cacheScore(c, now) {
  const ageMin = (now - (c.lastAccess || c.createdAt || 0)) / 60000;
  return 1 / (1 + ageMin) + Math.min(c.hits || 0, 10) * 0.15;
}
const kindOfKey = k => k.split('|')[0];
const ttlForKey = k => {
  if (kindOfKey(k) === 'cell') return CONFIG.CACHE_TTL_CELLULAR_MS;
  if (k.split('|')[1] === '?') return CONFIG.CACHE_TTL_WEAK_MS;
  return CONFIG.CACHE_TTL_WIFI_MS;
};

const Cache = {
  get(net) {
    const c = (State.read().caches || {})[net.fingerprint];
    if (!c) return null;
    if (Date.now() - (c.createdAt || 0) >= ttlForKey(net.fingerprint)) return null;
    return { loc: c.loc, mode: modeForLoc(c.loc), createdAt: c.createdAt, weak: !!net.weak, cell: !!net.isCellular };
  },
  set(net, loc) {
    if (!Token.isLatest()) { log('DEBUG', 'token 失效，放弃写缓存'); return; }
    const now = Date.now();
    State.mutate(s => {
      const caches = s.caches || {};
      for (const k in caches) if (now - (caches[k].createdAt || 0) >= ttlForKey(k)) delete caches[k];
      const old = caches[net.fingerprint];
      if (!old && Object.keys(caches).length >= CONFIG.MAX_CACHE_COUNT) {
        const keys = Object.keys(caches);
        const sameKind = keys.filter(k => kindOfKey(k) === net.kind);
        const pool = sameKind.length ? sameKind : keys;              // R9 优先淘汰同类
        delete caches[pool.sort((a, b) => cacheScore(caches[a], now) - cacheScore(caches[b], now))[0]];
      }
      caches[net.fingerprint] = { loc, createdAt: now, lastAccess: now, hits: (old ? old.hits || 0 : 0) + 1 };
      return { caches };
    });
  }
};

/** R7/R9：该缓存能否作为 fallback 直接沿用 */
function cacheUsableAsFallback(cached) {
  if (!cached) return false;
  if (cached.mode === 'direct' && (cached.weak || cached.cell)) return false;   // 弱指纹/蜂窝缓存只能作 rule 方向依据
  return true;
}

// ==================== 模式切换（R8 kind；R14 lastAppliedMode；R15 单次 mutate）====================
/** @returns 'switched' | 'skipped' | 'failed' */
function switchMode(mode, reason, opts = {}) {
  const { force = false, recordDecision = true, kind = '' } = opts;
  if (!mode) return 'failed';
  if (!Token.isLatest()) { log('DEBUG', `token 已失效，放弃切换 ${mode} (${reason})`); return 'skipped'; }
  if (!Platform.canSetMode()) {
    log('WARN', `当前环境(${Platform.name})不支持切换出站模式，跳过`);
    return 'failed';
  }
  let result = 'failed';
  const now = Date.now();
  State.mutate(st => {
    // P3：能读真实模式的平台（Loon）以真实值为准；否则退回 lastMode 记录
    const actual = Platform.getMode();
    const fresh = actual !== null
      ? actual === mode
      : st.lastMode === mode && st.lastModeKind === kind && st.lastModeTs && now - st.lastModeTs < CONFIG.MODE_REASSERT_MS;
    if (fresh && !force) { log('DEBUG', `模式已是 ${mode}（${reason}${actual !== null ? '，实测' : ''}），跳过`); result = 'skipped'; return actual !== null && st.lastAppliedMode !== mode ? { lastAppliedMode: mode } : {}; }
    if (actual !== null && actual !== st.lastAppliedMode && st.lastAppliedMode) log('INFO', `检测到模式被外部改为 ${actual.toUpperCase()}（记录为 ${st.lastAppliedMode}），将纠正`);
    try { Platform.setMode(mode); }
    catch (e) { log('ERROR', `切换失败: ${e}`); result = 'failed'; return {}; }
    result = 'switched';
    const changed = st.lastAppliedMode !== mode;
    const patch = { lastAppliedMode: mode };
    if (recordDecision) Object.assign(patch, { lastMode: mode, lastModeTs: now, lastModeKind: kind });
    if (changed && CONFIG.NOTIFY_ON_SWITCH && now - (st.lastNotifyTs || 0) > CONFIG.NOTIFY_MIN_INTERVAL_MS) {
      const n = Env.notify();
      if (n) { n.post('智能路由', `已切换为 ${mode.toUpperCase()}`, reason); patch.lastNotifyTs = now; }
    }
    return patch;
  });
  if (result === 'switched') log('INFO', `${CONFIG.USE_EMOJI ? '🚀 ' : ''}出站模式 → ${mode.toUpperCase()} (${reason})`);
  return result;
}

// ==================== 决策 ====================
/** 从一批探针结果中找与 first 不同来源的成功结果（R6 复用竞速败者） */
/** P7 自检：竞速全部结果到齐后，若两探针 loc 不一致，说明有探针未直连（policy/node 字段可能未生效） */
function auditProbeAgreement(tag, first) {
  if (!first || !first.all) return;
  first.all.then(all => {
    if (FINISHED || !Array.isArray(all)) return;
    const oks = all.filter(r => r && r.ok);
    if (oks.length < 2) return;
    const locs = new Set(oks.map(r => r.loc));
    const desc = oks.map(r => `${r.name}=${r.loc}(${r.ip || '?'})`).join(' vs ');
    if (locs.size > 1) log('WARN', `[${tag}] 探针结论不一致 ${desc}；若 IP 明显不同，说明 PROBE_FORCE_DIRECT 未生效或有探针走了代理`);
    else log('INFO', `[${tag}] 探针一致 ${desc}`);
  }).catch(() => {});
}

function pickSecond(results, first) {
  return (results || []).find(r => r && r.ok && r.name !== first.name) || null;
}

/**
 * 危险方向（direct）交叉验证。
 * @returns {'verified'|'conflict'|'unverified'}
 */
async function crossVerify(tag, first, ctx) {
  const firstUrl = (CONFIG.PROBES.find(p => p.name === first.name) || {}).url;
  const others = CONFIG.PROBES.filter(p => p.url !== firstUrl);
  if (!others.length) { log('WARN', `[${tag}] 无第二探针，无法验证 direct`); return 'unverified'; }

  // 1) 复用同一轮竞速中在飞的败者结果（等待其完成，最多 PROBE_ONCE）
  let second = null;
  if (first.all) {
    const all = await Promise.race([first.all, sleep(Math.min(Budget.PROBE_ONCE(), Math.max(0, budgetLeft() - 300))).then(() => null)]);
    second = pickSecond(all, first);
    if (second) log('DEBUG', `[${tag}] 复用竞速结果 ${second.name}=${second.loc}`);
  }
  // 2) 没有可复用结果 → 另发一次
  if (!second) {
    const r = await withBudget(`${tag}/交叉验证`, Budget.PROBE_ONCE(),
      () => fetchLoc(CONFIG.PROBE_TIMEOUT_MS, others, ctx), { ok: false, reason: 'NO_BUDGET' });
    if (!Token.isLatest()) return 'unverified';
    if (r.ok) second = r;
    else {
      const why = (r.reasons || [r.reason]).join('/');
      // 3) R18 双探针下第二探针不可用：按策略处理
      if (CONFIG.SINGLE_SOURCE_POLICY !== 'confirm' || r.reason === 'NO_BUDGET') {
        log('WARN', `[${tag}] 第二探针失败(${why})，direct 未获验证（policy=${CONFIG.SINGLE_SOURCE_POLICY}）`);
        return 'unverified';
      }
      log('WARN', `[${tag}] 第二探针失败(${why})，改用同源二次确认（${CONFIG.SINGLE_SOURCE_GAP_MS}ms 后）`);
      const same = CONFIG.PROBES.filter(p => p.url === firstUrl);
      const again = await withBudget(`${tag}/同源确认`, CONFIG.SINGLE_SOURCE_GAP_MS + Budget.PROBE_ONCE(), async () => {
        await sleep(CONFIG.SINGLE_SOURCE_GAP_MS);
        return fetchLoc(CONFIG.PROBE_TIMEOUT_MS, same, ctx);
      }, { ok: false, reason: 'NO_BUDGET' });
      if (!Token.isLatest()) return 'unverified';
      if (!again.ok) { log('WARN', `[${tag}] 同源确认失败(${again.reason})，direct 未获验证`); return 'unverified'; }
      if (again.loc !== first.loc) { log('WARN', `[${tag}] 同源确认不一致 ${first.loc} vs ${again.loc}`); return 'conflict'; }
      log('INFO', `[${tag}] 同源二次确认通过 ${first.name}=${first.loc}（弱验证）`);
      return 'verified';
    }
  }
  if (second.loc !== first.loc) {
    log('WARN', `[${tag}] 交叉冲突 ${first.name}=${first.loc}(${first.ip || '?'}) vs ${second.name}=${second.loc}(${second.ip || '?'})；若两 IP 明显不同，说明有探针走了代理`);
    return 'conflict';
  }
  log('INFO', `[${tag}] 交叉验证通过 ${first.name}=${first.loc}, ${second.name}=${second.loc}`);
  return 'verified';
}

/** 轻量路径：单次 liveness；切向 direct 只允许重申已验证缓存 */
async function decideLight(tag, net) {
  if (!Token.isLatest()) return;
  const cached = Cache.get(net);
  const live = await fetchLoc(CONFIG.LIVENESS_TIMEOUT_MS, CONFIG.PROBES, { ready: net.isReady });
  auditProbeAgreement(tag, live);
  if (!live.ok) { log('INFO', `[${tag}] 轻量复核失败(${live.reason})，保持现状`); return; }
  const target = modeForLoc(live.loc);
  if (target === 'direct' && !(cached && cached.loc === live.loc)) {
    log('WARN', `[${tag}] 单探针 ${live.name}=${live.loc} 指向 direct 但无已验证缓存，保持现状`);
    return;
  }
  if (cached && cached.loc !== live.loc) log('WARN', `[${tag}] 出口变化 ${cached.loc} → ${live.loc}`);
  Cache.set(net, live.loc);
  log('INFO', `[${tag}] 复核 ${live.loc} (${live.name}) → ${target.toUpperCase()}`);
  switchMode(target, `recheck:${live.loc}`, { kind: net.kind });
}

/** 完整路径 */
async function decideFull(tag, net) {
  if (!Token.isLatest()) { log('DEBUG', `[${tag}] token 已失效，退出`); return; }
  if (!net.isReady) log('WARN', `[${tag}] 尚无 IP，仍尝试探测`);
  if (net.loonAmbiguous) log('WARN', `[${tag}] Loon 未读到 SSID：可能是蜂窝，也可能是未授予精确定位的 Wi-Fi，按蜂窝保守处理`);
  else if (net.weak) log('WARN', `[${tag}] SSID/BSSID 不可读（请授予 ${Platform.name} 精确定位），使用弱指纹并缩短缓存 TTL`);
  const ctx = { ready: net.isReady };
  const sw = (mode, reason) => switchMode(mode, reason, { kind: net.kind });

  const cached = Cache.get(net);
  if (cached) {
    const live = await fetchLoc(CONFIG.LIVENESS_TIMEOUT_MS, CONFIG.PROBES, ctx);
    auditProbeAgreement(tag, live);
    if (live.ok) {
      const m = modeForLoc(live.loc);
      if (live.loc === cached.loc) {
        log('INFO', `[${tag}] 缓存命中且复核一致 (${live.loc})`);
        Cache.set(net, live.loc); sw(m, `cache:${live.loc}`); return;
      }
      log('WARN', `[${tag}] 出口变化 ${cached.loc} → ${live.loc}`);
      if (m === 'rule') { Cache.set(net, live.loc); sw(m, `relocated:${live.loc}`); return; }
      // R1：指向 direct 的变化必须走完整交叉验证，不在此写缓存/切换
      log('INFO', `[${tag}] 变化指向 direct，转入交叉验证`);
      const v = await crossVerify(tag, live, ctx);
      if (v === 'verified') { Cache.set(net, live.loc); sw('direct', `relocated:${live.loc}`); }
      else if (v === 'conflict') sw('rule', 'conflict');
      else log('WARN', `[${tag}] 变化未获验证，保持现状`);
      return;
    }
    if (live.reason === 'NO_BUDGET') { log('WARN', `[${tag}] 预算耗尽，保持现状`); return; }
    log('WARN', `[${tag}] 存活检测失败(${live.reason})，重新探测`);
  }

  const first = await fetchLocWithRetry(ctx);
  auditProbeAgreement(tag, first);
  if (!Token.isLatest()) return;
  if (!first.ok) {
    if (cached && cacheUsableAsFallback(cached)) { log('WARN', `[${tag}] 探测失败(${first.reason})，沿用缓存 ${cached.mode}`); sw(cached.mode, 'fallback:cache'); return; }
    if (cached) { log('WARN', `[${tag}] 探测失败，缓存为弱指纹/蜂窝 direct，不沿用，保持现状`); return; }
    const s = State.read();
    if (first.reason === 'NO_BUDGET' || s.lastModeTs) { log('WARN', `[${tag}] 探测失败(${first.reason})，保持现状`); return; }
    log('WARN', `[${tag}] 首次运行且探测失败，兜底 RULE`);
    sw('rule', 'fallback:unknown');
    return;
  }

  const target = modeForLoc(first.loc);
  if (target === 'direct') {
    const v = await crossVerify(tag, first, ctx);
    if (v === 'conflict') { sw('rule', 'conflict'); return; }
    if (v !== 'verified') { log('WARN', `[${tag}] direct 判定未获验证，保持现状`); return; }
  }
  Cache.set(net, first.loc);
  log('INFO', `[${tag}] 判定 ${first.loc} (${first.name}) → ${target.toUpperCase()}`);
  sw(target, `probe:${first.loc}`);
}

// ==================== 主流程 ====================
async function main() {
  try {
    validateConfig();
    await Token.register();                                          // R5
    await sleep(CONFIG.BOOT_DELAY_MS);
    if (!Token.isLatest()) return;

    let net = getNetworkInfo();
    log('INFO', `链路: ${net.kind}/${net.iface}${net.carrier ? '/' + net.carrier + (net.radio ? '(' + net.radio + ')' : '') : ''} | SSID=${net.ssid || '-'} | ready=${net.isReady} | fp=${net.fingerprint}`);

    if (inWhitelist(net)) {
      switchMode(CONFIG.WHITELIST_MODE, `whitelist:${net.ssid || net.bssid}`, { force: true, kind: net.kind });
      return;
    }

    // R8：bootstrap 的"新鲜决策"仅认同链路类型
    if (net.isCellular) {
      const s = State.read();
      const fresh = s.lastModeKind === 'cell' && s.lastModeTs && Date.now() - s.lastModeTs < CONFIG.MODE_REASSERT_MS * 5;
      if (!Cache.get(net) && !fresh) switchMode('rule', 'cellular-bootstrap', { recordDecision: false, kind: net.kind });
      else log('DEBUG', '蜂窝已有缓存/新鲜决策，跳过 bootstrap');
    }

    await sleep(net.isCellular ? CONFIG.CELLULAR_BUFFER_MS : net.isWired ? CONFIG.WIRED_BUFFER_MS : CONFIG.WIFI_BUFFER_MS);

    for (let i = 0; i < CONFIG.READY_POLL_MAX; i++) {
      net = getNetworkInfo();
      if (net.isReady || !Token.isLatest() || outOfBudget(Budget.READY_POLL())) break;
      await sleep(Math.min(CONFIG.READY_POLL_BASE_MS * Math.pow(2, i), CONFIG.READY_POLL_CAP_MS));
    }
    net = getNetworkInfo();
    if (!Token.isLatest()) return;

    await decideFull('First', net);

    const recheck = net.isCellular ? CONFIG.RECHECK_DELAY_CELLULAR_MS : CONFIG.RECHECK_DELAY_WIFI_MS;
    await withBudget('ReCheck', recheck + Budget.LIVENESS(), async () => {
      await sleep(recheck);
      if (Token.isLatest()) await decideLight('ReCheck', getNetworkInfo());
    });
  } catch (e) {
    log('ERROR', `状态机异常: ${e && e.stack ? e.stack : e}`);
    try {
      if (Token.isLatest() && !State.read().lastModeTs) switchMode('rule', 'exception', { force: true });
    } catch (_) {}
  } finally {
    // R17：给在飞请求一个短暂收尾窗口
    const t = Date.now();
    while (PENDING_REQUESTS > 0 && Date.now() - t < CONFIG.PENDING_DRAIN_MS) await new Promise(r => setTimeout(r, 50));
    Token.release();
    if (CONFIG.PROFILE) log('INFO', `总耗时 ${elapsed()}ms | pending=${PENDING_REQUESTS} | 探针 ${ProbeStats.summary() || '-'}`);
    FINISHED = true;
    Env.done();
  }
}

main();
