/**
 * InfoHunter - 抓取与提取引擎
 *
 * 依赖（由 background.js 通过 importScripts 载入，共享 classic SW 全局作用域）：
 *   rules.js -> nuclei_regex / static_file / non_static_file
 *
 * 相对旧版实现的修复与增强：
 *   [FIX] Promise.race + 全局 abort：开启超时后只要第一个 JS 返回就掐断其余全部请求，
 *         导致结果几乎为空。改为每个请求独立 AbortController + setTimeout。
 *   [FIX] 无并发上限：页面有几百个 JS 时一次性并发，浏览器排队卡死。改为定长并发队列。
 *   [FIX] search_data 纯内存，MV3 service worker 空闲 30s 被回收后结果全丢。
 *         改为增量落盘 + 启动时按 TTL 重建 + 过期清理。
 *   [FIX] console.log(tmp_data) 把提取到的密钥/身份证打印到控制台。
 *   [ADD] Sourcemap 抓取：从 .js.map 还原原始源码路径与源码内容，二次提取。
 *   [ADD] 框架路由：接收 MAIN world 的 framework-analyze 数据，产出 route 分类。
 *   [ADD] 惰性 chunk 枚举：从 webpack chunk 清单推测未加载的分包地址。
 */

// ------------------------------------------------------------------ 配置

var CONCURRENCY = 6;
var TIMEOUT_FAST = 2000;
var TIMEOUT_SLOW = 8000;
var MAX_TARGETS = 150;          // 单页最多抓取的资源数
var MAX_JS_BYTES = 5 * 1024 * 1024;
var MAX_MAP_BYTES = 24 * 1024 * 1024;
var MAX_PER_CATEGORY = 600;     // 单个分类最多保留条数
var STORAGE_TTL_DAYS = 3;
var FLUSH_DELAY_MS = 400;

// 展示顺序与 popup / content 保持一致
// api 是接口语义三元组（method + url + 参数），route 是框架路由表
var RESULT_KEYS = [
  'api', 'route', 'secret', 'jwt', 'algorithm', 'sfz', 'mobile', 'mail',
  'path', 'incomplete_path', 'url', 'static', 'domain', 'ip', 'ip_port', 'sourcemap',
  // 1.0.2 新增：运行时观测面
  'request',   // 页面实际发出的 XHR / fetch 地址（webRequest + 运行时钩子）
  'endpoint',  // WebSocket / SSE / Worker 端点
  'storage',   // Web Storage / cookie 的键名
  'param'      // 请求 URL 里的查询参数名
];
var NOT_STRIP_QUOTES = ['secret', 'route', 'sourcemap', 'api'];
var META_KEYS = [
  'current', 'tasklist', 'donetasklist', 'pretasknum', 'done', 'source',
  'framework', 'startedAt', 'updatedAt', 'secretMeta', 'jwtMeta', 'apiMeta',
  'runtimeMeta', 'endpointMeta'
];

// JS 递归抓取（depth 2）的安全上限：中等风险，默认关闭，开启也要严控
var MAX_RECURSIVE_JS = 30;
var RECURSIVE_CONCURRENCY = 2;

var search_data = Object.create(null);
var tab_url = Object.create(null);
var selected_id = -1;

// ------------------------------------------------------------------ storage 封装

function storageGet(keys) {
  return new Promise(function (resolve) {
    try {
      chrome.storage.local.get(keys, function (r) { resolve(r || {}); });
    } catch (e) { resolve({}); }
  });
}

function storageSet(obj) {
  return new Promise(function (resolve) {
    try {
      chrome.storage.local.set(obj, function () { resolve(true); });
    } catch (e) { resolve(false); }
  });
}

function storageRemove(keys) {
  return new Promise(function (resolve) {
    try {
      chrome.storage.local.remove(keys, function () { resolve(true); });
    } catch (e) { resolve(false); }
  });
}

// ------------------------------------------------------------------ 通用工具

function unique(arr) {
  if (!arr || arr === 'null') return [];
  var seen = Object.create(null);
  var out = [];
  for (var i = 0; i < arr.length; i++) {
    var v = arr[i];
    if (v === null || v === undefined || v === '') continue;
    var k = String(v);
    if (seen[k]) continue;
    seen[k] = 1;
    out.push(v);
  }
  return out;
}

function union(a, b) {
  var out = unique(a || []);
  var seen = Object.create(null);
  for (var i = 0; i < out.length; i++) seen[String(out[i])] = 1;
  for (var j = 0; j < (b || []).length; j++) {
    var k = String(b[j]);
    if (!seen[k]) { seen[k] = 1; out.push(b[j]); }
  }
  return out;
}

function cap(arr, n) {
  return arr && arr.length > n ? arr.slice(0, n) : arr;
}

function stripQuotes(arr) {
  var out = [];
  for (var i = 0; i < arr.length; i++) {
    var s = String(arr[i]);
    var start = (s.charAt(0) === "'" || s.charAt(0) === '"') ? 1 : 0;
    var end = (s.charAt(s.length - 1) === "'" || s.charAt(s.length - 1) === '"') ? 1 : 0;
    out.push(s.substring(start, s.length - end));
  }
  return out;
}

function sleep(ms) {
  return new Promise(function (r) { setTimeout(r, ms); });
}

// ------------------------------------------------------------------ 归一化与降噪
//
// 先归一化、再过滤，顺序不能反。
// 旧版实现完全没有这一步，导致以下东西全部进了结果集：
//   - \/ 转义与 %2F / %3A 编码残留，同一个路径被算成两条
//   - webpack / babel 压缩产物：*#__PURE__*、*$0*
//   - 数组切分残留的尾逗号
//   - javascript: / data: 这类不可请求的伪协议

// 归一化会破坏空白，所以私钥、证书这类文本型类别不能走激进模式
var URLISH_KEYS = ['path', 'incomplete_path', 'url', 'static', 'domain', 'ip', 'ip_port', 'sourcemap', 'route', 'request', 'endpoint'];

// 通用噪声：任何类别都不要
var NOISE_RE = [
  /\*#__PURE__\*/,
  /\*\$0\*/,
  /^data:/i,
  /^javascript:/i,
  /^blob:/i,
  /^about:/i,
  /^chrome-extension:/i,
  /www\.w3\.org/i,
  /schemas\.(microsoft|openxmlformats)\.com/i,
  /purl\.oclc\.org/i,
  /example\.(com|org|net)/i,
  /^[\\/\s.,;]+$/
];

// 仅地址类：JS 里以属性名结尾的伪路径，如 xxx.src、xxx.href
var URL_NOISE_RE = [
  /\.(src|href|url|att|path|replace)$/i,
  /^(location|javascript):/i,
  /application\/x-www-form-urlencoded/i,
  /[<>{}\[\]|^;]/
];

function decodeSafe(s) {
  try { return decodeURIComponent(s); } catch (e) { return s; }
}

/**
 * @param {string} v 原始值
 * @param {boolean} aggressive true = 地址类，可去空白；false = 文本类，保留空白
 */
function normalizeValue(v, aggressive) {
  var s = String(v).trim();
  if (!s) return '';

  s = s.replace(/\\u002F/gi, '/');
  s = s.replace(/\\\//g, '/');
  s = s.replace(/%2F/gi, '/');
  s = s.replace(/%3A/gi, ':');
  s = s.replace(/%3D/gi, '=');
  s = s.replace(/%26/gi, '&');
  if (/%[0-9A-Fa-f]{2}/.test(s)) s = decodeSafe(s);

  // 数组切分残留："/api/user", → "/api/user"
  s = s.replace(/[,;]+$/, '');

  if (aggressive) s = s.replace(/\s+/g, '');

  return s.trim();
}

/**
 * 协议白名单：带 scheme 但不在白名单里的一律丢弃。
 * ws / wss 从 1.0.2 起放行 —— WebSocket 端点常是独立攻击面，
 * 之前被这条规则连同运行时钩子记到的 wss:// 一起丢掉了。
 */
function hasBadScheme(v) {
  var m = String(v).match(/^([a-zA-Z][a-zA-Z0-9+.\-]*):/);
  if (!m) return false;
  var scheme = m[1].toLowerCase();
  return ['http', 'https', 'ws', 'wss'].indexOf(scheme) === -1;
}

function isNoise(value, aggressive) {
  var v = String(value);
  if (!v || v.length > 2048) return true;
  for (var i = 0; i < NOISE_RE.length; i++) {
    if (NOISE_RE[i].test(v)) return true;
  }
  if (aggressive) {
    for (var j = 0; j < URL_NOISE_RE.length; j++) {
      if (URL_NOISE_RE[j].test(v)) return true;
    }
    if (hasBadScheme(v)) return true;
  }
  return false;
}

// ------------------------------------------------------------------ 并发队列 + 单请求超时

/**
 * [FIX] 逐请求超时。原实现用 Promise.race 把「整体任务数组」和「一个 2 秒定时器」赛跑，
 * 定时器一到就 abort 掉共享的 AbortController，等于只保留最先返回的那个请求。
 */
function fetchWithTimeout(url, ms, init) {
  var ac = new AbortController();
  var timer = setTimeout(function () { try { ac.abort(); } catch (e) {} }, ms);
  var opts = Object.assign({}, init || {}, { signal: ac.signal });
  return fetch(url, opts).then(function (res) {
    clearTimeout(timer);
    return res;
  }, function (err) {
    clearTimeout(timer);
    throw err;
  });
}

/** [FIX] 定长并发，取代无上限的 Promise.all(map(...)) */
function runQueue(items, worker, limit) {
  var idx = 0;
  var total = items.length;
  var runners = [];
  var n = Math.max(1, Math.min(limit || CONCURRENCY, total || 1));
  for (var i = 0; i < n; i++) {
    runners.push((function () {
      return (async function () {
        while (idx < total) {
          var cur = idx++;
          try { await worker(items[cur], cur); } catch (e) { /* 单个失败不影响整体 */ }
        }
      })();
    })());
  }
  return Promise.all(runners);
}

// ------------------------------------------------------------------ 提取

function getSecret(data) {
  var result = [];
  for (var i = 0; i < nuclei_regex.length; i++) {
    var m = data.match(nuclei_regex[i]);
    if (m) {
      for (var j = 0; j < m.length; j++) result.push(m[j]);
    }
  }
  return unique(result);
}

var TLD = 'xin|com|cn|net|com.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|tw|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网';
var RE_IP = /['"](([a-zA-Z0-9]+:)?\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/.*?)?['"]/g;
var RE_IP_PORT = /['"](([a-zA-Z0-9]+:)?\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}(\/.*?)?['"]/g;
var RE_DOMAIN = new RegExp('[\'"](([a-zA-Z0-9]+:)?\\/\\/)?[a-zA-Z0-9\\-\\.]*?\\.(' + TLD + ')(\\:\\d{1,5})?(\\/)?[\'"]', 'g');
var RE_URL = new RegExp('[\'"](([a-zA-Z0-9]+:)?\\/\\/)?[a-zA-Z0-9\\-\\.]*?\\.(' + TLD + ')(\\:\\d{1,5})?(\\/.*?)?[\'"]', 'g');
var RE_PATH = /['"](?:\/|\.\.\/|\.\/)[^\/\>\< \)\(\{\}\,\'\"\\]([^\>\< \)\(\{\}\,\'\"\\])*?['"]/g;
var RE_INCOMPLETE = /['"][^\/\>\< \)\(\{\}\,\'\"\\][\w\/]*?\/[\w\/]*?['"]/g;
// 身份证（升级，旧版写法两处硬伤）：
//   1. 15 位老证分支末尾有个 $，在引号包住的文本里永远匹配不到 —— 纯死分支；
//   2. 号码必须被引号包住，正文裸文本（<td>110101...</td>）漏检。
//   现改为：引号可选、去掉死 $、前后 (?<!\d)(?!\d) 挡住更长数字串（18 位证不会被
//   从 19 位订单号里抠出子串）。日期段结构仍是主要防误报手段。
var RE_SFZ = /(?<!\d)(?:\d{8}(?:0\d|10|11|12)(?:[0-2]\d|30|31)\d{3}|\d{6}(?:18|19|20)\d{2}(?:0[1-9]|10|11|12)(?:[0-2]\d|30|31)\d{3}[0-9Xx])(?!\d)/g;
// 手机号（升级，旧版是 ['"](1[3-9]\d{7})['"] 两引号夹 11 位）：
//   1. 引号不再强制 —— 页面正文纯文本（<td>13800138000</td>、tel: 链接）此前全部漏检；
//   2. 号段对齐当前大陆分配：13x / 14[5-9] / 15x / 16[2567] / 17[0-8] / 18x / 19[0-3 5-9]，
//      旧版漏 170、171（虚拟运营商）与 190-193（含广电 192）；
//   3. 容忍 3-4-4 分隔（"138-0013-8000"、"138 0013 8000"）与可选 +86 / 86 前缀；
//   4. 前后 (?<!\d)(?!\d) 挡住更长数字串：12 位订单号、13 位毫秒时间戳不会被抠出子串误报。
//   代价：正文里恰好 11 位且 1[3-9] 开头的普通长数字（订单号）会被收进 mobile，肉眼在 popup 里过滤。
var RE_MOBILE = /(?<!\d)(?:\+?86[-\s]?)?1(?:3\d|4[5-9]|5\d|6[2567]|7[0-8]|8\d|9[0-35-9])[-\s]?\d{4}[-\s]?\d{4}(?!\d)/g;
// 邮箱（升级）：旧版要求引号包住且匹配值连引号一起返回，正文裸文本（联系邮箱 xxx@x.com）漏检。
// 现引号可选、输出干净地址；保留 TLD 黑名单 —— logo@2x.png 这类 retina 资源名不是邮箱。
var RE_MAIL = /(?<![\w@.\-])[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)*@[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)*\.(?!js|css|jpg|jpeg|png|ico|gif|svg|webp)[a-zA-Z]{2,}(?![\w@\-])/g;
var RE_JWT = /['"](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})['"]/g;
var RE_ALGO = /\W(Base64\.encode|Base64\.decode|btoa|atob|CryptoJS\.AES|CryptoJS\.DES|CryptoJS\.TripleDES|CryptoJS\.RC4|JSEncrypt|rsa|KJUR|$\.md5|md5|sha1|sha256|sha512|HmacSHA|AES\.encrypt|RSA\.encrypt)[\(\.]/gi;
var RE_SOURCEMAP = /sourceMappingURL\s*=\s*(\S+)/gi;

function extractInfo(data) {
  var d = {};
  d.sfz = data.match(RE_SFZ);
  d.mobile = data.match(RE_MOBILE);
  d.mail = data.match(RE_MAIL);
  d.ip = data.match(RE_IP);
  d.ip_port = data.match(RE_IP_PORT);
  d.domain = data.match(RE_DOMAIN);
  d.path = data.match(RE_PATH);
  d.incomplete_path = filterIncompletePath(data.match(RE_INCOMPLETE));
  d.url = data.match(RE_URL);
  d.jwt = data.match(RE_JWT);
  d.algorithm = data.match(RE_ALGO);
  // secret 在唯一出口统一降噪（analyzers.filterSecretNoise）：
  // 裸业务字段键（username=xxx）与 JS 代码值（passwordEl = document、PrivateKey=function）不是凭据
  d.secret = filterSecretNoise(getSecret(data));

  if (d.url) {
    for (var i = 0; i < d.url.length; i++) {
      var u = d.url[i];
      d.ip = union(d.ip, u.match(RE_IP));
      d.ip_port = union(d.ip_port, u.match(RE_IP_PORT));
      d.domain = union(d.domain, u.match(RE_DOMAIN));
    }
  }

  // 分类降噪统一出口（analyzers 纯函数）：正则保证「形似」，这里校验「真可能是」
  d.sfz = filterSfz(d.sfz);
  d.ip = filterIp(d.ip);
  d.path = filterPath(d.path);
  d.domain = filterNoiseHost(d.domain);
  d.url = filterNoiseHost(d.url);
  return d;
}

/** 从 JS 文本里找 sourceMappingURL 注释，解析成绝对地址 */
function findSourcemapUrls(text, baseUrl) {
  var out = [];
  var m;
  RE_SOURCEMAP.lastIndex = 0;
  while ((m = RE_SOURCEMAP.exec(text)) !== null) {
    var v = m[1].replace(/^["']|["']$/g, '').trim();
    if (!v) continue;
    if (v.indexOf('data:') === 0) continue;      // 内联 base64 map，暂不解析
    try { out.push(new URL(v, baseUrl).href); } catch (e) { /* 非法 URL */ }
  }
  return unique(out);
}

// ------------------------------------------------------------------ 结果容器

function ensureEntry(url) {
  if (!search_data[url]) {
    search_data[url] = {
      current: url,
      tasklist: [],
      donetasklist: [],
      source: Object.create(null),
      framework: null,
      secretMeta: Object.create(null),
      jwtMeta: Object.create(null),
      apiMeta: Object.create(null),
      startedAt: Date.now(),
      updatedAt: Date.now(),
      done: ''
    };
    for (var i = 0; i < RESULT_KEYS.length; i++) search_data[url][RESULT_KEYS[i]] = null;
  }
  return search_data[url];
}

function collectStatic(arr1, arr2) {
  var rest = arr1.slice(0);
  var statics = arr2 || [];
  for (var i = 0; i < arr1.length; i++) {
    var item = arr1[i];
    for (var s = 0; s < static_file.length; s++) {
      if (item.indexOf(static_file[s]) === -1) continue;
      if (static_file[s] === '.js' && item.indexOf('.jsp') !== -1) continue;
      var pos = rest.indexOf(item);
      if (pos !== -1) rest.splice(pos, 1);
      if (statics.indexOf(item) === -1) statics.push(item);
    }
  }
  return { arr1: rest, static: statics };
}

function mergeInto(entry, k, values, sourceUrl) {
  if (!values || !values.length) return;

  var aggressive = URLISH_KEYS.indexOf(k) > -1;
  var cleaned = NOT_STRIP_QUOTES.indexOf(k) === -1 ? stripQuotes(values) : values;

  // 归一化 → 降噪 → 去重，顺序固定，不能颠倒
  var stage = [];
  for (var n = 0; n < cleaned.length; n++) {
    var v = normalizeValue(cleaned[n], aggressive);
    if (!v) continue;
    if (isNoise(v, aggressive)) continue;
    stage.push(v);
  }
  cleaned = unique(stage);

  if (sourceUrl) {
    for (var i = 0; i < cleaned.length; i++) {
      if (!entry.source[cleaned[i]]) entry.source[cleaned[i]] = sourceUrl;
    }
  }

  var merged = union(entry[k], cleaned);
  if (k !== 'static') {
    var res = collectStatic(merged, entry.static || []);
    merged = res.arr1;
    entry.static = unique(res.static);
  }
  entry[k] = cap(merged.sort(), MAX_PER_CATEGORY);
}

function persist(tmp, reqUrl, current) {
  var entry = ensureEntry(current);
  for (var i = 0; i < RESULT_KEYS.length; i++) {
    var k = RESULT_KEYS[i];
    if (!tmp[k]) continue;
    mergeInto(entry, k, tmp[k], reqUrl);
  }
  entry.updatedAt = Date.now();
  // 每批合并都排一次落盘（flushTimer 去重，400ms 内合并为一次写入）。
  // SPA 批量抓取动辄数秒，此前只在整批结束时落盘一次，SW 中途回收会丢掉整批增量。
  markDirty(current);
}

// ------------------------------------------------------------------ 语义增强（纯分析，零请求）

var RE_JS_REF = /(['"`])([^'"`\s]{1,300}?\.js(?:on)?(?:\?[^\s'"`]*)?)\1/g;
var RE_DYNAMIC_IMPORT = /\bimport\s*\(\s*(['"`])([^'"`]+)\1\s*\)/g;

/**
 * 从已抓到的 JS 里再找出它引用的 JS —— 动态 import、require、chunk 名。
 * 只收「代码里真实引用」的，不做任何 URL 猜测；并且默认只取同源，
 * 避免把请求发到第三方 CDN 上。
 */
function extractJsRefs(text, baseUrl, sameOriginOnly) {
  var base = null;
  try { base = new URL(baseUrl); } catch (e) { return []; }

  var out = [];
  var seen = Object.create(null);
  var m;

  function add(raw) {
    if (!raw || !/\.m?js(\?|$)/i.test(raw)) return;
    if (/^(javascript|data|blob):/i.test(raw)) return;
    var abs;
    try { abs = new URL(raw, baseUrl).href; } catch (e) { return; }
    if (sameOriginOnly) {
      try { if (new URL(abs).origin !== base.origin) return; } catch (e) { return; }
    }
    if (seen[abs]) return;
    seen[abs] = 1;
    out.push(abs);
  }

  RE_JS_REF.lastIndex = 0;
  while ((m = RE_JS_REF.exec(text)) !== null) add(m[2]);

  RE_DYNAMIC_IMPORT.lastIndex = 0;
  while ((m = RE_DYNAMIC_IMPORT.exec(text)) !== null) add(m[2]);

  return out;
}

/** 接口语义还原：把 method+url+参数 存进 api 分类，结构化数据存 apiMeta */
function enrichApiCalls(entry, text, reqUrl) {
  if (!text || typeof extractApiCalls !== 'function') return;
  var calls = extractApiCalls(text, 200);
  if (!calls.length) return;

  var lines = [];
  for (var i = 0; i < calls.length; i++) {
    var line = formatApiCall(calls[i]);
    entry.apiMeta[line] = {
      method: calls[i].method,
      url: calls[i].url,
      params: calls[i].params
    };
    lines.push(line);
  }
  mergeInto(entry, 'api', lines, reqUrl);
}

/** 给每条 secret 打上类型与可信度 */
function annotateSecrets(entry) {
  if (typeof classifySecret !== 'function') return;
  var list = entry.secret || [];
  for (var i = 0; i < list.length; i++) {
    if (entry.secretMeta[list[i]]) continue;
    var c = classifySecret(list[i]);
    if (c) entry.secretMeta[list[i]] = c;
  }
}

/** 给每条 JWT 解码并标记风险 */
function annotateJwts(entry) {
  if (typeof decodeJwt !== 'function') return;
  var list = entry.jwt || [];
  for (var i = 0; i < list.length; i++) {
    if (entry.jwtMeta[list[i]]) continue;
    var d = decodeJwt(list[i]);
    if (d) entry.jwtMeta[list[i]] = d;
  }
}

/** 一次扫完所有文本型增强项，在抓取结束后统一调用 */
function finalizeEntry(entry, texts) {
  for (var i = 0; i < texts.length; i++) {
    enrichApiCalls(entry, texts[i].text, texts[i].url);
  }
  annotateSecrets(entry);
  annotateJwts(entry);
  entry.updatedAt = Date.now();
}

// ------------------------------------------------------------------ 落盘

var dirty = Object.create(null);
var flushTimer = null;

function markDirty(url) {
  dirty[url] = 1;
  // 每个数据批次都同步一次徽标：此前只有部分路径调 refreshBadge，
  // SPA 增量补扫等场景下徽标数（865）会明显落后于 popup 命中数（1490）
  refreshBadge();
  if (flushTimer) return;
  flushTimer = setTimeout(flushNow, FLUSH_DELAY_MS);
}

async function flushNow() {
  flushTimer = null;
  var urls = Object.keys(dirty);
  dirty = Object.create(null);
  if (!urls.length) return;
  var obj = {};
  for (var i = 0; i < urls.length; i++) {
    var u = urls[i];
    if (search_data[u]) obj['infohunter_result_' + u] = search_data[u];
  }
  if (Object.keys(obj).length) await storageSet(obj);
  await touchIndex(urls);
}

async function touchIndex(urls) {
  var idx = (await storageGet('fs_index'))['fs_index'] || {};
  var now = Date.now();
  for (var i = 0; i < urls.length; i++) idx[urls[i]] = now;
  await storageSet({ fs_index: idx });
}

async function cleanupExpired() {
  var idx = (await storageGet('fs_index'))['fs_index'] || {};
  var cutoff = Date.now() - STORAGE_TTL_DAYS * 86400000;
  var keep = {};
  var drop = [];
  var keys = Object.keys(idx);
  for (var i = 0; i < keys.length; i++) {
    var u = keys[i];
    if (idx[u] >= cutoff) keep[u] = idx[u];
    else drop.push('infohunter_result_' + u);
  }
  if (drop.length) await storageRemove(drop);
  await storageSet({ fs_index: keep });
}

/** MV3 的 SW 会被回收，启动时把当前打开的标签页结果读回内存 */
async function rehydrate() {
  var tabs = [];
  try {
    tabs = await new Promise(function (resolve) {
      chrome.tabs.query({}, function (t) { resolve(t || []); });
    });
  } catch (e) { tabs = []; }

  var wanted = [];
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i].url) wanted.push('infohunter_result_' + tabs[i].url);
  }
  if (!wanted.length) return;

  var stored = await storageGet(wanted);
  var keys = Object.keys(stored);
  for (var j = 0; j < keys.length; j++) {
    var url = keys[j].replace('infohunter_result_', '');
    if (stored[keys[j]]) search_data[url] = stored[keys[j]];
  }
}

// ------------------------------------------------------------------ 徽标与 webhook

function refreshBadge() {
  var cur = tab_url[selected_id];
  var entry = cur ? search_data[cur] : null;
  if (!entry) {
    try { chrome.action.setBadgeText({ text: '' }); } catch (e) {}
    return;
  }
  var cnt = 0;
  for (var i = 0; i < RESULT_KEYS.length; i++) {
    var v = entry[RESULT_KEYS[i]];
    if (v && v.length) cnt += v.length;
  }
  try {
    chrome.action.setBadgeText({ text: cnt ? String(cnt) : '' });
    chrome.action.setBadgeBackgroundColor({ color: '#d93025' });
  } catch (e) {}
}

function webhook(url) {
  storageGet('webhook_setting').then(function (r) {
    var cfg = r && r.webhook_setting;
    if (!cfg || !cfg.url) return;
    var payload = JSON.stringify(search_data[url] || {});
    var init = { method: cfg.method === 'POST' ? 'POST' : 'GET' };
    var target = cfg.url;
    if (init.method === 'GET') {
      target = target + (target.indexOf('?') > -1 ? '&' : '?') + encodeURIComponent(cfg.arg || 'data') + '=' + encodeURIComponent(payload);
    } else {
      var headers = { 'Content-Type': 'application/json' };
      if (cfg.headers && typeof cfg.headers === 'object') {
        for (var h in cfg.headers) headers[h] = cfg.headers[h];
      }
      init.headers = headers;
      init.body = cfg.arg ? (cfg.arg + '=' + payload) : payload;
    }
    fetchWithTimeout(target, TIMEOUT_SLOW, init).catch(function () {});
  });
}

// ------------------------------------------------------------------ 主扫描

function prioritize(urls, pageUrl) {
  var pageOrigin = null;
  try { pageOrigin = new URL(pageUrl).origin; } catch (e) {}

  function score(u) {
    var s = 0;
    try {
      var p = new URL(u);
      if (pageOrigin && p.origin === pageOrigin) s -= 100;
      if (/\.(js|mjs|cjs|jsx|ts|tsx)(\?|$)/i.test(p.pathname)) s -= 50;
      if (/\.(map)(\?|$)/i.test(p.pathname)) s -= 40;
      // 常见 CDN 与Polyfill 噪声往后排
      if (/(polyfill|jquery|bootstrap|echarts|chart\.js|three\.min)/i.test(p.href)) s += 60;
    } catch (e) { s += 200; }
    return s;
  }

  return unique(urls).sort(function (a, b) { return score(a) - score(b); });
}

async function handleFind(request, sender) {
  var current = request.current;
  var entry = ensureEntry(current);
  entry.done = '';
  entry.tasklist = [];
  entry.donetasklist = [];
  entry.startedAt = Date.now();

  if (sender && sender.tab && sender.tab.id) tab_url[sender.tab.id] = current;

  // 1) 页面自身源码
  var pageData = extractInfo(request.source || '');
  persist(pageData, current, current);

  // 所有拿到的文本留一份，抓完统一做语义分析（接口还原等），避免重复解析
  var collected = [{ text: request.source || '', url: current }];
  // depth 2 待抓队列：只装 JS 里真实引用的同源地址
  var pendingJs = [];

  var targets = prioritize(request.data || [], current);
  // 页面级 sourcemap（内联 script 的）
  var pendingMaps = unique(request.sourcemaps || []);

  targets = cap(targets, MAX_TARGETS);
  entry.pretasknum = targets.length;
  for (var t = 0; t < targets.length; t++) entry.tasklist.push(0);

  markDirty(current);
  refreshBadge();

  var settings = await storageGet(['fetch_timeout', 'enable_sourcemap', 'enable_js_recursive', 'concurrency']);
  var timeoutMs = settings.fetch_timeout === true ? TIMEOUT_FAST : TIMEOUT_SLOW;

  // .js.map 是站点自己在注释里声明的静态资源，单个 GET、并发 3、上限 20 个。
  // 风险低，默认开启。
  var enableMap = settings.enable_sourcemap !== false;

  // 递归抓取 JS 里引用到的 JS（动态 import、webpack chunk）会形成请求突发，
  // 在对方视角接近爬取行为。中等风险，默认关闭，需显式开启。
  var enableRecursive = settings.enable_js_recursive === true;
  var concurrency = parseInt(settings.concurrency, 10);
  if (isNaN(concurrency) || concurrency < 1) concurrency = CONCURRENCY;
  if (concurrency > 16) concurrency = 16;

  var headers = new Headers();
  headers.append('accept', '*/*');
  var init = {
    method: 'GET',
    headers: headers,
    mode: 'cors',
    cache: 'default',
    credentials: 'include'
  };

  await runQueue(targets, async function (reqUrl) {
    if (reqUrl === current) {
      entry.donetasklist.push(0);
      return;
    }
    try {
      var res = await fetchWithTimeout(reqUrl, timeoutMs, init);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var text = await res.text();
      if (text && text.length <= MAX_JS_BYTES) {
        persist(extractInfo(text), reqUrl, current);
        collected.push({ text: text, url: reqUrl });
        if (enableMap) {
          var maps = findSourcemapUrls(text, reqUrl);
          for (var m = 0; m < maps.length; m++) pendingMaps.push(maps[m]);
        }
        if (enableRecursive) {
          var refs = extractJsRefs(text, reqUrl, true);
          for (var r = 0; r < refs.length; r++) pendingJs.push(refs[r]);
        }
      }
    } catch (e) {
      /* 超时 / CORS / 404 均计入完成数，不影响整体 */
    }
    entry.donetasklist.push(0);
    markDirty(current);
    refreshBadge();
  }, concurrency);

  // 2) Sourcemap 二次提取
  pendingMaps = cap(unique(pendingMaps), 20);
  if (enableMap && pendingMaps.length) {
    await runQueue(pendingMaps, async function (mapUrl) {
      try {
        var res = await fetchWithTimeout(mapUrl, TIMEOUT_SLOW, { method: 'GET', credentials: 'include' });
        if (!res.ok) return;
        var json = await res.json();
        if (!json) return;

        entry.sourcemap = union(entry.sourcemap, [mapUrl]);

        var out = {};
        // sources：原始源码路径，比打包后的 chunk 名有价值得多
        if (Array.isArray(json.sources) && json.sources.length) {
          var paths = [];
          for (var i = 0; i < json.sources.length; i++) {
            var p = String(json.sources[i]);
            if (p.indexOf('webpack://') === 0) p = p.replace(/^webpack:\/\/\/?[^/]*\/?/, '');
            if (p.indexOf('node_modules') === 0) continue;
            paths.push(p);
          }
          out.path = paths;
        }
        // sourcesContent：还原后的原始源码，直接再跑一遍全量提取
        if (Array.isArray(json.sourcesContent)) {
          var blob = json.sourcesContent.filter(function (x) { return typeof x === 'string'; }).join('\n');
          if (blob && blob.length <= MAX_MAP_BYTES) out.merge = extractInfo(blob);
        }
        if (out.merge) {
          for (var k in out.merge) {
            if (RESULT_KEYS.indexOf(k) > -1) mergeInto(entry, k, out.merge[k], mapUrl);
          }
        }
        if (out.path && out.path.length) mergeInto(entry, 'path', out.path, mapUrl);
        entry.updatedAt = Date.now();
        markDirty(current);
      } catch (e) { /* map 解析失败忽略 */ }
    }, Math.max(2, Math.round(concurrency / 2)));
  }

  // 3) JS 递归（depth 2）
  //    只抓 JS 里「真实引用」的同源 chunk，不做任何 URL 猜测。
  //    中等风险：会提前拉取懒加载资源，形成请求突发，因此默认关闭、严控数量与并发，
  //    且不会为 depth 2 拉到的文件再去取 sourcemap（避免请求量再翻一倍）。
  if (enableRecursive && pendingJs.length) {
    var already = Object.create(null);
    already[current] = 1;
    for (var s = 0; s < targets.length; s++) already[targets[s]] = 1;

    var extra = cap(unique(pendingJs.filter(function (u) { return !already[u]; })), MAX_RECURSIVE_JS);
    for (var e2 = 0; e2 < extra.length; e2++) entry.tasklist.push(0);
    entry.pretasknum = entry.tasklist.length;

    await runQueue(extra, async function (reqUrl) {
      try {
        var res2 = await fetchWithTimeout(reqUrl, timeoutMs, init);
        if (!res2.ok) throw new Error('HTTP ' + res2.status);
        var t2 = await res2.text();
        if (t2 && t2.length <= MAX_JS_BYTES) {
          persist(extractInfo(t2), reqUrl, current);
          collected.push({ text: t2, url: reqUrl });
        }
      } catch (err) { /* 超时 / 404 忽略 */ }
      entry.donetasklist.push(0);
      markDirty(current);
    }, RECURSIVE_CONCURRENCY);
  }

  // 4) 语义增强：接口还原、凭据分类、JWT 解码
  //    全部在本地对已拿到的文本完成，不产生任何额外请求。
  finalizeEntry(entry, collected);

  // 页面扫描建好条目后，把此前缓存的网络请求并进来
  // （文档请求和早期 XHR 往往早于 handleFind，那时还没有条目可写）
  if (sender && sender.tab && sender.tab.id != null) flushRequests(sender.tab.id);

  entry.done = 'done';
  entry.updatedAt = Date.now();
  await flushNow();
  refreshBadge();
  webhook(current);
}

// ------------------------------------------------------------------ 框架路由

async function handleFramework(request) {
  var current = request.current;
  var payload = request.payload;
  if (!payload) return;
  var entry = ensureEntry(current);
  entry.framework = {
    frameworks: payload.frameworks || null,
    chunks: payload.chunks || null,
    at: Date.now()
  };

  var routes = payload.routes || [];
  if (routes.length) {
    var lines = [];
    for (var i = 0; i < routes.length; i++) {
      var r = routes[i];
      if (!r || !r.path) continue;
      var line = r.path;
      if (r.name) line += '   # ' + r.name;
      if (r.component) line += '   @ ' + r.component;
      lines.push(line);
    }
    if (lines.length) {
      mergeInto(entry, 'route', lines, current + ' [vue/router]');
    }
  }

  // 全局配置对象里常直接躺着后端地址与 AK/SK
  var globals = payload.globals || [];
  for (var g = 0; g < globals.length; g++) {
    var gd = globals[g];
    if (!gd || !gd.value) continue;
    var d = extractInfo(gd.value);
    for (var k in d) {
      if (RESULT_KEYS.indexOf(k) > -1 && d[k] && d[k].length) {
        mergeInto(entry, k, d[k], current + ' [window.' + gd.name + ']');
      }
    }
  }

  // webpack chunk 清单 -> 推测未加载的分包地址
  var chunks = payload.chunks || {};
  if (chunks.webpack && chunks.webpack.length && payload.url) {
    var urls = guessChunkUrls(chunks.webpack, payload.url);
    if (urls.length) mergeInto(entry, 'url', urls, current + ' [webpack-chunk]');
  }

  entry.updatedAt = Date.now();
  markDirty(current);
  refreshBadge();
}

// ------------------------------------------------------------------ 运行时观测面（1.0.2）
//
// 静态扫描只能看到「HTML 里写了什么」，这里收的是「页面实际做了什么」。
// 全部被动记录，不发起任何请求 —— 与工具一贯的请求边界一致。

/** 从 URL 里抠查询参数名。参数名是接口面的直接线索，价值很高 */
function paramNamesOf(urlStr) {
  var out = [];
  try {
    new URL(urlStr).searchParams.forEach(function (_v, k) {
      if (k && out.length < 40) out.push(k);
    });
  } catch (e) { /* 非绝对 URL，跳过 */ }
  return out;
}

/**
 * 记一条真实调用：URL 进 request，method 进 runtimeMeta，参数名进 param。
 * base 必传 —— axios 之类常配相对地址（axios.defaults.baseURL + "/api/x"），
 * 不补齐 base 的话记下来的就是一串没用的相对路径。
 */
function recordCall(entry, url, method, sourceTag, base) {
  if (!url) return;
  var abs = url;
  try { abs = new URL(url, base || undefined).href; } catch (e) { /* 保持原样 */ }

  if (method) {
    if (!entry.runtimeMeta) entry.runtimeMeta = {};
    if (!entry.runtimeMeta[abs]) entry.runtimeMeta[abs] = String(method).toUpperCase();
  }

  mergeInto(entry, 'request', [abs], sourceTag);
  var names = paramNamesOf(abs);
  if (names.length) mergeInto(entry, 'param', names, sourceTag);
}

async function handleRuntime(request) {
  var current = request.current;
  var p = request.payload;
  if (!p) return;
  var entry = ensureEntry(current);

  var calls = p.calls || [];
  for (var i = 0; i < calls.length; i++) {
    var c = calls[i];
    if (!c || !c.u) continue;
    recordCall(entry, c.u, c.m, current + ' [runtime]', current);
  }

  // 端点：值只存 URL，类型走 endpointMeta。
  // 不能拼成 'ws wss://...' —— 地址类归一化会去掉全部空白，压成 'wswss://'，
  // 协议白名单认不出来就被判成噪声丢掉。
  var eps = p.endpoints || [];
  if (eps.length) {
    var lines = [];
    for (var e2 = 0; e2 < eps.length; e2++) {
      var ep = eps[e2];
      if (!ep || !ep.u) continue;
      var abs2 = ep.u;
      try { abs2 = new URL(ep.u, current).href; } catch (err) { /* 保持原样 */ }
      lines.push(abs2);
      if (ep.k) {
        if (!entry.endpointMeta) entry.endpointMeta = {};
        if (!entry.endpointMeta[abs2]) entry.endpointMeta[abs2] = String(ep.k);
      }
    }
    if (lines.length) mergeInto(entry, 'endpoint', lines, current + ' [runtime]');
  }

  // 存储：键名本身进 storage，值过一遍规则，命中的落到各自分类并标注来源
  var st = p.storage;
  if (st) {
    if (st.keys && st.keys.length) {
      mergeInto(entry, 'storage', st.keys, current + ' [storage]');
    }
    var vals = st.values || [];
    for (var v = 0; v < vals.length; v++) {
      var d = extractInfo(String(vals[v]));
      for (var k in d) {
        if (RESULT_KEYS.indexOf(k) > -1 && d[k] && d[k].length) {
          mergeInto(entry, k, d[k], current + ' [storage-value]');
        }
      }
    }
  }

  // 接口响应体：页面自己读到的 fetch/XHR 响应文本（被动旁观，不发起请求）。
  // JSON 里往往直接躺着手机号 / 身份证 / 邮箱 / token，命中项标注 [response-body] 来源。
  // secret 已在 extractInfo 出口统一降噪，这里不再单独处理。
  var bods = p.bodies || [];
  for (var b = 0; b < bods.length; b++) {
    var bd = bods[b];
    if (!bd || typeof bd.t !== 'string' || !bd.t) continue;
    var dBody = extractInfo(bd.t);
    for (var kb in dBody) {
      if (RESULT_KEYS.indexOf(kb) > -1 && dBody[kb] && dBody[kb].length) {
        mergeInto(entry, kb, dBody[kb], current + ' [response-body]');
      }
    }
  }

  entry.updatedAt = Date.now();
  markDirty(current);
  refreshBadge();
}

/**
 * SPA 路由切换后懒加载进来的 script，增量补进来。
 * 只登记地址不抓内容的话，里面的密钥和接口就白白漏掉了，所以这里复用
 * 与首屏同一套抓取原语（fetchWithTimeout / extractInfo / findSourcemapUrls），
 * 但把规模压到 20 个，避免路由连续切换形成请求突发。
 */
async function handleSpa(request) {
  var current = request.current;
  var list = request.data || [];
  if (!list.length) return;
  var entry = ensureEntry(current);

  var settings = await storageGet(['fetch_timeout', 'enable_sourcemap', 'concurrency',
    'allowlist', 'use_default_allowlist', 'resource_blocklist']);
  if (!settings) return;

  // 懒加载列表同样要过资源黑名单：运行时注入的统计/广告 SDK 脚本
  // （hm.baidu.com 这类）不该被补抓，也不该经 url/static 分类入库
  list = list.filter(function (u) {
    return !IHHostMatch.isBlockedResource(u, '', settings);
  });
  if (!list.length) return;
  mergeInto(entry, 'url', list, current + ' [spa-lazy]');

  var timeoutMs = settings.fetch_timeout === true ? TIMEOUT_FAST : TIMEOUT_SLOW;
  var enableMap = settings.enable_sourcemap !== false;
  var concurrency = parseInt(settings.concurrency, 10);
  if (isNaN(concurrency) || concurrency < 1) concurrency = CONCURRENCY;
  if (concurrency > 16) concurrency = 16;

  var headers = new Headers();
  headers.append('accept', '*/*');
  var init = {
    method: 'GET', headers: headers, mode: 'cors',
    cache: 'default', credentials: 'include'
  };

  var targets = cap(prioritize(list, current), 20);
  await runQueue(targets, async function (reqUrl) {
    if (reqUrl === current) return;
    try {
      var res = await fetchWithTimeout(reqUrl, timeoutMs, init);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var text = await res.text();
      if (text && text.length <= MAX_JS_BYTES) {
        persist(extractInfo(text), reqUrl, current);
        if (enableMap) {
          var maps = findSourcemapUrls(text, reqUrl);
          for (var m = 0; m < maps.length; m++) pendingSpaMaps.push(maps[m]);
        }
      }
    } catch (e) { /* 超时 / CORS / 404 均忽略 */ }
  }, concurrency);

  if (pendingSpaMaps.length) {
    mergeInto(entry, 'sourcemap', unique(pendingSpaMaps), current + ' [spa-lazy]');
    pendingSpaMaps.length = 0;
  }

  entry.updatedAt = Date.now();
  markDirty(current);
  refreshBadge();
}
var pendingSpaMaps = [];

// ------------------------------------------------------------------ webRequest 记录

var REQ_TYPES = ['xmlhttprequest', 'websocket', 'other'];
var REQ_MAX = 400;                        // 每个标签页最多缓存 400 条待归并记录
var reqBuffer = Object.create(null);      // tabId -> [ {url, method} ]
var allowlistCache = null;                // 白名单缓存，避免每条请求都读一遍 storage
var requestLogOn = true;                  // enable_request_log 开关

/**
 * 白名单站点一个请求都不记。
 * 用的 hostmatch 与 content.js 是同一份实现（importScripts / content_scripts 各加载一次），
 * 不存在两边规则 drift 的可能。
 */
function siteBlocked(urlStr) {
  var h = '';
  try { h = new URL(urlStr).host; } catch (e) { return false; }
  if (!h) return false;
  return IHHostMatch.hostMatches(h, IHHostMatch.effectiveList(allowlistCache || {}));
}

var resourceBlockCache = null;            // 资源黑名单缓存：真实请求记录 / SPA 补扫共用

function resourceBlocked(urlStr) {
  var h = '';
  try { h = new URL(urlStr).host; } catch (e) { return false; }
  if (!h) return false;
  return IHHostMatch.isBlockedResource(urlStr, '', resourceBlockCache || {});
}

function refreshSettingsCache() {
  return storageGet(['allowlist', 'use_default_allowlist', 'enable_request_log', 'resource_blocklist'])
    .then(function (s) {
      if (!s) return;
      allowlistCache = { allowlist: s.allowlist, use_default_allowlist: s.use_default_allowlist,
        resource_blocklist: s.resource_blocklist };
      requestLogOn = !(s.enable_request_log === false);
    });
}
refreshSettingsCache();
try {
  chrome.storage.onChanged.addListener(function (changes, ns) {
    if (ns !== 'local') return;
    if (changes.allowlist || changes.use_default_allowlist || changes.enable_request_log) {
      refreshSettingsCache();
    }
  });
} catch (e) { /* 扩展上下文已失效 */ }

/** 把缓存的请求并进该标签页对应的结果条目 */
function flushRequests(tabId) {
  var buf = reqBuffer[tabId];
  if (!buf || !buf.length) return;
  var current = tab_url[tabId];
  if (!current) return;                  // 还没有结果条目，继续缓存等 handleFind
  var entry = ensureEntry(current);
  for (var i = 0; i < buf.length; i++) {
    recordCall(entry, buf[i].url, buf[i].method, current + ' [network]', current);
  }
  buf.length = 0;
  entry.updatedAt = Date.now();
  markDirty(current);
  refreshBadge();
}

try {
  if (chrome.webRequest && chrome.webRequest.onCompleted) {
    // MV3 要求监听器在顶层同步注册，否则 SW 冷启动后收不到事件
    chrome.webRequest.onCompleted.addListener(function (d) {
      try {
        if (!d || d.tabId == null || d.tabId < 0) return;
        if (d.statusCode >= 400) return;               // 4xx/5xx 噪声大，不记
        if (!requestLogOn) return;
        if (siteBlocked(d.url)) return;
        if (resourceBlocked(d.url)) return;         // 资源黑名单（统计/广告 SDK）的请求不记
        if (/\.(png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|mp4|webm|terrain)([?#]|$)/i.test(d.url)) return;

        var buf = reqBuffer[d.tabId] || (reqBuffer[d.tabId] = []);
        if (buf.length >= REQ_MAX) return;
        buf.push({ url: d.url, method: d.method });
        flushRequests(d.tabId);
      } catch (e) { /* 单条异常不影响整体 */ }
    }, { urls: ['<all_urls>'], types: REQ_TYPES });

    chrome.tabs.onRemoved.addListener(function (tabId) {
      delete reqBuffer[tabId];
      delete tab_url[tabId];
    });
  }
} catch (e) { /* 权限缺失或上下文失效，降级为不记录 */ }

/** 从 webpack chunk id 反推常见命名规则下的 chunk 文件地址（仅推测，需人工确认） */
function guessChunkUrls(ids, pageUrl) {
  var base;
  try {
    var u = new URL(pageUrl);
    base = u.origin + u.pathname.replace(/\/[^\/]*$/, '/');
  } catch (e) { return []; }
  var out = [];
  var patterns = ['{base}{id}.js', '{base}js/{id}.js', '{base}static/js/{id}.js', '{base}chunk-{id}.js'];
  for (var i = 0; i < ids.length && out.length < 60; i++) {
    var id = String(ids[i]);
    if (!/^[\w\-\.]+$/.test(id)) continue;
    for (var p = 0; p < patterns.length; p++) {
      out.push(patterns[p].replace('{base}', base).replace('{id}', id));
    }
  }
  return unique(out);
}

// ------------------------------------------------------------------ 规则校验
//
// 正则配置校验（保存时编译 + 捕获组检查）：
// 用户提供的正则必须在「保存时」就编译通过，且查找类规则必须含捕获组，
// 否则 match() 出来的是整串而不是想要的片段。
// 这是后续做「设置页热编辑规则」的前置能力，先把校验器落在这里。

var RULE_GROUPS_REQUIRE_CAPTURE = ['path', 'url', 'secret', 'jwt', 'sfz', 'mobile', 'mail'];

function validateRules(rules) {
  var errors = [];
  if (!rules || typeof rules !== 'object') return { ok: false, errors: ['规则对象为空'] };

  Object.keys(rules).forEach(function (group) {
    var list = rules[group];
    if (!Array.isArray(list)) {
      errors.push(group + ': 必须是数组');
      return;
    }
    var needCapture = RULE_GROUPS_REQUIRE_CAPTURE.indexOf(group) > -1;
    list.forEach(function (pattern, i) {
      if (typeof pattern !== 'string') {
        errors.push(group + '[' + i + ']: 必须是字符串');
        return;
      }
      var re;
      try {
        re = new RegExp(pattern);
      } catch (e) {
        errors.push(group + '[' + i + ']: ' + e.message);
        return;
      }
      if (needCapture && (re.source.match(/\((?!\?)/g) || []).length === 0) {
        errors.push(group + '[' + i + ']: 缺少捕获组，match() 会返回整串');
      }
    });
  });

  return { ok: errors.length === 0, errors: errors };
}

// ------------------------------------------------------------------ 消息入口

chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  if (!request || !request.greeting) return false;

  if (request.greeting === 'find') {
    handleFind(request, sender).catch(function () {});
    return true;
  }
  if (request.greeting === 'framework') {
    handleFramework(request).catch(function () {});
    return true;
  }
  if (request.greeting === 'runtime') {
    handleRuntime(request).catch(function () {});
    return true;
  }
  if (request.greeting === 'spa') {
    handleSpa(request).catch(function () {});
    return true;
  }
  if (request.greeting === 'get') {
    // 与 content.js 的 pageKey 同一语义：条目键不含 hash（hash 路由 SPA 按 hash 分桶会让数据对不上）
    var cur = String(request.current || '').split('#')[0];
    sendResponse(search_data[cur] || null);
    return true;
  }
  if (request.greeting === 'clear') {
    var target = request.current;
    if (target && search_data[target]) {
      delete search_data[target];
      storageRemove('infohunter_result_' + target);
    }
    sendResponse({ ok: true });
    return true;
  }
  return false;
});

// ------------------------------------------------------------------ 标签页事件

chrome.tabs.onUpdated.addListener(function (tabId, props) {
  if (props.status === 'complete' && tabId === selected_id) refreshBadge();
});

chrome.tabs.onActivated.addListener(function (activeInfo) {
  selected_id = activeInfo.tabId;
  refreshBadge();
});

chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  if (tabs && tabs[0]) {
    selected_id = tabs[0].id;
    refreshBadge();
  }
});

// ------------------------------------------------------------------ 启动

cleanupExpired().then(rehydrate).then(refreshBadge);
