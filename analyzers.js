/**
 * InfoHunter - 语义分析器（纯函数，不产生任何网络请求）
 *
 * 由 background.js 通过 importScripts 载入，engine.js 调用。
 * 三个能力全部是「对已拿到的文本做分析」，不会多发出去一个包：
 *   1. classifySecret  —— 凭据按厂商前缀归类 + 可信度分级
 *   2. decodeJwt       —— JWT 解码并标记风险（alg=none 等）
 *   3. extractApiCalls —— 接口语义还原，产出 method + url + 参数名
 */

// ------------------------------------------------------------------ 1. 凭据结构化
//
// 顺序敏感：具体规则在前，泛型规则在后，命中即返回。
// anchored=true 的只在整值完全匹配时才算数，避免把整段 JS 误判成 base64 密钥。

var CREDENTIAL_RULES = [
  { type: '阿里云 OSS/RAM AccessKey', re: /LTAI[A-Za-z0-9]{12,24}/, confidence: 'high' },
  { type: '腾讯云 SecretId',          re: /AKID[A-Za-z0-9]{32,40}/, confidence: 'high' },
  { type: 'AWS Access Key ID',        re: /AKIA[0-9A-Z]{16}/, confidence: 'high' },
  { type: 'GitHub Token',             re: /gh[pousr]_[A-Za-z0-9]{36,255}/, confidence: 'high' },
  { type: 'GitLab Personal Token',    re: /glpat-[A-Za-z0-9\-_]{20,}/, confidence: 'high' },
  { type: 'Grafana Service Account',  re: /glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}/, confidence: 'high' },
  { type: 'Grafana API Key',          re: /glc_[A-Za-z0-9\-_+/]{32,}={0,2}/, confidence: 'high' },
  { type: 'Slack Token',              re: /xox[baprs]-[A-Za-z0-9-]{10,72}/, confidence: 'high' },
  { type: 'Google API Key',           re: /AIza[0-9A-Za-z\-_]{35}/, confidence: 'high' },
  { type: 'Stripe Key',               re: /[srk]_(live|test)_[0-9a-zA-Z]{16,}/, confidence: 'high' },
  { type: 'SendGrid API Key',         re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, confidence: 'high' },
  { type: 'OpenAI API Key',           re: /sk-[A-Za-z0-9]{32,}/, confidence: 'medium' },
  { type: 'Mailgun API Key',          re: /key-[0-9a-zA-Z]{32}/, confidence: 'medium' },
  { type: '私钥 (PEM)',               re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, confidence: 'high' },
  { type: 'MongoDB 连接串',           re: /mongodb(\+srv)?:\/\/[^\s'"<>]+/, confidence: 'high' },
  { type: 'PostgreSQL 连接串',        re: /postgres(ql)?:\/\/[^\s'"<>]+/, confidence: 'high' },
  { type: 'MySQL 连接串',             re: /mysql:\/\/[^\s'"<>]+/, confidence: 'high' },
  { type: 'Redis 连接串',             re: /rediss?:\/\/[^\s'"<>]+/, confidence: 'high' },
  { type: 'JDBC 连接串',              re: /jdbc:[a-z0-9]+:[^\s'"<>]+/, confidence: 'high' },
  { type: '企业微信机器人',           re: /qyapi\.weixin\.qq\.com\/cgi-bin\/webhook\/send\?key=/, confidence: 'high' },
  { type: '钉钉机器人',               re: /oapi\.dingtalk\.com\/robot\/send\?access_token=/, confidence: 'high' },
  { type: '飞书机器人',               re: /open\.feishu\.cn\/open-apis\/bot\/v2\/hook\//, confidence: 'high' },
  { type: 'Slack Webhook',            re: /hooks\.slack\.com\/services\//, confidence: 'high' },
  { type: 'JWT',                      re: /ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}/, confidence: 'high' },
  { type: 'IPv4 内网地址',            re: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/, confidence: 'medium' },

  // 泛型兜底，必须整值匹配
  { type: 'Base64 长串（疑似密钥）',  re: /^[A-Za-z0-9+/]{40,}={0,2}$/, confidence: 'low', anchored: true },
  { type: '16 进制长串（疑似密钥）',  re: /^[0-9a-fA-F]{32,}$/, confidence: 'low', anchored: true }
];

function classifySecret(value) {
  var v = String(value == null ? '' : value).trim();
  if (!v) return null;
  for (var i = 0; i < CREDENTIAL_RULES.length; i++) {
    var rule = CREDENTIAL_RULES[i];
    var hit = rule.anchored ? rule.re.test(v) : rule.re.test(v);
    if (hit) return { type: rule.type, confidence: rule.confidence };
  }
  return null;
}

// ------------------------------------------------------------------ 2. JWT 解码

function b64urlDecode(seg) {
  var s = String(seg).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) {
    return null;
  }
}

var JWT_PRIVILEGE_KEYS = ['admin', 'isadmin', 'role', 'roles', 'authorities', 'permissions', 'perms', 'scope', 'scopes', 'group', 'groups', 'level'];

function decodeJwt(token) {
  var raw = String(token == null ? '' : token).trim();
  var parts = raw.split('.');
  if (parts.length < 2) return null;

  var header = null;
  var payload = null;
  try { header = JSON.parse(b64urlDecode(parts[0])); } catch (e) { header = null; }
  try { payload = JSON.parse(b64urlDecode(parts[1])); } catch (e) { payload = null; }
  if (!header && !payload) return null;

  var risks = [];
  var alg = header && header.alg ? String(header.alg) : '';

  if (alg.toLowerCase() === 'none') risks.push('alg=none，签名校验可绕过');
  else if (alg.indexOf('HS') === 0) risks.push('对称签名（' + alg + '），密钥有可能也在前端');
  else if (alg.indexOf('RS') === 0) risks.push('非对称签名（' + alg + '），需确认公钥校验是否严格');

  if (payload) {
    if (!payload.exp) {
      risks.push('无 exp，长效凭证');
    } else {
      var days = (payload.exp * 1000 - Date.now()) / 86400000;
      if (days > 365) risks.push('有效期超过 1 年');
      else if (days < 0) risks.push('已过期');
    }
    var hits = [];
    for (var k in payload) {
      if (Object.prototype.hasOwnProperty.call(payload, k) && JWT_PRIVILEGE_KEYS.indexOf(String(k).toLowerCase()) > -1) {
        hits.push(k);
      }
    }
    if (hits.length) risks.push('payload 含权限字段：' + hits.join(', '));
  }

  var subject = payload ? (payload.sub || payload.username || payload.user_name || payload.name || payload.account || '') : '';

  return {
    alg: alg,
    typ: header && header.typ ? String(header.typ) : '',
    subject: subject ? String(subject) : '',
    issuer: payload && payload.iss ? String(payload.iss) : '',
    expires: payload && payload.exp ? new Date(payload.exp * 1000).toISOString() : '',
    payloadKeys: payload ? Object.keys(payload) : [],
    hasSignature: !!(parts[2] && parts[2].length > 0),
    risks: risks
  };
}

// ------------------------------------------------------------------ 3. 接口语义还原

var RE_DOT_CALL = /\b(?:axios|this\.axios|\$http|this\.\$http|\$api|this\.\$api|http|service|request|ajax|api|fetch)\s*\.\s*(get|post|put|delete|patch|head)\s*\(\s*(['"`])([^'"`\s]+)\2/gi;

var RE_FETCH_CALL = /\bfetch\s*\(\s*(['"`])([^'"`\s]+)\1\s*(?:,\s*\{([\s\S]{0,400}?)\})?/gi;

var RE_OBJ_CALL = /\b(?:axios|request|http|service|ajax|api|fetch)\s*\(\s*\{/gi;

var INVALID_URL = /^(javascript|data|mailto|tel|about|blob|chrome-extension):/i;

/** 从一个以 '{' 开头的片段里取顶层键名（支持 key: 形态与 { u, p } 简写形态） */
function topLevelKeys(s) {
  s = String(s == null ? '' : s).trim();
  if (!s || s.charAt(0) !== '{') return [];

  var depth = 0;
  var keys = [];
  var segStart = 1;
  var inString = null;

  function pushKey(seg) {
    seg = String(seg == null ? '' : seg).trim();
    if (!seg) return;
    // 形如 key: xxx —— 取冒号前的键名
    var m = seg.match(/^(['"]?)([A-Za-z_$][\w$]*)\1\s*:/);
    if (m) { keys.push(m[2]); return; }
    // 简写属性 { username, password } —— 没有冒号，整段就是个标识符
    m = seg.match(/^([A-Za-z_$][\w$]*)$/);
    if (m) keys.push(m[1]);
    // 其余（表达式、嵌套展开、含运算符）一律忽略
  }

  for (var i = 0; i < s.length && i < 3000; i++) {
    var c = s.charAt(i);
    if (inString) {
      if (c === '\\') { i++; continue; }
      if (c === inString) inString = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { inString = c; continue; }
    if (c === '{' || c === '[') { depth++; continue; }
    if (c === '}' || c === ']') {
      if (depth === 1) pushKey(s.slice(segStart, i));
      depth--;
      if (depth <= 0) break;
      continue;
    }
    if (c === ',' && depth === 1) {
      pushKey(s.slice(segStart, i));
      segStart = i + 1;
    }
  }
  // 输入可能不配平（被截断的窗口），结尾兜底收一次
  if (depth === 1) pushKey(s.slice(segStart));
  return keys.slice(0, 24);
}

function pickQuoted(win, key) {
  var re = new RegExp(key + '\\s*:\\s*[\'"`]([^\'"`]*)[\'"`]', 'i');
  var m = win.match(re);
  return m ? m[1] : '';
}

function pickMethod(win) {
  var m = win.match(/\b(?:method|type)\s*:\s*['"`]([a-zA-Z]+)['"`]/i);
  return m ? m[1].toUpperCase() : '';
}

/** 从 startIdx 往后找第一个不在字符串里的 '{'，bound 内没有返回 -1 */
function findFirstBrace(text, startIdx, bound) {
  var inStr = null;
  var end = Math.min(text.length, startIdx + bound);
  for (var i = startIdx; i < end; i++) {
    var c = text.charAt(i);
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { inStr = c; continue; }
    if (c === '{') return i;
  }
  return -1;
}

/** 从 openIdx（'(' / '{' / '['）取配平片段，含字符串与嵌套 */
function extractBalanced(text, openIdx) {
  var open = text.charAt(openIdx);
  var close = open === '(' ? ')' : (open === '{' ? '}' : ']');
  var depth = 0;
  var inStr = null;
  for (var i = openIdx; i < text.length && i < openIdx + 3000; i++) {
    var c = text.charAt(i);
    if (inStr) {
      if (c === '\\') { i++; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { inStr = c; continue; }
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return text.slice(openIdx, i + 1);
    }
  }
  return null;
}

/**
 * 解析一个请求参数对象。
 * 裸对象 { id, name }        → 顶层键即请求体字段
 * 配置对象 { url, method, data:{...} } → 取 data / params / body 里的键
 */
function parseBodyObject(objStr) {
  var keys = topLevelKeys(objStr);
  var CONFIG_KEYS = ['url', 'path', 'api', 'method', 'type', 'params', 'data', 'body', 'json', 'headers', 'config', 'signal', 'timeout', 'responseType'];
  var isConfig = false;
  for (var i = 0; i < keys.length; i++) {
    if (CONFIG_KEYS.indexOf(keys[i]) > -1) { isConfig = true; break; }
  }
  if (!isConfig) return keys;

  var m = objStr.match(/\b(?:data|params|body|json)\s*:\s*\{/i);
  if (!m) return [];
  var idx = objStr.indexOf(m[0]) + m[0].length - 1; // 指向那个 '{'
  var sub = extractBalanced(objStr, idx);
  return sub ? topLevelKeys(sub) : [];
}

/** 从某个调用点往后做完整语义解析（method / url / params 就近取） */
function scanCallSite(text, idx, fallbackMethod, fallbackUrl) {
  var brace = findFirstBrace(text, idx, 600);
  var obj = brace > -1 ? extractBalanced(text, brace) : null;

  var url = fallbackUrl;
  var method = fallbackMethod;
  var params = [];

  if (obj) {
    if (!url) {
      url = pickQuoted(obj, 'url') || pickQuoted(obj, 'path') || pickQuoted(obj, 'api');
    }
    var m2 = pickMethod(obj);
    if (m2) method = m2;
    params = parseBodyObject(obj);
  }

  return { method: String(method || 'GET').toUpperCase(), url: url || '', params: params };
}

/**
 * 从 JS 文本里还原接口调用语义。
 * 只识别真实存在的调用点，不做任何 URL 猜测。
 */
function extractApiCalls(text, limit) {
  var out = [];
  var seen = Object.create(null);
  var cap = limit || 200;

  function push(method, url, params) {
    if (!url || INVALID_URL.test(url)) return;
    // 只要路径形态，不要整段的自然语言
    if (!/^[/]/.test(url) && !/^https?:\/\//i.test(url) && !/^\.\.?\//.test(url)) return;
    if (url.length > 300) return;
    var m = String(method || 'GET').toUpperCase();
    var key = m + ' ' + url;
    if (seen[key]) return;
    seen[key] = 1;
    if (out.length >= cap) return;
    out.push({ method: m, url: url, params: params || [] });
  }

  var m;

  // 形态一：axios.get('/x') / $http.post("/x", {...})
  RE_DOT_CALL.lastIndex = 0;
  while ((m = RE_DOT_CALL.exec(text)) !== null) {
    var c1 = scanCallSite(text, m.index, m[1], m[3]);
    push(c1.method, c1.url, c1.params);
  }

  // 形态二：fetch('/x', { method: 'POST', body: ... })
  RE_FETCH_CALL.lastIndex = 0;
  while ((m = RE_FETCH_CALL.exec(text)) !== null) {
    var c2 = scanCallSite(text, m.index, 'GET', m[2]);
    push(c2.method, c2.url, c2.params);
  }

  // 形态三：request({ url: '/x', method: 'post', data: { a, b } })
  RE_OBJ_CALL.lastIndex = 0;
  while ((m = RE_OBJ_CALL.exec(text)) !== null) {
    var c3 = scanCallSite(text, m.index, 'GET', '');
    if (!c3.url) continue;
    push(c3.method, c3.url, c3.params);
  }

  return out;
}

/** 把 api 三元组渲染成一行可直接读的文本 */
function formatApiCall(call) {
  var line = call.method + ' ' + call.url;
  if (call.params && call.params.length) line += '   [' + call.params.join(', ') + ']';
  return line;
}

// ------------------------------------------------------------------ 4. 上下文快照

/** 取命中值的上下文，便于分辨真密钥还是示例值 */
function contextAround(text, value, radius) {
  var r = radius || 80;
  var idx = String(text).indexOf(value);
  if (idx < 0) return '';
  var start = Math.max(0, idx - r);
  var end = Math.min(text.length, idx + value.length + r);
  var snip = text.slice(start, end).replace(/\s+/g, ' ').trim();
  return (start > 0 ? '…' : '') + snip + (end < text.length ? '…' : '');
}

// ------------------------------------------------------------------ 5. 响应体 / 存储值的 secret 降噪

/**
 * nuclei 规则里有大量泛化的 key=value 形态（如 ["']?username["']?[=:]["']?[\w-]+），
 * 噪声有两类，都在 extractInfo 出口统一过滤（源码 / 响应体 / 存储值一个语义）：
 *   1. 裸业务字段键：username / nickname / realName…，值是普通用户名或空串，
 *      源码与响应体里都毫无情报价值；
 *   2. JS 代码值：username = document、PrivateKey=function、passwordEl = document ——
 *      值是 JS 关键字或全局对象，明显是 DOM/逻辑赋值而非凭据。
 *   保留：带前缀的键（spring.mail.username、SMTP_USER）、真凭据值（LTAI…、jdbc://…）、
 *   PEM 私钥头这类无 key=value 结构的命中。
 */
var SECRET_NOISE_FIELDS = {
  username: 1, user: 1, userid: 1, uid: 1,
  nickname: 1, realname: 1, name: 1, displayname: 1, fullname: 1,
  creator: 1, createby: 1, updator: 1, updateby: 1, modifier: 1, operator: 1,
  author: 1, owner: 1, title: 1, label: 1, keyword: 1, keywordstr: 1,
  avatar: 1, icon: 1, photo: 1, filename: 1, filepath: 1, filetype: 1,
  remark: 1, description: 1, desc: 1, comment: 1, content: 1,
  chinesename: 1, englishname: 1, department: 1, dept: 1, company: 1,
  locale: 1, language: 1, timezone: 1, gender: 1, sex: 1
};


// 捕获组：1=键左引号 2=键 3=键右引号 4=值左引号 5=值。
// 值是否带引号是降噪的关键信号：带引号 = 字符串字面量（可能是真凭据）；
// 未加引号 = 代码里的变量/字面量引用（password:t、cancelToken=void 这类是混淆代码）。
var RE_KV_HIT = /^(["']?)([A-Za-z_][\w.-]*)(["']?)\s*[:=]\s*(["']?)([^"'{}\[\],\s]{1,120})\4$/;

/** 值为 JS 关键字 / 全局对象 / 全局对象开头（document.querySelector…）→ 代码赋值 */
var JS_VALUE_NOISE = {
  document: 1, window: 1, function: 1, null: 1, undefined: 1, true: 1, false: 1,
  this: 1, new: 1, typeof: 1, require: 1, module: 1, exports: 1, console: 1,
  location: 1, navigator: 1, localstorage: 1, sessionstorage: 1, math: 1,
  json: 1, object: 1, array: 1, string: 1, number: 1, boolean: 1, date: 1,
  regexp: 1, error: 1, promise: 1, symbol: 1, map: 1, event: 1, alert: 1,
  settimeout: 1, setinterval: 1, history: 1, screen: 1, self: 1, parent: 1,
  top: 1, globalthis: 1, fetch: 1, xmlhttprequest: 1,
  await: 1, void: 1, async: 1, yield: 1, encodeuricomponent: 1, decoduricomponent: 1,
  setimmediate: 1, queuemicrotask: 1, parseint: 1, parsefloat: 1
};

function isJsCodeValue(v) {
  var raw = String(v);
  if (JS_VALUE_NOISE.hasOwnProperty(raw.toLowerCase())) return true;
  return /^(document|window|console|localStorage|sessionStorage|this)\s*\./.test(raw);
}

/**
 * IncompletePath 降噪（纯函数，供单测）。
 * RE_INCOMPLETE 会命中任何「带斜杠的引号字符串」，在现代前端代码里命中的大半是
 * MIME 类型（application/json、image/jpeg）、注释残留（星号斜杠、冒号斜杠）这类结构碎片。
 * 规则：段/段 结构、段内只能有字母数字 - . 、整串至少含一个字母、
 *       首段不是 MIME 顶层类型。
 */
var MIME_TOP_TYPES = {
  application: 1, text: 1, image: 1, audio: 1, video: 1, multipart: 1,
  message: 1, font: 1, model: 1, example: 1, chemical: 1
};

function filterIncompletePath(hits) {
  if (!hits || !hits.length) return hits;
  var out = [];
  for (var i = 0; i < hits.length; i++) {
    var s = String(hits[i]).replace(/^['"]|['"]$/g, '');
    if (!/^[\w][\w\-.]*(?:\/[\w\-.]+)+$/.test(s)) continue;        // 结构碎片：*/ 、:/ 、image/
    if (MIME_TOP_TYPES[s.split('/')[0].toLowerCase()]) continue;   // MIME：application/json
    if (!/[a-z]/.test(s)) continue;                                // 全大写/数字：N/A、OS/2、DTLS/SCTP、YYYY/MM/DD
    var segs = s.split('/');
    var hasShortSeg = false;
    for (var j = 0; j < segs.length; j++) {
      if (segs[j].length < 2) { hasShortSeg = true; break; }       // 单字符段：o/i14u9pJrxRKAsu
    }
    if (hasShortSeg) continue;
    out.push(hits[i]);
  }
  return out;
}

/**
 * secret 降噪（纯函数，供单测）。核心判据是「值有没有加引号」：
 *   带引号 = 字符串字面量，只滤可确证的伪凭据（截断 JWT 前缀 / SCREAMING 错误码 /
 *            纯数值串 / 值与键同词的常量定义 / 算法名 / 环境名）；
 *   未加引号 = 代码上下文，混淆变量引用占九成（password:t、cancelToken=void、
 *            password = RSA、token_res = await），只保留像真凭据的（含数字、足够长）。
 * 非 key=value 形态（LTAI、PEM 头）原样保留。
 */
var VAR_REF_NOISE = {
  token: 1, password: 1, username: 1, secret: 1, key: 1, data: 1, config: 1,
  params: 1, res: 1, response: 1, result: 1, value: 1, val: 1, info: 1,
  user: 1, name: 1, code: 1, text: 1, str: 1, item: 1, query: 1, body: 1
};

/** 值为加密算法名（password = RSA / mqtt_password = sm3）—— 算法配置不是凭据 */
var CRYPTO_ALGO_VALUES = {
  rsa: 1, sm2: 1, sm3: 1, sm4: 1, aes: 1, des: 1, '3des': 1, md5: 1,
  sha1: 1, sha256: 1, sha512: 1, hmac: 1, base64: 1, rc4: 1, ecc: 1
};

/** 值为环境名（NODE_ENV:"production"）—— 部署配置不是凭据 */
var ENV_VALUE_NOISE = {
  production: 1, development: 1, test: 1, testing: 1, staging: 1, uat: 1, gray: 1, dev: 1, prod: 1
};

/** 键与值由完全相同的一组词组成（忽略大小写与分隔符）：
 *  DEST_TOKEN_EXPIRED="dest_token_expired" 是常量自定义，不是凭据 */
function sameWords(key, val) {
  var k = normWords(key), v = normWords(val);
  return k.length > 0 && k === v;
}

/** 值的词集 ⊆ 键的词集：ON_TOKEN_PRIVILEGE_DID_EXPIRE="token-privilege-did-expire"
 *  这类 SDK 事件名常量（值 = 键去掉 ON_ 前缀），同样不是凭据 */
function valueWordsSubset(key, val) {
  var k = normWords(key), v = normWords(val);
  if (!v.length || !k.length) return false;
  return v.every(function (w) { return k.indexOf(w) > -1; });
}

function normWords(x) {
  return String(x).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).sort();
}

function filterSecretNoise(hits) {
  if (!hits || !hits.length) return hits;
  var out = [];
  for (var i = 0; i < hits.length; i++) {
    var raw = String(hits[i]);
    var m = raw.match(RE_KV_HIT);
    if (!m) {
      // 非 key=value 形态（LTAI、PEM 头）原样保留；键后引号未闭合的是规则截断片段：
      // 值含数字且 ≥5 位的是真凭据前导（secretKey = '1qaz2wsx），其余（ACCOUNT="io）丢弃
      var trunc = raw.match(/^["']?[A-Za-z_][\w.-]*["']?\s*[:=]\s*["']([^"']*)$/);
      if (trunc) {
        if (/^eyJ/.test(trunc[1])) continue;                 // 截断的 JWT 前缀，完整的在 jwt 分类
        if (trunc[1].length >= 5 && /\d/.test(trunc[1])) out.push(hits[i]);
      } else {
        out.push(hits[i]);
      }
      continue;
    }
    var key = m[2].toLowerCase();
    var keyRaw = m[2];                                    // SCREAMING 常量判定要用原始大小写
    var val = m[5];
    var valQuoted = m[4] !== '';

    if (SECRET_NOISE_FIELDS.hasOwnProperty(key)) continue;   // 裸业务字段键
    if (!valQuoted && isJsCodeValue(val)) continue;          // JS 关键字 / 全局对象

    if (!valQuoted) {
      // 未加引号：代码上下文的变量 / 字面量
      var screaming = /^[A-Z0-9_]+$/.test(keyRaw);
      if (/^[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?\d+)?$/.test(val) && (!/pass/i.test(key) || screaming)) continue;
      if (/^[A-Za-z_$][\w$]*$/.test(val)) {
        if (val.length <= 3) continue;                                        // 混淆短名：RSA / sm3 / Cb
        if (/^[a-z0-9_]+$/.test(val) && val.indexOf('_') > -1) continue;      // snake_case：city_config
        if (/^[a-z][A-Za-z0-9]*$/.test(val) && /[A-Z]/.test(val)) continue;   // camelCase：encodeURIComponent
        if (VAR_REF_NOISE[val.toLowerCase()]) continue;                       // 通用变量名：token / data
      }
    } else {
      // 带引号：字符串字面量，只滤可确证的伪凭据
      if (/^eyJ/.test(val)) continue;                                         // 截断 JWT 前缀（完整的在 jwt 分类）
      if (/^[A-Z0-9_]+$/.test(keyRaw) && /^\d+$/.test(val)) continue;         // SCREAMING 键 + 错误码
      if (/^\d+(?:\.\d+)?(?:[eE]\d+)?$/.test(val) && !/pass/i.test(key)) continue; // "token":"123456"
      if (sameWords(key, val)) continue;                                      // 常量自定义
      if (valueWordsSubset(key, val)) continue;                               // 值的词集 ⊆ 键的词集：SDK 事件常量
      if (CRYPTO_ALGO_VALUES[val.toLowerCase()]) continue;                    // 算法名
      if (ENV_VALUE_NOISE[val.toLowerCase()]) continue;                       // 环境名
    }
    out.push(hits[i]);
  }
  return out;
}


// ------------------------------------------------------------------ 6. 分类降噪：sfz / ip / path / domain·url

/**
 * 身份证校验：正则只能保证「形似」，这里校验「真可能是」——
 * 省份区域码（GB/T 2260 前两位）+ 出生日期合理 + 18 位证 ISO 7064 MOD 11-2 校验码。
 * 15 位老证无校验位且早已停发，网页源码里的 15 位数字串（随机浮点/时间戳）全是误报，整体不再收录。
 */
var SFZ_REGION_RE = /^(11|12|13|14|15|21|22|23|31|32|33|34|35|36|37|41|42|43|44|45|46|50|51|52|53|54|61|62|63|64|65|71|81|82|91)/;
var SFZ_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
var SFZ_CHECK_MAP = '10X98765432';

function sfzChecksumOk(id18) {
  var sum = 0;
  for (var i = 0; i < 17; i++) sum += Number(id18.charAt(i)) * SFZ_WEIGHTS[i];
  return SFZ_CHECK_MAP.charAt(sum % 11) === id18.charAt(17).toUpperCase();
}

function plausibleSfz(rawId) {
  var s = String(rawId).replace(/^['"]|['"]$/g, '');
  if (!SFZ_REGION_RE.test(s) || s.length !== 18) return false;
  var y = Number(s.substr(6, 4)), mo = Number(s.substr(10, 2)), d = Number(s.substr(12, 2));
  var now = new Date();
  if (y < 1900 || y > now.getFullYear() || mo < 1 || mo > 12 || d < 1 || d > 31) return false;
  return sfzChecksumOk(s);
}

function filterSfz(hits) {
  if (!hits || !hits.length) return hits;
  var out = [];
  for (var i = 0; i < hits.length; i++) {
    if (plausibleSfz(hits[i])) out.push(hits[i]);
  }
  return out;
}

/** IP 降噪：八位组越界（4.0.0.999 这类版本号）与回环/通配地址（0.0.0.0、127.0.0.1）没有情报价值 */
function filterIp(hits) {
  if (!hits || !hits.length) return hits;
  var out = [];
  for (var i = 0; i < hits.length; i++) {
    var s = String(hits[i]);
    var m = s.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    if (!m) { out.push(hits[i]); continue; }
    var octets = [m[1], m[2], m[3], m[4]].map(Number);
    var valid = octets.every(function (o) { return o >= 0 && o <= 255; });
    if (!valid) continue;
    var ip = octets.join('.');
    if (ip === '0.0.0.0' || ip === '127.0.0.1') continue;
    out.push(hits[i]);
  }
  return out;
}

/**
 * PATH 降噪：JS 产物里 './xxx' / '../xxx' 是打包器模块导入（moment 语言包、zlib 内部模块），
 * 'webpack/runtime/*' 是 webpack 自身代码，'/1' 这类单字符段是碎片 —— 都不是服务端路径。
 */
function filterPath(hits) {
  if (!hits || !hits.length) return hits;
  var out = [];
  for (var i = 0; i < hits.length; i++) {
    var s = String(hits[i]).replace(/^['"]|['"]$/g, '');
    if (/^(\.\.?\/)/.test(s)) continue;                 // 模块导入：./af、../utils
    if (/^webpack\//.test(s)) continue;                   // webpack runtime
    if (/^\/[#\w-]{0,2}$/.test(s)) continue;             // 碎片：/1、/#、/3
    out.push(hits[i]);
  }
  return out;
}

/**
 * domain / url 降噪：XML 命名空间与协议标识（opengis.net、w3.org、webrtc.org 这些是
 * 规范常量不是站点资产）、声网 SDK 云（sd-rtn.com，一个 SDK 就能带出 30+ 条）。
 */
var NOISE_URL_PREFIXES = [
  'http://www.w3.org/', 'https://www.w3.org/',
  'http://www.opengis.net/', 'https://www.opengis.net/',
  'http://earth.google.com/kml', 'http://www.webrtc.org/',
  'http://www.topografix.com/', 'http://www.mapinfo.com/',
  'http://get.webgl.org', 'http://www.esri.com/wms',
  'http://schemas.', 'http://ns.adobe.com/', 'https://schemas.'
];
var NOISE_DOMAIN_SUFFIXES = ['sd-rtn.com', 'w3.org', 'opengis.net', 'webrtc.org'];

function filterNoiseHost(hits) {
  if (!hits || !hits.length) return hits;
  var out = [];
  for (var i = 0; i < hits.length; i++) {
    var s = String(hits[i]).replace(/^['"]|['"]$/g, '').toLowerCase();
    var noisy = false;
    for (var j = 0; j < NOISE_URL_PREFIXES.length; j++) {
      if (s.indexOf(NOISE_URL_PREFIXES[j]) === 0) { noisy = true; break; }
    }
    if (!noisy) {
      for (var k = 0; k < NOISE_DOMAIN_SUFFIXES.length; k++) {
        var suf = NOISE_DOMAIN_SUFFIXES[k];
        if (s === suf || s.endsWith('.' + suf) || s.indexOf(suf) > -1) { noisy = true; break; }
      }
    }
    if (!noisy) out.push(hits[i]);
  }
  return out;
}
