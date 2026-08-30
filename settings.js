/**
 * InfoHunter - 设置页逻辑
 *
 * 相对旧版实现的修复：
 *   [FIX] JSON.parse(headers) 未捕获异常，填错格式会导致整个设置页脚本中断
 *   [FIX] allowlist 用 forEach + splice 过滤空行，边遍历边删除会漏掉元素
 *   [ADD] Sourcemap 抓取 / 框架运行时分析 / 并发数 三个新开关
 */

'use strict';

//
// 请求边界（重要）：
//   本扩展默认只发「浏览器本来就会发」的请求——即页面 HTML 里引用的 JS。
//   会额外产生请求的能力有两项，按风险分级：
//     enable_sourcemap    低风险  → 默认开。.js.map 是站点自己在注释里声明的静态资源，
//                                   单个 GET、并发 3、上限 20 个，不会被判为扫描。
//     enable_js_recursive 中风险  → 默认关。会提前拉取懒加载 chunk，形成请求突发，
//                                   在对方视角接近爬取行为。
//   任何「探测不存在的路径」的能力（Swagger 主动探测、路由可访问性、敏感路径枚举）
//   一律不实现——那才是真正会被标记成攻击的行为。
//
var DEFAULTS = {
  settingSafeMode: true,
  fetch_timeout: false,
  enable_sourcemap: true,
  enable_js_recursive: false,
  enable_framework: true,
  enable_runtime: true,
  enable_request_log: true,
  enable_spa_rescan: true,
  use_default_allowlist: true,
  concurrency: 6,
  global_float: false
};

var TOGGLE_KEYS = [
  'settingSafeMode', 'fetch_timeout', 'enable_sourcemap',
  'enable_js_recursive', 'enable_framework', 'enable_runtime',
  'enable_request_log', 'enable_spa_rescan',
  'use_default_allowlist', 'global_float'
];

function $(id) { return document.getElementById(id); }

function flash(msgEl) {
  if (!msgEl) return;
  msgEl.classList.add('show');
  setTimeout(function () { msgEl.classList.remove('show'); }, 1500);
}

/**
 * 文本框内容 → 域名规则数组。站点白名单与资源黑名单共用。
 * 必须与 content.js 的 normalizeRule 保持同一套语义：去协议 / 去路径查询锚点 /
 * 去 `*.` 和前导点 / 转小写。否则会出现"设置页看着保存了、匹配器却不认"的错配。
 */
function normalizeHostList(text) {
  var seen = Object.create(null);
  var out = [];
  String(text || '').split(/[\r\n]+/).forEach(function (line) {
    var s = String(line).trim();
    if (!s) return;
    s = s.replace(/^[a-z][a-z0-9+.\-]*:\/\//i, '')   // 协议
      .replace(/^\/+/, '')                            // //host 形式
      .split(/[/?#]/)[0]                              // 路径 / 查询 / 锚点
      .replace(/^[\s"'<>]+|[\s"'<>]+$/g, '')
      .replace(/\.$/, '')
      .toLowerCase();
    if (!s || seen[s]) return;
    seen[s] = 1;
    out.push(s);
  });
  return out;
}

/** 开关状态只切 class 与 aria：圆钮位置由 CSS 过渡，文字放 title 里不挤占轨道 */
function renderToggle(key, value) {
  var node = $(key);
  if (!node) return;
  var on = value === true;
  node.className = 'switch' + (on ? ' on' : '');
  node.setAttribute('role', 'switch');
  node.setAttribute('aria-checked', on ? 'true' : 'false');
  node.title = on ? '开启（点击关闭）' : '关闭（点击开启）';
}

function bindToggle(key) {
  var node = $(key);
  if (!node) return;
  node.addEventListener('click', function () {
    chrome.storage.local.get([key], function (s) {
      // 从未设置过的项，以默认值作为当前状态
      var cur = (key in s) ? s[key] === true : DEFAULTS[key] === true;
      var next = !cur;
      var patch = {};
      patch[key] = next;
      chrome.storage.local.set(patch, function () { renderToggle(key, next); });
    });
  });
}

// ------------------------------------------------------------------ 载入

function loadAll() {
  chrome.storage.local.get(Object.keys(DEFAULTS), function (s) {
    for (var i = 0; i < TOGGLE_KEYS.length; i++) {
      var k = TOGGLE_KEYS[i];
      var v = (k in s) ? s[k] === true : DEFAULTS[k] === true;
      renderToggle(k, v);
    }
    var conc = (s.concurrency !== undefined && s.concurrency !== null) ? s.concurrency : DEFAULTS.concurrency;
    $('concurrency').value = conc;
  });

  chrome.storage.local.get(['allowlist', 'resource_blocklist'], function (s) {
    if (s && s.allowlist && s.allowlist.length) $('allowlist').value = s.allowlist.join('\n');
    if (s && s.resource_blocklist && s.resource_blocklist.length) {
      $('resource_blocklist').value = s.resource_blocklist.join('\n');
    }
  });

  chrome.storage.local.get(['webhook_setting'], function (s) {
    var w = s && s.webhook_setting;
    if (!w) return;
    $('url').value = w.url || '';
    $('method').value = w.method || 'GET';
    $('arg').value = w.arg || '';
    try {
      $('headers').value = JSON.stringify(w.headers || {}, null, 2);
    } catch (e) {
      $('headers').value = '{}';
    }
  });
}

/**
 * 把「文本框 + 保存 + 置空 + 提示」这套交互绑到指定的 storage key 上。
 * 站点白名单与资源黑名单结构完全一样，抽出来避免两份复制粘贴的 diverge。
 */
function bindHostList(textId, saveId, resetId, msgId, storageKey, emptyText) {
  function commit(arr, note) {
    var patch = {};
    patch[storageKey] = arr;
    $(textId).value = arr.join('\n');
    chrome.storage.local.set(patch, function () {
      var m = $(msgId);
      if (!m) return;
      m.textContent = note || (arr.length ? ('已保存 ' + arr.length + ' 条') : emptyText);
      flash(m);
    });
  }

  $(saveId).addEventListener('click', function () {
    // 归一化结果回写，让用户一眼看到实际生效的规则，
    // 避免填了一串完整网址、匹配器却只认主机部分这种"填了不生效"的落差
    commit(normalizeHostList($(textId).value));
  });

  $(resetId).addEventListener('click', function () { commit([], emptyText); });
}

// ------------------------------------------------------------------ 事件绑定

document.addEventListener('DOMContentLoaded', function () {
  for (var i = 0; i < TOGGLE_KEYS.length; i++) bindToggle(TOGGLE_KEYS[i]);

  $('concurrency').addEventListener('change', function (e) {
    var v = parseInt(e.target.value, 10);
    if (isNaN(v) || v < 1) v = 1;
    if (v > 16) v = 16;
    e.target.value = v;
    chrome.storage.local.set({ concurrency: v });
  });

  bindHostList('allowlist', 'save_allowlist', 'reset_allowlist', 'allowlist_msg',
    'allowlist', '用户名单已置空，仍走内置默认');

  bindHostList('resource_blocklist', 'save_blocklist', 'reset_blocklist', 'blocklist_msg',
    'resource_blocklist', '用户名单已置空，仍走内置默认');

  $('save').addEventListener('click', function () {
    var cfg = {
      url: $('url').value.trim(),
      method: $('method').value,
      arg: $('arg').value.trim()
    };
    // [FIX] headers 解析失败时不再让整个脚本抛异常中断
    try {
      var h = $('headers').value.trim();
      cfg.headers = h ? JSON.parse(h) : {};
      if (typeof cfg.headers !== 'object' || cfg.headers === null) throw new Error('headers 必须是对象');
    } catch (e) {
      alert('自定义 headers 不是合法 JSON：' + e.message);
      return;
    }
    chrome.storage.local.set({ webhook_setting: cfg }, function () { flash($('webhook_msg')); });
  });

  $('reset').addEventListener('click', function () {
    $('url').value = '';
    $('arg').value = '';
    $('headers').value = '{}';
    chrome.storage.local.set({ webhook_setting: { url: '', method: 'GET', arg: '', headers: {} } });
  });

  $('settingClearLocalStorage').addEventListener('click', function () {
    if (!confirm('确认清空全部本地扫描结果？此操作不可撤销。')) return;
    chrome.storage.local.clear(function () {
      loadAll();
      alert('已清理');
    });
  });

  loadAll();
});
