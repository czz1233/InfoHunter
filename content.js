/**
 * InfoHunter - content script（隔离世界）
 *
 * 职责：
 *   1. 从页面 HTML 中抽取 href / src / data-* 等资源地址，交给 background 二次抓取
 *   2. 探测页面级 sourceMappingURL 注释
 *   3. 把 MAIN world 的 framework-analyze.js 回传的框架数据转发给 background
 *   4. 可选：渲染页面内悬浮结果面板
 *
 * 相对旧版实现的修复：
 *   - [FIX] settingSafeMode 异步读取却同步使用导致的竞态（改为一次性加载并缓存）
 *   - [FIX] tmp_target_list.pop(href) —— pop() 不接受参数，本意是剔除当前页 URL
 *   - [FIX] substring(6,...) / substring(5,...) 硬编码偏移，遇 data-href / 带空格等号即错位
 *   - [FIX] 悬浮面板 sleep(100) 未 await 导致 get_info() 高频递归，CPU 打满
 *   - [FIX] window.onresize = ... 覆盖宿主页面原有 handler
 *   - [FIX] 白名单 host.endsWith(rule) 裸后缀匹配：`.a.com` 匹配不到 `a.com`，
 *           完整 URL / 通配符 / 大小写全部失效，且 `a.com` 会误杀 `nota.com`
 *   - [FIX] 白名单只拦 find，framework 路由与全局配置回传完全绕过白名单
 *   - [FIX] 白名单改动后必须刷新页面才生效（settingsPromise 永久缓存）
 */
(function () {
  'use strict';

  var SETTINGS_DEFAULTS = {
    settingSafeMode: true,
    allowlist: [],
    resource_blocklist: [],
    use_default_allowlist: true,
    enable_framework: true,
    enable_runtime: true,
    enable_spa_rescan: true,
    global_float: false
  };

  /** 条目键统一去掉 #hash：hash 路由的 SPA 每次导航都变 href，但文档没变 ——
   *  数据必须合并进同一条目，按 hash 分桶会让徽标与 popup 各说各话。 */
  function pageKey(u) {
    var s = String(u || location.href);
    var h = s.indexOf('#');
    return h > -1 ? s.slice(0, h) : s;
  }

  // 名单匹配器抽到 src/utils/hostmatch.js（content 与 background 共用）
  // 防御：hostmatch.js 因扩展缓存了旧 manifest 而未注入时，不再让整份 content script 硬崩，
  // 降级为「不做任何名单过滤 + 控制台报错」，抓取主流程照常工作。
  var HM = globalThis.IHHostMatch;
  if (!HM) {
    // eslint-disable-next-line no-console
    console.error('[InfoHunter] hostmatch.js 未注入（manifest 应在 content.js 之前加载它）。' +
      '请到 chrome://extensions 点击重新加载扩展，并刷新已打开的标签页。本次页面将不做白名单过滤。');
  }
  var hostOfUrl = HM ? HM.hostOfUrl : function (u) {
    try { return new URL(u).host || ''; } catch (e) { return ''; }
  };
  var isWhitelisted = HM ? HM.hostMatches : function () { return false; };
  var effectiveList = HM ? HM.effectiveList : function (s) { return (s && s.allowlist) || []; };
  var isBlockedResource = HM ? HM.isBlockedResource : function () { return false; };


  // 需要抽取的属性。meta 的 content、a 的 title 之类一律不收，避免噪声爆炸。
  var ATTR_NAMES = 'href|src|data-src|data-href|data-original|data-url|data-main|action|formaction';
  var ATTR_RE = new RegExp('\\b(?:' + ATTR_NAMES + ')\\s*=\\s*(["\'])(.*?)\\1', 'gi');
  var SCRIPT_SRC_RE = /<script\b[^>]*\bsrc\s*=\s*(["'])(.*?)\1/gi;
  var SOURCEMAP_RE = /sourceMappingURL\s*=\s*(\S+)/gi;

  var settingsPromise = null;
  var blocked = false;   // 当前 host 是否被白名单拦下

  // ------------------------------------------------------------ 设置加载

  function loadSettings() {
    if (settingsPromise) return settingsPromise;
    settingsPromise = new Promise(function (resolve) {
      if (!chrome.runtime || !chrome.runtime.id) {
        resolve(Object.assign({}, SETTINGS_DEFAULTS));
        return;
      }
      try {
        chrome.storage.local.get(SETTINGS_DEFAULTS, function (s) {
          resolve(s || {});
        });
      } catch (e) {
        resolve(Object.assign({}, SETTINGS_DEFAULTS));
      }
    });
    return settingsPromise;
  }

  /** 设置被改动后丢弃缓存，下一帧生效，不必刷新页面 */
  function invalidateSettings() { settingsPromise = null; }

  try {
    if (chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener(function (changes, area) {
        if (area !== 'local') return;
        invalidateSettings();
        loadSettings().then(function (s) {
          var nowBlocked = isWhitelisted(location.host, effectiveList(s));
          // 从「允许」变成「拦截」时，把已经挂上去的悬浮面板摘掉
          if (nowBlocked && !blocked) removeFloatPanel();
          blocked = nowBlocked;
        });
      });
    }
  } catch (e) { /* 扩展上下文已失效 */ }

  // ------------------------------------------------------------ URL 处理

  /** 用 URL 构造器做解析，取代原先手写的 substring 偏移逻辑 */
  function resolveUrl(raw, base) {
    if (!raw) return null;
    var v = String(raw).trim().replace(/^[\s"']+|[\s"']+$/g, '');
    if (!v) return null;
    if (/^(javascript|data|mailto|tel|about|chrome-extension|blob):/i.test(v)) return null;
    try {
      return new URL(v, base).href;
    } catch (e) {
      return null;
    }
  }

  function looksLikeScript(urlStr) {
    try {
      var p = new URL(urlStr).pathname.toLowerCase();
      p = p.replace(/[?#].*$/, '');
      return /\.(js|mjs|cjs|jsx|ts|tsx)$/.test(p);
    } catch (e) {
      return false;
    }
  }

  // ------------------------------------------------------------ 抽取

  function extractAttrs(html) {
    var out = [];
    var m;
    ATTR_RE.lastIndex = 0;
    while ((m = ATTR_RE.exec(html)) !== null) out.push(m[2]);
    return out;
  }

  function extractScriptSrcs(html) {
    var out = [];
    var m;
    SCRIPT_SRC_RE.lastIndex = 0;
    while ((m = SCRIPT_SRC_RE.exec(html)) !== null) out.push(m[2]);
    return out;
  }

  function extractSourceMaps(html) {
    var out = [];
    var m;
    SOURCEMAP_RE.lastIndex = 0;
    while ((m = SOURCEMAP_RE.exec(html)) !== null) {
      var v = m[1].replace(/^["']|["']$/g, '');
      if (v && v.indexOf('data:') !== 0) out.push(v);
    }
    return out;
  }

  // ------------------------------------------------------------ 白名单
  //
  // 旧实现是 `host === w || host.endsWith(w)` 的裸串后缀匹配，两类问题都很致命：
  //   漏拦 —— `.example.com` 匹配不到 `example.com` 本身；
  //           `https://www.example.com/`、`*.example.com`、`WWW.Example.com` 一律失效。
  //   误拦 —— `example.com` 会把 `notexample.com` 一起拦掉。
  // 现在统一走「归一化成 host[:port] → 精确匹配 or 子域匹配」两条路径。

  function dedupe(arr) {
    var seen = Object.create(null);
    var out = [];
    for (var i = 0; i < arr.length; i++) {
      if (!arr[i] || seen[arr[i]]) continue;
      seen[arr[i]] = 1;
      out.push(arr[i]);
    }
    return out;
  }

  /** 收集当前文档的资源地址 */
  function collectTargets(html, baseHref, s) {
    var safeMode = s.settingSafeMode !== false;
    var rawAttrs = extractAttrs(html);
    var scriptSrcs = extractScriptSrcs(html);
    // <script src> 上的地址即使不带 .js 后缀也一定是脚本，纳入白名单判断
    var confirmedScripts = Object.create(null);
    for (var s = 0; s < scriptSrcs.length; s++) confirmedScripts[scriptSrcs[s]] = true;

    var baseHost = hostOfUrl(baseHref);
    var targets = [];
    for (var i = 0; i < rawAttrs.length; i++) {
      var raw = rawAttrs[i];
      var abs = resolveUrl(raw, baseHref);
      if (!abs) continue;
      if (safeMode && !looksLikeScript(abs) && !confirmedScripts[raw]) continue;
      if (isBlockedResource(abs, baseHost, s)) continue;
      targets.push(abs);
    }

    targets = dedupe(targets);

    // [FIX] 原来写成 pop(href)，pop 不接受参数，实际删掉的是最后一个元素
    var self = baseHref.split('#')[0];
    targets = targets.filter(function (u) { return u.split('#')[0] !== self; });

    return targets;
  }

  // ------------------------------------------------------------ 主流程

  function scanDocument(html, baseHref, s) {
    // 按「被扫描文档的 host」判断，而不是顶层 location.host —— 第三方 iframe 也要能拦
    if (isWhitelisted(hostOfUrl(baseHref) || location.host, effectiveList(s))) return;

    var targets = collectTargets(html, baseHref, s);
    var maps = extractSourceMaps(html).map(function (m) {
      return resolveUrl(m, baseHref);
    }).filter(Boolean);

    send({
      greeting: 'find',
      data: targets,
      current: pageKey(baseHref),
      source: html,
      sourcemaps: dedupe(maps)
    });
  }

  function send(msg) {
    try {
      if (!chrome.runtime || !chrome.runtime.id) return;
      chrome.runtime.sendMessage(msg, function () {
        // 吞掉 "Receiving end does not exist"，SW 冷启动时属正常
        if (chrome.runtime.lastError) { /* noop */ }
      });
    } catch (e) { /* 扩展上下文已失效 */ }
  }

  function boot() {
    loadSettings().then(function (s) {
      // 白名单命中的页面整体停摆：不扫描、不转发框架数据、不挂悬浮窗
      blocked = isWhitelisted(location.host, effectiveList(s));
      if (blocked) {
        removeFloatPanel();
        return;
      }

      var html = document.documentElement.outerHTML;
      scanDocument(html, location.href, s);

      // 同源 iframe 才读得到 contentDocument，跨域直接跳过
      var iframes = document.querySelectorAll('iframe');
      for (var i = 0; i < iframes.length; i++) {
        /* jshint loopfunc: true */
        (function (frame) {
          frame.addEventListener('load', function () {
            try {
              var doc = frame.contentDocument || (frame.contentWindow && frame.contentWindow.document);
              if (!doc || !doc.documentElement) return;
              // [FIX] base 用 iframe 自己的 URL，原来写成 location.href，
              //       相对地址会解析到顶层域，第三方 iframe 的资源被算到当前站点头上
              var frameUrl = '';
              try { frameUrl = frame.contentWindow.location.href; } catch (e) { /* 跨域 */ }
              scanDocument(doc.documentElement.outerHTML, frameUrl || frame.src || location.href, s);
            } catch (e) { /* 跨域 iframe，忽略 */ }
          });
        })(iframes[i]);
      }

      if (s.enable_spa_rescan !== false) watchSpaInsertions(s);

      if (s.global_float === true) renderFloatPanel();
    });
  }

  // ------------------------------------------------------------ SPA 增量补扫
  //
  // 首屏扫完就结束的话，SPA 路由切换后懒加载进来的 chunk 全部漏掉。
  // 这里只盯「新插入的 <script src>」，不重复扫整棵 DOM：
  //   - 用 Set 记已见过的地址，重复插入不会重复上报
  //   - 节流 1.5 秒，路由切换时一堆节点连续插入也只触发一次
  //   - 3 分钟后断开，避免长期挂在页面上

  var SPA_MAX_MS = 180000;
  var SPA_DEBOUNCE_MS = 1500;

  function watchSpaInsertions(s) {
    if (typeof MutationObserver !== 'function') return;

    var seen = Object.create(null);
    var pending = [];
    var debounce = null;

    function flush() {
      debounce = null;
      if (blocked || !pending.length) { pending.length = 0; return; }
      var batch = pending.slice();
      pending.length = 0;
      send({
        greeting: 'spa',
        current: pageKey(),
        data: batch
      });
    }

    var observer = new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var nodes = records[i].addedNodes;
        if (!nodes || !nodes.length) continue;
        for (var j = 0; j < nodes.length; j++) {
          var n = nodes[j];
          if (!n || n.nodeType !== 1) continue;
          var src = (n.tagName === 'SCRIPT') ? n.getAttribute('src')
            : (n.getAttribute && n.getAttribute('src'));
          if (!src) continue;
          var abs = resolveUrl(src, location.href);
          if (!abs || seen[abs]) continue;
          seen[abs] = true;
          pending.push(abs);
        }
      }
      if (pending.length && !debounce) {
        debounce = setTimeout(flush, SPA_DEBOUNCE_MS);
      }
    });

    try {
      observer.observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) { return; }
    setTimeout(function () { observer.disconnect(); }, SPA_MAX_MS);
  }

  // ------------------------------------------------------------ 框架数据转发
  //
  // MAIN world 的 framework-analyze.js 由 manifest 静态注册，无法在运行时注销，
  // 因此开关放在隔离世界这一侧：关闭时直接不转发，数据就不会进入结果集。

  // 白名单判断在这里必须再做一次：旧代码只在 scanDocument 里判，
  // 白名单站点上的 Vue / Next / Nuxt 路由表与全局配置照样被回传，白名单等于半失效。

  // MAIN world 的回传统一走这里，白名单只在这一处判断，避免漏掉某条通路
  window.addEventListener('message', function (ev) {
    if (!ev || ev.source !== window || !ev.data) return;

    var type = ev.data.type;
    if (type !== '__FS_FRAMEWORK_DATA__' && type !== '__IH_RUNTIME__') return;

    var isFramework = (type === '__FS_FRAMEWORK_DATA__');
    var settingKey = isFramework ? 'enable_framework' : 'enable_runtime';

    // MAIN world 脚本在 document_start 注入，消息可能早于设置读取完成。
    // 每次都重新走一次（已缓存的）loadSettings，避免竞态下白名单被绕过。
    loadSettings().then(function (s) {
      if (s[settingKey] === false) return;
      if (blocked || isWhitelisted(location.host, effectiveList(s))) return;
      send({
        greeting: isFramework ? 'framework' : 'runtime',
        current: pageKey(),
        payload: ev.data.payload
      });
    });
  });

  // ------------------------------------------------------------ 悬浮面板

  var FLOAT_POLL_MS = 400;
  var FLOAT_MAX_POLL = 150; // 约 60 秒后停止，避免无限轮询

  function removeFloatPanel() {
    var el = document.getElementById('infohunter-float-div');
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  function renderFloatPanel() {
    if (blocked) return;
    if (document.getElementById('infohunter-float-div')) return;

    var host = document.documentElement;
    var wrap = document.createElement('div');
    wrap.setAttribute('id', 'infohunter-float-div');

    var cats = (window.FS_CATEGORIES || []).map(function (c) {
      return '<fs-div class="fs-title">' + c.label +
        '<button type="button" class="fs_copy" data-fs-key="' + c.key + '">复制</button></fs-div>' +
        '<fs-p id="infohunter_' + c.key + '" class="fs-body">🈚️</fs-p>';
    }).join('');

    wrap.innerHTML =
      '<fs-div id="fs_panel">' +
        '<fs-div id="fs_titlebar">' +
          '<span id="infohunter_taskstatus">等待数据…</span>' +
          '<span id="fs_hide">隐藏</span>' +
        '</fs-div>' +
        '<fs-div id="fs_searchwrap">' +
          '<input id="fs_search" type="text" placeholder="过滤结果…" />' +
          '<button type="button" id="fs_close">×</button>' +
        '</fs-div>' +
        '<fs-div id="fs_content">' + cats + '</fs-div>' +
      '</fs-div>' +
      '<style>' +
        /* 配色走变量：跟随系统暗色模式，避免页面夜间浏览时浮窗白块刺眼 */
        '#fs_panel{--fsbg:#fff;--fsfg:#111;--fsmut:#6b7280;--fsline:#e5e7eb;--fsbar:#f6f7f9;' +
          '--fssoft:#374151;--fsacc:#2563eb;--fsmono:ui-monospace,Menlo,Consolas,monospace;' +
          'position:fixed;right:12px;top:56px;width:420px;max-height:520px;overflow:auto;' +
          'z-index:2147483646;background:var(--fsbg);color:var(--fsfg);font:13px/1.5 system-ui,sans-serif;' +
          'border:1px solid var(--fsline);border-radius:12px;box-shadow:0 8px 28px rgba(0,0,0,.14)}' +
        '@media (prefers-color-scheme:dark){' +
          '#fs_panel{--fsbg:#1c2128;--fsfg:#e6edf3;--fsmut:#8b949e;--fsline:#30363d;--fsbar:#161b22;--fssoft:#c9d1d9;' +
            '--fsacc:#3b82f6;border-color:#30363d;box-shadow:0 8px 28px rgba(0,0,0,.5)}}' +
        '#fs_titlebar{display:flex;justify-content:space-between;align-items:center;padding:0 12px;' +
          'height:36px;line-height:36px;cursor:move;background:var(--fsbar);border-bottom:1px solid var(--fsline);' +
          'font-weight:600;user-select:none;border-radius:12px 12px 0 0}' +
        '#fs_hide,#fs_close{cursor:pointer;color:var(--fsmut);padding:0 4px;border-radius:4px}' +
        '#fs_hide:hover,#fs_close:hover{color:var(--fsfg)}' +
        '#fs_searchwrap{display:flex;gap:6px;padding:8px 10px;border-bottom:1px solid var(--fsline)}' +
        '#fs_search{flex:1;padding:5px 8px;border:1px solid var(--fsline);border-radius:7px;font-size:12px;' +
          'background:var(--fsbg);color:var(--fsfg);outline:none}' +
        '#fs_search:focus{border-color:var(--fsacc)}' +
        '.fs-title{font-weight:600;border-left:3px solid var(--fsacc);padding-left:7px;margin:10px 0 2px 10px;font-size:13px}' +
        '.fs-body{margin:0 0 6px 14px;white-space:pre-wrap;word-break:break-all;color:var(--fssoft);font-size:12px;font-family:var(--fsmono);max-height:170px;overflow:auto}' +
        '.fs_copy{float:right;margin-right:8px;border:none;background:transparent;cursor:pointer;font-size:12px;color:var(--fsmut);border-radius:4px;padding:0 5px}' +
        '.fs_copy:hover{color:var(--fsacc)}' +
        'fs-div,fs-p{display:block}' +
      '</style>';

    host.appendChild(wrap);

    var panel = wrap.querySelector('#fs_panel');

    wrap.querySelector('#fs_hide').onclick = function () { wrap.remove(); };
    wrap.querySelector('#fs_close').onclick = function () { wrap.remove(); };

    var searchInput = wrap.querySelector('#fs_search');
    searchInput.addEventListener('input', function () { applyFilter(wrap, searchInput.value); });

    setupDrag(wrap, panel);
    setupEdgeSnap(wrap, panel);
    pollFloat(wrap, 0);
  }

  function applyFilter(wrap, kw) {
    var k = (kw || '').trim().toLowerCase();
    var bodies = wrap.querySelectorAll('.fs-body');
    for (var i = 0; i < bodies.length; i++) {
      var el = bodies[i];
      var title = el.previousElementSibling;
      var text = el.textContent || '';
      if (!k) {
        el.style.display = '';
        if (title) title.style.display = '';
        continue;
      }
      var lines = text.split('\n').filter(function (l) { return l.toLowerCase().indexOf(k) > -1; });
      if (!lines.length) {
        el.style.display = 'none';
        if (title) title.style.display = 'none';
      } else {
        el.style.display = '';
        if (title) title.style.display = '';
        el.dataset.fsRaw = text;
        el.textContent = lines.join('\n');
      }
    }
  }

  /** [FIX] 原来 sleep(100) 未 await，get_info() 在回调里同步递归，等于死循环 */
  function pollFloat(wrap, attempt) {
    if (!document.body || !wrap.isConnected) return;
    if (attempt >= FLOAT_MAX_POLL) return;

    try {
      chrome.runtime.sendMessage({ greeting: 'get', current: pageKey() }, function (d) {
        if (chrome.runtime.lastError) { /* SW 未就绪 */ }
        if (d) {
          paintFloat(wrap, d);
          var status = wrap.querySelector('#infohunter_taskstatus');
          if (status) {
            var done = d.donetasklist ? d.donetasklist.length : 0;
            var total = d.tasklist ? d.tasklist.length : 0;
            status.textContent = d.done === 'done' ? ('完成 ' + done + '/' + total) : ('处理中 ' + done + '/' + total);
          }
          if (d.done === 'done' && d.donetasklist && d.tasklist &&
              d.donetasklist.length === d.tasklist.length) {
            return; // 已完成，停止轮询
          }
        }
        setTimeout(function () { pollFloat(wrap, attempt + 1); }, FLOAT_POLL_MS);
      });
    } catch (e) {
      setTimeout(function () { pollFloat(wrap, attempt + 1); }, FLOAT_POLL_MS);
    }
  }

  function paintFloat(wrap, d) {
    var cats = window.FS_CATEGORIES || [];
    for (var i = 0; i < cats.length; i++) {
      var key = cats[i].key;
      var el = wrap.querySelector('#infohunter_' + key);
      if (!el) continue;
      var raw = el.dataset.fsRaw;
      var v = d[key];
      if (Array.isArray(v) && v.length) {
        el.textContent = v.join('\n');
      } else if (typeof v === 'string' && v) {
        el.textContent = v;
      } else if (!el.textContent || el.textContent === '🈚️') {
        el.textContent = '🈚️';
      }
      if (raw) el.dataset.fsRaw = raw;
    }
  }

  function setupDrag(wrap, panel) {
    var bar = wrap.querySelector('#fs_titlebar');
    if (!bar) return;
    var dragging = false, ox = 0, oy = 0;
    bar.addEventListener('mousedown', function (e) {
      dragging = true;
      ox = e.clientX - panel.offsetLeft;
      oy = e.clientY - panel.offsetTop;
      panel.style.right = 'auto';
      e.preventDefault();
    });
    document.addEventListener('mousemove', function (e) {
      if (!dragging) return;
      panel.style.left = Math.max(0, Math.min(window.innerWidth - 60, e.clientX - ox)) + 'px';
      panel.style.top = Math.max(0, Math.min(window.innerHeight - 30, e.clientY - oy)) + 'px';
    });
    document.addEventListener('mouseup', function () { dragging = false; });
  }

  /** [FIX] 用 addEventListener 取代 window.onresize = ...，不覆盖宿主页面 handler */
  function setupEdgeSnap(wrap, panel) {
    window.addEventListener('resize', function () {
      if (parseInt(panel.style.left, 10) > window.innerWidth - 80) {
        panel.style.left = Math.max(0, window.innerWidth - 440) + 'px';
      }
      if (parseInt(panel.style.top, 10) > window.innerHeight - 40) {
        panel.style.top = Math.max(0, window.innerHeight - 120) + 'px';
      }
    });
  }

  // ------------------------------------------------------------ 启动

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
