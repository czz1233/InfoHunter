/**
 * InfoHunter - popup 逻辑
 *
 * 相对旧版实现的修复与增强：
 *   [FIX] 结果读取依赖 background 内存态，SW 被回收后 popup 一片空白。
 *         改为直接读 chrome.storage.local 并监听 onChanged，完全不依赖 SW 存活。
 *   [FIX] link.setAttribute("href", source) 把页面可控数据写进 href，存在 javascript: 注入面。
 *         改为纯文本渲染，来源只在 title 提示里展示，不生成任何链接。
 *   [FIX] while((ele = container.firstChild)) 中 ele 未声明，泄漏成全局变量。
 *   [ADD] 分类计数、实时搜索过滤、作用域过滤、来源溯源、四种格式导出。
 */

'use strict';

var CATEGORIES = [
  { key: 'secret',          label: '敏感信息',         group: 'primary' },
  { key: 'jwt',             label: 'JWT',            group: 'primary' },
  { key: 'sfz',             label: '身份证',           group: 'primary' },
  { key: 'mobile',          label: '手机号',           group: 'primary' },
  { key: 'mail',            label: '邮箱',            group: 'primary' },
  { key: 'algorithm',       label: '算法',            group: 'primary' },
  { key: 'api',             label: '接口',            group: 'primary' },
  { key: 'route',           label: '路由',            group: 'primary' },
  { key: 'domain',          label: '域名',            group: 'network' },
  { key: 'ip_port',         label: 'IP加端口',         group: 'network' },
  { key: 'ip',              label: 'IP',             group: 'network' },
  { key: 'url',             label: 'URL',            group: 'network' },
  { key: 'path',            label: 'PATH',           group: 'network' },
  { key: 'incomplete_path', label: 'IncompletePath', group: 'network' },
  { key: 'static',          label: 'StaticPath',     group: 'network' },
  { key: 'sourcemap',       label: 'Sourcemap',      group: 'network' },
  { key: 'request',         label: '真实请求',        group: 'runtime' },
  { key: 'endpoint',        label: '端点',           group: 'runtime' },
  { key: 'storage',         label: '存储键名',        group: 'runtime' },
  { key: 'param',           label: '参数名',          group: 'runtime' }
];

// 分组展示顺序与中文名。runtime 组是 1.0.2 的运行时观测面，单列一组便于一眼看到
var GROUPS = [
  { key: 'primary', label: '主信息' },
  { key: 'network', label: '网络资源' },
  { key: 'runtime', label: '运行时观测' }
];

var state = {
  url: '',
  data: null,
  keyword: '',
  scope: 'all',
  filterCategory: '',
  collapsed: {}
};

// ------------------------------------------------------------------ 工具

function $(id) { return document.getElementById(id); }

function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function copyText(text) {
  if (!text) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function () { fallbackCopy(text); });
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) { /* 忽略 */ }
  ta.remove();
}

function download(filename, content, mime) {
  var blob = new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(function () {
    URL.revokeObjectURL(url);
    a.remove();
  }, 1000);
}

function hostOf(u) {
  try { return new URL(u).host; } catch (e) { return ''; }
}

function ts() {
  var d = new Date();
  function p(n) { return n < 10 ? '0' + n : '' + n; }
  return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}

// ------------------------------------------------------------------ 过滤

function matchScope(key, value, data) {
  if (state.scope === 'all') return true;
  if (state.scope === 'route') return key === 'route';

  var src = (data.source && data.source[value]) || '';

  if (state.scope === 'js') {
    // 来源是 JS / map / 框架运行时，而不是页面 HTML 本身
    return !!src && src !== data.current;
  }
  if (state.scope === 'self') {
    var host = hostOf(state.url);
    if (key === 'route' || key === 'path' || key === 'incomplete_path' || key === 'algorithm') return true;
    if (!host) return true;
    if (value.indexOf(host) > -1) return true;
    return !!(src && hostOf(src) === host);
  }
  return true;
}

function filterItems(key, data) {
  var raw = data[key];
  if (!raw || !raw.length) return [];
  if (state.filterCategory && state.filterCategory !== key) return [];
  var kw = state.keyword.trim().toLowerCase();
  var out = [];
  for (var i = 0; i < raw.length; i++) {
    var v = raw[i];
    if (kw && String(v).toLowerCase().indexOf(kw) === -1) continue;
    if (!matchScope(key, v, data)) continue;
    out.push(v);
  }
  return out;
}

// ------------------------------------------------------------------ 渲染

function renderSummary(data) {
  var box = $('summary');
  box.textContent = '';

  var byGroup = {};
  GROUPS.forEach(function (g) { byGroup[g.key] = []; });

  var total = 0;
  for (var i = 0; i < CATEGORIES.length; i++) {
    var c = CATEGORIES[i];
    var items = filterItems(c.key, data);
    total += items.length;
    if (!items.length) continue;
    (byGroup[c.group] || byGroup.network).push({ cat: c, count: items.length });
  }

  function buildGroup(groupDef, list) {
    if (!list.length) return;
    var g = el('div', 'sum-group');
    g.appendChild(el('span', 'sum-tag', groupDef.label));
    for (var j = 0; j < list.length; j++) {
      (function (c, n) {
        var chip = el('span', 'chip' + (state.filterCategory === c.key ? ' active' : ''));
        chip.appendChild(el('b', null, String(n)));
        chip.appendChild(document.createTextNode(' ' + c.label));
        chip.title = '点击只看 ' + c.label;
        chip.addEventListener('click', function () {
          state.filterCategory = state.filterCategory === c.key ? '' : c.key;
          if (state.data) render(state.data);
        });
        g.appendChild(chip);
      })(list[j].cat, list[j].count);
    }
    box.appendChild(g);
  }

  var first = true;
  GROUPS.forEach(function (gd) {
    if (!byGroup[gd.key] || !byGroup[gd.key].length) return;
    if (!first) box.appendChild(el('div', 'sum-sep'));
    first = false;
    buildGroup(gd, byGroup[gd.key]);
  });

  var sum = el('div', 'sum-total');
  sum.appendChild(el('b', null, String(total)));
  sum.appendChild(document.createTextNode(' 命中'));
  if (state.filterCategory) {
    sum.title = '点击清除筛选';
    sum.style.cursor = 'pointer';
    sum.addEventListener('click', function () {
      state.filterCategory = '';
      if (state.data) render(state.data);
    });
  }
  box.appendChild(sum);

  // 关键词 / 作用域 / 分类筛选把结果全滤没时，给一句明确解释，避免像「没数据」
  if (!total && (state.keyword.trim() || state.scope !== 'all' || state.filterCategory)) {
    var nf = el('span', 'sum-tag', '当前筛选条件下无命中 —— 调整关键词或作用域试试');
    nf.style.fontSize = '12px';
    box.insertBefore(nf, sum);
  }
}

function renderFramework(data) {
  var box = $('framework');
  box.textContent = '';
  var fw = data.framework;
  if (!fw) { box.className = 'collapsed'; return; }

  var names = [];
  var f = fw.frameworks || {};
  if (f.vue) names.push('Vue ' + (f.vue.version === 3 ? '3' : '2') + (f.vue.mode ? ' (' + f.vue.mode + ')' : ''));
  if (f.next) names.push('Next.js' + (f.next.buildId ? ' #' + f.next.buildId : ''));
  if (f.nuxt) names.push('Nuxt');
  if (f.reactRouter) names.push('React Router');
  if (!names.length && !fw.chunks) { box.className = 'collapsed'; return; }

  var parts = [];
  if (names.length) parts.push('框架：' + names.join(' / '));
  if (fw.chunks) {
    if (fw.chunks.runtime) parts.push('打包器：' + fw.chunks.runtime);
    if (fw.chunks.webpack && fw.chunks.webpack.length) parts.push('chunk：' + fw.chunks.webpack.length + ' 个');
    if (fw.chunks.vite) parts.push('Vite：是');
  }
  if (f.vue && f.vue.storeKeys && f.vue.storeKeys.length) {
    parts.push('store：' + f.vue.storeKeys.slice(0, 12).join(', '));
  }
  box.textContent = parts.join('　|　');
  box.className = '';
}

function renderGroup(c, data, container) {
  var items = filterItems(c.key, data);

  // 零命中的分类整组不渲染：20 个分类里通常大半是 0，全铺开全是 🈚️ 噪声，
  // 总量在顶部 summary 的 chip 上一眼可见
  if (!items.length) return;

  var group = el('div', 'group');

  var title = el('div', 'gtitle');
  title.appendChild(document.createTextNode(c.label));

  var cnt = el('span', 'count' + (items.length ? '' : ' zero'), String(items.length));
  title.appendChild(cnt);

  var copy = el('span', 'gact', '复制');
  copy.title = '复制该分类的全部结果';
  copy.addEventListener('click', function (e) {
    e.stopPropagation();
    copyText(items.join('\n'));
    copy.textContent = '已复制';
    setTimeout(function () { copy.textContent = '复制'; }, 1200);
  });
  title.appendChild(copy);

  // 有 URL 语义的分类额外给一个「复制为绝对 URL」
  if (c.key === 'path' || c.key === 'incomplete_path') {
    var copyUrl = el('span', 'gact', '复制URL');
    copyUrl.title = '拼成绝对 URL 后复制';
    copyUrl.addEventListener('click', function (e) {
      e.stopPropagation();
      var origin;
      try { origin = new URL(state.url).origin; } catch (err) { origin = ''; }
      copyText(items.map(function (p) {
        if (String(p).charAt(0) === '.') return origin + '/' + p;
        return origin + p;
      }).join('\n'));
      copyUrl.textContent = '已复制';
      setTimeout(function () { copyUrl.textContent = '复制URL'; }, 1200);
    });
    title.appendChild(copyUrl);
  }

  title.addEventListener('click', function () {
    state.collapsed[c.key] = !state.collapsed[c.key];
    body.className = state.collapsed[c.key] ? 'gbody collapsed' : 'gbody';
  });

  var body = el('div', 'gbody' + (state.collapsed[c.key] ? ' collapsed' : ''));

  if (!items.length) {
    body.appendChild(el('div', 'empty', '🈚️'));
  } else {
    // 大列表懒渲染：先画前 300 条，滚动到底再补
    var LIMIT = 300;
    var shown = Math.min(items.length, LIMIT);
    for (var i = 0; i < shown; i++) {
      body.appendChild(makeLine(items[i], data));
    }
    if (items.length > shown) {
      var more = el('div', 'empty', '…还有 ' + (items.length - shown) + ' 条，滚动到底部加载');
      body.appendChild(more);
      var observer = new IntersectionObserver(function (entries, obs) {
        if (!entries[0].isIntersecting) return;
        obs.disconnect();
        more.remove();
        for (var j = shown; j < items.length; j++) body.appendChild(makeLine(items[j], data));
      });
      observer.observe(more);
    }
  }

  group.appendChild(title);
  group.appendChild(body);
  container.appendChild(group);
}

function makeLine(value, data) {
  var line = el('div', 'line');
  var text = String(value);

  // 接口语义还原：方法徽标
  var am = data.apiMeta && data.apiMeta[value];
  if (am && am.method) {
    line.appendChild(el('span', 'm-badge m-' + am.method.toLowerCase(), am.method));
  } else {
    // 运行时观测：真实请求的 method（webRequest / fetch 钩子记下来的）
    var rm = data.runtimeMeta && data.runtimeMeta[value];
    if (rm) line.appendChild(el('span', 'm-badge m-' + String(rm).toLowerCase(), rm));
  }

  // 运行时观测：端点类型（ws / sse / worker）
  var em = data.endpointMeta && data.endpointMeta[value];
  if (em) line.appendChild(el('span', 'm-tag', em));

  line.appendChild(document.createTextNode(text));

  // 凭据分类：类型标签（带可信度配色）
  var sm = data.secretMeta && data.secretMeta[value];
  if (sm && sm.type) {
    line.appendChild(el('span', 'm-tag conf-' + (sm.confidence || 'low'), sm.type));
  }

  // JWT：解码标签 + 风险提示
  var jm = data.jwtMeta && data.jwtMeta[value];
  var tips = [];
  if (jm) {
    var jtag = el('span', 'm-tag jwt-tag', (jm.alg || '?') + (jm.hasSignature === false ? ' 无签名' : ''));
    if (jm.risks && jm.risks.length) {
      jtag.className += ' jwt-warn';
      tips.push(jm.risks.join('\n'));
    }
    line.appendChild(jtag);
  }

  // [FIX] 不再把来源写进 href，改用 title 提示，杜绝 javascript: 注入面
  var src = data.source && data.source[value];
  if (src) tips.push('来源：' + src);
  if (tips.length) line.title = tips.join('\n') + '\n点击复制';

  line.addEventListener('click', function () {
    copyText(text);
    var old = line.style.background;
    line.style.background = 'var(--flash)';
    setTimeout(function () { line.style.background = old; }, 400);
  });

  return line;
}

function render(data) {
  if (!data) {
    renderEmpty(state.url);
    return;
  }
  // 动态刷新防乱序：存储落盘与 SW 实时态可能交错到达，旧快照直接丢弃
  var ua = data.updatedAt || 0;
  if (state.data && (state.data.updatedAt || 0) > ua && ua > 0) return;
  document.body.classList.remove('no-data');
  $('empty').style.display = 'none';
  state.data = data;

  // 全量重渲染会重置滚动，刷新前后保持位置（SPA 增量补扫会高频触发这里）
  var scroller = document.scrollingElement || document.body;
  var scrollY = scroller.scrollTop;

  var done = data.donetasklist ? data.donetasklist.length : 0;
  var total = data.tasklist ? data.tasklist.length : 0;
  // 运行时 / SPA 消息单独创建的条目没有任务列表，显示「处理中 0/0」是误导
  $('status').textContent = data.done === 'done'
    ? ('完成 ' + done + '/' + total)
    : (total ? ('处理中 ' + done + '/' + total) : '运行时观测中');

  // 展开按钮的文案随状态走：有折叠的组 → 「展开全部」，否则 → 「折叠全部」
  var anyCollapsed = false;
  for (var c2 = 0; c2 < CATEGORIES.length; c2++) {
    if (state.collapsed[CATEGORIES[c2].key]) { anyCollapsed = true; break; }
  }
  $('btn-expand').textContent = anyCollapsed ? '展开全部' : '折叠全部';

  var primary = $('col-primary');
  var network = $('col-network');
  var runtime = $('col-runtime');
  primary.textContent = '';
  network.textContent = '';
  if (runtime) runtime.textContent = '';

  // 左右两列按命中量动态均衡（贪心：每组放进当前更轻的列）。
  // 固定「主信息=左、网络资源=右」在大站上会出现一侧几千像素、一侧大片留白的断层。
  // 注意：增量记在实际放入的列上，而不是分类的语义分组 —— 否则计数器失真，
  // 从第二组起全部涌进同一列，均衡形同虚设。
  var primLoad = 0, netLoad = 0;
  for (var i = 0; i < CATEGORIES.length; i++) {
    var c = CATEGORIES[i];
    var box;
    if (c.group === 'runtime') {
      box = runtime || network;
    } else {
      var items = filterItems(c.key, data);
      var preferPrimary = (c.group === 'primary') ? (primLoad <= netLoad) : (primLoad < netLoad);
      if (preferPrimary) { box = primary; primLoad += items.length; }
      else { box = network; netLoad += items.length; }
    }
    renderGroup(c, data, box);
  }

  renderSummary(data);
  renderFramework(data);

  scroller.scrollTop = scrollY;
}

/**
 * 空状态不再是干巴巴的空白：说清楚「为什么是空的」。
 * 最常见的困惑是目标站命中白名单被整体跳过 —— 这里直接读共享匹配器给出结论，
 * 而不是让用户去猜。?url= 参数也在这里生效，便于对任意历史结果做排查。
 */
function renderEmpty(url) {
  state.data = null;
  document.body.classList.add('no-data');
  $('status').textContent = '暂无数据';

  var box = $('empty');
  box.style.display = 'block';
  box.textContent = '';

  function fill(why, hint, showSettings) {
    box.appendChild(el('div', 'big', '🛈'));
    box.appendChild(el('div', 'why', why));
    var h = el('div', 'hint');
    h.textContent = hint;
    box.appendChild(h);
    if (showSettings) {
      var b = el('div', 'ebtn', '打开配置页');
      b.addEventListener('click', function () { location.href = 'settings.html'; });
      box.appendChild(b);
    }
  }

  var host = hostOf(url);
  if (!/^https?:/i.test(url) && !/^file:/i.test(url)) {
    fill('该页面类型不支持扫描', 'chrome:// 等浏览器内部页面不在扫描范围内。打开任意 http(s) 页面即可开始。');
    return;
  }

  chrome.storage.local.get(['use_default_allowlist', 'allowlist'], function (s) {
    var whitelisted = false;
    try {
      whitelisted = !!(window.IHHostMatch &&
        window.IHHostMatch.hostMatches(host, window.IHHostMatch.effectiveList(s)));
    } catch (e) { /* 匹配器缺席时按未命中处理 */ }
    if (whitelisted) {
      fill('该站点在白名单内，未被扫描',
        host + ' 命中站点级白名单（内置默认名单或你在配置页添加的条目），扫描引擎会整体跳过它：' +
        '不抓资源、不记请求、不挂浮窗。要扫描它请在配置页把它从名单中移除。', true);
    } else {
      fill('暂无扫描结果',
        '目标页面可能还在扫描中，出结果后这里会自动刷新；也可以刷新目标页面后重新打开本面板。' +
        '若页面含框架懒加载内容，路由切换几次会有更多发现。');
    }
  });
}

// ------------------------------------------------------------------ 导出

function doExport(kind) {
  var data = state.data;
  if (!data) return;
  var name = hostOf(state.url) || 'infohunter';
  var stamp = ts();

  if (kind === 'json') {
    var out = {};
    for (var i = 0; i < CATEGORIES.length; i++) {
      var k = CATEGORIES[i].key;
      out[k] = filterItems(k, data);
    }
    out._meta = { url: state.url, exportedAt: new Date().toISOString(), framework: data.framework || null };
    download(name + '-' + stamp + '.json', JSON.stringify(out, null, 2), 'application/json');
    return;
  }

  if (kind === 'csv') {
    var rows = ['category,value,source'];
    for (var c = 0; c < CATEGORIES.length; c++) {
      var key = CATEGORIES[c].key;
      var items = filterItems(key, data);
      for (var r = 0; r < items.length; r++) {
        var v = String(items[r]);
        var s = (data.source && data.source[items[r]]) || '';
        rows.push([key, '"' + v.replace(/"/g, '""') + '"', '"' + s.replace(/"/g, '""') + '"'].join(','));
      }
    }
    download(name + '-' + stamp + '.csv', rows.join('\n'), 'text/csv;charset=utf-8');
    return;
  }

  if (kind === 'urls') {
    var urls = filterItems('url', data).concat(filterItems('sourcemap', data));
    download(name + '-urls-' + stamp + '.txt', unique(urls).join('\n'));
    return;
  }

  if (kind === 'paths') {
    var paths = filterItems('path', data).concat(filterItems('incomplete_path', data));
    download(name + '-paths-' + stamp + '.txt', unique(paths).join('\n'));
  }
}

function unique(a) {
  var seen = {}, out = [];
  for (var i = 0; i < a.length; i++) {
    if (seen[a[i]]) continue;
    seen[a[i]] = 1;
    out.push(a[i]);
  }
  return out;
}

// ------------------------------------------------------------------ 数据装载

function load() {
  // ?url= 调试参数：直接查看任意页面的落盘结果，不必真的切到那个标签页
  // （例如 popup.html?url=https://target.com/ ）
  var qurl = '';
  try { qurl = new URLSearchParams(location.search).get('url') || ''; } catch (e) { /* 老内核忽略 */ }

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs && tabs[0];
    // 与 content.js 的 pageKey 同一语义：键不含 hash（hash 路由 SPA 的 tab.url 带 #，查不到条目）
    state.url = (qurl || (tab && tab.url) || '').split('#')[0];
    if (!state.url) return;
    var key = 'infohunter_result_' + state.url;

    chrome.storage.local.get([key], function (r) {
      render(r && r[key] ? r[key] : null);
    });

    // SW 还活着的话再要一次最新内存态（可能比落盘更新）
    try {
      chrome.runtime.sendMessage({ greeting: 'get', current: state.url }, function (live) {
        if (chrome.runtime.lastError) return;
        if (live) render(live);
      });
    } catch (e) { /* SW 未就绪，用落盘数据即可 */ }
  });
}

// ------------------------------------------------------------------ 事件

document.addEventListener('DOMContentLoaded', function () {
  var search = $('search');
  search.addEventListener('input', function () {
    state.keyword = search.value;
    if (state.data) render(state.data);
  });

  $('scope').addEventListener('change', function (e) {
    state.scope = e.target.value;
    if (state.data) render(state.data);
  });

  $('export').addEventListener('change', function (e) {
    var v = e.target.value;
    e.target.value = '';
    if (v) doExport(v);
  });

  $('btn-expand').addEventListener('click', function () {
    var anyCollapsed = false;
    for (var i = 0; i < CATEGORIES.length; i++) {
      if (state.collapsed[CATEGORIES[i].key]) { anyCollapsed = true; break; }
    }
    state.collapsed = {};
    if (!anyCollapsed) {
      for (var j = 0; j < CATEGORIES.length; j++) state.collapsed[CATEGORIES[j].key] = true;
    }
    if (state.data) render(state.data);
  });

  // 引擎处理过程中持续把增量落盘，这里跟着刷新即可
  chrome.storage.onChanged.addListener(function (changes, ns) {
    if (ns !== 'local' || !state.url) return;
    var k = 'infohunter_result_' + state.url;
    if (changes[k] && changes[k].newValue) render(changes[k].newValue);
  });

  load();
});
