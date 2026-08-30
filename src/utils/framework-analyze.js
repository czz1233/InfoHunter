/**
 * InfoHunter - 框架运行时分析（MAIN world）
 *
 * 以 world: "MAIN" 注入，直接读取页面 JS 运行时上下文，抓取「静态正则扫不到」的东西：
 *   - Vue 2 / Vue 3 + vue-router 的完整路由表（含 children、alias、动态段、懒加载组件）
 *   - Next.js Pages Router（__NEXT_DATA__）与 App Router（RSC flight 流）
 *   - Nuxt 2 / Nuxt 3 路由与运行时配置
 *   - React Router（经 React fiber 树回溯）
 *   - webpack / vite 分包 chunk 清单（用于后续抓取惰性 chunk）
 *   - 全局配置对象（常见 API base、环境变量、后端地址泄露点）
 *
 * 结果通过 window.postMessage 回传给隔离世界的 content.js。
 *
 * 注意事项：
 *   1. 本文件运行在页面主世界，任何异常都可能影响宿主页面 —— 所有逻辑必须包裹 try/catch。
 *   2. 所有主动触发网络请求的行为（加载懒加载组件、抓取 chunk 清单）默认关闭，
 *      仅在 content.js 显式下发 { aggressive: true } 时执行。
 *   3. 载荷大小硬上限 200KB，超出即截断，避免拖垮消息通道。
 */
(function () {
  'use strict';

  var MESSAGE_TYPE = '__FS_FRAMEWORK_DATA__';
  var MAX_PAYLOAD = 200 * 1024;
  var MAX_ROUTES = 800;
  var MAX_COMPONENTS = 60;
  var MAX_GLOBALS = 40;
  var SEQ = 0;

  // ------------------------------------------------------------------ 工具

  function safe(fn, fallback) {
    try {
      var r = fn();
      return r === undefined ? fallback : r;
    } catch (e) {
      return fallback;
    }
  }

  function trim(str, max) {
    if (typeof str !== 'string') return str;
    return str.length > max ? str.slice(0, max) : str;
  }

  /** 递归展开 vue-router 的 routes 树 */
  function walkRoutes(routes, out, prefix, depth) {
    if (!Array.isArray(routes) || depth > 6) return out;
    for (var i = 0; i < routes.length; i++) {
      if (out.length >= MAX_ROUTES) return out;
      var r = routes[i];
      if (!r) continue;
      var p = r.path || '';
      var full = p;
      if (p && p.charAt(0) !== '/' && prefix) {
        full = prefix.replace(/\/$/, '') + '/' + p;
      } else {
        full = p;
      }
      out.push({
        path: trim(String(full), 300),
        name: r.name ? String(r.name) : '',
        redirect: r.redirect ? trim(safe(function () { return JSON.stringify(r.redirect); }, ''), 200) : '',
        alias: r.alias ? trim(safe(function () { return JSON.stringify(r.alias); }, ''), 200) : '',
        meta: r.meta ? trim(safe(function () { return JSON.stringify(r.meta); }, ''), 400) : '',
        props: r.props ? true : false,
        lazy: typeof r.component === 'function' && !r.component.options && !r.component.render,
        component: componentName(r.component),
        depth: depth
      });
      if (r.children && r.children.length) {
        walkRoutes(r.children, out, full, depth + 1);
      }
    }
    return out;
  }

  function componentName(c) {
    if (!c) return '';
    if (typeof c === 'string') return c;
    if (c.name) return String(c.name);
    if (c.__name) return String(c.__name);
    if (c.options && c.options.name) return String(c.options.name);
    if (c.__file) return String(c.__file);
    if (typeof c === 'function') {
      if (c.name) return String(c.name);
      var src = safe(function () { return c.toString().slice(0, 120); }, '');
      var m = src && src.match(/(?:return|=>)\s*(?:import\()?\s*["']([^"']+)["']/);
      if (m) return m[1];
    }
    return '';
  }

  // ------------------------------------------------------------------ Vue

  function findVueRoots() {
    var found = [];
    safe(function () {
      var all = document.querySelectorAll('*');
      for (var i = 0; i < all.length; i++) {
        var el = all[i];
        if (el.__vue_app__) {
          found.push({ version: 3, root: el.__vue_app__, el: el });
        } else if (el.__vue__) {
          found.push({ version: 2, root: el.__vue__, el: el });
        }
      }
    });
    return found;
  }

  function extractVue(roots) {
    var routes = [];
    var meta = { version: 0, routerMode: '', routerCount: 0, storeKeys: [], globalProps: [] };

    for (var i = 0; i < roots.length; i++) {
      var inst = roots[i];
      meta.version = inst.version;

      // Vue 3: config.globalProperties.$router
      var router3 = safe(function () {
        return inst.root && inst.root.config && inst.root.config.globalProperties
          ? inst.root.config.globalProperties.$router : null;
      }, null);

      // Vue 2: $router on the root instance
      var router2 = safe(function () { return inst.root ? inst.root.$router : null; }, null);

      var router = router3 || router2;
      if (!router) continue;

      meta.routerCount++;
      meta.routerMode = safe(function () {
        if (router.options && router.options.mode) return String(router.options.mode);
        if (router.mode) return String(router.mode);
        return '';
      }, '');

      // vue-router 4 提供 getRoutes()，拿到的是扁平化后的完整路由（含未挂载的）
      var flat = safe(function () { return typeof router.getRoutes === 'function' ? router.getRoutes() : null; }, null);
      if (flat && flat.length) {
        for (var f = 0; f < flat.length; f++) {
          if (routes.length >= MAX_ROUTES) break;
          var rr = flat[f];
          routes.push({
            path: trim(String(rr.path || ''), 300),
            name: rr.name ? String(rr.name) : '',
            redirect: '',
            alias: '',
            meta: rr.meta ? trim(safe(function () { return JSON.stringify(rr.meta); }, ''), 400) : '',
            props: false,
            lazy: true,
            component: '',
            depth: 0
          });
        }
      } else {
        // vue-router 3 只有嵌套的 options.routes
        var nested = safe(function () { return router.options && router.options.routes; }, null);
        if (nested) walkRoutes(nested, routes, '', 0);

        // 兜底：从已注册的 matcher 里捞
        var matcherRoutes = safe(function () {
          return router.matcher && router.matcher.getRoutes ? router.matcher.getRoutes() : null;
        }, null);
        if (matcherRoutes && matcherRoutes.length && !routes.length) {
          for (var m = 0; m < matcherRoutes.length; m++) {
            routes.push({
              path: trim(String(matcherRoutes[m].path || ''), 300),
              name: '', redirect: '', alias: '', meta: '', props: false,
              lazy: true, component: '', depth: 0
            });
          }
        }
      }

      // Vuex / Pinia 的 store 顶层模块名，常暴露业务域
      var store = safe(function () {
        if (inst.root && inst.root.config && inst.root.config.globalProperties) {
          return inst.root.config.globalProperties.$store || null;
        }
        return inst.root && inst.root.$store ? inst.root.$store : null;
      }, null);
      var storeKeys = safe(function () {
        if (!store || !store.state) return [];
        return Object.keys(store.state);
      }, []);
      if (storeKeys.length) meta.storeKeys = storeKeys.slice(0, 60);

      var gprops = safe(function () {
        if (inst.root && inst.root.config && inst.root.config.globalProperties) {
          return Object.keys(inst.root.config.globalProperties);
        }
        return [];
      }, []);
      if (gprops.length) meta.globalProps = gprops.slice(0, 60);

      break; // 单个页面通常只有一个根应用
    }
    return { routes: routes, meta: meta };
  }

  // ------------------------------------------------------------------ Next.js

  function extractNext() {
    var out = { detected: false, buildId: '', pages: [], appRouterPaths: [] };
    safe(function () {
      var nd = window.__NEXT_DATA__;
      if (nd) {
        out.detected = true;
        out.buildId = nd.buildId ? String(nd.buildId) : '';
        // buildManifest 里能看到全量页面与所用 chunk
        var pages = safe(function () { return Object.keys(nd.buildManifest ? nd.buildManifest.pages : {}); }, []);
        out.pages = pages.slice(0, MAX_ROUTES).map(function (p) { return trim(String(p), 300); });
      }
    });
    // App Router：RSC 流式负载里埋着路由段
    safe(function () {
      var flight = window.__next_f;
      if (flight && flight.length) {
        out.detected = true;
        var blob = flight.map(function (x) { return typeof x === 'string' ? x : ''; }).join('');
        var re = /\\?"(\/[A-Za-z0-9\-_/{}\[\]().]{1,120})\\?"/g;
        var seen = {};
        var m;
        while ((m = re.exec(blob)) !== null && out.appRouterPaths.length < MAX_ROUTES) {
          var p = m[1];
          if (p.indexOf('/_next') === 0 || /\.(js|css|json|png|svg|ico)$/i.test(p)) continue;
          if (seen[p]) continue;
          seen[p] = 1;
          out.appRouterPaths.push(trim(p, 300));
        }
      }
    });
    return out;
  }

  // ------------------------------------------------------------------ Nuxt

  function extractNuxt() {
    var out = { detected: false, version: '', routes: [] };
    safe(function () {
      var n = window.__NUXT__ || window.__NUXT_DATA__;
      if (!n) return;
      out.detected = true;
      out.version = n.state ? '2/3' : '';
      var routes = safe(function () {
        if (window.$nuxt && window.$nuxt.$router && window.$nuxt.$router.options) {
          return window.$nuxt.$router.options.routes;
        }
        return null;
      }, null);
      if (routes) walkRoutes(routes, out.routes, '', 0);
      var flat = safe(function () {
        return window.$nuxt && window.$nuxt.$router && typeof window.$nuxt.$router.getRoutes === 'function'
          ? window.$nuxt.$router.getRoutes() : null;
      }, null);
      if (flat) {
        for (var i = 0; i < flat.length && out.routes.length < MAX_ROUTES; i++) {
          out.routes.push({
            path: trim(String(flat[i].path || ''), 300), name: flat[i].name ? String(flat[i].name) : '',
            redirect: '', alias: '', meta: '', props: false, lazy: true, component: '', depth: 0
          });
        }
      }
    });
    return out;
  }

  // ------------------------------------------------------------------ React Router

  function extractReactRouter() {
    var out = { detected: false, routes: [] };
    safe(function () {
      // React Router v6 把状态挂在 history / router 上，通常只能在 fiber 里找
      var hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
      var routers = hook && hook.router ? hook.router : null;
      if (routers && routers.routes) {
        out.detected = true;
        walkReactRoutes(routers.routes, out.routes, '');
        return;
      }
      // fallback：从 DOM 上的 react fiber 回溯 RouterProvider
      var fiberKey = Object.keys(document.body || {}).filter(function (k) {
        return k.indexOf('__reactContainer') === 0 || k.indexOf('__reactFiber') === 0;
      })[0];
      if (!fiberKey) return;
      var fiber = document.body[fiberKey];
      var seenRouters = 0;
      while (fiber && seenRouters < 4000) {
        seenRouters++;
        var state = fiber.memoizedState;
        while (state) {
          var val = state.memoizedState || state.baseState;
          if (val && typeof val === 'object') {
            if (val.router && val.router.routes) {
              out.detected = true;
              walkReactRoutes(val.router.routes, out.routes, '');
              return;
            }
            if (Array.isArray(val.routes) && val.routes.length && val.routes[0] && val.routes[0].path !== undefined) {
              out.detected = true;
              walkReactRoutes(val.routes, out.routes, '');
              return;
            }
          }
          state = state.next;
        }
        fiber = fiber.return;
      }
    });
    return out;
  }

  function walkReactRoutes(routes, out, prefix) {
    if (!Array.isArray(routes) || out.length >= MAX_ROUTES) return;
    for (var i = 0; i < routes.length; i++) {
      var r = routes[i];
      if (!r) continue;
      var p = r.path || '';
      var full = p.charAt(0) === '/' ? p : (prefix ? prefix.replace(/\/$/, '') + '/' + p : p);
      out.push({
        path: trim(String(full), 300),
        name: r.id ? String(r.id) : '',
        redirect: '', alias: '',
        meta: r.handle ? trim(safe(function () { return JSON.stringify(r.handle); }, ''), 300) : '',
        props: false, lazy: r.lazy ? true : false,
        component: r.Component ? componentName(r.Component) : '',
        depth: 0
      });
      if (r.children) walkReactRoutes(r.children, out, full);
    }
  }

  // ------------------------------------------------------------------ 分包 chunk

  function extractChunks() {
    var out = { webpack: [], vite: false, runtime: '' };
    safe(function () {
      var keys = Object.keys(window);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k.indexOf('webpackChunk') === 0 && Array.isArray(window[k])) {
          out.runtime = 'webpack';
          var chunks = window[k];
          for (var c = 0; c < chunks.length; c++) {
            var ids = chunks[c][0];
            if (Array.isArray(ids)) {
              for (var d = 0; d < ids.length; d++) out.webpack.push(String(ids[d]));
            } else if (ids !== undefined && ids !== null) {
              out.webpack.push(String(ids));
            }
          }
        }
        if (k === '__vitePreload' || k.indexOf('__vite') === 0) out.vite = true;
      }
      out.webpack = out.webpack.slice(0, 500);
    });
    return out;
  }

  // ------------------------------------------------------------------ 全局配置泄露

  var GLOBAL_HINTS = [
    'config', 'CONFIG', '__CONFIG__', 'AppConfig', 'appConfig', 'ENV', 'env',
    'BASE_URL', 'baseUrl', 'API_URL', 'apiUrl', 'VITE_', 'process',
    '__INITIAL_STATE__', '__APP_CONFIG__', 'settings', 'globalConfig'
  ];

  function extractGlobals() {
    var out = [];
    safe(function () {
      var keys = Object.keys(window);
      for (var i = 0; i < keys.length; i++) {
        if (out.length >= MAX_GLOBALS) break;
        var k = keys[i];
        var hit = false;
        for (var h = 0; h < GLOBAL_HINTS.length; h++) {
          if (k === GLOBAL_HINTS[h] || k.indexOf(GLOBAL_HINTS[h]) === 0) { hit = true; break; }
        }
        if (!hit) continue;
        var v = safe(function () { return window[k]; }, null);
        if (v === null || typeof v !== 'object') continue;
        var serialized = safe(function () { return JSON.stringify(v); }, '');
        if (!serialized || serialized.length < 4) continue;
        out.push({ name: k, value: trim(serialized, 2000) });
      }
    });
    return out;
  }

  // ------------------------------------------------------------------ 聚合

  function collect() {
    var vueRoots = findVueRoots();
    var vue = extractVue(vueRoots);
    var next = extractNext();
    var nuxt = extractNuxt();
    var react = extractReactRouter();

    var routes = [].concat(vue.routes, next.pages.map(function (p) {
      return { path: p, name: '', redirect: '', alias: '', meta: '', props: false, lazy: false, component: '', depth: 0 };
    }), next.appRouterPaths.map(function (p) {
      return { path: p, name: '', redirect: '', alias: '', meta: '', props: false, lazy: false, component: '', depth: 0 };
    }), nuxt.routes, react.routes);

    // 去重
    var seen = {};
    var uniq = [];
    for (var i = 0; i < routes.length; i++) {
      var key = routes[i].path + '|' + routes[i].name;
      if (seen[key]) continue;
      seen[key] = 1;
      uniq.push(routes[i]);
    }

    var payload = {
      seq: ++SEQ,
      url: location.href,
      frameworks: {
        vue: vue.meta.version ? { version: vue.meta.version, mode: vue.meta.routerMode, storeKeys: vue.meta.storeKeys, globalProps: vue.meta.globalProps } : null,
        next: next.detected ? { buildId: next.buildId } : null,
        nuxt: nuxt.detected ? { version: nuxt.version } : null,
        reactRouter: react.detected ? {} : null
      },
      routes: uniq.slice(0, MAX_ROUTES),
      chunks: extractChunks(),
      globals: extractGlobals()
    };

    var raw = safe(function () { return JSON.stringify(payload); }, '{}');
    if (raw.length > MAX_PAYLOAD) {
      // 先砍 globals，再砍 routes，保住最有价值的路由表
      payload.globals = [];
      raw = safe(function () { return JSON.stringify(payload); }, '{}');
      if (raw.length > MAX_PAYLOAD) {
        payload.routes = payload.routes.slice(0, Math.floor(payload.routes.length / 3));
        raw = safe(function () { return JSON.stringify(payload); }, '{}');
      }
    }
    return payload;
  }

  function emit(reason) {
    var payload = collect();
    payload.reason = reason || 'init';
    try {
      window.postMessage({ type: MESSAGE_TYPE, payload: payload }, '*');
    } catch (e) { /* 页面冻结了 message 通道，忽略 */ }
  }

  // ------------------------------------------------------------------ 启动

  var debounce = null;
  function schedule(reason, delay) {
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(function () { emit(reason); }, delay || 800);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { schedule('dom-ready', 1200); }, { once: true });
  } else {
    schedule('already-ready', 1200);
  }

  // SPA 路由是异步挂载的，监听 DOM 变化补抓
  var observer = null;
  safe(function () {
    observer = new MutationObserver(function () { schedule('dom-change', 1500); });
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(function () { if (observer) observer.disconnect(); }, 60000);
  });

  // 响应隔离世界的按需请求
  window.addEventListener('message', function (ev) {
    if (!ev || ev.source !== window) return;
    var d = ev.data;
    if (!d || d.type !== '__FS_FRAMEWORK_REQUEST__') return;
    schedule('manual', 0);
  });
})();
