/**
 * InfoHunter - 运行时钩子（MAIN world，document_start 注入）
 *
 * 静态扫描只能看到「HTML 里写了什么」。这里补的是「浏览器实际做了什么」：
 *   fetch / XHR   → 真实被调用的接口路径 + method
 *   WebSocket     → ws/wss 端点
 *   EventSource   → SSE 端点
 *   Worker        → worker 脚本地址
 *   本地存储      → Web Storage / cookie 的键名与值
 *
 * 全部是**被动记录**：不发起任何请求，只是把页面本来就会做的事记下来。
 * 这是对工具原有「不主动探测」红线的严格补充，不是突破。
 *
 * 注意事项（比 framework-analyze.js 更严格）：
 *   1. 本文件运行在页面主世界，且会替换宿主页面的全局对象。
 *      任何异常都必须就地吞掉，绝不能冒泡到宿主页面 —— 宁可少收一条信息，
 *      也不能把目标站点搞挂。
 *   2. 包装函数必须完整保留原语义：返回值、this、参数一个都不能改。
 *   3. 替换构造函数时要把静态常量一起搬过去，否则页面读 WebSocket.OPEN 会拿到 undefined。
 *   4. 钩子一旦装不上就跳过，不重试。
 */
(function () {
  'use strict';

  var MESSAGE_TYPE = '__IH_RUNTIME__';

  var MAX_CALLS = 300;        // 累计最多记 300 次调用
  var MAX_ENDPOINTS = 80;
  var MAX_STORAGE = 60;       // 存储条目上限
  var VALUE_MAX = 4096;       // 单条存储值的长度上限
  var HOLD_MS = 2000;         // 推送节流
  var MAX_EMIT = 90;          // 最多推 90 次（约 3 分钟），之后收工

  var calls = [];
  var endpoints = [];
  var bodies = [];
  var storage = null;
  var storageDone = false;
  var emitted = 0;
  var timer = null;

  var MAX_BODIES = 30;        // 单页响应体条数上限
  var BODY_MAX = 131072;      // 单个响应体 128KB，超出截断
  var bodySeen = [];          // 轻量去重：轮询接口反复返回同一段内容不重复推

  function safe(fn) {
    try { return fn(); } catch (e) { return null; }
  }

  function push(arr, item, cap) {
    if (arr.length < cap) arr.push(item);
  }

  // ---------------------------------------------------------------- 网络调用

  safe(function () {
    if (typeof window.fetch !== 'function') return;
    var orig = window.fetch;
    window.fetch = function (input, init) {
      safe(function () {
        var u = (typeof input === 'string') ? input : (input && input.url);
        var m = (init && init.method) || 'GET';
        if (u) push(calls, { m: String(m).toUpperCase(), u: String(u) }, MAX_CALLS);
      });
      return orig.apply(this, arguments);
    };
    // 页面偶尔会读 fetch.name / 拿 fetch 去做类型判断，补回去
    safe(function () {
      Object.defineProperty(window.fetch, 'name', { value: 'fetch', configurable: true });
    });
  });

  safe(function () {
    var P = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
    if (!P || typeof P.open !== 'function') return;

    var origOpen = P.open;
    P.open = function (method, url) {
      safe(function () {
        // 挂在实例上，等 send 时再记 —— 这样能拿到最终 URL（open 之后还可能被改）
        this.__ih_call = { m: String(method || '').toUpperCase(), u: String(url || '') };
      });
      return origOpen.apply(this, arguments);
    };

    if (typeof P.send === 'function') {
      var origSend = P.send;
      P.send = function () {
        safe(function () {
          var c = this.__ih_call;
          if (c && c.u) push(calls, { m: c.m, u: c.u }, MAX_CALLS);
        });
        return origSend.apply(this, arguments);
      };
    }
  });

  // ---------------------------------------------------------------- 响应体旁观

  /**
   * 接口返回的 JSON 里往往直接躺着手机号 / 身份证 / 邮箱 / token，但响应体
   * 只有页面读的那一刻才真正进过页面。这里只包「页面自己读响应」这一步：
   * fetch 的 Response.text()/json()、XHR 的 responseText / response。
   * 响应体本来就下载完了，旁观这一步不发起任何请求，仍是被动记录。
   */

  /** 二进制类响应（图片/视频/字体...）没有文本价值，跳过 */
  function isTextualType(ct) {
    if (!ct) return true;                       // 没写 content-type 的当文本试一次
    return !/image\/|video\/|audio\/|font\/|octet-stream|application\/pdf|application\/zip/i.test(String(ct));
  }

  /** 同一 URL 返回同一段内容（前端轮询）只记一次 */
  function sameBody(u, t) {
    var fp = u + '|' + t.length + '|' + t.slice(0, 120);
    if (bodySeen.indexOf(fp) > -1) return true;
    if (bodySeen.length > 120) bodySeen.shift();
    bodySeen.push(fp);
    return false;
  }

  function captureBody(url, ct, toStr) {
    safe(function () {
      if (bodies.length >= MAX_BODIES) return;
      if (!isTextualType(ct)) return;
      var s = toStr();
      if (typeof s !== 'string' || s.length < 8) return;
      if (s.length > BODY_MAX) s = s.slice(0, BODY_MAX);
      if (sameBody(url, s)) return;
      push(bodies, { u: String(url || ''), t: s }, MAX_BODIES);
      schedule();
    });
  }

  safe(function () {
    var RP = window.Response && window.Response.prototype;
    if (!RP || typeof RP.text !== 'function') return;

    // 一个 Response 的流只能被读一次，text/json 不会双计；页面不读就不记
    var origText = RP.text;
    RP.text = function () {
      var resp = this;
      return origText.apply(this, arguments).then(function (txt) {
        safe(function () {
          var ct = null;
          safe(function () { ct = resp.headers && resp.headers.get('content-type'); });
          captureBody(resp.url || '', ct, function () { return txt; });
        });
        return txt;
      });
    };

    var origJson = RP.json;
    RP.json = function () {
      var resp = this;
      return origJson.apply(this, arguments).then(function (obj) {
        safe(function () {
          var ct = null;
          safe(function () { ct = resp.headers && resp.headers.get('content-type'); });
          captureBody(resp.url || '', ct, function () {
            try { return JSON.stringify(obj); } catch (e) { return ''; }
          });
        });
        return obj;
      });
    };
  });

  safe(function () {
    var P = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
    if (!P) return;

    /**
     * 包原型 getter：页面「读」responseText / response 时旁观一眼。
     * onreadystatechange 在 readyState=3 就能读到半截响应体，所以只在
     * DONE 状态记一次；responseType 限文本与 json，二进制类型跳过。
     */
    function wrapGetter(prop, isJsonable) {
      var desc = Object.getOwnPropertyDescriptor(P, prop);
      if (!desc || !desc.get || !desc.configurable) return;
      Object.defineProperty(P, prop, {
        get: function () {
          var v = desc.get.call(this);
          var xhr = this;
          safe(function () {
            if (xhr.__ih_body || xhr.readyState !== 4) return;
            var rt = xhr.responseType;
            if (rt && rt !== 'text' && rt !== 'json') return;      // arraybuffer / blob 不要
            if (typeof v !== 'string' && !(isJsonable && rt === 'json')) return;
            xhr.__ih_body = true;
            captureBody(
              xhr.responseURL || (xhr.__ih_call && xhr.__ih_call.u) || '',
              safe(function () { return xhr.getResponseHeader('content-type'); }),
              function () {
                if (typeof v === 'string') return v;
                try { return JSON.stringify(v); } catch (e) { return ''; }
              }
            );
          });
          return v;
        },
        set: desc.set,
        configurable: true,
        enumerable: !!desc.enumerable
      });
    }
    wrapGetter('responseText', false);
    wrapGetter('response', true);
  });

  // ---------------------------------------------------------------- 端点

  /**
   * 包装构造函数。返回对象会覆盖 new 出来的 this，所以页面拿到的仍是原生实例；
   * 静态常量一并复制，避免 WebSocket.OPEN 之类读成 undefined。
   */
  function wrapCtor(name, kind) {
    safe(function () {
      var Orig = window[name];
      if (typeof Orig !== 'function') return;

      var Wrapped = function (a, b) {
        safe(function () { push(endpoints, { k: kind, u: String(a) }, MAX_ENDPOINTS); });
        try {
          return (arguments.length > 1) ? new Orig(a, b) : new Orig(a);
        } catch (e) {
          return Orig.apply(this, arguments);
        }
      };

      Wrapped.prototype = Orig.prototype;
      safe(function () {
        Object.getOwnPropertyNames(Orig).forEach(function (k) {
          if (k === 'prototype' || k === 'length' || k === 'name' || k === 'caller') return;
          var d = Object.getOwnPropertyDescriptor(Orig, k);
          if (!d || !('value' in d)) return;        // getter/setter 不搬，避免触发副作用
          try { Object.defineProperty(Wrapped, k, d); } catch (e) { /* 只读属性，跳过 */ }
        });
        Object.defineProperty(Wrapped, 'name', { value: name, configurable: true });
      });

      window[name] = Wrapped;
    });
  }

  wrapCtor('WebSocket', 'ws');
  wrapCtor('EventSource', 'sse');
  wrapCtor('Worker', 'worker');
  wrapCtor('SharedWorker', 'worker');

  // ---------------------------------------------------------------- 本地存储

  // 键名本身就是情报（token / userInfo / apiBase 这类），值里可能直接躺着凭据
  function readStorage() {
    if (storageDone) return;
    storageDone = true;
    var out = { keys: [], values: [] };
    var n = 0;

    safe(function () {
      var LS = window.localStorage;
      if (LS) {
        for (var i = 0; i < LS.length && n < MAX_STORAGE; i++) {
          var k = LS.key(i);
          if (k == null) continue;
          out.keys.push('local:' + k);
          var v = safe(function () { return LS.getItem(k); }) || '';
          if (v && v.length <= VALUE_MAX) out.values.push(v);
          n++;
        }
      }
    });
    safe(function () {
      var SS = window.sessionStorage;
      if (SS) {
        for (var i = 0; i < SS.length && n < MAX_STORAGE; i++) {
          var k = SS.key(i);
          if (k == null) continue;
          out.keys.push('session:' + k);
          var v = safe(function () { return SS.getItem(k); }) || '';
          if (v && v.length <= VALUE_MAX) out.values.push(v);
          n++;
        }
      }
    });
    safe(function () {
      var ck = document.cookie;
      if (!ck) return;
      ck.split(';').forEach(function (part) {
        var eq = part.indexOf('=');
        var k = (eq > -1 ? part.slice(0, eq) : part).trim();
        if (k) out.keys.push('cookie:' + k);
      });
    });

    storage = out;
  }

  // ---------------------------------------------------------------- 回传

  function emit() {
    if (emitted >= MAX_EMIT) return;
    if (!calls.length && !endpoints.length && !storage && !bodies.length) return;
    emitted++;

    var payload = {
      calls: calls.slice(),
      endpoints: endpoints.slice(),
      bodies: bodies.slice(),
      storage: storage,
      reason: 'runtime'
    };
    calls.length = 0;
    endpoints.length = 0;
    bodies.length = 0;
    storage = null;               // 存储只推一次，之后不再读

    try {
      window.postMessage({ type: MESSAGE_TYPE, payload: payload }, '*');
    } catch (e) { /* 页面冻结了 message 通道，忽略 */ }
  }

  function schedule() {
    if (timer) return;
    timer = setTimeout(function () { timer = null; emit(); }, HOLD_MS);
  }

  // 页面加载完成后读一次存储，并起一个低频轮询把陆续发生的调用捞回来
  safe(function () {
    var kick = function () {
      readStorage();
      schedule();
      var iv = setInterval(function () {
        if (emitted >= MAX_EMIT) { clearInterval(iv); return; }
        schedule();
      }, HOLD_MS);
      safe(function () { setTimeout(function () { clearInterval(iv); }, 180000); });
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', kick, { once: true });
    } else {
      kick();
    }
  });
})();
