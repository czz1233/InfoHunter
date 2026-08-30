/**
 * InfoHunter - 站点白名单 / 资源黑名单 匹配器
 *
 * 为什么独立成文件：
 *   白名单原先只被 content.js 用到，1.0.2 加了 webRequest 请求记录后，
 *   background 也需要判断「这个站要不要记录」。与其复制一份实现（必然 diverge），
 *   不如抽成共享模块：content 侧走 manifest 的 content_scripts，
 *   background 侧走 importScripts，两边拿到的是同一份代码。
 *
 * 加载方式：
 *   content world  —— manifest.content_scripts 里排在 content.js 之前
 *   service worker —— background.js 的 importScripts
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------- 内置默认名单
  //
  // 分两层，作用点完全不同：
  //
  //   DEFAULT_WHITELIST       站点级 —— 命中的页面整个不扫：不抓资源、不转发框架数据、不挂浮窗。
  //                           放的是「扫了既没意义又容易踩 ToS」的公共互联网平台。
  //
  //   DEFAULT_RESOURCE_BLOCK  资源级 —— 页面照扫，但页面引用到的这些域名的脚本跳过不抓。
  //                           放的是统计/广告/风控/客服/地图/错误监控这类第三方 SDK，
  //                           动辄几百 KB 压缩代码，除了噪声什么都产不出。
  //                           注意：目标自有的 cdn.xxx.com 不该进这张表，这里只列公共 SaaS 域。
  //
  // 匹配语义统一为「域名自身 + 所有子域」，写法见 ruleMatches。
  // 用户在设置页填的条目会叠加在这两张表之上；也可以用「使用内置默认名单」开关整体关掉。

  var DEFAULT_WHITELIST = [
    // 搜索 / 门户
    'google.com', 'youtube.com', 'bing.com', 'baidu.com', 'duckduckgo.com',
    'yandex.com', 'yandex.ru', 'sogou.com', 'so.com', 'startpage.com',
    'ecosia.org', 'brave.com', 'naver.com', 'daum.net',

    // 社交 / 内容社区
    'facebook.com', 'instagram.com', 'threads.net', 'twitter.com', 'x.com',
    'linkedin.com', 'reddit.com', 'tiktok.com', 'douyin.com', 'kuaishou.com',
    'pinterest.com', 'quora.com', 'snapchat.com', 'telegram.org', 'whatsapp.com',
    'discord.com', 'weibo.com', 'zhihu.com', 'bilibili.com', 'xiaohongshu.com',
    'douban.com', 'toutiao.com',

    // 电商 / 支付
    'amazon.com', 'ebay.com', 'aliexpress.com', 'walmart.com', 'taobao.com',
    'tmall.com', 'jd.com', 'pinduoduo.com', 'shopee.com', 'rakuten.co.jp',
    'paypal.com', 'stripe.com', 'alipay.com',

    // 代码托管 / 开发者社区
    'github.com', 'githubusercontent.com', 'github.io', 'gitlab.com', 'gitee.com',
    'bitbucket.org', 'sourceforge.net', 'stackoverflow.com', 'stackexchange.com',
    'npmjs.com', 'pypi.org', 'codepen.io', 'jsfiddle.net',
    'csdn.net', 'juejin.cn', 'segmentfault.com', 'oschina.net', 'cnblogs.com', '51cto.com',

    // 协作 / 办公 / SaaS
    'notion.so', 'notion.site', 'figma.com', 'slack.com', 'zoom.us', 'dropbox.com',
    'box.com', 'atlassian.net', 'trello.com', 'asana.com', 'airtable.com',
    'miro.com', 'canva.com', 'salesforce.com', 'hubspot.com', 'zendesk.com',
    'feishu.cn', 'larkoffice.com', 'dingtalk.com',

    // 邮箱 / 即时通讯
    'gmail.com', 'outlook.com', 'live.com', 'hotmail.com', 'mail.ru',
    'qq.com', '163.com', '126.com', 'sina.com.cn', 'foxmail.com', 'yeah.net',

    // 视频 / 音乐 / 流媒体
    'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com', 'hbomax.com',
    'iqiyi.com', 'youku.com', 'vimeo.com', 'twitch.tv',

    // 大厂官网 / 软硬件厂商
    'microsoft.com', 'apple.com', 'adobe.com', 'oracle.com', 'ibm.com',
    'intel.com', 'nvidia.com', 'amd.com', 'samsung.com', 'xiaomi.com',
    'huawei.com', 'oppo.com', 'vivo.com', 'lenovo.com', 'sony.com',

    // 安全社区 / 情报平台（参考类站点，扫它没有资产意义）
    'portswigger.net', 'owasp.org', 'exploit-db.com', 'offsec.com',
    'hackthebox.com', 'tryhackme.com', 'cve.mitre.org', 'nvd.nist.gov',
    'virustotal.com', 'shodan.io', 'fofa.info', 'zoomeye.org', 'threatbook.com', 'threatbook.cn'
  ];

  var DEFAULT_RESOURCE_BLOCK = [
    // 统计 / 埋点
    'google-analytics.com', 'googletagmanager.com', 'gstatic.com',
    'hm.baidu.com', 'bdstatic.com', 'cnzz.com', '51.la',
    'growingio.com', 'sensorsdata.cn', 'sensorsdata.com',
    'mixpanel.com', 'amplitude.com', 'segment.com', 'segment.io',
    'hotjar.com', 'clarity.ms', 'statcounter.com', 'clicky.com',
    'umeng.com', 'matomo.cloud', 'analytics.tiktok.com', 'metrika.yandex.ru',

    // 广告 / 营销
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'googletagservices.com', 'criteo.com', 'adroll.com', 'taboola.com',
    'outbrain.com', 'pubmatic.com', 'rubiconproject.com', 'openx.net',
    'adnxs.com', 'casalemedia.com', 'facebook.net', 'adsrvr.org',

    // 验证码 / 风控 / 反爬
    'recaptcha.net', 'geetest.com', 'gtimg.com', 'yunpian.com',
    'cloudflare.com', 'cloudflareinsights.com', 'akamaihd.net', 'akamized.net',
    'incapsula.com', 'imperva.com', 'datadome.co', 'kasada.io',
    'perimeterx.net', 'humansecurity.com', 'arkoselabs.com',

    // 客服 / 会话
    'intercom.io', 'intercomcdn.com', 'drift.com', 'crisp.chat', 'tidio.co',
    'livechat.com', 'zopim.com', 'olark.com', 'freshchat.com',

    // 地图
    'amap.com', 'autonavi.com', 'mapbox.com', 'tianditu.gov.cn',
    'map.qq.com', 'api.map.baidu.com',

    // 错误监控 / APM
    'sentry.io', 'sentry-cdn.com', 'bugsnag.com', 'rollbar.com',
    'newrelic.com', 'nr-data.net', 'raygun.com', 'trackjs.com',
    'appdynamics.com', 'dynatrace.com', 'browser-intake-datadoghq.com', 'datadoghq.com',

    // A/B 测试 / 远程配置 / 消息推送
    'optimizely.com', 'abtasty.com', 'launchdarkly.com', 'split.io',
    'firebaseio.com', 'onesignal.com', 'pusher.com',

    // 社交 / 视频嵌入 SDK
    'twimg.com', 'ytimg.com', 'vimeocdn.com', 'instagram.com',
    'platform.twitter.com', 'connect.facebook.net',

    // 公共 CDN（只放公开库托管，目标自有 CDN 域名不要加进来）
    'jsdelivr.net', 'unpkg.com', 'cdnjs.com', 'bootstrapcdn.com',
    'alicdn.com', 'at.alicdn.com',
    'staticfile.org', 'bootcdn.net', 'loli.net', 'jsdelivr.fastly.net'
  ];

  /** 把用户写的一条规则归一化成 { host, port }，port 为空表示不限端口 */
  function normalizeRule(raw) {
    if (raw === null || raw === undefined) return null;
    var s = String(raw).trim();
    if (!s) return null;

    // 容忍 https://www.example.com/path?a=1#frag 这类完整 URL 写法
    s = s.replace(/^[a-z][a-z0-9+.\-]*:\/\//i, '');
    s = s.replace(/^\/+/, '');
    s = s.split(/[/?#]/)[0];
    s = s.replace(/^[\s"'<>]+|[\s"'<>]+$/g, '').replace(/\.$/, '');
    if (!s) return null;

    // `*.example.com` / `.example.com` / `example.com` 语义统一：自身 + 所有子域
    s = s.replace(/^\*\.?/, '').replace(/^\./, '').toLowerCase();

    var t = splitHostPort(s);
    return t.host ? t : null;
  }

  /**
   * 拆 location.host / URL.host 为 { host, port }，兼容 IPv6 字面量。
   * 只有一个冒号才算 host:port —— 多个冒号是裸 IPv6（::1），整串都是 host。
   */
  function splitHostPort(hostPort) {
    var h = String(hostPort === null || hostPort === undefined ? '' : hostPort)
      .trim().toLowerCase().replace(/\.$/, '');
    if (!h) return { host: '', port: '' };

    var port = '';
    if (h.charAt(0) === '[') {                       // [::1] 或 [::1]:8080
      var close = h.indexOf(']');
      if (close > -1) {
        port = (h.charAt(close + 1) === ':') ? h.slice(close + 2) : '';
        h = h.slice(1, close);                       // 去掉方括号，与规则写法对齐
      }
    } else {
      var first = h.indexOf(':');
      if (first > -1 && first === h.lastIndexOf(':')) {
        port = h.slice(first + 1);
        h = h.slice(0, first);
      }
    }
    return { host: h, port: port };
  }

  /** 从绝对 URL 取 host（含端口），取不到返回空串 */
  function hostOfUrl(u) {
    try { return new URL(u).host || ''; } catch (e) { return ''; }
  }

  function ruleMatches(rule, hostPort) {
    var t = splitHostPort(hostPort);
    if (!t.host) return false;
    if (rule.port && rule.port !== t.port) return false;   // 规则写明端口才要求端口一致
    if (t.host === rule.host) return true;
    // 子域：必须以 "." 分隔，杜绝 notexample.com 命中 example.com
    return (t.host.length > rule.host.length) &&
      (t.host.slice(-(rule.host.length + 1)) === '.' + rule.host);
  }

  /** host 是否命中名单中任意一条规则。站点白名单与资源黑名单共用同一套匹配语义。 */
  function hostMatches(hostPort, list) {
    if (!list || !list.length) return false;
    for (var i = 0; i < list.length; i++) {
      var rule = normalizeRule(list[i]);
      if (rule && ruleMatches(rule, hostPort)) return true;
    }
    return false;
  }

  /** 站点级判定，语义可读性保留 */
  function isWhitelisted(hostPort, list) { return hostMatches(hostPort, list); }

  function useBuiltin(s) { return !(s && s.use_default_allowlist === false); }

  /**
   * 站点级名单 = 内置默认 + 用户配置。
   * 旧行为是「用户一填，内置整体失效」，于是填了一条自己的就把 google 放出来了 —— 现在是叠加。
   */
  function effectiveList(s) {
    var user = (s && s.allowlist) || [];
    return useBuiltin(s) ? DEFAULT_WHITELIST.concat(user) : user.slice();
  }

  /** 资源级名单，同样与内置叠加 */
  function effectiveResourceList(s) {
    var user = (s && s.resource_blocklist) || [];
    return useBuiltin(s) ? DEFAULT_RESOURCE_BLOCK.concat(user) : user.slice();
  }

  /** 该脚本是否属于「不抓的第三方 SDK」。页面自身的域名永远不拦。 */
  function isBlockedResource(absUrl, baseHost, s) {
    var h = hostOfUrl(absUrl);
    if (!h || (baseHost && h === baseHost)) return false;
    return hostMatches(h, effectiveResourceList(s));
  }

  global.IHHostMatch = {
    DEFAULT_WHITELIST: DEFAULT_WHITELIST,
    DEFAULT_RESOURCE_BLOCK: DEFAULT_RESOURCE_BLOCK,
    normalizeRule: normalizeRule,
    splitHostPort: splitHostPort,
    hostOfUrl: hostOfUrl,
    ruleMatches: ruleMatches,
    hostMatches: hostMatches,
    useBuiltin: useBuiltin,
    effectiveList: effectiveList,
    effectiveResourceList: effectiveResourceList,
    isBlockedResource: isBlockedResource
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
