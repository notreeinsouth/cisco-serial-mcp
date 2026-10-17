"""
操作实时看板（串口/Console + Telnet 双通道，带"释放"按钮）

给"我想看着它干活"用的窗口。两个 MCP 服务器各自把每一笔收发写成 JSONL 流水：
  - ciscoserial (server_serial.py) → D:\\DSH\\logs\\serial-live.jsonl   （channel=serial）
  - ciscomcp    (server2.py)       → D:\\DSH\\logs\\telnet-live.jsonl   （channel=telnet）
本看板把这些流水分通道合并，用 SSE 推给浏览器。

"释放"按钮怎么工作的：
  看板是独立进程，调不到 MCP 工具，所以用文件当信箱 —— 看板写 <channel>.release，
  对应服务器里的看护线程发现后释放全部会话，并回写 <channel>.result。这样不需要
  额外开监听端口，也不用 DSH 宿主参与。用途：串口/VTY 是独占的，我一松手你才能
  在 MobaXterm 里接管。

用法：
    python live_view.py                        # 默认 http://127.0.0.1:8777/
    python live_view.py --port 8888
    python live_view.py --log a.jsonl --log b.jsonl    # 自定义要盯的流水文件

安全性：只绑 127.0.0.1，无认证。页面里是设备控制台的完整内容，还能一键释放会话——
别把它暴露到本机之外。
"""

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# 回填多少行历史（每个流水文件各回填这么多）
BACKFILL_LINES = 500
# 增量轮询间隔（秒）：越小越"实时"，代价是空转
POLL_SECONDS = 0.15

# 自启动时用无窗口方式(pythonw)运行，没有任何控制台输出 —— 日志文件是唯一线索
LOG_PATH = Path(os.environ.get("CISCO_LIVE_VIEW_LOG", r"D:\DSH\logs\live-view.log"))


def log_line(msg: str) -> None:
    """同时打到 stdout 与日志文件"""
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception:
        pass

DEFAULT_LOGS = [
    r"D:\DSH\logs\serial-live.jsonl",
    r"D:\DSH\logs\telnet-live.jsonl",
]

# 控制通道：localhost TCP，端口随机；只有"手里真有设备的那个进程"才公布端点文件
CONTROL_DIR = Path(os.environ.get("CISCO_LIVE_CONTROL_DIR", r"D:\DSH\logs\control"))
CHANNELS = ("serial", "telnet")


def read_endpoint(channel: str) -> dict:
    """
    读端点文件，拿到"持有设备会话的那个进程"的端口与令牌

    端点文件由服务器在**拿到会话时**公布、**释放完会话后**撤下。所以它的存在
    本身就等于"现在有会话"，而且天然指向那个手里真有设备的进程——即使 DSH 留下了
    残留的旧服务器进程，那些进程没有会话、不会公布端点，也就不会被连到。
    """
    try:
        info = json.loads((CONTROL_DIR / f"{channel}.endpoint.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        return {"_error": f"端点文件读不了: {exc}"}
    if not isinstance(info, dict) or not info.get("port") or not info.get("token"):
        return {"_error": "端点文件内容不完整（可能正在写入）"}
    return info


def endpoint_summary(channel: str) -> dict:
    """端点摘要（**不带令牌**，避免把令牌泄露到 /health 上）"""
    info = read_endpoint(channel)
    if not info:
        return {"present": False}
    if info.get("_error"):
        return {"present": True, "error": info["_error"]}
    return {"present": True, "pid": info.get("pid"),
            "port": info.get("port"), "device": info.get("device")}


def control_request(channel: str, payload: dict, timeout: float = 6.0) -> dict:
    """向"持有设备的那个进程"发一条控制请求（input / release / status）"""
    info = read_endpoint(channel)
    if info.get("_error"):
        return {"ok": False, "error": info["_error"]}
    if not info:
        return {"ok": False,
                "error": "当前没有打开的会话（端点文件不存在）—— 先让我连上设备"}
    body = {"token": info["token"]}
    body.update(payload)
    try:
        with socket.create_connection(("127.0.0.1", int(info["port"])), timeout=timeout) as sock:
            sock.sendall((json.dumps(body, ensure_ascii=False) + "\n").encode("utf-8"))
            line = sock.makefile("rb").readline()
        return json.loads(line.decode("utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False,
                "error": f"连不上控制通道 127.0.0.1:{info.get('port')}（{exc}）"
                         f"—— 端点文件可能是残留进程留下的失效文件"}


def send_input(channel: str, data: str, kind: str, sensitive: bool) -> dict:
    """
    把网页上的输入转给"持有设备的那一端"（走 localhost TCP，不走文件）

    为什么不走文件信箱：输入里可能是口令。文件会把明文写到磁盘上，而且目标进程
    没在运行时明文会一直躺在那里。TCP 通道只在内存里过一遍；带令牌是因为
    仅靠"只绑 127.0.0.1"挡不住第三方网页往 localhost 发请求（CSRF），
    而网页读不到本地令牌文件。

    本函数只负责转发，**不记录、不回显 data**。
    """
    return control_request(channel, {"action": "input", "data": data,
                                     "kind": kind, "sensitive": bool(sensitive)})


def request_release(channel: str) -> dict:
    """让持有设备的那个进程释放会话（走同一条 TCP 控制通道）"""
    result = control_request(channel, {"action": "release"})
    result.setdefault("channel", channel)
    return result


PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>操作实时看板</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --line:#30363d; --fg:#c9d1d9;
          --tx:#58a6ff; --ev:#d29922; --err:#f85149; --ok:#3fb950; --dim:#8b949e;
          --ts:#484f58; --ser:#3fb950; --tel:#a371f7; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:13px/1.55 "Cascadia Mono",Consolas,"Microsoft YaHei Mono",monospace; }
  header { position:sticky; top:0; z-index:9; display:flex; gap:10px; align-items:center;
           flex-wrap:wrap; padding:9px 14px; background:var(--panel);
           border-bottom:1px solid var(--line); }
  #dot { width:9px; height:9px; border-radius:50%; background:var(--err); flex:none; }
  #dot.on { background:var(--ok); box-shadow:0 0 8px #3fb95088; }
  header strong { font-weight:600; }
  #st { color:var(--dim); font-size:12px; }
  #legend { color:var(--dim); font-size:11px; }
  .ser { color:var(--ser); } .tel { color:var(--tel); }
  .grp { display:flex; align-items:center; gap:5px; padding-left:10px;
         border-left:1px solid var(--line); }
  .badge { font-size:11px; color:var(--dim); padding:2px 7px; border-radius:99px;
           border:1px solid var(--line); white-space:nowrap; }
  .badge.busy { color:#0d1117; background:var(--ev); border-color:var(--ev); font-weight:600; }
  .badge.free { color:var(--ok); border-color:#23863666; }
  button { background:#21262d; color:var(--fg); border:1px solid var(--line);
           border-radius:6px; padding:3px 11px; cursor:pointer; font:inherit; font-size:12px; }
  button:hover:enabled { background:#30363d; }
  button:disabled { opacity:.5; cursor:default; }
  button.rel:hover:enabled { background:#3d1d1d; border-color:#f8514966; color:#ffb3ad; }
  #meta { margin-left:auto; color:var(--dim); font-size:12px; }
  label { user-select:none; color:var(--dim); font-size:12px; display:flex; align-items:center; gap:4px; }
  #wrap { padding:10px 14px calc(45vh + 80px); }
  .ln { white-space:pre-wrap; word-break:break-word; display:flex; gap:8px; }
  .ln .t { color:var(--ts); flex:none; }
  .ln .ch { flex:none; width:2.4em; font-weight:600; }
  .ln .tag { color:#6e7681; flex:none; width:2.4em; }
  .ln .v { flex:1; }
  .tx .v { color:var(--tx); font-weight:600; }
  .rx .v { color:var(--fg); }
  .ev .v { color:var(--ev); }
  .err .v { color:var(--err); font-weight:600; }
  #empty { color:var(--dim); padding:18px 2px; }
  /* —— 底部输入条 —— */
  #bar { position:fixed; left:0; right:0; bottom:0; z-index:10; display:flex; gap:8px;
         align-items:center; flex-wrap:wrap; padding:8px 14px; background:var(--panel);
         border-top:1px solid var(--line); }
  #cmd { flex:1 1 300px; min-width:180px; background:#0d1117; color:var(--fg);
         border:1px solid var(--line); border-radius:6px; padding:6px 10px;
         font:inherit; font-size:13px; }
  #cmd:focus { outline:none; border-color:#58a6ff; }
  #cmd:disabled { opacity:.5; }
  #sensWrap { cursor:pointer; padding:2px 9px; border:1px solid var(--line);
              border-radius:99px; }
  #sensWrap.on { color:#ffa657; border-color:#ffa65766; background:#2b1d0d; }
  .keys { padding-left:10px; }
  .key { padding:3px 8px; }
  #hint { flex-basis:100%; color:var(--dim); font-size:11px; }
  #hint code { color:#8b949e; }
</style>
</head>
<body>
<header>
  <span id="dot"></span>
  <strong>操作实时看板</strong>
  <span id="st">连接中…</span>

  <span class="grp">
    <span id="st-serial" class="badge">串口 —</span>
    <button class="rel" data-ch="serial" title="关闭我持有的会话，把 COM 口让给 MobaXterm">释放串口</button>
  </span>

  <span class="grp">
    <span id="st-telnet" class="badge">Telnet —</span>
    <button class="rel" data-ch="telnet" title="关闭我持有的 Telnet/VTY 会话">释放 Telnet</button>
  </span>

  <button class="rel" id="rel-all" title="两个通道一起释放">全部释放</button>

  <span id="legend"><b class="ser">串</b>=串口&nbsp;<b class="tel">tel</b>=Telnet&nbsp;发→我发的&nbsp;收←设备回的&nbsp;··事件</span>

  <label><input type="checkbox" id="auto" checked> 自动滚动</label>
  <button id="clr">清屏</button>
  <span id="meta">0 条</span>
</header>
<div id="wrap"><div id="empty">等待设备活动…（打开着就行，我这边一操作就会出现在这里）</div></div>

<div id="bar">
  <span id="target" class="badge">目标：—</span>
  <input id="cmd" placeholder="输入命令后回车发送" autocomplete="off" spellcheck="false" disabled>
  <button id="send" disabled>发送</button>
  <label id="sensWrap" title="勾上后，你输入的内容不会写进流水/审计，也不会回传给模型">
    <input type="checkbox" id="sens"> 🙈 密文输入
  </label>
  <span class="grp keys">
    <button class="key" data-key="03" title="Ctrl+C：中断当前命令">Ctrl+C</button>
    <button class="key" data-key="1a" title="Ctrl+Z：退回特权模式">Ctrl+Z</button>
    <button class="key" data-key="0d" title="只发一个回车（Enter）">Enter</button>
    <button class="key" data-key="20" title="空格：分页时翻页">空格</button>
    <button class="key" data-key="3f" title="? 查看当前可用命令">?</button>
  </span>
  <span id="hint">你的输入<b>直达设备</b>（不经过危险命令拦截），并以 <code>source=web</code> 记入审计日志。
    口令请走 🙈 <b>密文输入</b>——勾上后明文不落盘、不进流水、不回传给模型；设备显示口令提示符时会自动切过去。</span>
</div>
<script>
const wrap  = document.getElementById('wrap');
const dot   = document.getElementById('dot');
const st    = document.getElementById('st');
const auto  = document.getElementById('auto');
const empty = document.getElementById('empty');
const state = { serial: null, telnet: null };
const cmdEl = document.getElementById('cmd');
const sensEl = document.getElementById('sens');
const sensWrap = document.getElementById('sensWrap');
const sendBtn = document.getElementById('send');
const targetEl = document.getElementById('target');
let count = 0, everOpened = false;

function meta() { document.getElementById('meta').textContent = count + ' 条'; }

document.getElementById('clr').onclick = () => {
  wrap.innerHTML = ''; count = 0; meta();
};

function channelLabel(ch) {
  if (ch === 'serial') return '串';
  if (ch === 'telnet') return 'tel';
  return ch ? String(ch).slice(0, 4) : '—';
}

function paintState(ch) {
  const el = document.getElementById('st-' + ch);
  if (!el) return;
  const name = ch === 'serial' ? '串口' : 'Telnet';
  const s = state[ch];
  el.textContent = name + ' ' + (s === 'connected' ? '● 占用中' : s === 'idle' ? '○ 空闲' : '—');
  el.className = 'badge' + (s === 'connected' ? ' busy' : s === 'idle' ? ' free' : '');
}

function targetChannel() {
  if (state.serial === 'connected') return 'serial';
  if (state.telnet === 'connected') return 'telnet';
  return null;
}

function paintTarget() {
  const ch = targetChannel();
  const inputOk = ch === 'serial';           // 目前只有串口通道实现了输入
  targetEl.textContent = '目标：' + (ch === 'serial' ? '串口' : ch === 'telnet' ? 'Telnet' : '无会话');
  targetEl.className = 'badge' + (ch ? ' free' : '');
  cmdEl.disabled = !inputOk;
  sendBtn.disabled = !inputOk;
  cmdEl.placeholder = !ch ? '当前没有打开的会话 —— 先让我连上设备'
    : (ch === 'telnet' ? 'Telnet 通道暂不支持网页输入'
                       : '输入命令后回车发送（空回车 = 只按一次 Enter）');
}

function applySens() {
  cmdEl.type = sensEl.checked ? 'password' : 'text';
  sensWrap.classList.toggle('on', sensEl.checked);
}

function maybeAutoSensitive(rec) {
  const tail = (rec.text || '').slice(-60).replace(/[\r\n]+$/, '');
  if (!/(password|passwd|secret|口令)\s*:\s*$/i.test(tail)) return;
  if (!sensEl.checked) {
    sensEl.checked = true;
    applySens();
    localLine(rec.channel, 'ev',
      '检测到设备正在等口令 → 已自动切到 🙈 密文输入（你输入的内容不会进流水/审计，也不会回传给模型）');
  }
  cmdEl.focus();
}

async function sendInput(kind, data) {
  const ch = targetChannel();
  if (!ch) { localLine('serial', 'err', '当前没有打开的会话，先让我连上设备'); return; }
  // 只有"整行输入"才可能是口令；快捷键（Ctrl+C 之类）不算，也不该消耗掉密文模式
  const sensitive = (kind === 'line') && sensEl.checked;
  try {
    const r = await fetch('/input?channel=' + ch, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: data, kind: kind, sensitive: sensitive })
    });
    const j = await r.json();
    if (!j.ok) {
      localLine(ch, 'err', '发送失败：' + (j.error || '未知错误'));
      return;
    }
    if (j.autoSensitive) {
      localLine(ch, 'ev', '服务端检测到设备正等口令 → 该输入已按密文处理（未记录明文）');
    }
    if (sensitive) {
      // 密文输入是一次性的：发完自动关掉，免得后面的正常命令也被藏起来
      sensEl.checked = false;
      applySens();
      localLine(ch, 'ev', '密文输入已送达设备，密文模式已自动关闭');
    }  } catch (e) {
    localLine(ch, 'err', '发送失败：' + e);
  }
}

function addLine(rec) {
  if (rec.state) { state[rec.channel] = rec.state; paintState(rec.channel); paintTarget(); }
  if (empty && empty.parentNode) empty.remove();

  const d = document.createElement('div');
  const kind = rec.dir === 'tx' ? 'tx' : rec.dir === 'rx' ? 'rx' : (rec.dir === 'err' ? 'err' : 'ev');
  d.className = 'ln ' + kind;

  const t = document.createElement('span');
  t.className = 't'; t.textContent = (rec.ts || '').slice(11, 23);

  const c = document.createElement('span');
  c.className = 'ch ' + (rec.channel === 'serial' ? 'ser' : rec.channel === 'telnet' ? 'tel' : '');
  c.textContent = channelLabel(rec.channel);

  const g = document.createElement('span');
  g.className = 'tag';
  g.textContent = rec.dir === 'tx' ? '发→' : rec.dir === 'rx' ? '收←' : '··';

  const v = document.createElement('span');
  v.className = 'v';
  // 原始流水里带设备的退格控制符和 --More-- 擦除序列，直接显示很难看。
  // 用 textContent 赋值（天然防注入），显示前去掉控制字符，并把翻页渲染成清晰标记。
  v.textContent = (rec.text || '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '')
    .replace(/-{2,}\s*More\s*-{2,} */gi, ' ⟪翻页⟫ ');

  d.append(t, c, g, v);
  wrap.appendChild(d);
  count++; meta();
  if (auto.checked) window.scrollTo(0, document.body.scrollHeight);
  if (rec.dir === 'rx') maybeAutoSensitive(rec);     // 口令提示符自动切密文
}

function localLine(channel, dir, text) {
  addLine({ ts: new Date().toISOString(), dir: dir, channel: channel, text: '【网页操作】' + text });
}

async function release(ch) {
  if (!confirm('释放后，如果我正在执行命令会被打断。确定释放 ' + ch + ' 吗？')) return;
  const btn = document.querySelector('button[data-ch="' + ch + '"]');
  const all = document.getElementById('rel-all');
  const label = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = '释放中…'; }
  if (ch === 'all' && all) { all.disabled = true; }
  try {
    const r = await fetch('/release?channel=' + ch, { method: 'POST' });
    const j = await r.json();
    if (j.ok) {
      localLine(ch === 'all' ? 'serial' : ch, 'ev',
        '释放 ' + ch + '：已释放 ' + j.released + ' 个会话' +
        (j.released === 0 ? '（本来就没有活动会话，端口已是空闲）' : '，端口已归还'));
    } else {
      const why = (j.results || []).map(x => x.channel + ': ' + x.error).join('；') || j.error;
      localLine(ch === 'all' ? 'serial' : ch, 'err', '释放 ' + ch + ' 失败：' + why);
    }
  } catch (e) {
    localLine(ch === 'all' ? 'serial' : ch, 'err', '释放请求出错：' + e);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = label; }
    if (ch === 'all' && all) { all.disabled = false; }
  }
}

document.querySelectorAll('button[data-ch]').forEach(b => {
  b.onclick = () => release(b.dataset.ch);
});
document.getElementById('rel-all').onclick = () => release('all');

cmdEl.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  const v = cmdEl.value;
  cmdEl.value = '';                  // 立刻清空，密文模式下尤其重要
  sendInput('line', v);
});
sendBtn.onclick = () => { const v = cmdEl.value; cmdEl.value = ''; sendInput('line', v); };
document.querySelectorAll('button.key').forEach((b) => {
  b.onclick = () => {
    sendInput('raw', String.fromCharCode(parseInt(b.dataset.key, 16)));
    cmdEl.focus();
  };
});
sensEl.onchange = applySens;
applySens();
paintTarget();

function connect() {
  const es = new EventSource('/events');
  es.onopen = () => {
    dot.classList.add('on');
    st.textContent = '已连接';
    // 每次(重)连服务端都会回填全量历史，所以先清空，避免重连后内容翻倍
    if (everOpened) { wrap.innerHTML = ''; count = 0; meta(); }
    everOpened = true;
  };
  es.onerror = () => { dot.classList.remove('on'); st.textContent = '断线，重连中…'; };
  es.onmessage = (e) => { try { addLine(JSON.parse(e.data)); } catch (_) {} };
}
connect();
</script>
</body>
</html>
"""


class Tailer:
    """按字节偏移增量读取一个 JSONL 流水文件"""

    def __init__(self, path):
        self.path = Path(path)
        self.offset = 0
        self.pending = b""
        # 老记录是在 channel 字段加进服务器之前写的，会缺这个字段；
        # 按文件名推断一个默认通道补上，免得看板上出现一排空白通道。
        name = self.path.name.lower()
        if "telnet" in name:
            self.default_channel = "telnet"
        elif "serial" in name:
            self.default_channel = "serial"
        else:
            self.default_channel = ""

    def _tag(self, raw_line: str) -> str:
        if not self.default_channel or '"channel"' in raw_line:
            return raw_line
        try:
            rec = json.loads(raw_line)
        except ValueError:
            return raw_line
        if not isinstance(rec, dict):
            return raw_line
        rec.setdefault("channel", self.default_channel)
        return json.dumps(rec, ensure_ascii=False)

    def backfill(self, lines):
        """返回文件末尾 lines 行（并记住当前位置，避免重复推送）"""
        try:
            raw = self.path.read_bytes()
        except (FileNotFoundError, OSError):
            return []
        self.offset = len(raw)
        return [self._tag(l.decode("utf-8", errors="replace"))
                for l in raw.split(b"\n")[-lines:] if l.strip()]

    def poll(self):
        """返回自上次调用后新增的完整行"""
        try:
            size = self.path.stat().st_size
        except (FileNotFoundError, OSError):
            return []
        if size < self.offset:            # 文件被截断/轮转 → 从头来
            self.offset = 0
            self.pending = b""
        if size <= self.offset:
            return []
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.offset)
                raw = fh.read(size - self.offset)
        except OSError:
            return []
        self.offset += len(raw)
        # 用二进制残留缓冲拼行，这样中文不会因为截到半个字符而乱码
        self.pending += raw
        *complete, self.pending = self.pending.split(b"\n")
        return [self._tag(l.decode("utf-8", errors="replace")) for l in complete if l.strip()]


class Handler(BaseHTTPRequestHandler):
    server_version = "LiveView"
    logs = []

    def log_message(self, *args):        # 静音，别把后台任务日志刷满
        pass

    # ---- 响应助手 ----
    def _send(self, status, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    # ---- 页面 ----
    def _page(self):
        self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")

    # ---- SSE 事件流 ----
    def _event(self, payload: str):
        self.wfile.write(b"data: " + payload.encode("utf-8") + b"\n\n")

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        tailers = [Tailer(p) for p in self.logs]

        # 1) 回填历史，打开页面就能看到"刚才发生了什么"
        for t in tailers:
            for line in t.backfill(BACKFILL_LINES):
                self._event(line)

        # 2) 增量推送（多通道合并；两个通道同时活跃时，跨文件的先后顺序以轮询为准）
        try:
            while True:
                for t in tailers:
                    for line in t.poll():
                        self._event(line)
                self.wfile.write(b": ping\n\n")   # 心跳，兼作断线探测
                self.wfile.flush()
                time.sleep(POLL_SECONDS)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    # ---- 释放 ----
    def _release(self, query: str):
        ch = (parse_qs(query).get("channel", ["all"])[0] or "all").lower()
        if ch == "all":
            targets = list(CHANNELS)
        elif ch in CHANNELS:
            targets = [ch]
        else:
            self._json(400, {"ok": False, "error": f"未知通道: {ch}（可用 serial/telnet/all）"})
            return
        results = []
        for t in targets:
            ep = read_endpoint(t)
            if not ep:
                # 没有端点 = 本来就没有会话，这不算失败（端口本来就是空闲的）
                results.append({"ok": True, "channel": t, "released": 0,
                                "note": "本来就没有活动会话"})
                continue
            results.append(request_release(t))
        self._json(200, {
            "ok": all(r.get("ok") for r in results),
            "released": sum(int(r.get("released") or 0) for r in results),
            "results": results,
        })

    # ---- 网页输入 ----
    def _input(self, query: str, body: bytes):
        ch = (parse_qs(query).get("channel", ["serial"])[0] or "serial").lower()
        if ch not in CHANNELS:
            self._json(400, {"ok": False, "error": f"未知通道: {ch}"})
            return
        raw = body.decode("utf-8", errors="replace") if body else ""
        if not raw:
            raw = parse_qs(query).get("data", [""])[0]
        try:
            payload = json.loads(raw) if raw.strip().startswith("{") else {"data": raw}
        except ValueError:
            self._json(400, {"ok": False, "error": "请求体不是合法 JSON"})
            return
        data = str(payload.get("data", ""))
        kind = str(payload.get("kind", "line")).lower()
        if kind not in ("line", "raw"):
            self._json(400, {"ok": False, "error": f"未知 kind: {kind}（可用 line/raw）"})
            return
        # 只转发，不回显、不记录 data（里面可能有口令）
        result = send_input(ch, data, kind, bool(payload.get("sensitive")))
        self._json(200 if result.get("ok") else 502, {"channel": ch, **result})

    def _route(self, method: str, body: bytes = b""):
        parsed = urlparse(self.path)
        path, query = parsed.path, parsed.query
        try:
            if path in ("/", "/index.html") and method == "GET":
                self._page()
            elif path == "/events" and method == "GET":
                self._stream()
            elif path == "/health" and method == "GET":
                self._json(200, {
                    "ok": True,
                    "logs": [{"path": str(p), "exists": Path(p).exists()} for p in self.logs],
                    "controlDir": str(CONTROL_DIR),
                    "controlDirExists": CONTROL_DIR.exists(),
                    "endpoints": {ch: endpoint_summary(ch) for ch in CHANNELS},
                })
            elif path == "/release" and method in ("GET", "POST"):
                self._release(query)
            elif path == "/input" and method in ("GET", "POST"):
                self._input(query, body)
            else:
                self.send_error(404)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_body(self) -> bytes:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return b""
        return self.rfile.read(n)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST", self._read_body())


def main():
    ap = argparse.ArgumentParser(description="操作实时看板（串口 + Telnet，带释放与输入）")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址（默认只绑本机）")
    ap.add_argument("--port", type=int, default=8777, help="监听端口（默认 8777）")
    ap.add_argument("--log", action="append", default=None,
                    help="要盯的流水文件，可重复指定；默认同时盯串口和 Telnet 两路")
    args = ap.parse_args()

    Handler.logs = [Path(p) for p in (args.log or DEFAULT_LOGS)]
    try:
        httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        log_line(f"启动失败：{args.host}:{args.port} 绑不上（{exc}）"
                 f" —— 很可能已经有一个看板在跑（同端口只能有一个）")
        sys.exit(1)

    url = f"http://{args.host}:{args.port}/"
    log_line(f"操作实时看板已启动: {url}")
    for p in Handler.logs:
        log_line(f"  盯: {p}")
    log_line(f"控制目录（端点文件）: {CONTROL_DIR}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_line("已停止")


if __name__ == "__main__":
    main()
