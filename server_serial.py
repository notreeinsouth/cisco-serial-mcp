"""
Cisco Serial (Console) MCP Server
=================================

通过本机串口（USB 转串口 / Console 线）连接 Cisco 设备的 MCP 服务器，
用于带外管理（OOB）——设备没网、Telnet/SSH 进不去、需要进 ROMMON 时的最后通道。

设计目标：与已有的 Telnet 版 cisco-cli-mcpv2 行为对齐
  - 同样的工具语义（connect / execute / list_sessions / disconnect + confirm 二次确认）
  - 同样的危险命令拦截规则（DANGEROUS_PATTERNS，逐行匹配、支持 IOS 缩写、去 'do ' 前缀）
  - 同样的 JSONL 审计日志（默认 D:\\DSH\\logs\\audit-serial.log）

串口相对 Telnet 的额外能力：
  1. serial_send_break —— 发送 Break 信号（进入 ROMMON / 密码恢复的关键动作）
  2. 波特率自动探测 —— baud="auto" 时先试 9600，无输出再试 115200
  3. 分页自动适配 —— 出现 --More-- 自动送空格，长输出（show run / show tech）不会被卡住
  4. 端口自动选择 —— port 留空时按 hwid 挑 USB 串口，自动排除蓝牙虚拟口

实现要点：
  - pyserial 是阻塞式 API，故每个会话起一个后台读线程把字节堆入缓冲区，
    MCP 侧用 asyncio.to_thread 调用阻塞逻辑，避免阻塞事件循环
  - stdout 只允许出现 MCP 协议消息，所有诊断信息一律写 stderr

已知局限：
  - 应用层危险命令拦截只是减速带，替代不了设备侧 AAA / TACACS+ 命令授权
  - 串口是独占资源：MobaXterm 等程序占用同一 COM 口时本服务器会打开失败（会明确报错）
"""

import argparse
import asyncio
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import serial
from serial.tools import list_ports

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Cisco Serial (Console) MCP Server")


# ============ 危险命令拦截（规则与 cisco-cli-mcpv2 完全一致）============

# 规则列表：(正则, 命中原因)。命中后需 confirm=true 才会执行，按需增删。
# 说明：
# - 正则按"每一行"匹配，多行命令的任意一行命中即拦截
# - 匹配前会去掉行首的 "do " 前缀（配置模式下 do reload / do wr 同样能被拦住）
# - 备份方向命令（copy running-config tftp: / write terminal / write net）不受限
DANGEROUS_PATTERNS = [
    # —— 设备级破坏性操作 ——
    # 允许缩写：reload/rel/relo/reloa；放行 'in'/'cancel' 及其缩写（定时保险丝与取消）
    (r"^(?:reload|reloa|relo|rel)\b(?!\s+(?:i|in|c|ca|can|canc|cance|cancel)\b)",
     "立即重启设备。定时保险丝 'reload in <分钟>' 与 'reload cancel' 不受限制"),
    # write/wri/wr：放行 terminal/net 及其缩写（查看/备份），其余参数（memory、erase、空）一律拦截
    (r"^(?:write|wri|wr)\b(?!\s+(?:t|te|ter|term|termi|termin|termina|terminal|n|ne|net)\b)",
     "将运行配置持久化到启动配置（write memory / wr），变更从此落盘"),
    (r"^(?:write|wr)\s+(?:e|er|era|eras|erase)\b",
     "擦除启动配置（write erase）"),
    # era* 只可能是 erase 家族
    (r"^era",
     "擦除配置或文件系统（erase startup-config / erase nvram: 等）"),
    (r"^fo(?:r(?:m(?:a(?:t)?)?)?)?\b",
     "格式化文件系统"),
    (r"^(?:delete|del)\b.*\bconf",
     "删除配置类文件"),
    (r"^boot\b",
     "修改启动镜像或启动参数"),
    # —— 覆盖/持久化配置（备份方向如 copy running-config tftp: 不受限）——
    (r"^copy\s+\S+\s+(?:nvram:)?(?:run(?:ning)?(?:-?config)?|ru|start(?:up)?(?:-?config)?|st)\s*$",
     "用外部/本地文件覆盖运行配置，或将配置持久化到启动配置（copy <源> running-config/startup-config）"),
    # —— 可能导致管理通道自锁 ——
    (r"^(?:no\s+)?user(?:name)?\b",
     "增删登录账号，可能造成管理自锁"),
    # enable 后跟 secret/password（含缩写）才拦；'enable'/'ena'/'enable 15'（进特权模式）不受限
    (r"^(?:no\s+)?en(?:a|able)\s+(?:s(?:e(?:c(?:r(?:e(?:t)?)?)?)?)?|p(?:a(?:s(?:s(?:w(?:o(?:r(?:d)?)?)?)?)?)?)?)\b",
     "enable 密码变更，可能造成管理自锁"),
    (r"^(?:no\s+)?aaa\b",
     "AAA 配置变更，可能造成登录自锁"),
    # 注意：本规则修正了 telnet 版 v2 的一处漏网——v2 的 c(?:o(?:n)?)? 因 \b 边界
    # 只能拦住缩写 "line con 0"，拦不住完整拼写 "line console 0"。此处补全全拼。
    (r"^(?:line|lin|li)\s+(?:c(?:o(?:n(?:s(?:o(?:l(?:e)?)?)?)?)?)?|v(?:t(?:y)?)?|a(?:u(?:x)?)?)\b",
     "Console/VTY/AUX 线路变更，可能锁定管理通道"),
    # —— 业务/性能影响 ——
    (r"^shut",
     "关闭接口或特性，会中断流量"),
    (r"^def(?:ault)?\s+int(?:erface)?\b",
     "接口恢复默认配置，接口下已有配置全部丢失"),
    (r"^cle(?:a)?r?\s+ip\s+b(?:g(?:p)?)?\b",
     "硬清 BGP 会话，路由收敛期间丢流量"),
    (r"^deb",
     "debug 可能大量消耗 CPU，影响生产设备"),
]
DANGEROUS_PATTERNS = [(re.compile(p, re.IGNORECASE), reason) for p, reason in DANGEROUS_PATTERNS]


def check_dangerous_command(command: str) -> Optional[str]:
    """逐行检查命令是否命中危险规则；命中返回原因，安全返回 None"""
    if not command:
        return None
    for raw_line in command.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # 配置模式下可用 do 前缀执行特权命令，例如 "do reload"
        line = re.sub(r'^(?:do\s+)+', '', line, flags=re.IGNORECASE)
        for pattern, reason in DANGEROUS_PATTERNS:
            if pattern.search(line):
                return reason
    return None


class DangerousCommandError(Exception):
    """命令命中危险规则且未携带 confirm=true，已拦截未执行"""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ============ 审计日志 ============

AUDIT_OUTPUT_MAX_CHARS = 2000
AUDIT_LOG_PATH = Path(
    os.environ.get("CISCO_SERIAL_AUDIT_LOG",
                   r"D:\DSH\logs\audit-serial.log")
)

_audit_logger = logging.getLogger("cisco-serial-audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False
try:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _handler = logging.FileHandler(AUDIT_LOG_PATH, encoding="utf-8")
except OSError as exc:
    print(f"[cisco-serial-mcp] 审计日志初始化失败({exc})，审计内容改写 stderr: {AUDIT_LOG_PATH}",
          file=sys.stderr)
    _handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("%(message)s"))
_audit_logger.addHandler(_handler)


def audit_log(event: str, **fields) -> None:
    """以 JSONL 追加一条审计记录（一行一个 JSON 对象）"""
    record = {"ts": datetime.now().isoformat(timespec="milliseconds"),
              "event": event, "channel": "serial"}
    record.update(fields)
    _audit_logger.info(json.dumps(record, ensure_ascii=False, default=str))


def truncate_for_audit(output: str) -> str:
    if not output:
        return ""
    if len(output) <= AUDIT_OUTPUT_MAX_CHARS:
        return output
    return output[:AUDIT_OUTPUT_MAX_CHARS] + f"...(截断，原始长度 {len(output)} 字符)"


# ============ 实时镜像流水（给 live_view.py 看板用）============

# 与审计日志分工不同：
#   - 审计日志(audit-serial.log)：只留"谁在什么时候执行了什么命令 + 截断输出"，防超大输出
#   - 镜像流水(serial-live.jsonl)：完整收发流水（TX/RX/事件），供 live_view.py 实时展示
# 镜像失败绝不能影响串口主流程，故全程 try/except 兜底。
LIVE_LOG_PATH = Path(os.environ.get("CISCO_SERIAL_LIVE_LOG",
                                    r"D:\DSH\logs\serial-live.jsonl"))
LIVE_MAX_BYTES = 8 * 1024 * 1024      # 超过就清空重来，防止无限增长

_live_lock = threading.Lock()
_live_disabled = False


def live_emit(direction: str, text: str, **fields) -> None:
    """向实时镜像追加一条记录（dir: tx=发给设备 / rx=设备回显 / ev=事件 / err=异常）"""
    global _live_disabled
    if _live_disabled or not text:
        return
    record = {
        "ts": datetime.now().isoformat(timespec="milliseconds"),
        "dir": direction,
        "channel": "serial",
        "text": text,
    }
    record.update(fields)
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    try:
        with _live_lock:
            LIVE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            try:
                if LIVE_LOG_PATH.exists() and LIVE_LOG_PATH.stat().st_size > LIVE_MAX_BYTES:
                    LIVE_LOG_PATH.write_text("", encoding="utf-8")
            except OSError:
                pass
            with open(LIVE_LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
    except Exception as exc:
        # 镜像坏了就当没这回事，串口操作照常
        _live_disabled = True
        print(f"[cisco-serial-mcp] 实时镜像已禁用（写入失败: {exc}）", file=sys.stderr)


# ============ 看板控制通道（网页输入 / 释放 / 状态）============

# 看板(live_view.py)是独立进程，调不到 MCP 工具，所以走一条 localhost TCP 控制通道。
#
# 关键设计：端口由系统随机分配（bind 到 :0），并且**只有真正持有设备会话的进程**
# 才把"端口+令牌"公布到端点文件里；看板每次请求都重新读这个文件。
#
# 为什么不用固定端口 + 令牌文件（第一版就是那么写的，结果翻车了）：
#   1. DSH 热重载/新建会话会留下没被回收的旧服务进程，于是可能同时有两个串口服务器；
#   2. 固定端口 + SO_REUSEADDR 在 Windows 上**允许两个进程绑同一个端口**（本该直接
#      失败），于是后启动的进程把新令牌写进文件，而实际接到连接的却是先启动的进程
#      → 令牌永远不匹配（现象：网页上每次发送都回 "token 不匹配"）；
#   3. 改用随机端口 + "谁有会话谁公布" 之后就没有"连到哪个进程"的歧义了：端点文件
#      天然指向手里真有设备的那个进程，残留进程没有会话所以根本不会公布。
CONTROL_DIR = Path(os.environ.get("CISCO_LIVE_CONTROL_DIR", r"D:\DSH\logs\control"))
CONTROL_HOST = os.environ.get("CISCO_SERIAL_CONTROL_HOST", "127.0.0.1")
ENDPOINT_PATH = CONTROL_DIR / "serial.endpoint.json"
_CONTROL_PORT = 0               # _control_server() 绑到随机端口后填入

# 已输入过的口令（明文, 过期时间）。只存内存，用来把"设备万一回显了口令"从
# 日志和回传内容里擦掉。TTL 到了就丢。
SECRET_TTL_SECONDS = 120.0
SECRET_PROMPT_RE = re.compile(r'(?:password|passwd|secret|口令)\s*:\s*$', re.IGNORECASE)
_secret_lock = threading.Lock()
_recent_secrets: list[tuple[str, float]] = []
_CONTROL_TOKEN = ""


def remember_secret(text: str) -> None:
    """记住刚输入的口令，供后续擦除回显用（太短的会误伤正常输出，不记）"""
    if not text or len(text) < 4:
        return
    with _secret_lock:
        _recent_secrets.append((text, time.time() + SECRET_TTL_SECONDS))


def scrub_secrets(text: str) -> str:
    """
    把刚输入过的口令从任何"要落盘或要回传给模型"的文本里擦掉

    这是防"设备回显口令"的兜底：IOS 在口令提示符下不回显，但万一在普通提示符下
    误开了密文输入、或设备行为特殊，口令就会出现在回显里——这里统一擦成占位符。
    """
    if not text or not _recent_secrets:
        return text
    now = time.time()
    with _secret_lock:
        _recent_secrets[:] = [(s, exp) for s, exp in _recent_secrets if exp > now]
        alive = list(_recent_secrets)
    for secret, _ in alive:
        if secret in text:
            text = text.replace(secret, "🙈<已隐藏>")
    return text


def _endpoint_alive() -> bool:
    """端点文件指向的控制通道还能连上吗（用来判断对方是活进程还是残留）"""
    try:
        info = json.loads(ENDPOINT_PATH.read_text(encoding="utf-8"))
        with socket.create_connection(("127.0.0.1", int(info["port"])), timeout=1):
            return True
    except Exception:
        return False


def cleanup_stale_endpoint() -> None:
    """启动时清掉失效的端点文件，免得看板连到一个已经死掉的进程"""
    try:
        if ENDPOINT_PATH.exists() and not _endpoint_alive():
            ENDPOINT_PATH.unlink(missing_ok=True)
            print("[cisco-serial-mcp] 清掉了失效的端点文件（上个进程的残留）", file=sys.stderr)
    except Exception:
        pass


def publish_endpoint(device: str = "") -> None:
    """
    公布"我持有设备会话" → 看板据此找到我

    只在真的持有会话时才公布；这样即使有残留进程同时活着，看板也永远找得到
    那个手里有设备的进程。
    """
    if not _CONTROL_PORT:
        return
    try:
        CONTROL_DIR.mkdir(parents=True, exist_ok=True)
        ENDPOINT_PATH.write_text(json.dumps({
            "channel": "serial",
            "port": _CONTROL_PORT,
            "token": _CONTROL_TOKEN,
            "pid": os.getpid(),
            "device": device,
            "ts": datetime.now().isoformat(timespec="milliseconds"),
        }, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        print(f"[cisco-serial-mcp] 端点公布失败: {exc}", file=sys.stderr)


def unpublish_endpoint() -> None:
    """不再持有任何会话 → 撤下端点（看板就会得到准确的"没有会话"答复）"""
    try:
        if ENDPOINT_PATH.exists():
            info = json.loads(ENDPOINT_PATH.read_text(encoding="utf-8"))
            if int(info.get("pid", -1)) == os.getpid():     # 只撤自己公布的
                ENDPOINT_PATH.unlink(missing_ok=True)
    except Exception:
        pass


# ---- 网页输入：处理与 TCP 控制服务 ----

def _apply_web_input(payload: dict) -> dict:
    """
    把一条"网页输入"写进设备

    两条重要约定：
    1. **网页输入不经过危险命令拦截** —— 按回车的是人不是模型。拦下来只会让正常配置
       寸步难行，所以这里不做拦截；取而代之的是全部以 source="web" 记入审计日志，
       和模型的操作（source="mcp"）分得清清楚楚。
    2. **密文输入不落盘** —— sensitive=true 时，流水与审计里只记占位符，
       明文只经过内存和串口线；同时记住它，万一设备回显也会被擦掉。
    """
    data = str(payload.get("data", ""))
    kind = str(payload.get("kind", "line"))
    flag_sensitive = bool(payload.get("sensitive"))

    sessions = list(session_manager.sessions.values())
    if not sessions:
        live_emit("err", "网页输入被丢弃：当前没有打开的串口会话（先用 serial_connect 连上设备）",
                  state="idle")
        return {"ok": False,
                "error": "当前没有打开的串口会话，先用 serial_connect 连上设备"}

    # 纵深防御：设备正停在口令提示符上时，无论看板有没有勾"密文"，一律按密文处理
    at_secret_prompt = any(SECRET_PROMPT_RE.search(s.rx_tail or "") for s in sessions)
    sensitive = flag_sensitive or at_secret_prompt
    if at_secret_prompt and not flag_sensitive:
        live_emit("ev", "检测到设备正等待口令输入 → 本次输入自动按密文处理（不记录明文）")

    if session_manager.exec_busy() and not session_manager.wait_idle(2.0):
        live_emit("ev", "⚠ 网页输入与模型正在执行的命令交叉了（两边输出会混在一起）")

    if sensitive and kind != "raw":
        remember_secret(data)

    shown = "🙈 密文输入（已隐藏）" if sensitive else (data if data.strip() else "(回车)")
    written = 0
    for s in sessions:
        try:
            s.write_raw(data if kind == "raw" else data + "\r", raw=(kind == "raw"))
            live_emit("tx", shown, port=s.port, source="web", sensitive=sensitive)
            audit_log("EXECUTE", sessionId=s.session_id, port=s.port, source="web",
                      command=("***（密文输入，未记录明文）" if sensitive else data),
                      kind=kind)
            written += 1
        except Exception as exc:
            live_emit("err", f"网页输入写入失败: {exc}", port=s.port)
    if written:
        session_manager.note_web_activity()      # 让人流优先：模型稍后发命令时会让路
    return {"ok": written > 0, "written": written, "sensitive": sensitive,
            "autoSensitive": bool(at_secret_prompt and not flag_sensitive)}


def _handle_control_request(payload: dict) -> dict:
    """处理一条控制请求（只绑本机，但网页仍可能被第三方网页 CSRF，故校验 token）"""
    if not _CONTROL_TOKEN or payload.get("token") != _CONTROL_TOKEN:
        return {"ok": False, "error": "token 不匹配"}
    action = str(payload.get("action", "")).lower()
    if action == "input":
        return _apply_web_input(payload)
    if action == "release":
        ids = session_manager.release_all(reason="看板请求释放")
        return {"ok": True, "released": len(ids), "sessionIds": ids}
    if action == "status":
        return {"ok": True, "pid": os.getpid(), "sessions": session_manager.list_sessions(),
                "busy": session_manager.exec_busy()}
    return {"ok": False, "error": f"未知 action: {action}"}


def _serve_control_conn(conn: "socket.socket") -> None:
    """一条控制连接：按行收发 JSON"""
    try:
        with conn:
            conn.settimeout(10)
            fh = conn.makefile("rwb")
            for raw in fh:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except ValueError:
                    reply = {"ok": False, "error": "请求不是合法 JSON"}
                else:
                    try:
                        reply = _handle_control_request(payload)
                    except Exception as exc:
                        reply = {"ok": False, "error": str(exc)}
                fh.write((json.dumps(reply, ensure_ascii=False) + "\n").encode("utf-8"))
                fh.flush()
    except Exception:
        pass


def _control_server() -> None:
    """
    网页控制通道（只绑本机 127.0.0.1，端口由系统随机分配）

    刻意**不设** SO_REUSEADDR：Windows 上它允许两个进程绑同一端口（本该直接失败），
    会造成"令牌在 A、连接进 B"的分裂。随机端口本身就不会撞车。
    """
    global _CONTROL_PORT
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind((CONTROL_HOST, 0))
    except OSError as exc:
        print(f"[cisco-serial-mcp] 控制通道绑定失败（{exc}）—— 网页输入/释放将不可用",
              file=sys.stderr)
        return
    _CONTROL_PORT = srv.getsockname()[1]
    srv.listen(8)
    print(f"[cisco-serial-mcp] 控制通道就绪 {CONTROL_HOST}:{_CONTROL_PORT}"
          f"（pid {os.getpid()}，有会话时才公布端点）", file=sys.stderr)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            time.sleep(0.5)
            continue
        threading.Thread(target=_serve_control_conn, args=(conn,), daemon=True).start()


# ============ 提示符 / 分页 / 控制字符处理 ============

# 设备提示符：整行就是 "名字(子模式)?#或>"。
# 注意：设备名未知时这是兜底形态匹配，输出里形似提示符的文本会误命中
# （例如 show switch 的表头 "Switch#"），所以一旦学到设备名就要用带名字的版本。
PROMPT_RE = re.compile(r'^[A-Za-z0-9_.-]+(?:\([a-z0-9-]+\))?[#>]$')
# 登录/口令提示
CREDENTIAL_RE = re.compile(r'(?:username|login|password)\s*:\s*$', re.IGNORECASE)
# 分页提示（IOS: --More-- ；部分平台: <--- More --->）
MORE_RE = re.compile(r'(?:<+)?-+\s*[Mm]ore\s*-+(?:>+)?')
# 分页提示 + 设备随后用来擦掉它的那一串「退格/空格」。
# 只用于清理【显示/审计】文本；检测分页必须用上面的 MORE_RE 直接匹配原始文本。
# 注意必须带上前导空格：设备是 "\r\n --More-- " 这样发的。
MORE_NOISE_RE = re.compile(r'[ \t]*(?:<+)?-+\s*[Mm]ore\s*-+(?:>+)?(?:[ \x08]*\x08[ \x08]*)?')


def clean_console_text(text: str) -> str:
    """去掉退格控制字符与分页提示残留，便于提示符/模式识别与阅读"""
    if not text:
        return ""
    # 顺序要紧：先带标记一起吃掉「擦除序列」（那时退格还在，才认得出来），
    # 再统一删掉剩余的退格字符。反过来的话擦除序列就变成一串孤立空格。
    clean = MORE_NOISE_RE.sub('', text)
    clean = clean.replace('\x08', '').replace(' \b', '')
    return clean


def prompt_name_of(prompt: str) -> str:
    """从 "SW3(config-if)#" 这样的提示符里取出设备名 "SW3"；取不到返回空串"""
    if not prompt or prompt == "unknown":
        return ""
    m = re.match(r'^([A-Za-z0-9_.-]+)(?:\([a-z0-9-]+\))?[#>]$', prompt.strip())
    return m.group(1) if m else ""


def _prompt_re(name: str = "") -> re.Pattern:
    """
    提示符正则（匹配"整行"）

    给了设备名就只认这个设备名的提示符 —— 这一点非常关键：IOS 的输出里到处是
    形似提示符的文本（`show switch` 的表头就是 "Switch#   Role ..."），只按通用
    形态匹配会把它当成"命令执行完毕"而提前收工，把输出腰斩
    （曾实测踩到：show switch 只回来半行）。
    """
    if name:
        return re.compile(r'^' + re.escape(name) + r'(?:\([a-z0-9-]+\))?[#>]$', re.IGNORECASE)
    return PROMPT_RE


def _last_nonempty_line(text: str) -> str:
    """最后一行非空内容（去掉退格/分页残留后）"""
    lines = [ln.strip() for ln in clean_console_text(text).splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def has_prompt(text: str, name: str = "") -> bool:
    """输出末尾是否已停在设备提示符上（最后一行整行就是提示符）"""
    if not text:
        return False
    return bool(_prompt_re(name).match(_last_nonempty_line(text)))


def detect_device_mode(output: str, name: str = "") -> str:
    """
    从输出中检测设备当前模式

    Args:
        output: 设备输出
        name: 已知设备名；给了就只认该设备名的提示符（防止误命中输出正文）

    Returns:
        "SW3#"(特权) / "SW3>"(用户) / "SW3(config)#"(全局) / "SW3(config-if)#"(接口) / "unknown"
    """
    if not output:
        return "unknown"

    pattern = _prompt_re(name)
    last = _last_nonempty_line(output)
    if pattern.match(last):
        return last

    # 提示符后面可能又跟了设备异步打印的内容 → 往前多找几行
    lines = [ln.strip() for ln in clean_console_text(output).splitlines() if ln.strip()]
    for line in reversed(lines[-8:]):
        if pattern.match(line):
            return line

    return "unknown"


# ============ 串口辅助 ============

# 看上去像控制台/串口转换器的特征（用于 port="auto" 时挑选）
CONSOLE_HINTS = ("usb", "uart", "cp210", "ch340", "ftdi", "prolific", "pl2303", "silicon labs")


def _is_bluetooth_port(info) -> bool:
    hwid = (info.hwid or "").upper()
    desc = (info.description or "").upper()
    return "BTHENUM" in hwid or "BLUETOOTH" in hwid or "蓝牙" in (info.description or "") or "BLUETOOTH" in desc


def _looks_like_console_adapter(info) -> bool:
    if _is_bluetooth_port(info):
        return False
    haystack = f"{info.hwid or ''} {info.description or ''} {info.manufacturer or ''}".lower()
    return any(h in haystack for h in CONSOLE_HINTS)


def list_serial_ports() -> list[dict]:
    """枚举本机串口，并标注哪个像 USB 控制台线"""
    result = []
    for info in sorted(list_ports.comports(), key=lambda i: i.device):
        result.append({
            "port": info.device,
            "description": info.description or "",
            "manufacturer": info.manufacturer or "",
            "hwid": info.hwid or "",
            "bluetooth": _is_bluetooth_port(info),
            "likelyConsoleAdapter": _looks_like_console_adapter(info),
        })
    return result


def resolve_port(port: str) -> str:
    """端口解析：留空或 auto 时自动挑选像控制台线的 USB 串口"""
    port = (port or "").strip()
    if port and port.lower() not in ("auto", "?"):
        return port

    ports = list_serial_ports()
    if not ports:
        raise ConnectionError(
            "本机没有枚举到任何串口。请检查 USB 转串口线是否插好、驱动是否安装"
            "（设备管理器里应出现 COMx），必要时用 serial_list_ports 复查。")

    candidates = [p for p in ports if p["likelyConsoleAdapter"]]
    if not candidates:
        candidates = [p for p in ports if not p["bluetooth"]]
    if not candidates:
        raise ConnectionError(
            "只找到蓝牙虚拟串口，未找到可用控制台线: "
            + ", ".join(p["port"] for p in ports)
            + "。请插好 USB 转串口线后重试，或显式指定 port。")

    if len(candidates) > 1:
        raise ConnectionError(
            "检测到多个候选串口，无法自动选择，请显式指定 port: "
            + ", ".join(f"{p['port']}({p['description']})" for p in candidates))

    return candidates[0]["port"]


def parse_baud_candidates(baud) -> list[int]:
    """
    解析波特率参数

    - "auto"/""/None → [9600, 115200]（先试 9600，无输出再试 115200）
    - "9600,115200"  → [9600, 115200]
    - 9600           → [9600]
    """
    if baud is None:
        return [9600, 115200]
    if isinstance(baud, int):
        return [baud]
    text = str(baud).strip().lower()
    if text in ("", "auto", "detect"):
        return [9600, 115200]
    out: list[int] = []
    for part in re.split(r'[,\s]+', text):
        if not part:
            continue
        if not part.isdigit():
            raise ValueError(f"无法识别的波特率: {part!r}（应为数字或 'auto'）")
        out.append(int(part))
    if not out:
        return [9600, 115200]
    return out


# ============ 串口会话 ============

@dataclass
class SerialSession:
    """一个已打开的串口会话"""
    session_id: str
    port: str
    baud: int
    ser: serial.Serial
    detected: bool = True
    connected_at: datetime = field(default_factory=datetime.now)
    # 打开端口时"敲回车探测"读到的内容。必须带进登录/模式识别，
    # 否则探测阶段看到的提示符会被丢掉，连接结果白白报成 unknown。
    probe_text: str = ""
    # 学到的设备名（如 "JS-KPL-CORE"）。有了它，提示符识别就只认这个设备的提示符，
    # 不会再把输出正文里形似提示符的文本（show switch 表头 "Switch#"）当真。
    prompt_name: str = ""
    # 最近一段设备回显（只留尾部 200 字符）。用于判断"设备是不是正停在口令提示符上"，
    # 从而把网页输入自动按密文处理（勾没勾"密文"都算）。
    rx_tail: str = ""

    # 读线程共享缓冲
    _buf: bytearray = field(default_factory=bytearray, repr=False)
    _offset: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: Optional[threading.Thread] = None
    read_error: Optional[str] = None

    def start_reader(self) -> None:
        self._thread = threading.Thread(target=self._reader_loop, name=f"serial-rx-{self.port}",
                                        daemon=True)
        self._thread.start()

    def _reader_loop(self) -> None:
        # 回显按"小批"刷进实时镜像：来一个字就写一行会让看板很难读，
        # 但等太久又不叫实时了；折中是静默 50ms 就落一批。
        pending = bytearray()
        last_data = time.time()

        def flush_pending():
            if pending:
                text = bytes(pending).decode("utf-8", errors="replace")
                pending.clear()
                # 设备万一回显了口令，落盘前先擦掉（IOS 在口令提示符下不回显，这是兜底）
                self.rx_tail = scrub_secrets((self.rx_tail + text)[-200:])
                live_emit("rx", scrub_secrets(text), port=self.port)

        while not self._stop.is_set():
            try:
                waiting = self.ser.in_waiting
            except Exception:
                waiting = 0
            try:
                data = self.ser.read(waiting if waiting else 1)
            except Exception as exc:  # 串口被拔掉 / 驱动异常
                if not self._stop.is_set():
                    self.read_error = f"串口读取失败: {exc}"
                    live_emit("err", self.read_error, port=self.port)
                flush_pending()
                return
            now = time.time()
            if data:
                with self._lock:
                    self._buf.extend(data)
                pending.extend(data)
                last_data = now
            elif pending and (now - last_data) >= 0.05:
                flush_pending()
        flush_pending()

    def read_new(self) -> str:
        """取出并消费自上次调用以来的新数据"""
        with self._lock:
            if self._offset >= len(self._buf):
                return ""
            chunk = bytes(self._buf[self._offset:])
            self._offset = len(self._buf)
            # 缓冲区回收，避免长会话无限增长
            if self._offset > 65536:
                del self._buf[:self._offset]
                self._offset = 0
        return chunk.decode("utf-8", errors="replace")

    def send_line(self, text: str = "") -> None:
        """发送一行（串口控制台用 CR 作为回车）"""
        if self.read_error:
            raise ConnectionError(self.read_error)
        self.ser.write((text + "\r").encode("utf-8", errors="replace"))
        self.ser.flush()
        live_emit("tx", text if text.strip() else "(回车)", port=self.port, source="mcp")

    def write_raw(self, data: str, raw: bool = False) -> None:
        """
        原样写字节（不追加回车、不自己记流水）

        给"网页输入"用：行模式下把 CR 拼好再传进来；raw 模式下直接写控制字符
        （Ctrl+C = 0x03 之类），所以按 latin-1 编码，保证单字节控制符原样落地。
        """
        if self.read_error:
            raise ConnectionError(self.read_error)
        payload = data.encode("latin-1", errors="replace") if raw \
            else data.encode("utf-8", errors="replace")
        self.ser.write(payload)
        self.ser.flush()

    def send_break(self, duration_ms: int = 500) -> None:
        """发送 Break 信号（进 ROMMON / 密码恢复用）"""
        if self.read_error:
            raise ConnectionError(self.read_error)
        self.ser.send_break(duration=duration_ms / 1000.0)
        live_emit("ev", f"BREAK 信号 {duration_ms}ms", port=self.port)

    def close(self) -> None:
        self._stop.set()
        try:
            self.ser.close()
        except Exception:
            pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def to_dict(self) -> dict:
        return {
            "sessionId": self.session_id,
            "port": self.port,
            "baud": self.baud,
            "channel": "serial",
            "connectedAt": self.connected_at.isoformat(),
            "detected": self.detected,
            "readError": self.read_error,
        }


# 耗时命令：自动加大等待时间（与 telnet 版一致）
LONG_RUNNING_COMMANDS = ('ping', 'traceroute', 'tracert', 'show tech', 'copy',
                         'write', 'reload', 'debug')


class SerialSessionManager:
    """串口会话管理器"""

    def __init__(self):
        self.sessions: dict[str, SerialSession] = {}
        self._connect_lock = threading.Lock()
        # "模型正在执行命令"标志：网页输入会据此稍等一下，避免两边输出交叉
        self._exec_busy = threading.Event()
        # 人刚在网页上操作过的时间戳：模型发命令前会让路几秒，
        # 免得模型把缓冲里的数据清掉、把人正在看的输出冲走
        self._web_quiet_until = 0.0

    # ---------- 底层打开 / 探测 ----------

    @staticmethod
    def _open(port: str, baud: int, data_bits: int, parity: str, stopbits: int) -> serial.Serial:
        try:
            ser = serial.Serial(
                port=port,
                baudrate=baud,
                bytesize=data_bits,
                parity=parity,
                stopbits=stopbits,
                timeout=0.1,
                write_timeout=2.0,
                rtscts=False,
                dsrdtr=False,
                xonxoff=False,
            )
        except serial.SerialException as exc:
            msg = str(exc)
            if "拒绝访问" in msg or "Access is denied" in msg or "PermissionError" in msg:
                raise ConnectionError(
                    f"串口 {port} 被其他程序占用（常见是 MobaXterm / SecureCRT / 另一个会话）。"
                    f"请关闭占用该口的程序后重试。原始错误: {msg}")
            raise ConnectionError(f"打开串口 {port} 失败: {msg}")

        # 多数 USB 控制台线需要 DTR/RTS 置位才能收数据
        try:
            ser.dtr = True
            ser.rts = True
        except Exception:
            pass
        return ser

    @staticmethod
    def _probe(ser: serial.Serial, seconds: float = 1.6) -> str:
        """
        敲回车探测设备是否有输出

        返回探测期间收到的文本（空字符串表示该波特率下没有任何数据）
        """
        buf = bytearray()
        end = time.time() + seconds
        ser.reset_input_buffer()
        ser.write(b"\r")
        ser.flush()
        while time.time() < end:
            data = ser.read(ser.in_waiting or 1)
            if data:
                buf.extend(data)
            elif buf:
                # 已有输出后再静默 0.3s 就认为读完了
                break
        return bytes(buf).decode("utf-8", errors="replace")

    # ---------- 登录 / 初始化 ----------

    def _login(self, session: SerialSession, username: str, password: str,
               enable_password: str, deadline: float) -> str:
        """
        按设备提示逐步完成登录与 enable

        串口控制台通常不需要用户名（line con 0 只有 password），
        这里兼容 Username:/Login:/Password: 与 "Press RETURN to get started"。
        """
        acc = session.probe_text or ""
        enable_pending = False
        for _ in range(10):
            chunk = self._read_until_quiet(session, 1.2)
            acc += chunk
            last = [ln.strip() for ln in clean_console_text(acc).splitlines() if ln.strip()]
            last = last[-1] if last else ""
            low = last.lower()

            # 口令/用户名提示 → 按类型发送凭据
            if CREDENTIAL_RE.search(last):
                if low.startswith(('username', 'login')):
                    if not username:
                        return acc
                    session.send_line(username)
                elif enable_pending:
                    if not enable_password:
                        return acc
                    session.send_line(enable_password)
                else:
                    if not password:
                        return acc
                    session.send_line(password)
                continue

            # "Press RETURN to get started"
            if 'press return' in acc.lower() and not last:
                session.send_line("")
                continue

            # 用户模式 ">" → 进特权模式
            if last.endswith('>'):
                if not enable_password:
                    return acc
                session.send_line("enable")
                enable_pending = True
                continue

            # 特权模式 "#" → 完成
            if last.endswith('#'):
                return acc

            if time.time() > deadline:
                return acc

        return acc

    @staticmethod
    def _read_until_quiet(session: SerialSession, seconds: float) -> str:
        """持续读取 seconds 秒（无数据也等满），返回收到的文本"""
        buf = ""
        end = time.time() + seconds
        while time.time() < end:
            chunk = session.read_new()
            if chunk:
                buf += chunk
            time.sleep(0.05)
        return buf

    # ---------- 对外：连接 ----------

    def connect(self, port: str = "", baud="auto", timeout_ms: int = 8000,
                data_bits: int = 8, parity: str = "N", stopbits: int = 1,
                username: str = "", password: str = "", enable_password: str = "") -> dict:
        """
        打开串口并完成登录

        Returns:
            dict(session_id, port, baud, device_mode, detected, warning)
        """
        with self._connect_lock:
            resolved = resolve_port(port)
            candidates = parse_baud_candidates(baud)
            deadline = time.time() + max(5.0, timeout_ms / 1000.0)

            chosen: Optional[serial.Serial] = None
            chosen_baud = candidates[0]
            chosen_probe = ""
            detected = False
            warning = ""
            fallback: Optional[tuple[int, str]] = None

            for cand in candidates:
                ser = self._open(resolved, cand, data_bits, parity, stopbits)
                probe = ""
                try:
                    probe = self._probe(ser)
                except Exception:
                    probe = ""
                if probe and has_prompt(probe):
                    chosen, chosen_baud, detected, chosen_probe = ser, cand, True, probe
                    break
                if probe and fallback is None:
                    # 有数据但没提示符（典型：设备正卡在 --More-- 分页上）：
                    # "有可读数据"本身就说明此波特率是对的，先记下来继续试后面的
                    # 候选；若没有一个候选给出提示符，就回退到这个能通数据的波特率。
                    # 不能在这里直接关掉它去选一个毫无数据的候选 —— 那会把会话连在
                    # 错误的波特率上（曾实测踩到）。
                    fallback = (cand, probe)
                ser.close()

            if chosen is None:
                # 没有任何候选给到提示符：优先回退到"有数据"的那个波特率
                if fallback is not None:
                    chosen_baud, chosen_probe = fallback
                else:
                    chosen_baud, chosen_probe = candidates[0], ""
                chosen = self._open(resolved, chosen_baud, data_bits, parity, stopbits)
                detected = False

            if not detected:
                warning = ("未在候选波特率上探测到设备提示符"
                           f"（已试: {', '.join(str(c) for c in candidates)}）。"
                           "设备可能已关机 / 未连好 / 波特率特殊，"
                           "可显式指定 baud 重连，或用 serial_send_break 唤出设备。")

            session = SerialSession(
                session_id=str(uuid.uuid4()),
                port=resolved,
                baud=chosen_baud,
                ser=chosen,
                detected=detected,
                probe_text=chosen_probe,
            )
            session.start_reader()
            self.sessions[session.session_id] = session

            try:
                login_output = self._login(session, username, password, enable_password, deadline)

                # 处于配置模式则退回特权模式
                if '(config' in login_output:
                    session.send_line("end")
                    login_output += self._read_until_quiet(session, 0.6)

                mode = detect_device_mode(login_output) if login_output else "unknown"
                # 顺手学下设备名，供后续所有提示符识别使用
                session.prompt_name = prompt_name_of(mode)

                # 特权模式下关闭分页（分页还有自动送空格的兜底）
                if mode.endswith('#'):
                    session.send_line("terminal length 0")
                    self._read_until_quiet(session, 0.6)
                    # 注意：detect_device_mode() 无匹配时返回字符串 "unknown"，它是【真值】，
                    # 所以这里必须显式比较，不能用 `... or mode` —— 否则设备其实已进特权模式，
                    # 却被 "unknown" 覆盖掉（曾实测踩到，表现为 terminal length 0 明明下发成功
                    # 但连接结果报 unknown）。
                    refreshed = detect_device_mode(session.read_new(), session.prompt_name)
                    if refreshed != "unknown":
                        mode = refreshed
                        session.prompt_name = prompt_name_of(mode) or session.prompt_name

                # 会话可用 → 公布端点，让看板能找过来（网页输入/释放都靠它）
                publish_endpoint(device=resolved)

                return {
                    "session_id": session.session_id,
                    "port": resolved,
                    "baud": chosen_baud,
                    "device_mode": mode,
                    "prompt_name": session.prompt_name,
                    "detected": detected,
                    "warning": warning,
                }
            except Exception:
                session.close()
                self.sessions.pop(session.session_id, None)
                raise

    # ---------- 对外：执行命令 ----------

    def exec_busy(self) -> bool:
        """模型是否正在执行命令"""
        return self._exec_busy.is_set()

    def note_web_activity(self, seconds: float = 3.0) -> None:
        """记一次"人刚在网页上操作过"：接下来几秒内模型的命令会让路"""
        self._web_quiet_until = time.time() + seconds

    def wait_web_quiet(self, cap: float = 4.0) -> float:
        """人刚操作过就先等一会儿，返回实际等待秒数"""
        remain = self._web_quiet_until - time.time()
        if remain <= 0:
            return 0.0
        wait = min(remain, cap)
        time.sleep(wait)
        return wait

    def wait_idle(self, seconds: float) -> bool:
        """等模型手上的命令跑完；返回 True 表示已空闲"""
        end = time.time() + seconds
        while time.time() < end:
            if not self._exec_busy.is_set():
                return True
            time.sleep(0.05)
        return not self._exec_busy.is_set()

    def execute(self, session_id: str, command: str, wait_ms: int = 2000,
                confirm: bool = False) -> str:
        """
        在指定串口会话执行命令（对外入口）

        这里只多做一件事：标记"模型正在执行命令"。网页输入会先等这个标志清掉，
        免得两边的输出交叉在一起。真正的逻辑在 _execute_locked()。
        """
        # 人刚在网页上敲过东西 → 让路，别把人正在看的输出冲掉
        waited = self.wait_web_quiet()
        if waited:
            live_emit("ev", f"你刚在网页上操作过 → 模型让路 {waited:.1f}s 再发命令")
        self._exec_busy.set()
        try:
            return self._execute_locked(session_id, command, wait_ms, confirm)
        finally:
            self._exec_busy.clear()

    def _execute_locked(self, session_id: str, command: str, wait_ms: int = 2000,
                        confirm: bool = False) -> str:
        """在指定串口会话执行命令，返回设备输出"""
        if session_id not in self.sessions:
            raise ValueError(f"会话不存在: {session_id}")

        session = self.sessions[session_id]

        # 危险命令拦截：发送到设备之前
        reason = check_dangerous_command(command)
        if reason and not confirm:
            audit_log("BLOCKED", sessionId=session_id, port=session.port,
                      baud=session.baud, command=command, reason=reason)
            live_emit("ev", f"⛔ 危险命令已拦截（未下发设备）: {command} —— {reason}",
                      port=session.port)
            raise DangerousCommandError(reason)

        command_lower = command.lower().strip()
        for cmd in LONG_RUNNING_COMMANDS:
            if command_lower.startswith(cmd):
                wait_ms = max(wait_ms, 12000)
                break

        wait_seconds = wait_ms / 1000.0

        # 清掉发送前残留的旧数据，避免上一次的尾巴混进来
        session.read_new()

        session.send_line(command)

        output = ""
        start_time = time.time()
        last_data_time = start_time
        more_count = 0

        while True:
            now = time.time()
            if now - start_time >= wait_seconds:
                break

            chunk = session.read_new()
            if chunk:
                output += chunk
                last_data_time = now
                clean_tail = clean_console_text(output)

                # 分页：自动送空格翻页
                # 关键：必须在【原始输出】尾部找 --More--。clean_console_text() 会把
                # 分页标记本身删掉，若拿清理后的文本去找就永远匹配不到 —— 曾实测因此
                # 卡在 show version 的 --More-- 上等到超时。
                if MORE_RE.search(output[-80:]):
                    more_count += 1
                    if more_count > 2000:      # 防止病态输出死循环
                        break
                    session.ser.write(b" ")
                    session.ser.flush()
                    time.sleep(0.1)
                    continue

                if has_prompt(output, session.prompt_name):
                    # 认出提示符后不要立刻收工：9600 波特率下输出是"涓流"过来的
                    # （每秒约 960 字符），固定 0.15s 的宽限期只能捞到下一小段，
                    # 于是把输出腰斩（曾实测踩到）。改成等"真正安静下来"：
                    # 0.4s 无新数据才确认完成，最多再多等 3s；期间若又来了内容
                    # 且末尾不再是提示符，就退回主循环继续等。
                    quiet_since = time.time()
                    confirm_until = quiet_since + 3.0
                    still_done = True
                    while time.time() < confirm_until:
                        time.sleep(0.05)
                        extra = session.read_new()
                        if extra:
                            output += extra
                            quiet_since = time.time()
                            if not has_prompt(output, session.prompt_name):
                                still_done = False
                                break
                        elif time.time() - quiet_since >= 0.4:
                            break
                    if still_done:
                        break
                    continue
            else:
                quiet = now - last_data_time
                if output:
                    # 正常路径：认出本设备的提示符 + 短暂静默 → 收工
                    if quiet >= 0.8 and has_prompt(output, session.prompt_name):
                        break
                    # 兜底：设备名可能被改过 / 提示符不是标准形态，拉长静默阈值再认通用形态。
                    # 宁可多等两秒，也不要把输出腰斩。
                    if session.prompt_name and quiet >= 2.5 and has_prompt(output):
                        break
                time.sleep(0.03)

        if session.read_error:
            output += f"\n[串口异常] {session.read_error}"

        # 返回前清掉退格/分页擦除残渣，避免 --More-- 的 \b 序列污染可读性。
        # （循环里检测分页用的始终是原始 output，不受这一步影响。）
        display = scrub_secrets(clean_console_text(output))

        if command.strip():
            audit_log("EXECUTE", sessionId=session_id, port=session.port,
                      baud=session.baud, command=command,
                      dangerous=bool(reason),
                      paginated=more_count,
                      deviceMode=detect_device_mode(display, session.prompt_name),
                      outputPreview=truncate_for_audit(display))

        return display

    # ---------- 对外：Break ----------

    def send_break(self, session_id: str, duration_ms: int = 500,
                   repeat: int = 1, interval_ms: int = 300) -> None:
        """发送 Break 信号（可重复发送，用于打断启动过程进 ROMMON）"""
        if session_id not in self.sessions:
            raise ValueError(f"会话不存在: {session_id}")
        session = self.sessions[session_id]
        for i in range(max(1, min(repeat, 20))):
            session.send_break(duration_ms)
            if i + 1 < repeat:
                time.sleep(max(0, interval_ms) / 1000.0)
        audit_log("BREAK", sessionId=session_id, port=session.port,
                  durationMs=duration_ms, repeat=repeat)

    def release_all(self, reason: str = "看板请求释放") -> list[str]:
        """
        关闭并释放全部串口会话，返回被释放的会话ID列表

        这是"把 COM 口让给 MobaXterm"的入口：串口独占，我握着口你就打不开。
        正在执行的命令会读到异常并返回错误（不会静默丢数据）——这是有意的：
        让出串口优先于把某条命令跑完。
        """
        ids = list(self.sessions.keys())
        for sid in ids:
            session = self.sessions.pop(sid, None)
            if session is None:
                continue
            try:
                session.close()
            except Exception:
                pass
            audit_log("RELEASE", sessionId=sid, port=session.port, reason=reason)
            live_emit("ev", f"串口 {session.port} 已释放（{reason}）",
                      port=session.port, state="idle")
        if not self.sessions:
            unpublish_endpoint()        # 没有会话了 → 撤下端点
        return ids

    def list_sessions(self) -> list[dict]:
        return [s.to_dict() for s in self.sessions.values()]

    def disconnect(self, session_id: str) -> bool:
        if session_id not in self.sessions:
            raise ValueError(f"会话不存在: {session_id}")
        session = self.sessions.pop(session_id)
        session.close()
        if not self.sessions:
            unpublish_endpoint()        # 没有会话了 → 撤下端点
        return True


session_manager = SerialSessionManager()


# ============ MCP 工具定义 ============

@mcp.tool()
async def serial_list_ports() -> str:
    """
    列出本机所有串口（COM 口）

    Returns:
        JSON 数组，每项含 port / description / manufacturer / hwid /
        bluetooth（是否蓝牙虚拟口）/ likelyConsoleAdapter（是否像 USB 转串口控制台线）。
        连接前建议先调用本工具确认控制台线的实际 COM 口号（插拔后口号可能变化）。
    """
    ports = list_serial_ports()
    return json.dumps({
        "success": True,
        "count": len(ports),
        "ports": ports,
    }, ensure_ascii=False)


@mcp.tool()
async def serial_connect(port: str = "", baud: str = "auto", timeout_ms: int = 8000,
                         data_bits: int = 8, parity: str = "N", stopbits: int = 1,
                         username: str = "", password: str = "",
                         enable_password: str = "") -> str:
    """
    打开本机串口（Console 口）连接 Cisco 设备

    Args:
        port: 串口号，如 "COM3"。留空或 "auto" 时自动挑选像 USB 控制台线的串口
              （自动排除蓝牙虚拟口；若有多个候选会报错并列出，请你显式指定）
        baud: 波特率。默认 "auto" = 先试 9600，无输出再试 115200；
              也可写 "9600"、或 "9600,115200" 指定尝试顺序
        timeout_ms: 连接与登录的总超时（毫秒，默认 8000）
        data_bits: 数据位，默认 8
        parity: 校验位，默认 "N"（无校验）
        stopbits: 停止位，默认 1
        username: 登录用户名（控制台一般不需要，设备提示 Username:/Login: 时使用）
        password: 登录口令（设备提示 Password: 时自动填写）
        enable_password: enable 口令（处于 ">" 用户模式时自动 enable）

    Returns:
        JSON：
        - success: 是否成功
        - sessionId: 会话ID（后续 serial_execute 使用）
        - port / baud: 实际使用的串口与波特率
        - deviceMode: 设备当前模式（如 "SW3#"、"SW3>"）、"unknown" 表示未识别到提示符
        - warning: 未探测到设备时的提示（设备可能关机/波特率特殊）

    说明：串口是独占资源。若 MobaXterm 等程序已占用该 COM 口，本工具会明确报错。
    """
    try:
        result = await asyncio.to_thread(
            session_manager.connect,
            port, baud, timeout_ms, data_bits, parity, stopbits,
            username, password, enable_password,
        )
        audit_log("CONNECT", sessionId=result["session_id"], port=result["port"],
                  baud=result["baud"], detected=result["detected"],
                  deviceMode=result["device_mode"], promptName=result["prompt_name"])
        live_emit("ev",
                  f"串口已连接 {result['port']} @ {result['baud']}bps，设备模式 {result['device_mode']}"
                  + (f"，已记住设备名 {result['prompt_name']}" if result["prompt_name"] else "")
                  + (f"｜{result['warning']}" if result["warning"] else ""),
                  port=result["port"], state="connected")
        payload = {
            "success": True,
            "sessionId": result["session_id"],
            "port": result["port"],
            "baud": result["baud"],
            "deviceMode": result["device_mode"],
            "message": "串口连接成功" if result["detected"] else "串口已打开，但未探测到设备",
        }
        if result["prompt_name"]:
            payload["promptName"] = result["prompt_name"]
        if result["warning"]:
            payload["warning"] = result["warning"]
        return json.dumps(payload, ensure_ascii=False)
    except (ConnectionError, ValueError, serial.SerialException) as e:
        audit_log("CONNECT_FAILED", port=port, baud=baud, error=str(e))
        live_emit("err", f"串口连接失败: {e}", port=port)
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def serial_execute(session_id: str, command: str, wait_ms: int = 2000,
                         confirm: bool = False) -> str:
    """
    在指定串口会话执行命令

    Args:
        session_id: 会话ID（来自 serial_connect）
        command: 要发送的命令
        wait_ms: 最大等待时间（毫秒，默认2000）。
                 检测到设备提示符会立即返回；ping/traceroute/show tech 等耗时命令自动加长到12秒。
                 出现 --More-- 分页会自动送空格继续读，无需手动处理。
        confirm: 确认执行危险命令，默认 False。
                 命中危险命令规则（reload、write memory/erase、覆盖配置、shutdown、
                 账号/AAA/line 变更、debug 等）时命令会被拦截不执行，
                 返回 needsConfirmation=true 和命中原因；
                 此时必须先向用户说明风险并获得明确同意，再携带 confirm=true 重新调用。

    Returns:
        JSON：
        - success: 是否成功
        - output: 命令输出内容
        - deviceMode: 当前设备模式（如 SW3#、SW3(config)#）
        - needsConfirmation / matchedRule: 仅在命中危险命令规则且未确认时出现
    """
    try:
        output = await asyncio.to_thread(
            session_manager.execute, session_id, command, wait_ms, confirm
        )
        sess = session_manager.sessions.get(session_id)
        return json.dumps({
            "success": True,
            "output": output if output else "",
            "deviceMode": detect_device_mode(output, sess.prompt_name if sess else ""),
        }, ensure_ascii=False)
    except DangerousCommandError as e:
        return json.dumps({
            "success": False,
            "needsConfirmation": True,
            "matchedRule": e.reason,
            "command": command,
            "message": "命令命中危险命令规则，已拦截未执行。请先向用户说明风险并获得明确同意后，"
                       "携带 confirm=true 重新调用本工具。",
        }, ensure_ascii=False)
    except (ValueError, ConnectionError, serial.SerialException) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)


@mcp.tool()
async def serial_send_break(session_id: str, duration_ms: int = 500,
                            repeat: int = 1, interval_ms: int = 300) -> str:
    """
    发送串口 Break 信号（Telnet/SSH 做不到，Console 口独有）

    典型用途：
    - 打断设备启动过程进入 ROMMON（密码恢复 / 救砖）：设备上电后立刻反复发送
    - 打断卡住的启动流程或让设备重新进入加载状态
    - 某些平台用它唤出被挂起的控制台

    Args:
        session_id: 会话ID（来自 serial_connect）
        duration_ms: 每次 Break 持续时间（毫秒，默认 500）
        repeat: 连续发送次数（默认 1，最多 20）
        interval_ms: 多次之间的间隔（毫秒，默认 300）

    Returns:
        JSON：success / message / 建议的后续观察方式
    """
    try:
        await asyncio.to_thread(
            session_manager.send_break, session_id, duration_ms, repeat, interval_ms
        )
        return json.dumps({
            "success": True,
            "message": f"已发送 Break：{repeat} 次 × {duration_ms}ms（间隔 {interval_ms}ms）",
            "hint": "接着用 serial_execute(session_id, '', wait_ms=3000) 读取设备回显，"
                    "看是否出现 ROMMON 提示符（如 'rommon 1 >'）。",
        }, ensure_ascii=False)
    except (ValueError, ConnectionError, serial.SerialException) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)


@mcp.tool()
def serial_list_sessions() -> str:
    """
    列出所有活动的串口会话

    Returns:
        会话信息（含 sessionId / port / baud / 连接时间 / 是否探测到设备）
    """
    sessions = session_manager.list_sessions()
    if not sessions:
        return "当前没有活动会话"
    result = "活动串口会话列表:\n"
    for s in sessions:
        result += f"- ID: {s['sessionId']}\n"
        result += f"  串口: {s['port']} @ {s['baud']} bps\n"
        result += f"  连接时间: {s['connectedAt']}\n"
        if s["readError"]:
            result += f"  异常: {s['readError']}\n"
    return result


@mcp.tool()
async def serial_disconnect(session_id: str) -> str:
    """
    断开指定串口会话（关闭并释放 COM 口，释放后 MobaXterm 才能占用）

    Args:
        session_id: 会话ID

    Returns:
        断开结果
    """
    try:
        session = session_manager.sessions.get(session_id)
        await asyncio.to_thread(session_manager.disconnect, session_id)
        if session:
            audit_log("DISCONNECT", sessionId=session_id, port=session.port)
            live_emit("ev", f"会话已断开，串口 {session.port} 已释放",
                      port=session.port, state="idle")
        return f"会话 {session_id} 已断开，串口已释放"
    except ValueError as e:
        return f"错误: {str(e)}"


def main():
    parser = argparse.ArgumentParser(description="Cisco Serial (Console) MCP Server")
    parser.add_argument("--selftest", action="store_true",
                        help="运行离线自测（不打开串口）后退出")
    args = parser.parse_args()

    if args.selftest:
        run_selftest()
        return

    # 启动控制通道：localhost TCP，端口随机；只有持有会话时才公布端点文件
    global _CONTROL_TOKEN
    try:
        CONTROL_DIR.mkdir(parents=True, exist_ok=True)
        cleanup_stale_endpoint()        # 清掉上个进程留下的失效端点
        # 令牌用来挡"第三方网页往 localhost 发请求"这类 CSRF：网页读不到本地文件。
        _CONTROL_TOKEN = uuid.uuid4().hex
        threading.Thread(target=_control_server, name="control", daemon=True).start()
    except Exception as exc:
        print(f"[cisco-serial-mcp] 控制通道未启动（网页输入/释放将不可用）: {exc}",
              file=sys.stderr)

    mcp.run()


# ============ 离线自测（不接触硬件）============

def run_selftest() -> None:
    """验证提示符识别、分页清理、危险命令拦截等纯逻辑"""
    failures = []

    def check(name, got, want):
        ok = got == want
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: got={got!r} want={want!r}")
        if not ok:
            failures.append(name)

    # 提示符 / 模式识别
    check("mode privileged", detect_device_mode("SW3#"), "SW3#")
    check("mode user", detect_device_mode("SW3>"), "SW3>")
    check("mode global", detect_device_mode("SW3(config)#"), "SW3(config)#")
    check("mode iface", detect_device_mode("SW3(config-if)#"), "SW3(config-if)#")
    check("mode router", detect_device_mode("R1(config-router)#"), "R1(config-router)#")
    check("mode unknown", detect_device_mode("garbage"), "unknown")

    # 回归：detect_device_mode("") 返回的 "unknown" 是真值，调用方不能用 `or` 兜底
    check("empty detects as truthy unknown", (detect_device_mode("") or "FALLBACK"), "unknown")

    # 分页清理
    check("more cleanup", clean_console_text("line1\r\n--More-- ").strip(), "line1")
    check("more cleanup2", clean_console_text("line1\r\n<--- More --->").strip(), "line1")

    # 回归：分页检测必须看【原始】文本。clean_console_text() 会删掉标记本身，
    # 若在清理后的文本里找就永远匹配不到（这就是卡在 --More-- 的根因）。
    stuck = "line1\r\n --More-- "
    check("more detected in raw text", bool(MORE_RE.search(stuck[-80:])), True)
    check("more gone after clean", bool(MORE_RE.search(clean_console_text(stuck)[-80:])), False)

    # 回归：设备擦掉 --More-- 时发的「退格+空格」残渣要一并清掉，不能留一串孤立空格
    backs = "\x08" * 9
    noisy = "a\r\n --More-- " + backs + " " * 8 + backs + "b"
    check("pager erase noise stripped", clean_console_text(noisy), "a\r\nb")

    # has_prompt 判断
    check("prompt true", has_prompt("SW3# "), True)
    check("prompt false", has_prompt("SW3(config"), False)

    # 回归：输出正文里形似提示符的文本（show switch 的表头 "Switch#"）
    # 在设备名未知时会误判成"命令执行完毕"，导致输出被腰斩。学到设备名后必须只认它。
    show_switch = ("show switch\r\n"
                   "Mac persistency wait time: Indefinite\r\n"
                   "Switch#   Role    Mac Address     Priority Version  State \r\n"
                   "-------\r\n")
    cut = show_switch.index("Switch#") + len("Switch#")      # 模拟数据正好断在这里
    check("表头误判(设备名未知)", has_prompt(show_switch[:cut]), True)
    check("表头不再误判(已知设备名)", has_prompt(show_switch[:cut], "JS-KPL-CORE"), False)
    check("模式也不误判表头", detect_device_mode(show_switch[:cut], "JS-KPL-CORE"), "unknown")
    check("真提示符仍认得", has_prompt("x\r\nJS-KPL-CORE#", "JS-KPL-CORE"), True)
    check("配置模式提示符", has_prompt("JS-KPL-CORE(config)#", "JS-KPL-CORE"), True)
    check("接口模式提示符", has_prompt("JS-KPL-CORE(config-if)#", "JS-KPL-CORE"), True)
    check("别的设备提示符不认", has_prompt("R1#", "JS-KPL-CORE"), False)
    check("设备名提取", prompt_name_of("JS-KPL-CORE(config-if)#"), "JS-KPL-CORE")
    check("设备名提取(无子模式)", prompt_name_of("SW3>"), "SW3")
    check("unknown 不提取名字", prompt_name_of("unknown"), "")

    # 危险命令拦截
    check("block reload", bool(check_dangerous_command("reload")), True)
    check("block wr", bool(check_dangerous_command("wr")), True)
    check("block do wr", bool(check_dangerous_command("do write memory")), True)
    check("block shutd", bool(check_dangerous_command("shutd")), True)
    check("block line con", bool(check_dangerous_command("line console 0")), True)
    check("block line con abbr", bool(check_dangerous_command("li c 0")), True)
    check("block line vty", bool(check_dangerous_command("line vty 0 4")), True)
    check("block line aux", bool(check_dangerous_command("line aux 0")), True)
    check("block user", bool(check_dangerous_command("username hacker privilege 15")), True)
    check("block aaa", bool(check_dangerous_command("aaa new-model")), True)
    check("block erase", bool(check_dangerous_command("erase startup-config")), True)
    check("block copy to run", bool(check_dangerous_command("copy tftp: running-config")), True)
    check("block debug", bool(check_dangerous_command("debug ip packet")), True)
    check("allow reload in", check_dangerous_command("reload in 5"), None)
    check("allow reload cancel", check_dangerous_command("reload cancel"), None)
    check("allow show run", check_dangerous_command("show running-config"), None)
    check("allow copy run tftp", check_dangerous_command("copy running-config tftp:"), None)
    check("allow write terminal", check_dangerous_command("write terminal"), None)
    check("allow enable", check_dangerous_command("enable"), None)

    # 波特率解析
    check("baud auto", parse_baud_candidates("auto"), [9600, 115200])
    check("baud explicit", parse_baud_candidates(115200), [115200])
    check("baud list", parse_baud_candidates("9600,115200"), [9600, 115200])

    # 串口枚举（只读，不打开端口）
    ports = list_serial_ports()
    print(f"[INFO] 本机串口: {[(p['port'], p['likelyConsoleAdapter'], p['bluetooth']) for p in ports]}")

    print()
    if failures:
        print(f"自测失败 {len(failures)} 项: {failures}")
        sys.exit(1)
    print("自测全部通过（all selftests passed）")


if __name__ == "__main__":
    main()
