# cisco-serial-mcp

Cisco 设备的 **Console/串口 MCP 服务器**：让 AI 助手通过本机 USB 转串口线直接操作交换机与路由器。

设备没网、Telnet/SSH 进不去、配置改坏进不了设备、需要进 ROMMON 做密码恢复时，这是最后一条通道（带外管理 / OOB）。

工具语义、危险命令拦截规则与 Telnet 版 `cisco-cli-mcpv2` 保持一致：把 `telnet_*` 换成 `serial_*` 即可套用。

## 安装

```powershell
pip install -r requirements.txt
```

依赖：`mcp`（FastMCP）、`pyserial`。无其他第三方依赖。

在 MCP 客户端里注册（以 `mcpServers` 配置为例）：

```json
{
  "mcpServers": {
    "ciscoserial": {
      "command": "python",
      "args": ["D:\\path\\to\\cisco-serial-mcp\\server_serial.py"]
    }
  }
}
```

## 工具

| 工具 | 作用 |
|---|---|
| `serial_list_ports` | 列出本机串口，标注哪个像 USB 控制台线、哪个是蓝牙虚拟口 |
| `serial_connect` | 打开串口并登录。`port=""` 自动挑线；`baud="auto"` 先 9600 再 115200 |
| `serial_execute` | 执行命令，`--More--` 自动翻页；危险命令需 `confirm=true` |
| `serial_send_break` | 发 Break 信号（进 ROMMON / 密码恢复，Telnet 做不到） |
| `serial_list_sessions` | 列出活动会话 |
| `serial_disconnect` | 断开并**释放 COM 口**（释放后 MobaXterm 才能占用） |

## 用法

### 连设备执行命令

```
serial_list_ports()                                          # 确认控制台线的 COM 口号
serial_connect(port="", baud="auto", enable_password="xxx")   # port 留空 = 自动选线
serial_execute(session_id="...", command="show version")
serial_execute(session_id="...", command="show ip interface brief")
serial_disconnect(session_id="...")                          # 用完务必释放串口
```

### 进 ROMMON 做密码恢复

Break 必须在**设备刚上电、启动早期**发送才有效：

```
serial_connect(port="COM3", baud=9600)                        # 先开串口，设备可先不开电
# 给设备上电，然后立刻连续发 Break
serial_send_break(session_id="...", duration_ms=500, repeat=5, interval_ms=300)
serial_execute(session_id="...", command="", wait_ms=3000)     # 读回显，找 "rommon 1 >"
```

ROMMON 里的标准流程：`confreg 0x2142` → `reset` → 免密码进特权 → `copy start run` →
改回 `confreg 0x2102` → `copy run start` → `reload`。

### 实时看板（可选）

把每一笔收发投到浏览器里看，也被网页用来输入口令（口令不经过模型、不落盘）：

```powershell
python live_view.py                 # 默认 http://127.0.0.1:8777/
python live_view.py --port 8888
python live_view.py --log a.jsonl --log b.jsonl    # 自定义盯哪几路流水
```

页面里：**发→** 命令、**收←** 设备回显（含设备空闲时异步打印的日志）、**·** 事件，
并可一键**释放串口/Telnet**、在底部输入条直接给设备敲命令（勾 🙈 走密文输入，发完自动关闭）。

看板只读 JSONL 流水、不抢串口也不占 VTY，所以你和助手看到的是同一份真相。
它只绑 `127.0.0.1`、无认证，**别往外暴露**。

### 离线自测

```powershell
python server_serial.py --selftest      # 不接触硬件，验证提示符识别/分页清理/危险命令规则
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `CISCO_SERIAL_AUDIT_LOG` | `D:\DSH\logs\audit-serial.log` | 审计日志（JSONL，输出截断到 2000 字符） |
| `CISCO_SERIAL_LIVE_LOG` | `D:\DSH\logs\serial-live.jsonl` | 实时流水（完整收发，超过 8MB 自动清空） |
| `CISCO_LIVE_VIEW_LOG` | `D:\DSH\logs\live-view.log` | 看板自身的启动/错误日志 |
| `CISCO_LIVE_CONTROL_DIR` | `D:\DSH\logs\control` | 看板与服务器之间的控制端点文件目录 |
| `CISCO_SERIAL_CONTROL_HOST` | `127.0.0.1` | 控制通道绑定地址 |

> 默认路径是 Windows 风格。其它平台或想换位置，用上表的环境变量指定即可。

## 注意事项

1. **串口是独占资源**：MobaXterm / SecureCRT / 另一个会话占着同一个 COM 口时会打开失败并明确报错。
   用之前先关掉占用该口的标签页；用完 `serial_disconnect` 释放。
2. **COM 口号会变**：换 USB 口或重装驱动后可能变（`COM3` → `COM6`），所以 `port` 留空自动挑，不要硬编码。
   枚举不到说明线没插好或驱动没装（设备管理器里应出现 `COMx`）。
3. **蓝牙虚拟口自动排除**（`hwid` 含 `BTHENUM`），避免误连。
4. **波特率探测**只试 9600 与 115200；其他速率请显式指定，如 `baud="38400"` 或 `baud="9600,115200,38400"`。
5. **未探测到设备不等于失败**：设备关机时串口照样能打开，返回 `success=true` + `warning`、`deviceMode="unknown"`；
   开机后直接 `serial_execute` 就能看到启动日志。
6. **危险命令拦截**：命中规则（`reload`、`line console 0`、`no login`、`shutdown` 等）的命令不会下发到设备，
   返回 `needsConfirmation=true` 与命中原因，确认风险后才带 `confirm=true` 重调。
   `reload in <分钟>` / `reload cancel` / `copy running-config tftp:` 等安全方向命令不受拦截。
7. **应用层拦截只是减速带**，替代不了设备侧 AAA / TACACS+ 命令授权。
8. 连接时若设备已在特权模式，程序会自动下发 `terminal length 0` 关掉该 console 线的分页
   （不写进 startup-config，但会保持到线路重置）。不想让程序改动设备状态，删掉 `server_serial.py` 里那一步即可。
