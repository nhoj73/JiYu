#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
极域学生机局域网 IP 扫描器 (跨平台: macOS / Windows / Linux)
================================================================
用途:
    自动探测本机所在教室网段 -> 并行 ping 扫描 + ARP 表收集活主机
    -> (可选) 极域端口探测精滤 -> 把所有在线 IP 用英文分号(;)拼接
    -> 一键/自动复制到系统剪贴板，直接粘贴进极域/管理工具的「IP 地址」栏。

说明:
    - 本工具只做「网络发现 + 剪贴板」，不向任何主机发送控制/管理报文。
    - 极域端口探测为可选精滤；不同版本端口可能不同，探测不到时请关闭该开关，
      直接对所有"活着的局域网主机"使用即可(教室网段里基本就是学生机)。

用法:
    图形界面:   python lan_ip_scanner.py
    命令行:     python lan_ip_scanner.py --cli [--cidr 192.168.1.0/24] [--jiyu 4806,4808]
"""

import os
import re
import sys
import platform
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor

OS = platform.system()  # 'Darwin' / 'Windows' / 'Linux'


# --------------------------------------------------------------------------- #
# 1. 获取本机 IP / 网段
# --------------------------------------------------------------------------- #
def get_local_ip() -> str:
    """通过 UDP 套接字拿到本机对外 IP (不真正发包)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _hex_netmask_to_dotted(hexmask: str) -> str:
    try:
        return socket.inet_ntoa(int(hexmask, 16).to_bytes(4, "big"))
    except Exception:
        return ""


def detect_subnet(local_ip: str):
    """
    返回 (network_cidr, broadcast) 或 (None, None)。
    解析系统命令匹配本机 IP 所在的网卡，取出子网掩码计算网段与广播地址。
    """
    try:
        if OS == "Darwin":
            out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                m_inet = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                if m_inet and m_inet.group(1) == local_ip:
                    m_nm = re.search(r"netmask (0x[0-9a-fA-F]{8})", line)
                    m_nm2 = re.search(r"netmask (\d+\.\d+\.\d+\.\d+)", line)
                    nm = m_nm2.group(1) if m_nm2 else (_hex_netmask_to_dotted(m_nm.group(1)) if m_nm else None)
                    if nm:
                        net = ipaddress.ip_network(f"{local_ip}/{nm}", strict=False)
                        return str(net), str(net.broadcast_address)
        elif OS == "Linux":
            out = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if m and m.group(1) == local_ip:
                    net = ipaddress.ip_network(f"{local_ip}/{m.group(2)}", strict=False)
                    return str(net), str(net.broadcast_address)
        elif OS == "Windows":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=10).stdout
            blocks = re.split(r"\r?\n\r?\n", out)
            for blk in blocks:
                if local_ip in blk:
                    m_ip = re.search(r"IPv4 Address[ .:]+(\d+\.\d+\.\d+\.\d+)", blk)
                    m_nm = re.search(r"Subnet Mask[ .:]+(\d+\.\d+\.\d+\.\d+)", blk)
                    if m_ip and m_nm:
                        net = ipaddress.ip_network(f"{local_ip}/{m_nm.group(1)}", strict=False)
                        return str(net), str(net.broadcast_address)
    except Exception:
        pass
    # 兜底: 用 /24 估算
    try:
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(net), str(net.broadcast_address)
    except Exception:
        return None, None


# --------------------------------------------------------------------------- #
# 2. ping 扫描 + ARP 表
# --------------------------------------------------------------------------- #
def ping_cmd(ip: str, timeout_ms: int = 500):
    if OS == "Windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    if OS == "Darwin":
        return ["ping", "-c", "1", "-W", str(timeout_ms), "-t", "1", ip]
    # Linux: -W 单位为秒
    return ["ping", "-c", "1", "-W", "1", ip]


def ping_host(ip: str, timeout_ms: int = 500) -> bool:
    try:
        proc = subprocess.run(
            ping_cmd(ip, timeout_ms),
            capture_output=True,
            timeout=(timeout_ms / 1000.0) + 1.5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def arp_table() -> dict:
    """返回 {ip: mac} ，仅保留有真实 MAC 的条目 (过滤 incomplete/failed)。"""
    result = {}
    try:
        if OS == "Windows":
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if m:
                    result[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:  # Darwin / Linux
            if OS == "Darwin":
                out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10).stdout
                for line in out.splitlines():
                    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{17}|\(incomplete\))", line)
                    if m and m.group(2) != "(incomplete)":
                        result[m.group(1)] = m.group(2).lower()
            else:
                out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=10).stdout
                for line in out.splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-fA-F:]{17})", line)
                    if m:
                        result[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return result


def probe_jiyu(ip: str, ports, timeout: float = 0.35) -> bool:
    """TCP 连接探测: 任一候选端口可连上即视为极域主机 (best-effort)。"""
    for p in ports:
        try:
            s = socket.create_connection((ip, p), timeout=timeout)
            s.close()
            return True
        except Exception:
            continue
    return False


# --------------------------------------------------------------------------- #
# 3. 核心发现
# --------------------------------------------------------------------------- #
def discover(cidr: str, jiyu_ports=None, max_workers: int = 80):
    """
    返回 list[(ip, mac, is_jiyu)] ，按 IP 排序。
    jiyu_ports=None 时不探测端口，is_jiyu 记为 None。
    """
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    local_ip = get_local_ip()

    # 第一轮: 并行 ping，同时先取一次 ARP
    arp = arp_table()

    def probe(ip):
        replied = ping_host(ip)
        mac = arp.get(ip)
        return ip, replied, mac

    alive = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for ip, replied, mac in ex.map(probe, hosts):
            if ip == local_ip:
                continue
            if replied or (mac is not None):
                alive[ip] = [mac, None]

    # 第二轮: 扫描后再取一次 ARP (捕捉延迟出现的条目)
    arp2 = arp_table()
    for ip in list(alive.keys()):
        if alive[ip][0] is None:
            alive[ip][0] = arp2.get(ip)

    # 第三轮(可选): 极域端口探测
    if jiyu_ports:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for ip, ok in zip(alive.keys(), ex.map(lambda x: probe_jiyu(x, jiyu_ports), alive.keys())):
                alive[ip][1] = ok

    out = []
    for ip in sorted(alive.keys(), key=lambda x: ipaddress.ip_address(x)):
        mac, is_jiyu = alive[ip]
        out.append((ip, mac, is_jiyu))
    return out


def join_ips(ips) -> str:
    """用英文分号拼接 (用户特别强调要英文分号)。"""
    return ";".join(ips)


# --------------------------------------------------------------------------- #
# 4. 剪贴板
# --------------------------------------------------------------------------- #
def copy_to_clipboard(text: str) -> bool:
    """优先用 Tkinter(跨平台、无需额外依赖)；失败则回退到系统命令。"""
    try:
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.destroy()
        return True
    except Exception:
        pass
    # 回退
    try:
        if OS == "Darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return True
        if OS == "Windows":
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
            p.communicate(text.encode("gbk", errors="ignore"))
            return True
        if OS == "Linux":
            for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    p.communicate(text.encode("utf-8"))
                    return True
                except Exception:
                    continue
    except Exception:
        pass
    return False


# --------------------------------------------------------------------------- #
# 5. 命令行模式
# --------------------------------------------------------------------------- #
def cli_mode(cidr=None, jiyu_ports=None):
    local_ip = get_local_ip()
    if not cidr:
        cidr, _ = detect_subnet(local_ip)
    if not cidr:
        print("无法自动探测网段，请用 --cidr 手动指定，例如 192.168.1.0/24")
        return
    print(f"[*] 本机 IP: {local_ip}")
    print(f"[*] 扫描网段: {cidr}  (极域端口过滤: {jiyu_ports or '关闭'})")
    found = discover(cidr, jiyu_ports=jiyu_ports)
    if jiyu_ports:
        found = [f for f in found if f[2]]
    ips = [f[0] for f in found]
    joined = join_ips(ips)
    print(f"[+] 发现 {len(ips)} 台在线主机:")
    for ip, mac, j in found:
        tag = " [极域]" if j else ""
        print(f"    {ip}   {mac or '?':17}{tag}")
    print("\n[+] 分号拼接结果:")
    print(joined)
    if copy_to_clipboard(joined):
        print("\n[✓] 已复制到剪贴板，直接 Ctrl/⌘+V 粘贴即可。")
    else:
        print("\n[!] 剪贴板复制失败，请手动复制上面的拼接结果。")


# --------------------------------------------------------------------------- #
# 6. 图形界面
# --------------------------------------------------------------------------- #
def gui_mode():
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext

    local_ip = get_local_ip()
    auto_cidr, auto_bcast = detect_subnet(local_ip)

    root = tk.Tk()
    root.title("极域学生机局域网 IP 扫描器")
    root.geometry("720x560")
    root.resizable(True, True)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # ---- 顶部参数区 ----
    frm_top = ttk.LabelFrame(root, text="扫描设置", padding=8)
    frm_top.pack(fill="x", padx=10, pady=8)

    ttk.Label(frm_top, text="本机 IP:").grid(row=0, column=0, sticky="w")
    ttk.Label(frm_top, text=local_ip, foreground="#c0392b").grid(row=0, column=1, sticky="w")

    ttk.Label(frm_top, text="网段 CIDR:").grid(row=1, column=0, sticky="w")
    cidr_var = tk.StringVar(value=auto_cidr or (local_ip + "/24"))
    cidr_entry = ttk.Entry(frm_top, textvariable=cidr_var, width=22)
    cidr_entry.grid(row=1, column=1, sticky="w", padx=(0, 8))
    ttk.Label(frm_top, text="(自动探测，可改)").grid(row=1, column=2, sticky="w")

    jiyu_var = tk.BooleanVar(value=False)
    jiyu_chk = ttk.Checkbutton(frm_top, text="只保留极域端口响应的主机", variable=jiyu_var)
    jiyu_chk.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
    ttk.Label(
        frm_top,
        text="极域端口(逗号分隔, TCP): 4806,4808  | 官方端口 4806-4809/4604/4805 等",
        foreground="#666",
    ).grid(row=3, column=0, columnspan=4, sticky="w")
    ports_var = tk.StringVar(value="4806,4808")

    btn_scan = ttk.Button(frm_top, text="▶ 扫描")
    btn_scan.grid(row=0, column=3, rowspan=2, padx=(10, 0))

    # ---- 结果列表 ----
    frm_list = ttk.LabelFrame(root, text="发现的在线主机 (勾选=纳入复制)", padding=6)
    frm_list.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    cols = ("check", "ip", "mac", "jiyu")
    tree = ttk.Treeview(frm_list, columns=cols, show="headings", height=12)
    tree.heading("check", text="✓")
    tree.heading("ip", text="IP 地址")
    tree.heading("mac", text="MAC")
    tree.heading("jiyu", text="极域")
    tree.column("check", width=40, anchor="center")
    tree.column("ip", width=140)
    tree.column("mac", width=180)
    tree.column("jiyu", width=60, anchor="center")
    tree.pack(fill="both", expand=True, side="left")
    vsb = ttk.Scrollbar(frm_list, orient="vertical", command=tree.yview)
    vsb.pack(side="right", fill="y")
    tree.configure(yscrollcommand=vsb.set)

    checked = {}  # ip -> BooleanVar

    def toggle_all(state):
        for ip, var in checked.items():
            var.set(state)
            tree.set(ip, "check", "☑" if state else "☐")

    frm_list_btns = ttk.Frame(frm_list)
    frm_list_btns.pack(fill="x", pady=(4, 0))
    ttk.Button(frm_list_btns, text="全选", command=lambda: toggle_all(True)).pack(side="left")
    ttk.Button(frm_list_btns, text="全不选", command=lambda: toggle_all(False)).pack(side="left", padx=(6, 0))

    # ---- 输出区 ----
    frm_out = ttk.LabelFrame(root, text="分号拼接结果 (自动复制到剪贴板)", padding=8)
    frm_out.pack(fill="x", padx=10, pady=(0, 8))

    out_box = scrolledtext.ScrolledText(frm_out, height=3, wrap="word")
    out_box.pack(fill="x")
    out_box.insert("1.0", "点击「扫描」后，这里会显示英文分号拼接的 IP，并自动复制。")

    bcast_var = tk.StringVar(value=auto_bcast or "")
    frm_bcast = ttk.Frame(frm_out)
    frm_bcast.pack(fill="x", pady=(6, 0))
    ttk.Label(frm_bcast, text="网段广播地址:").pack(side="left")
    bcast_entry = ttk.Entry(frm_bcast, textvariable=bcast_var, width=20)
    bcast_entry.pack(side="left", padx=(4, 8))
    ttk.Label(frm_bcast, text="(粘贴到「网段广播地址」栏可全班批量执行)").pack(side="left")

    status = ttk.Label(root, text="就绪", foreground="#666")
    status.pack(fill="x", padx=10, pady=(0, 6))

    def do_scan():
        cidr = cidr_var.get().strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except Exception:
            messagebox.showerror("网段错误", f"CIDR 格式不正确: {cidr}\n示例: 192.168.1.0/24")
            return
        ports = None
        if jiyu_var.get():
            try:
                ports = [int(x.strip()) for x in ports_var.get().split(",") if x.strip()]
            except Exception:
                messagebox.showerror("端口错误", "极域端口必须是逗号分隔的数字，如 4806,4808")
                return

        for item in tree.get_children():
            tree.delete(item)
        checked.clear()
        status.configure(text="扫描中…请稍候", foreground="#c0392b")
        btn_scan.configure(state="disabled")
        root.update()

        def worker():
            try:
                found = discover(cidr, jiyu_ports=ports)
                if ports:
                    found = [f for f in found if f[2]]
            except Exception as e:
                root.after(0, lambda: messagebox.showerror("扫描失败", str(e)))
                root.after(0, lambda: btn_scan.configure(state="normal"))
                return

            def ui():
                for ip, mac, j in found:
                    var = tk.BooleanVar(value=True)
                    checked[ip] = var
                    tree.insert("", "end", iid=ip, values=("☑", ip, mac or "?", "是" if j else ""))
                ips = [ip for ip in checked if checked[ip].get()]
                joined = join_ips(ips)
                out_box.delete("1.0", "end")
                out_box.insert("1.0", joined)
                ok = copy_to_clipboard(joined)
                status.configure(
                    text=f"发现 {len(found)} 台在线主机，已选中 {len(ips)} 台"
                    + (" · 已复制到剪贴板 ✓" if ok else " · 复制失败，请手动复制"),
                    foreground="#27ae60" if ok else "#c0392b",
                )
                btn_scan.configure(state="normal")

            root.after(0, ui)

        threading.Thread(target=worker, daemon=True).start()

    # 勾选状态回写
    def on_click(event):
        item = tree.identify_row(event.y)
        col = tree.identify_column(event.x)
        if item and col == "#1":
            var = checked.get(item)
            if var:
                new = not var.get()
                var.set(new)
                tree.set(item, "check", "☑" if new else "☐")
                # 重新拼接并更新剪贴板
                ips = [ip for ip in checked if checked[ip].get()]
                joined = join_ips(ips)
                out_box.delete("1.0", "end")
                out_box.insert("1.0", joined)
                copy_to_clipboard(joined)

    tree.bind("<Button-1>", on_click)

    btn_copy = ttk.Button(frm_out, text="↻ 重新复制选中", command=lambda: copy_to_clipboard(out_box.get("1.0", "end").strip()))
    btn_copy.pack(anchor="e", pady=(6, 0))

    btn_scan.configure(command=do_scan)

    # 提示
    ttk.Label(
        root,
        text="提示: 若教室有人禁 ping，部分机器可能不出现在列表——可关闭「极域端口过滤」并改用「网段广播地址」批量执行。",
        foreground="#888",
    ).pack(fill="x", padx=10, pady=(0, 8))

    root.mainloop()


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    args = sys.argv[1:]
    if "--cli" in args:
        cidr = None
        jiyu = None
        for i, a in enumerate(args):
            if a == "--cidr" and i + 1 < len(args):
                cidr = args[i + 1]
            if a == "--jiyu" and i + 1 < len(args):
                try:
                    jiyu = [int(x.strip()) for x in args[i + 1].split(",") if x.strip()]
                except Exception:
                    jiyu = None
        cli_mode(cidr=cidr, jiyu_ports=jiyu)
    else:
        try:
            gui_mode()
        except Exception as e:
            print(f"[!] 图形界面启动失败 ({e})，自动切换到命令行模式:")
            cli_mode()
