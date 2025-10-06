import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, colorchooser, simpledialog
import json, os, inspect
import threading
import time
import re
import mimetypes
import csv
from collections import defaultdict, Counter, deque

try:
    from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP, UDP, ICMP, Raw
    try:
        from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSCertificate
        TLS_AVAILABLE = True
    except Exception:
        TLS_AVAILABLE = False
except Exception as e:
    raise SystemExit("scapy is required. Install with: pip install scapy") from e

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except Exception:
    PANDAS_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.ticker import MaxNLocator, FuncFormatter
    import numpy as np
    plt.rcParams.update({
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.grid": True,
        "grid.linestyle": "--",
        "grid.alpha": 0.25,
        "axes.edgecolor": "#eeeeee",
        "axes.labelsize": 10,
        "axes.titlesize": 12,
        "font.size": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.frameon": False,
    })
except Exception:
    raise SystemExit("matplotlib is required. Install with: pip install matplotlib")

captured_packets = []
stop_sniffing_flag = False

tcp_streams = defaultdict(list)
http_sessions = []
tls_sessions = []
http_objects = []
credentials = []

protocol_counter = Counter()
ip_counter = Counter()
total_bytes = 0
bandwidth_data = deque(maxlen=60)

pending_ui_updates = deque()

PROTO_COLORS = {
    "TCP": "#ff0000",
    "UDP": "#e6f7ff",
    "ICMP": "#e6ffe6",
    "HTTP": "#fff2cc",
    "TLS": "#e6ccff",
    "Ethernet": "#f2f2f2",
    "IP": "#ffffff",
    "Other": "#ffffff"
}

PREFERENCES_DEFAULTS = {
    "default_filter": "tcp",
    "proto_colors": {
        "TCP": "#00ff40",
        "UDP": "#e6f7ff",
        "ICMP": "#e6ffe6",
        "HTTP": "#fff2cc",
        "TLS": "#e6ccff",
        "Ethernet": "#ff8040",
        "IP": "#ffffff",
        "Other": "#ffffff",
    },
}

def _this_file_path():
    try:
        return os.path.abspath(__file__)
    except NameError:
        return os.path.abspath(inspect.getsourcefile(lambda:0))
def save_preferences_to_source(prefs):
    path = _this_file_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        start = content.find("PREFERENCES_DEFAULTS = {")
        if start == -1:
            messagebox.showerror("Preferences", "Could not find PREFERENCES_DEFAULTS in the script")
            return False
        brace_count = 0
        i = start
        while i < len(content):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    break
            i += 1
        
        if brace_count != 0:
            messagebox.showerror("Preferences", "Could not parse PREFERENCES_DEFAULTS structure")
            return False
            
        end = i + 1
        prefs_python = "{\n"
        for key, value in prefs.items():
            if key == "proto_colors":
                prefs_python += f'    "proto_colors": {{\n'
                for proto, color in value.items():
                    prefs_python += f'        "{proto}": "{color}",\n'
                prefs_python += '    },\n'
            else:
                prefs_python += f'    "{key}": "{value}",\n'
        prefs_python += "}"
        new_content = content[:start] + f"PREFERENCES_DEFAULTS = {prefs_python}" + content[end:]
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return True
    except Exception as e:
        messagebox.showerror("Preferences", f"Could not save preferences inside the script: {e}")
        return False

PREFERENCES = dict(PREFERENCES_DEFAULTS)
PREFERENCES_DEFAULTS.update(PREFERENCES)
for k, v in PREFERENCES_DEFAULTS.get("proto_colors", {}).items():
    if k in PROTO_COLORS:
        PROTO_COLORS[k] = v
        
DEFAULT_CAPTURE_FILTER = PREFERENCES_DEFAULTS.get("default_filter", "tcp")

def schedule_ui(func, *args, **kwargs):
    pending_ui_updates.append((func, args, kwargs))

def detect_credentials(payload, src, dst):
    if not payload:
        return False
    findings = []
    kv_patterns = [
        r"(?:^|&|\?|;)(user(?:name)?|login|email)[=:]\s*([^&\s]+)",
        r"(?:^|&|\?|;)(pass(?:word)?|pwd)[=:]\s*([^&\s]+)",
    ]
    line_patterns = [
        r"^\s*USER\s+(\S+)",
        r"^\s*PASS\s+(\S+)"
    ]

    for pat in kv_patterns:
        for m in re.findall(pat, payload, re.IGNORECASE | re.MULTILINE):
            if isinstance(m, tuple) and len(m) >= 2:
                findings.append((m[0], m[1]))

    for pat in line_patterns:
        for m in re.findall(pat, payload, re.IGNORECASE | re.MULTILINE):
            findings.append(("cred", m))

    if findings:
        entry = {"src": src, "dst": dst, "payload_snippet": payload[:400], "creds": findings}
        credentials.append(entry)
        schedule_ui(_gui_add_credential, entry)
        return True
    return False

def parse_http_payload(payload, src, dst):
    if not payload:
        return False
    if payload.startswith("HTTP/"):
        headers, sep, body = payload.partition("\r\n\r\n")
        if not sep:
            return False
        lines = headers.split("\r\n")

        request_line = lines[0]
        http_session = {"src": src, "dst": dst, "headers": {}, "request_line": request_line}

        header_lines = lines[1:]
        headers_dict = {}
        for line in header_lines:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers_dict[k.lower()] = v
                http_session["headers"][k] = v

        if request_line.startswith("HTTP/"):
            parts = request_line.split(" ")
            if len(parts) >= 2:
                http_session["status"] = parts[1]
                http_session["type"] = "response"
        else:
            parts = request_line.split(" ")
            if len(parts) >= 2:
                http_session["method"] = parts[0]
                http_session["path"] = parts[1]
                http_session["type"] = "request"
        http_sessions.append(http_session)
        schedule_ui(lambda: refresh_http_list())
        if body and body.strip():
            ct = headers_dict.get("content-type", "")
            cd = headers_dict.get("content-disposition", "")
            filename = None
            if "filename=" in cd:
                try:
                    filename = cd.split("filename=")[1].strip().strip('"')
                except Exception:
                    filename = None
            if not filename and ct:
                ext = mimetypes.guess_extension(ct.split(";")[0].strip())
                filename = f"object_{len(http_objects)+1}{ext or '.dat'}"
            obj = {"src": src, "dst": dst, "headers": headers_dict, "payload": body.encode(errors="ignore"), "filename": filename or f"object_{len(http_objects)+1}.dat"}
            http_objects.append(obj)
            schedule_ui(_gui_add_http_object, obj)
            return True
    return False

def process_packet(pkt):
    global total_bytes
    captured_packets.append(pkt)
    length = len(pkt)
    total_bytes += length

    timestamp = time.strftime("%H:%M:%S", time.localtime())
    proto_name = "Other"
    src = dst = ""

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        if TLS_AVAILABLE and pkt.haslayer(TLS):
            proto_name = "TLS"
            tls_layer = pkt[TLS]
            try:
                if hasattr(tls_layer, 'msg'):
                    for msg in tls_layer.msg:
                        if hasattr(msg, 'msgtype') and msg.msgtype == 1:
                            sni = None
                            if hasattr(msg, 'ext'):
                                for ext in msg.ext:
                                    if hasattr(ext, 'type') and ext.type == 0:
                                        if hasattr(ext, 'servernames'):
                                            for sn in ext.servernames:
                                                if hasattr(sn, 'servername'):
                                                    sni = sn.servername.decode() if isinstance(sn.servername, bytes) else sn.servername
                                                    break
                                        break
                            obj = {"type": "ClientHello", "src": src, "dst": dst, "sni": sni}
                            tls_sessions.append(obj)
                            schedule_ui(_gui_add_tls, obj)
                        elif hasattr(msg, 'msgtype') and msg.msgtype == 2:
                            version = getattr(msg, 'version', None)
                            cipher = getattr(msg, 'cipher', None)
                            obj = {"type": "ServerHello", "src": src, "dst": dst, "version": version, "cipher": cipher}
                            tls_sessions.append(obj)
                            schedule_ui(_gui_add_tls, obj)
                        elif hasattr(msg, 'msgtype') and msg.msgtype == 11:
                            certs = []
                            if hasattr(msg, 'certs'):
                                for cert in msg.certs:
                                    subject = getattr(cert, 'subject', None)
                                    if subject:
                                        certs.append(str(subject))
                            obj = {"type": "Certificate", "src": src, "dst": dst, "certs": certs}
                            tls_sessions.append(obj)
                            schedule_ui(_gui_add_tls, obj)
            except Exception as e:
                print(f"TLS processing error: {e}")
        if pkt.haslayer(TCP):
            if proto_name != "TLS":
                proto_name = "TCP"
            tcp = pkt[TCP]
            sid = (ip.src, tcp.sport, ip.dst, tcp.dport)
            rid = (ip.dst, tcp.dport, ip.src, tcp.sport)
            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode(errors="ignore")
                except Exception:
                    payload = pkt[Raw].load.hex()
                tcp_streams[sid].append((src, payload))
                tcp_streams[rid].append((src, payload))
                detect_credentials(payload, src, dst)
                parse_http_payload(payload, src, dst)

        elif pkt.haslayer(UDP):
            proto_name = "UDP"
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"
        else:
            proto_name = "IP"

    elif pkt.haslayer(Ether):
        eth = pkt[Ether]
        src, dst = eth.src, eth.dst
        proto_name = "Ethernet"

    protocol_counter[proto_name] += 1
    ip_counter[src] += 1

    schedule_ui(_gui_add_packet_row, (len(captured_packets), timestamp, src, dst, proto_name, length), proto_name)

def _gui_add_packet_row(values, proto_tag):
    at_bottom = False
    try:
        first, last = packet_table.yview()
        at_bottom = (1.0 - last) < 0.02
    except Exception:
        at_bottom = True

    iid = packet_table.insert("", "end", values=values, tags=(proto_tag,))
    color = PROTO_COLORS.get(proto_tag, PROTO_COLORS["Other"])
    packet_table.tag_configure(proto_tag, background=color)
    if at_bottom:
        packet_table.see(iid)

def _gui_add_credential(entry):
    cred_listbox.insert(tk.END, f"{entry['src']} -> {entry['dst']}")

def _gui_add_http_object(obj):
    obj_listbox.insert(tk.END, f"{obj['filename']} ({obj['headers'].get('content-type','unknown')})")

def _gui_add_tls(obj):
    if obj['type'] == 'ClientHello':
        display_text = f"ClientHello -> SNI: {obj.get('sni', 'N/A')}"
    elif obj['type'] == 'ServerHello':
        version = obj.get('version', 'N/A')
        cipher = obj.get('cipher', 'N/A')
        display_text = f"ServerHello -> Version: {version}, Cipher: {cipher}"
    elif obj['type'] == 'Certificate':
        cert_count = len(obj.get('certs', []))
        display_text = f"Certificate -> {cert_count} cert(s)"
    else:
        display_text = f"{obj.get('type')}"
    tls_listbox.insert(tk.END, f"{obj.get('type')} {obj.get('sni', obj.get('version',''))}")

def _sniff_thread(filter_expr=None):
    try:
        if filter_expr:
            sniff(prn=process_packet, store=0, filter=filter_expr, stop_filter=lambda x: stop_sniffing_flag)
        else:
            sniff(prn=process_packet, store=0, stop_filter=lambda x: stop_sniffing_flag)
    except Exception as e:
        schedule_ui(messagebox.showerror, "Sniff Error", str(e))

def start_sniffing():
    global stop_sniffing_flag
    if hasattr(start_btn, "running") and start_btn.running:
        messagebox.showinfo("Info", "Capture already running")
        return
    stop_sniffing_flag = False
    start_btn.running = True
    set_status("green", "Capturing")
    t = threading.Thread(target=_sniff_thread, args=(filter_entry.get() or None,), daemon=True)
    t.start()

def stop_sniffing():
    global stop_sniffing_flag
    stop_sniffing_flag = True
    start_btn.running = False
    set_status("yellow", "Stopped")

def save_pcap_to_file():
    if not captured_packets:
        messagebox.showwarning("Save PCAP", "No packets to save.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if not path:
        return
    try:
        wrpcap(path, captured_packets)
        messagebox.showinfo("Save PCAP", f"Saved {len(captured_packets)} packets to {path}")
    except Exception as e:
        messagebox.showerror("Save PCAP", str(e))

def load_pcap_from_file():
    path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if not path:
        return
    try:
        pkts = rdpcap(path)
        for p in pkts:
            process_packet(p)
            refresh_tls_list()
        messagebox.showinfo("Load PCAP", f"Loaded {len(pkts)} packets from {path}")
    except Exception as e:
        messagebox.showerror("Load PCAP", str(e))

def export_packets(fmt="csv"):
    rows = []
    headers = ("ID", "Time", "Source", "Destination", "Protocol", "Length")
    for iid in packet_table.get_children():
        rows.append(packet_table.item(iid)["values"])
    if not rows:
        messagebox.showwarning("Export", "No packets to export.")
        return
    if fmt == "csv":
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            messagebox.showinfo("Export", f"Exported {len(rows)} packets to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
    elif fmt == "excel":
        if not PANDAS_AVAILABLE:
            messagebox.showerror("Export Error", "pandas/openpyxl required for Excel export. Install: pip install pandas openpyxl")
            return
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel","*.xlsx")])
        if not path: return
        try:
            df = pd.DataFrame(rows, columns=headers)
            df.to_excel(path, index=False)
            messagebox.showinfo("Export", f"Exported {len(rows)} packets to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

def export_credentials(fmt="csv"):
    if not credentials:
        messagebox.showwarning("Export", "No credentials detected to export.")
        return
    rows = []
    headers = ("Source", "Destination", "Pairs", "PayloadSnippet")
    for c in credentials:
        pairs = "; ".join(f"{k}={v}" if isinstance(k, str) else str(k) for (k, v) in c["creds"])
        rows.append((c["src"], c["dst"], pairs, c["payload_snippet"]))
    if fmt == "csv":
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            messagebox.showinfo("Export", f"Exported {len(rows)} credentials to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
    elif fmt == "excel":
        if not PANDAS_AVAILABLE:
            messagebox.showerror("Export Error", "pandas/openpyxl required for Excel export. Install: pip install pandas openpyxl")
            return
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel","*.xlsx")])
        if not path: return
        try:
            df = pd.DataFrame(rows, columns=headers)
            df.to_excel(path, index=False)
            messagebox.showinfo("Export", f"Exported {len(rows)} credentials to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

def follow_stream():
    sel = packet_table.focus()
    if not sel:
        messagebox.showwarning("Follow Stream", "Select a packet row first.")
        return
    idx = int(packet_table.item(sel)["values"][0]) - 1
    pkt = captured_packets[idx]
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        messagebox.showwarning("Follow Stream", "Selected packet is not TCP.")
        return
    ip = pkt[IP]; tcp = pkt[TCP]
    sid = (ip.src, tcp.sport, ip.dst, tcp.dport)
    if sid not in tcp_streams or not tcp_streams[sid]:
        messagebox.showinfo("Follow Stream", "No stream payloads available.")
        return

    win = tk.Toplevel(root)
    win.title(f"Follow TCP Stream {sid}")
    txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Courier", 10))
    txt.pack(fill=tk.BOTH, expand=True)
    for src_ip, payload in tcp_streams[sid]:
        color = "blue" if src_ip == ip.src else "red"
        txt.insert(tk.END, f"{src_ip}:\n", (color,))
        txt.insert(tk.END, payload + "\n\n")
    txt.tag_config("blue", foreground="blue")
    txt.tag_config("red", foreground="red")

    def export_text():
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for src_ip, payload in tcp_streams[sid]:
                    f.write(f"{src_ip}:\n{payload}\n\n")
            messagebox.showinfo("Export", f"Saved conversation to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    btn_frame = tk.Frame(win)
    btn_frame.pack(fill=tk.X)
    tk.Button(btn_frame, text="Export Conversation (txt)", command=export_text, bg="green", fg="white").pack(side=tk.LEFT, padx=5, pady=5)

def clear_captured():
    global captured_packets, tcp_streams, http_sessions, tls_sessions, http_objects, credentials, protocol_counter, ip_counter, total_bytes, bandwidth_data
    captured_packets.clear()
    tcp_streams.clear()
    http_sessions.clear()
    tls_sessions.clear()
    http_objects.clear()
    credentials.clear()
    protocol_counter.clear()
    ip_counter.clear()
    total_bytes = 0
    bandwidth_data.clear()

    for item in packet_table.get_children():
        packet_table.delete(item)
    packet_details.delete("1.0", tk.END)

    cred_listbox.delete(0, tk.END)
    http_listbox.delete(0, tk.END)
    tls_listbox.delete(0, tk.END)
    obj_listbox.delete(0, tk.END)

    set_status("red", "Idle")
    messagebox.showinfo("Capture Cleared", "All captured packets and data have been cleared.")

def gui_flush_pending():
    while pending_ui_updates:
        func, args, kwargs = pending_ui_updates.popleft()
        try:
            func(*args, **kwargs)
        except Exception:
            print("GUI update error:", func, args, kwargs)
    root.after(300, gui_flush_pending)

def open_preferences_dialog():
    dlg = tk.Toplevel(root)
    dlg.title("Preferences")
    dlg.transient(root)
    dlg.grab_set()

    tk.Label(dlg, text="Default capture filter").grid(row=0, column=0, padx=10, pady=8, sticky="w")
    filter_var = tk.StringVar(value=filter_entry.get() or DEFAULT_CAPTURE_FILTER)
    tk.Entry(dlg, textvariable=filter_var, width=30).grid(row=0, column=1, padx=10, pady=8, sticky="w")

    tk.Label(dlg, text="Protocol colors").grid(row=1, column=0, padx=10, pady=(8,2), sticky="nw")
    colors_frame = ttk.Frame(dlg)
    colors_frame.grid(row=1, column=1, padx=10, pady=(8,2), sticky="w")

    color_vars = {}
    row_idx = 0
    for proto in ["TCP","UDP","ICMP","HTTP","TLS","Ethernet","IP","Other"]:
        tk.Label(colors_frame, text=proto, width=10, anchor="w").grid(row=row_idx, column=0, sticky="w", padx=(0,6), pady=2)
        var = tk.StringVar(value=PROTO_COLORS.get(proto, "#ffffff"))
        color_vars[proto] = var
        ent = tk.Entry(colors_frame, textvariable=var, width=12)
        ent.grid(row=row_idx, column=1, sticky="w")
        def make_pick(p=proto, v=var):
            def pick():
                initial = v.get()
                rgb, hexv = colorchooser.askcolor(color=initial, title=f"Pick color for {p}")
                if hexv:
                    v.set(hexv)
            return pick
        tk.Button(colors_frame, text="Pick", command=make_pick()).grid(row=row_idx, column=2, padx=6)
        row_idx += 1

    btns = ttk.Frame(dlg)
    btns.grid(row=99, column=0, columnspan=2, pady=12)
    def on_save():
        for p, v in color_vars.items():
            PROTO_COLORS[p] = v.get()
            try:
                packet_table.tag_configure(p, background=v.get())
            except Exception:
                pass
        PREFERENCES_DEFAULTS["default_filter"] = filter_var.get()
        PREFERENCES_DEFAULTS["proto_colors"] = dict(PROTO_COLORS)
        ok = save_preferences_to_source(PREFERENCES_DEFAULTS)
        if ok:
            messagebox.showinfo("Preferences", "Colors updated successfully.")
        dlg.destroy()

    ttk.Button(btns, text="Save", command=on_save).pack(side=tk.LEFT, padx=6)
    ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side=tk.LEFT, padx=6)

root = tk.Tk()
root.title("Parzival")
root.geometry("1400x820")

menubar = tk.Menu(root)
root.config(menu=menubar)

def _ask_save_pcap():
    save_pcap_to_file()

def _export_packets_excel():
    export_packets("excel")

def _export_credentials_excel():
    export_credentials("excel")

def _exit_app():
    root.quit()

file_menu = tk.Menu(menubar, tearoff=0)
file_menu.add_command(label="Save PCAP", command=save_pcap_to_file)
file_menu.add_command(label="Load PCAP", command=load_pcap_from_file)
file_menu.add_separator()
file_menu.add_command(label="Export Packets Excel", command=_export_packets_excel)
file_menu.add_command(label="Export Credentials Excel", command=_export_credentials_excel)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=_exit_app)
menubar.add_cascade(label="File", menu=file_menu)

app_menu = tk.Menu(menubar, tearoff=0)
app_menu.add_command(label="Preferences...", command=open_preferences_dialog)
menubar.add_cascade(label="Settings", menu=app_menu)

toolbar = tk.Frame(root)
toolbar.pack(side=tk.TOP, fill=tk.X)

start_btn = tk.Button(toolbar, text="Start Capture", bg="green", fg="white", command=start_sniffing)
start_btn.pack(side=tk.LEFT, padx=4, pady=4)
stop_btn = tk.Button(toolbar, text="Stop Capture", bg="red", fg="white", command=stop_sniffing)
stop_btn.pack(side=tk.LEFT, padx=4, pady=4)

tk.Button(toolbar, text="Follow Stream", bg="darkcyan", fg="white", command=follow_stream).pack(side=tk.LEFT, padx=4)
tk.Button(toolbar, text="Clear Capture", bg="orange", fg="black", command=clear_captured).pack(side=tk.LEFT, padx=6)

status_canvas = tk.Canvas(toolbar, width=18, height=18, highlightthickness=0)
status_canvas.pack(side=tk.LEFT, padx=4)
status_circle = status_canvas.create_oval(2, 2, 16, 16, fill="red", outline="black")

status_label = tk.Label(toolbar, text="Idle", font=("Arial", 10, "bold"))
status_label.pack(side=tk.LEFT, padx=4)

tk.Label(toolbar, text="Capture Filter (BPF):").pack(side=tk.LEFT, padx=(10,2))
filter_entry = tk.Entry(toolbar, width=30)
filter_entry.pack(side=tk.LEFT, padx=4)
filter_entry.insert(0, DEFAULT_CAPTURE_FILTER)

PORT_OPTIONS = [
    ("All", ""),
    ("HTTP (80)", "port 80"),
    ("HTTPS (443)", "port 443"),
    ("DNS (53)", "port 53"),
    ("FTP (21)", "port 21"),
    ("SSH (22)", "port 22"),
    ("SMTP (25)", "port 25"),
    ("POP3 (110)", "port 110"),
    ("IMAP (143)", "port 143"),
    ("TCP Any", "tcp"),
    ("UDP Any", "udp"),
    ("TCP Common", "tcp port (80 or 443 or 22 or 21 or 25 or 110 or 143)"),
    ("UDP Common", "udp port (53 or 67 or 68 or 123 or 161 or 162)"),
    ("Custom...", "custom")
]

port_var = tk.StringVar(value="")
port_combo = ttk.Combobox(toolbar, textvariable=port_var, values=[p[0] for p in PORT_OPTIONS], width=18, state="readonly")
port_combo.pack(side=tk.LEFT, padx=6)
port_combo.current(0)

def on_port_select(event=None):
    sel = port_combo.get()
    for label, val in PORT_OPTIONS:
        if label == sel:
            if val == "custom":
                custom = simpledialog.askstring("Custom Port", "Enter port number:")
                if custom:
                    filter_entry.delete(0, tk.END)
                    filter_entry.insert(0, f"port {custom}")
            else:
                filter_entry.delete(0, tk.END)
                filter_entry.insert(0, val)
            break

port_combo.bind("<<ComboboxSelected>>", on_port_select)

def set_status(color, text):
    status_canvas.itemconfig(status_circle, fill=color)
    status_label.config(text=text)

tabs = ttk.Notebook(root)
tabs.pack(fill=tk.BOTH, expand=True)

packet_tab = ttk.Frame(tabs)
tabs.add(packet_tab, text="Packets")

columns = ("ID", "Time", "Source", "Destination", "Protocol", "Length")

packet_paned = ttk.PanedWindow(packet_tab, orient=tk.VERTICAL)
packet_paned.pack(fill=tk.BOTH, expand=True)

upper_frame = ttk.Frame(packet_paned)
lower_frame = ttk.Frame(packet_paned)
packet_paned.add(upper_frame, weight=3)
packet_paned.add(lower_frame, weight=1)
table_wrap = ttk.Frame(upper_frame)
table_wrap.pack(fill=tk.BOTH, expand=True)

packet_table = ttk.Treeview(table_wrap, columns=columns, show="headings")
for col in columns:
    packet_table.heading(col, text=col)
    packet_table.column(col, width=140, anchor="center")

vsb = ttk.Scrollbar(table_wrap, orient="vertical", command=packet_table.yview)
hsb = ttk.Scrollbar(table_wrap, orient="horizontal", command=packet_table.xview)
packet_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
table_wrap.columnconfigure(0, weight=1)
table_wrap.rowconfigure(0, weight=1)
packet_table.grid(row=0, column=0, sticky="nsew")
vsb.grid(row=0, column=1, sticky="ns")
hsb.grid(row=1, column=0, sticky="ew")

packet_details = scrolledtext.ScrolledText(lower_frame, wrap=tk.WORD, height=12)
packet_details.pack(fill=tk.BOTH, expand=True)

def on_packet_double(event):
    sel = packet_table.focus()
    if not sel:
        return
    idx = int(packet_table.item(sel)["values"][0]) - 1
    pkt = captured_packets[idx]
    packet_details.delete("1.0", tk.END)
    try:
        packet_details.insert(tk.END, pkt.show(dump=True))
    except Exception:
        packet_details.insert(tk.END, str(pkt.summary()))
packet_table.bind("<Double-1>", on_packet_double)

stats_tab = ttk.Frame(tabs)
tabs.add(stats_tab, text="Statistics")
fig, axs = plt.subplots(1, 3, figsize=(13, 4), constrained_layout=True)
stats_canvas = FigureCanvasTkAgg(fig, master=stats_tab)
stats_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def monitor_bandwidth_thread():
    global total_bytes
    prev = 0
    prev_time = time.time()
    while True:
        time.sleep(2)
        now = time.time()
        elapsed = now - prev_time if prev_time else 1
        delta = total_bytes - prev
        prev = total_bytes
        prev_time = now
        mbps = (delta * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
        bandwidth_data.append(mbps)

threading.Thread(target=monitor_bandwidth_thread, daemon=True).start()
def _smooth(vals, window=5):
    if len(vals) < 3:
        return list(vals)
    w = min(window, len(vals))
    kernel = np.ones(w) / w
    return np.convolve(vals, kernel, mode="same").tolist()

def periodic_stats_draw():
    try:
        axs[0].clear(); axs[1].clear(); axs[2].clear()
        if protocol_counter:
            axs[0].bar(list(protocol_counter.keys()), list(protocol_counter.values()))
            axs[0].set_title("Protocol Distribution")

        if ip_counter:
            top = ip_counter.most_common(5)
            if top:
                labels, sizes = zip(*top)
                wedges, _ = axs[1].pie(
                    sizes,
                    startangle=90,
                    wedgeprops=dict(width=0.45, edgecolor="white")
                )
                axs[1].add_artist(plt.Circle((0, 0), 0.45, color="white", zorder=10))
                axs[1].set_title("Top Talkers")
                axs[1].legend(
                    labels,
                    loc="upper center",
                    bbox_to_anchor=(0.5, 0.08), 
                    title="IP",
                    ncol=min(3, len(labels)),
                    frameon=False
                )

        bw = list(bandwidth_data)
        if bw:
            x = list(range(len(bw)))
            y = _smooth(bw, window=5)
            axs[2].plot(x, y, linewidth=2)
            axs[2].fill_between(x, y, step=None, alpha=0.15)
            axs[2].set_title("Bandwidth Mbps")
            axs[2].xaxis.set_major_locator(MaxNLocator(nbins=6, integer=True))
            axs[2].yaxis.set_major_locator(MaxNLocator(nbins=5))
            axs[2].yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.1f}"))
            axs[2].margins(x=0)
            axs[2].grid(True, which="major", axis="both")

        stats_canvas.draw()
    except Exception:
        pass
    root.after(2000, periodic_stats_draw)
root.after(2000, periodic_stats_draw)

http_tab = ttk.Frame(tabs)
tabs.add(http_tab, text="HTTP")
http_search_var = tk.StringVar()
http_search_frame = tk.Frame(http_tab)
http_search_frame.pack(side=tk.TOP, fill=tk.X)
tk.Entry(http_search_frame, textvariable=http_search_var, width=40).pack(side=tk.LEFT, padx=5, pady=4)
tk.Button(http_search_frame, text="Find", command=lambda: refresh_http_list()).pack(side=tk.LEFT, padx=4)
http_listbox = tk.Listbox(http_tab, width=40)
http_listbox.pack(side=tk.LEFT, fill=tk.Y)
http_text = scrolledtext.ScrolledText(http_tab)
http_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

def refresh_http_list():
    q = http_search_var.get().lower()
    http_listbox.delete(0, tk.END)
    for i, h in enumerate(http_sessions, 1):
        if h.get('type') == 'request':
            label = f"{i}: {h.get('method', 'UNKNOWN')} {h.get('path', '')}"
        elif h.get('type') == 'response':
            label = f"{i}: HTTP {h.get('status', '')}"
        else:
            label = f"{i}: {h.get('request_line', 'HTTP Session')}"
        
        if not q or q in label.lower() or q in str(h).lower():
            http_listbox.insert(tk.END, label)

def show_http_detail(evt):
    sel = http_listbox.curselection()
    if not sel: return
    idx = sel[0]
    h = http_sessions[idx]
    http_text.delete("1.0", tk.END)
    http_text.insert(tk.END, f"Type: {h.get('type', 'unknown').upper()}\n")
    http_text.insert(tk.END, f"Source: {h['src']}\n")
    http_text.insert(tk.END, f"Destination: {h['dst']}\n")
    http_text.insert(tk.END, f"\nRequest/Status Line:\n{h.get('request_line', 'N/A')}\n")
    if h.get('method'):
        http_text.insert(tk.END, f"\nMethod: {h['method']}\n")
    if h.get('path'):
        http_text.insert(tk.END, f"Path: {h['path']}\n")
    if h.get('status'):
        http_text.insert(tk.END, f"Status: {h['status']}\n")
    
    http_text.insert(tk.END, f"\nHeaders:\n")
    for k, v in h.get("headers", {}).items():
        http_text.insert(tk.END, f"  {k}: {v}\n")
http_listbox.bind("<<ListboxSelect>>", show_http_detail)

tls_tab = ttk.Frame(tabs)
tabs.add(tls_tab, text="TLS")
tls_search_var = tk.StringVar()
tls_search_frame = tk.Frame(tls_tab)
tls_search_frame.pack(side=tk.TOP, fill=tk.X)
tk.Entry(tls_search_frame, textvariable=tls_search_var, width=40).pack(side=tk.LEFT, padx=5, pady=4)
tk.Button(tls_search_frame, text="Find", command=lambda: refresh_tls_list()).pack(side=tk.LEFT, padx=4)
tls_listbox = tk.Listbox(tls_tab, width=40)
tls_listbox.pack(side=tk.LEFT, fill=tk.Y)
tls_text = scrolledtext.ScrolledText(tls_tab)
tls_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

def refresh_tls_list():
    q = tls_search_var.get().lower()
    tls_listbox.delete(0, tk.END)
    for i, t in enumerate(tls_sessions, 1):
        label = f"{i}: {t['type']} {t.get('sni','')}"
        if not q or q in label.lower() or q in str(t).lower():
            tls_listbox.insert(tk.END, label)

def show_tls_detail(evt):
    sel = tls_listbox.curselection()
    if not sel: return
    t = tls_sessions[sel[0]]
    tls_text.delete("1.0", tk.END)
    tls_text.insert(tk.END, f"Type: {t['type']}\n")
    tls_text.insert(tk.END, f"Source: {t['src']}\n")
    tls_text.insert(tk.END, f"Destination: {t['dst']}\n")
    
    if t['type'] == 'ClientHello':
        tls_text.insert(tk.END, f"SNI: {t.get('sni', 'Not available')}\n")
    elif t['type'] == 'ServerHello':
        tls_text.insert(tk.END, f"Version: {t.get('version', 'N/A')}\n")
        tls_text.insert(tk.END, f"Cipher: {t.get('cipher', 'N/A')}\n")
    elif t['type'] == 'Certificate':
        tls_text.insert(tk.END, f"Certificates: {len(t.get('certs', []))}\n")
        for i, cert in enumerate(t.get('certs', [])):
            tls_text.insert(tk.END, f"  Cert {i+1}: {cert}\n")
    tls_text.insert(tk.END, str(t))
tls_listbox.bind("<<ListboxSelect>>", show_tls_detail)

obj_tab = ttk.Frame(tabs)
tabs.add(obj_tab, text="HTTP Objects")
obj_search_var = tk.StringVar()
obj_search_frame = tk.Frame(obj_tab)
obj_search_frame.pack(side=tk.TOP, fill=tk.X)
tk.Entry(obj_search_frame, textvariable=obj_search_var, width=40).pack(side=tk.LEFT, padx=5, pady=4)
tk.Button(obj_search_frame, text="Find", command=lambda: refresh_obj_list()).pack(side=tk.LEFT, padx=4)
obj_listbox = tk.Listbox(obj_tab, width=40)
obj_listbox.pack(side=tk.LEFT, fill=tk.Y)
obj_text = scrolledtext.ScrolledText(obj_tab)
obj_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

def refresh_obj_list():
    q = obj_search_var.get().lower()
    obj_listbox.delete(0, tk.END)
    for i, o in enumerate(http_objects, 1):
        label = f"{i}: {o['filename']}"
        if not q or q in label.lower() or q in str(o).lower():
            obj_listbox.insert(tk.END, label)

def show_obj_detail(evt):
    sel = obj_listbox.curselection()
    if not sel: return
    o = http_objects[sel[0]]
    obj_text.delete("1.0", tk.END)
    obj_text.insert(tk.END, f"Filename: {o['filename']}\nHeaders:\n")
    for k, v in o["headers"].items():
        obj_text.insert(tk.END, f"  {k}: {v}\n")
    obj_text.insert(tk.END, f"\nPayload size: {len(o['payload'])} bytes\n")
obj_listbox.bind("<<ListboxSelect>>", show_obj_detail)

cred_tab = ttk.Frame(tabs)
tabs.add(cred_tab, text="Credentials")
cred_search_var = tk.StringVar()
cred_search_frame = tk.Frame(cred_tab)
cred_search_frame.pack(side=tk.TOP, fill=tk.X)
tk.Entry(cred_search_frame, textvariable=cred_search_var, width=40).pack(side=tk.LEFT, padx=5, pady=4)
tk.Button(cred_search_frame, text="Find", command=lambda: refresh_cred_list()).pack(side=tk.LEFT, padx=4)
cred_listbox = tk.Listbox(cred_tab, width=40)
cred_listbox.pack(side=tk.LEFT, fill=tk.Y)
cred_text = scrolledtext.ScrolledText(cred_tab)
cred_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

def refresh_cred_list():
    q = cred_search_var.get().lower()
    cred_listbox.delete(0, tk.END)
    for i, c in enumerate(credentials, 1):
        label = f"{i}: {c['src']} -> {c['dst']}"
        if not q or q in label.lower() or q in str(c).lower():
            cred_listbox.insert(tk.END, label)

def show_cred_detail(evt):
    sel = cred_listbox.curselection()
    if not sel: return
    c = credentials[sel[0]]
    cred_text.delete("1.0", tk.END)
    cred_text.insert(tk.END, f"Source: {c['src']}\nDestination: {c['dst']}\n\nDetected pairs:\n")
    for k, v in c["creds"]:
        cred_text.insert(tk.END, f"  {k}: {v}\n")
    cred_text.insert(tk.END, f"\nPayload snippet:\n{c['payload_snippet']}\n")
cred_listbox.bind("<<ListboxSelect>>", show_cred_detail)

def periodic_refresh_lists():
    current = tabs.select()
    tab_text = tabs.tab(current, "text")
    if tab_text == "HTTP":
        refresh_http_list()
    elif tab_text == "TLS":
        refresh_tls_list()
    elif tab_text == "HTTP Objects":
        refresh_obj_list()
    elif tab_text == "Credentials":
        refresh_cred_list()
    root.after(1500, periodic_refresh_lists)

root.after(1500, periodic_refresh_lists)
root.after(300, gui_flush_pending)

if __name__ == "__main__":
    try:
        root.mainloop()
    except KeyboardInterrupt:
        stop_sniffing_flag = True
        print("Exiting...")