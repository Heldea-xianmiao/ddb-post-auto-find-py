import os
import sys
import subprocess
import threading
import time
import requests
import logging
import webbrowser
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import tkinter.font as tkfont

# --- 自动环境检测与安装 ---
def setup_environment():
    """检测并安装依赖库 (使用清华源加速)"""
    # 如果处于打包环境（sys.frozen），则跳过安装逻辑，因为依赖已打包在内
    if getattr(sys, 'frozen', False):
        return

    required_packages = ["requests"]
    missing = []
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        index_url = "https://pypi.tuna.tsinghua.edu.cn/simple"
        print(f"检测到缺失依赖: {missing}，正在通过中国大陆镜像源安装...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--index-url", index_url, *missing])
            print("依赖安装成功！")
        except Exception as e:
            print(f"安装失败: {e}")

setup_environment()

# 尝试导入核心逻辑
try:
    import monitor_core as core
except ImportError:
    messagebox.showerror("错误", "未找到 monitor_core.py，请确保该文件在同一目录下。")
    sys.exit(1)

class DDBMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("✨ DDB Beyond Sentinel v1.4")
        self.root.geometry("950x750")
        self.root.configure(bg="#1e1e2e")
        
        self.monitoring = False
        self.stop_event = threading.Event()
        
        # 记录已通报过的 ID 状态，防止重复报警（特别是针对 Timeout 后又重新探测到的情况）
        # 格式: {id: (present, viewable)}
        self.alert_history = {} 
        
        self._init_fonts()
        self._setup_ui()
        self._setup_logging()

    def _init_fonts(self):
        available = tkfont.families()
        pref_mono = ["Cascadia Code", "Cascadia Mono", "Fira Code", "Consolas", "Courier New"]
        pref_ui = ["Segoe UI Variable Text", "Segoe UI Semibold", "Microsoft YaHei UI", "SimSun"]
        self.mono_font = next((f for f in pref_mono if f in available), "Courier")
        self.ui_font = next((f for f in pref_ui if f in available), "System")

    def _setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        bg_col = "#1e1e2e"
        fg_col = "#cdd6f4"
        accent_col = "#89b4fa"
        
        style.configure("TLabel", background=bg_col, foreground=fg_col, font=(self.ui_font, 10))
        style.configure("TFrame", background=bg_col)
        style.configure("TLabelframe", background=bg_col, foreground=accent_col, font=(self.ui_font, 11, "bold"))
        style.configure("TLabelframe.Label", background=bg_col, foreground=accent_col)
        
        # 配置区
        config_frame = ttk.LabelFrame(self.root, text=" ⚙️ 监控配置中心 ", padding=15)
        config_frame.pack(fill="x", padx=15, pady=10)
        
        # ID 范围
        row1 = ttk.Frame(config_frame)
        row1.pack(fill="x", pady=7)
        ttk.Label(row1, text="起始 ID:").pack(side="left", padx=5)
        self.start_id_entry = tk.Entry(row1, width=12, bg="#313244", fg="#a6e3a1", insertbackground="white", relief="flat", font=(self.mono_font, 10, "bold"))
        self.start_id_entry.insert(0, "2150")
        self.start_id_entry.pack(side="left", padx=5)
        
        ttk.Label(row1, text="终止 ID:").pack(side="left", padx=15)
        self.end_id_entry = tk.Entry(row1, width=12, bg="#313244", fg="#a6e3a1", insertbackground="white", relief="flat", font=(self.mono_font, 10, "bold"))
        self.end_id_entry.insert(0, "2170")
        self.end_id_entry.pack(side="left", padx=5)

        # 间隔设置
        row2 = ttk.Frame(config_frame)
        row2.pack(fill="x", pady=7)
        ttk.Label(row2, text="🌅 日间探测时长 (s):").pack(side="left", padx=5)
        self.day_int_entry = tk.Entry(row2, width=10, bg="#313244", fg=fg_col, relief="flat", font=(self.mono_font, 10))
        self.day_int_entry.insert(0, "3600")
        self.day_int_entry.pack(side="left", padx=5)
        
        ttk.Label(row2, text="🌃 夜间探测时长 (s):").pack(side="left", padx=15)
        self.night_int_entry = tk.Entry(row2, width=10, bg="#313244", fg=fg_col, relief="flat", font=(self.mono_font, 10))
        self.night_int_entry.insert(0, "900")
        self.night_int_entry.pack(side="left", padx=5)

        # Qmsg 设置与指南
        row3 = ttk.Frame(config_frame)
        row3.pack(fill="x", pady=7)
        ttk.Label(row3, text="⚓ Qmsg 识别码 (可选):").pack(side="left", padx=5)
        self.qmsg_key_entry = tk.Entry(row3, width=35, bg="#313244", fg="#f9e2af", insertbackground="white", relief="flat", font=(self.mono_font, 9))
        self.qmsg_key_entry.pack(side="left", padx=5)
        
        guide_btn = tk.Label(row3, text="[ 获取指南 ]", fg="#89dceb", bg=bg_col, cursor="hand2", font=(self.ui_font, 9, "underline"))
        guide_btn.pack(side="left", padx=10)
        guide_btn.bind("<Button-1>", lambda e: self._open_qmsg_guide())

        # 启动/停止按钮
        self.btn_toggle = tk.Button(config_frame, text="开始监测", 
                                   command=self.toggle_monitoring,
                                   bg="#a6e3a1", fg="#11111b", 
                                   font=(self.ui_font, 11, "bold"),
                                   activebackground="#94e2d5", relief="flat", padx=30, pady=5)
        self.btn_toggle.pack(side="right", pady=5)
        
        # 输出区
        output_frame = ttk.LabelFrame(self.root, text=" 📝 实时监测情报回传 ", padding=10)
        output_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        self.log_area = scrolledtext.ScrolledText(
            output_frame, state='disabled', wrap='none', 
            bg="#11111b", fg="#cdd6f4", font=(self.mono_font, 10),
            padx=15, pady=15, relief="flat"
        )
        self.log_area.pack(fill="both", expand=True)

    def _open_qmsg_guide(self):
        msg = "Qmsg 个人识别码获取教程：\n\n1. 访问官网 https://qmsg.zendee.cn/\n2. 点击『管理台』，使用 QQ 扫码登录\n3. 在『个人中心』页面复制您的『KEY』\n4. 将 KEY 填入程序对应的输入框即可\n\n注意：如果留空，程序将只在本地输出结果，不通过 QQ 推送。"
        messagebox.showinfo("Qmsg 操作指南", msg)
        webbrowser.open("https://qmsg.zendee.cn/")

    def _setup_logging(self):
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget
                self.colors = {"INFO": "#cdd6f4", "WARNING": "#fab387", "ERROR": "#f38ba8"}

            def emit(self, record):
                msg = self.format(record)
                color = self.colors.get(record.levelname, "#cdd6f4")
                def append():
                    self.text_widget.configure(state='normal')
                    tag_name = f"tag_{record.levelname}"
                    self.text_widget.tag_config(tag_name, foreground=color)
                    self.text_widget.insert(tk.END, msg + '\n', tag_name)
                    self.text_widget.configure(state='disabled')
                    self.text_widget.yview(tk.END)
                self.text_widget.after(0, append)

        logger = logging.getLogger()
        handler = TextHandler(self.log_area)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def toggle_monitoring(self):
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        try:
            start_id = int(self.start_id_entry.get())
            end_id = int(self.end_id_entry.get())
            day_iv = int(self.day_int_entry.get())
            night_iv = int(self.night_int_entry.get())
            qmsg_key = self.qmsg_key_entry.get().strip() or None
            ids_str = f"{start_id}-{end_id}"
        except ValueError:
            messagebox.showwarning("核验异常", "请确保 ID 范围与间隔时间均为有效的整数数值。")
            return

        self.monitoring = True
        self.stop_event.clear()
        self.btn_toggle.config(text="结束监测", bg="#f38ba8")
        
        # 启动时重置报警历史，以确认为新任务
        self.alert_history = {} 
        
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, 
            args=(start_id, end_id, day_iv, night_iv, qmsg_key), 
            daemon=True
        )
        self.monitor_thread.start()
        logging.info(f"Sentinel 任务已挂载，扫描 ID 范围: {ids_str}")

    def stop_monitoring(self):
        self.monitoring = False
        self.stop_event.set()
        self.btn_toggle.config(text="开始监测", bg="#a6e3a1")
        logging.warning("监控系统已被用户手动挂起。")

    def _monitor_loop(self, s_id, e_id, day_iv, night_iv, qmsg_key):
        ids_str = f"{s_id}-{e_id}"
        target_ids = list(range(s_id, e_id + 1))
        session = requests.Session()
        session.headers.update({"User-Agent": core.USER_AGENT})
        
        if qmsg_key:
            try:
                core.send_qq_msg(f"ddb帖子监测已启动 (ID: {s_id}-{e_id})", key=qmsg_key)
            except:
                pass

        while self.monitoring:
            try:
                current_results = core.run_scan(session, target_ids)
                notifications = []

                for n, info in current_results.items():
                    # 处理异常探测结果（如 Timed out 等）
                    if info["reason"].startswith("error:"):
                        continue
                    
                    # 只有当探测结果真正“正常”时才检查报警逻辑
                    old_state = self.alert_history.get(n)
                    current_state = (info["present"], info["viewable"])

                    # 如果状态与上次报警时一致，则不再通报
                    if old_state == current_state:
                        continue

                    # 发现新变化
                    if current_state[0] and (not old_state or not old_state[0]):
                        notifications.append(f"【发现新篇】ID {n}:\n{info['title']}")
                        self.alert_history[n] = current_state
                    elif current_state[1] and (not old_state or not old_state[1]):
                        notifications.append(f"【全文解锁】ID {n}:\n{info['title']}")
                        self.alert_history[n] = current_state

                if notifications and qmsg_key:
                    msg = "\n\n".join(notifications)
                    core.flash_taskbar()
                    core.show_notification("DDB Sentinel 警报", f"捕获到 {len(notifications)} 条关键更新")
                    core.send_qq_msg(msg, key=qmsg_key)

                # 间隔休眠逻辑
                hour = time.localtime().tm_hour
                wait = day_iv if 8 <= hour < 20 else night_iv
                logging.info(f"周期完成 ({'日间' if 8 <= hour < 20 else '夜间'})，休眠 {wait}s...")

                for _ in range(wait):
                    if self.stop_event.is_set(): break
                    time.sleep(1)
                
            except Exception as e:
                logging.error(f"侦察期间发生执行冲突: {e}")
                time.sleep(10)
                if self.stop_event.is_set(): break

        logging.info("Sentinel 已停机。")

if __name__ == "__main__":
    root = tk.Tk()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    root.geometry('%dx%d+%d+%d' % (950, 750, (screen_width/2)-475, (screen_height/2)-375))
    app = DDBMonitorGUI(root)
    root.mainloop()
