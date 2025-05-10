import requests
import time
import socket
import uuid
from datetime import datetime
import threading
from tkinter import *
from tkinter import ttk, scrolledtext
import os
import json  # 顶部新增导入
import winreg  # 新增：用于操作Windows注册表
import sys     # 新增：用于获取程序路径


class CampusNetworkApp:
    def __init__(self, root):
        # 初始化网络请求session用于连接复用
        self.session = requests.Session()
        # 缓存本地IP和MAC地址（每5分钟刷新一次）
        self.cached_ip = None
        self.cached_mac = None
        self.last_cache_time = datetime.now()
        self.root = root
        self.root.title("海软网络助手")
        self.root.geometry("700x600")
        self.root.configure(bg="#202020")  # 设置根窗口背景色

        # 初始化ttk样式
        style = ttk.Style()

        # 配置项（改为从输入框获取）
        self.LOGIN_URL = "http://222.17.244.41/eportal/InterFace.do?method=login"
        self.CHECK_URL = "http://edge-http.microsoft.com/captiveportal/generate_204"
        self.USER_ID = ""  # 从输入框获取
        self.PASSWORD = ""  # 从输入框获取
        self.CHECK_INTERVAL = 15  # 从输入框获取

        # 请求头（保持原逻辑）
        self.headers = {
            "Host": "222.17.244.41",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "http://222.17.244.41",
            "Referer": "http://222.17.244.41/eportal/index.jsp?wlanuserip=10.81.41.86&wlanacname=NAS&ssid=Ruijie&nasip=172.16.200.100&mac=eef156836597&t=wireless-v2-plain&url=http://www.msftconnecttest.com/redirect",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cookie": "EPORTAL_COOKIE_PASSWORD=; EPORTAL_COOKIE_USERNAME=20210101088; EPORTAL_COOKIE_SERVER=; EPORTAL_COOKIE_SERVER_NAME=%E8%AF%B7%E9%80%89%E6%8B%A9%E6%9C%8D%E5%8A%A1; EPORTAL_COOKIE_DOMAIN=; EPORTAL_COOKIE_SAVEPASSWORD=true; EPORTAL_COOKIE_OPERATORPWD=; JSESSIONID=A6AC484A75B6B829DB48625ED4025F27",
            "Connection": "close"
        }

        # 初始化ttk样式（正确位置：组件创建前）
        style = ttk.Style()
        style.theme_use("clam")  # 使用支持自定义颜色的主题
        # 标签：深灰背景+白色文字
        style.configure("TLabel", background="#202020", foreground="#FFFFFF")
        # 按钮：深灰背景（悬停/按下时变深）+白色文字
        style.configure("TButton", 
                        background="#333333", 
                        foreground="#FFFFFF", 
                        padding=20,  # 增加内边距使按钮更圆润
                        borderwidth=2,  # 增加边框宽度
                        relief="flat")  # 初始边框样式为flat
        style.map("TButton", 
                 background=[("active", "#404040"), ("pressed", "#2a2a2a")],
                 relief=[("active", "groove"), ("pressed", "sunken")])  # 悬停/按下时的边框效果

        # 输入框：深灰背景+白色文字+浅色边框
        style.map("TEntry",
                  fieldbackground=[("active", "#333333"), ("!active", "#333333")],
                  bordercolor=[("focus", "#606060")])  # 聚焦时边框颜色
        # 框架背景与主窗口一致
        style.configure("TFrame", background="#202020")

        # 新增：复选框样式配置（背景与主窗口一致）
        style.configure("TCheckbutton",
                        background="#202020",  # 与主窗口背景色一致
                        foreground="#FFFFFF",  # 文字白色
                        indicatorbackground="#333333",  # 勾选框区域背景色（与输入框一致）
                        indicatorforeground="#00FF00")  # 新增：勾选标记颜色设为绿色
        style.map("TCheckbutton",
                 background=[("active", "#202020")],  # 悬停时保持背景色不变
                 foreground=[("active", "#FFFFFF")])  # 悬停时文字颜色不变

        # GUI 组件（新增输入框）
        # 账号输入
        self.user_frame = ttk.Frame(root)
        self.user_frame.pack(pady=5)
        ttk.Label(self.user_frame, text="账号：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5)
        self.user_entry = ttk.Entry(self.user_frame, width=30)
        self.user_entry.grid(row=0, column=1, padx=5)
        self.user_entry.insert(0, "")  # 默认值

        # 密码输入（隐藏显示）
        self.pwd_frame = ttk.Frame(root)
        self.pwd_frame.pack(pady=5)
        ttk.Label(self.pwd_frame, text="密码：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5)
        self.pwd_entry = ttk.Entry(self.pwd_frame, width=30, show="*")  # 隐藏密码输入
        self.pwd_entry.grid(row=0, column=1, padx=5)
        self.pwd_entry.insert(0, "")  # 默认值

        # 新增：记住密码复选框
        self.remember_var = IntVar()  # 用于存储复选框状态（1=选中，0=未选中）
        self.remember_check = ttk.Checkbutton(
            self.pwd_frame,
            text="记住密码",
            variable=self.remember_var,
            style="TCheckbutton"  # 使用统一样式
        )
        self.remember_check.grid(row=1, column=1, padx=5, pady=2, sticky=W)  # 放在密码框下方左侧

        # 新增：自启动复选框（新增代码）
        self.remember_launch_var = IntVar()  # 自启动状态变量
        self.remember_launch_check = ttk.Checkbutton(
            self.pwd_frame,
            text="开机自启动",
            variable=self.remember_launch_var,
            style="TCheckbutton"  # 使用统一样式
        )
        self.remember_launch_check.grid(row=2, column=1, padx=5, pady=2, sticky=W)  # 放在记住密码下方

        # 检测间隔输入（秒）
        self.interval_frame = ttk.Frame(root)
        self.interval_frame.pack(pady=5)
        ttk.Label(self.interval_frame, text="检测间隔（秒）：", font=("微软雅黑", 10)).grid(row=0, column=0, padx=5)
        self.interval_entry = ttk.Entry(self.interval_frame, width=10)
        self.interval_entry.grid(row=0, column=1, padx=5)
        self.interval_entry.insert(0, "2")  # 默认值

        # 状态标签（已通过style统一设置颜色）
        self.status_label = ttk.Label(root, text="状态：未启动", font=("微软雅黑", 12))
        self.status_label.pack(pady=10)

        # 新增：开启时间标签
        self.duration_label = ttk.Label(root, text="开启时间：未启动", font=("微软雅黑", 12))
        self.duration_label.pack(pady=5)

        # 新增：重连计数标签
        self.reconnect_label = ttk.Label(root, text="重连次数：0", font=("微软雅黑", 12))
        self.reconnect_label.pack(pady=5)

        # 日志框（单独设置背景和文字颜色）
        self.log_text = scrolledtext.ScrolledText(root, wrap=WORD, width=70, height=15,
                                                  bg="#3a3a3a",  # 原#202020改为更明显
                                                  fg="#FFFFFF",
                                                  insertbackground="#FFFFFF",  # 光标白色
                                                  bd=1, relief="solid",  # 增加边框
                                                  highlightthickness=0)  # 移除Tk默认高亮边框
        self.log_text.pack(padx=10, pady=5)
        
        # 配置日志分类颜色（与Windows深色主题更协调）
        self.log_text.tag_config("success", foreground="#00FF00")  # 绿色
        self.log_text.tag_config("warning", foreground="#FFD700")  # 金色（替代纯黄）
        self.log_text.tag_config("error", foreground="#FF6347")    # 珊瑚红（替代纯红）

        # 控制按钮框架背景色同步
        self.control_frame = ttk.Frame(root, style="TFrame")
        self.control_frame.pack(pady=10)

        self.start_btn = ttk.Button(self.control_frame, text="启动", command=self.start_monitor)
        self.start_btn.grid(row=0, column=0, padx=10)
        self.stop_btn = ttk.Button(self.control_frame, text="停止", command=self.stop_monitor, state=DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=10)

        # 线程控制变量
        self.running = False
        self.thread = None
        self.stop_event = threading.Event()
        self.reconnect_count = 0  # 新增：重连计数初始化

        # 新增：配置文件路径（必须在__init__方法内初始化）
        self.config_path = os.path.join(
            os.environ.get("APPDATA", os.path.expanduser("~")),
            "campus_network_config.json"
        )

        # 新增：启动时加载保存的配置（关键修复）
        self.load_saved_config()  # 添加此行

    def log(self, message):
        """线程安全的日志输出（带颜色分类）"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        full_msg = f"[{timestamp}] {message}\n"
        # 限制日志最多保留1000行
        if int(self.log_text.index('end-1c').split('.')[0]) > 1000:
            self.log_text.delete('1.0', '2.0')  # 删除最旧的一行
        self.log_text.insert(END, full_msg)
        
        # 根据消息内容添加颜色标签
        if "成功" in message:
            self.log_text.tag_add("success", f"end-{len(full_msg)+1}c", "end-1c")
        elif "警告" in message:
            self.log_text.tag_add("warning", f"end-{len(full_msg)+1}c", "end-1c")
        elif "错误" in message:
            self.log_text.tag_add("error", f"end-{len(full_msg)+1}c", "end-1c")
            
        self.log_text.see(END)  # 自动滚动到最新日志

    def get_local_ip(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def get_local_mac(self):
        try:
            mac_int = uuid.getnode()
            return ":".join(f"{(mac_int >> i) & 0xFF:02x}" for i in reversed(range(0, 48, 8))).replace(":", "").lower()
        except Exception:
            return "000000000000"

    def check_online_status(self):
        """优化：多站点冗余检测在线状态（替换为国内可用测试URL）"""
        # 使用更严格的204状态检测（标准 captive portal 检测码）
        test_urls = [
            "http://edge-http.microsoft.com/captiveportal/generate_204",  # 微软标准检测点
            "http://www.gstatic.com/generate_204",                        # Google 检测点
            "http://connect.qq.com/generate_204"                          # 腾讯检测点
        ]
        success_count = 0
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 204:  # 严格匹配204状态码
                    success_count += 1
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                # 明确捕获连接失败/超时异常（网络断开时的典型错误）
                continue
            except requests.exceptions.RequestException:
                # 其他异常统一处理
                continue
        
        # 需要至少2个检测点返回204才算在线（提高准确性）
        return success_count >= 2

    def send_login_request(self):
        try:
            # 每5分钟刷新一次缓存
            if (datetime.now() - self.last_cache_time).total_seconds() > 300:
                self.cached_ip = self.get_local_ip()
                self.cached_mac = self.get_local_mac()
                self.last_cache_time = datetime.now()
            current_ip = self.cached_ip
            current_mac = self.cached_mac
            self.log(f"当前获取的IP: {current_ip}, MAC: {current_mac}")

            query_string = (
                f"wlanuserip%3D{current_ip}"
                "%26wlanacname%3DNAS"
                "%26ssid%3DRuijie"
                "%26nasip%3D172.16.200.100"
                f"%26mac%3D{current_mac}"
                "%26t%3Dwireless-v2-plain"
                "%26url%3Dhttp%3A%2F%2Fwww.msftconnecttest.com%2Fredirect"
            )

            data = {
                "userId": self.USER_ID,
                "password": self.PASSWORD,
                "service": "",
                "queryString": query_string,
                "operatorPwd": "",
                "operatorUserId": "",
                "validcode": "",
                "passwordEncrypt": "false"
            }

            response = self.session.post(self.LOGIN_URL, headers=self.headers, data=data, timeout=20)
            response.raise_for_status()
            resp_data = response.json()

            if resp_data.get("result") == "success":
                # 新增：检查userIndex是否存在并计数
                user_index = resp_data.get("userIndex")
                if user_index:
                    self.reconnect_count += 1
                    # 线程安全更新UI
                    self.root.after(0, lambda: self.reconnect_label.config(text=f"重连次数：{self.reconnect_count}"))
                self.log(f"登录成功，userIndex: {user_index}")
                return True
            else:
                self.log(f"登录失败，原因: {resp_data.get('message', '无错误信息')}")
                return False

        except requests.exceptions.RequestException as e:
            self.log(f"请求失败: {str(e)}")
            return False
        except Exception as e:
            self.log(f"未知错误: {str(e)}")
            return False

    def is_campus_network(self):
        """判断是否连接校园网（IP以10.81.开头）"""
        local_ip = self.get_local_ip()
        return local_ip.startswith("10.81.")  # 修改：检测前缀为10.81.，支持10.81.x.x任意子网

    def monitor_loop(self):
        """后台监控循环（新增停止状态检查）"""
        while self.running:  # 循环条件已包含running状态
            # 新增：每次循环开始前再次检查状态（防止stop_event触发后仍执行剩余代码）
            if not self.running:
                break

            is_online = self.check_online_status()
            is_campus = self.is_campus_network()
            status_text = "在线" if is_online else "离线"
            campus_text = "已连接" if is_campus else "未连接"
            
            # 更新状态标签（仅在运行时执行）
            if self.running:
                # 新增：根据在线状态设置文字颜色（在线绿色，离线红色）
                local_ip = self.get_local_ip()
                wifi_status = "已连接" if local_ip != "127.0.0.1" else "未连接"
                self.root.after(0, lambda: self.status_label.config(
                    text=f"互联网状态：{status_text} | 校园网：{campus_text} | WiFi：{wifi_status}",
                    foreground="#00FF00" if status_text == "在线" else "#FF0000"
                ))
                self.log(f"当前互联网状态: {status_text}，校园网连接状态: {campus_text}")  # 日志显示双状态

            # 新增：计算并更新开启时间（仅在运行时执行）
            if self.running and self.start_time:
                current_time = datetime.now()
                duration = current_time - self.start_time
                days = duration.days
                hours, remainder = divmod(duration.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                duration_text = f"开启时间：{days}天{hours}小时{minutes}分{seconds}秒"
                self.root.after(0, lambda: self.duration_label.config(text=duration_text))  # 线程安全更新UI

            if self.running and not is_online:  # 仅在运行时执行登录逻辑
                self.log("检测到离线，尝试重新登录...")
                self.send_login_request()

            # 等待前再次检查状态（防止等待期间被停止）
            if self.running:
                self.stop_event.wait(self.CHECK_INTERVAL)


    # 新增/调整：将方法移动到类内部，并补充保存逻辑
    def load_saved_config(self):
        """加载保存的账号密码配置"""
        if not os.path.exists(self.config_path):
            return  # 无配置文件则跳过

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                # 填充账号
                self.user_entry.delete(0, END)
                self.user_entry.insert(0, config.get("user_id", ""))
                # 填充密码（仅当记住密码勾选时）
                if config.get("remember", False):
                    self.pwd_entry.delete(0, END)
                    self.pwd_entry.insert(0, config.get("password", ""))
                    self.remember_var.set(1)  # 勾选复选框
                # 新增：加载自启动状态
                self.remember_launch_var.set(1 if config.get("remember_launch", False) else 0)  # 恢复自启动勾选状态
        except (json.JSONDecodeError, PermissionError) as e:
            self.log(f"警告：加载配置失败 - {str(e)}")

    def save_config(self, user_id, password, remember):
        """保存账号密码配置（新增自启动状态）"""
        config = {
            "user_id": user_id,
            "password": password if remember else "",
            "remember": remember,
            "remember_launch": self.remember_launch_var.get() == 1  # 新增自启动状态
        }
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            self.log("配置保存成功")
        except (IOError, PermissionError) as e:
            self.log(f"错误：保存配置失败 - {str(e)}")

    def start_monitor(self):
        """启动监控（新增自启动逻辑）"""
        # 保持原有输入框实例，直接获取值（无需重复创建）
        user_id = self.user_entry.get().strip() or self.user_entry.get()
        password = self.pwd_entry.get().strip() or self.pwd_entry.get()
        interval = self.interval_entry.get().strip() or self.interval_entry.get()

        if not all([user_id, password, interval]):
            self.log("错误：账号、密码或检测间隔不能为空！")
            return

        try:
            self.CHECK_INTERVAL = int(interval)
            if self.CHECK_INTERVAL < 2:
                raise ValueError("间隔不能小于2秒")
        except ValueError:
            self.log("错误：检测间隔必须为大于2的整数！")
            return

        # 更新配置
        self.USER_ID = user_id
        self.PASSWORD = password

        # 新增：记录启动时间戳
        self.start_time = datetime.now()  # 记录启动时刻

        # 保存配置（获取记住密码状态）
        remember = self.remember_var.get() == 1
        self.save_config(user_id, password, remember)  # 调用保存方法

        # 新增：处理自启动（需以管理员权限运行）
        try:
            remember_launch = self.remember_launch_var.get() == 1
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                app_path = os.path.abspath(sys.argv[0])  # 获取当前程序路径
                if remember_launch:
                    winreg.SetValueEx(key, "CampusNetworkHelper", 0, winreg.REG_SZ, app_path)
                    self.log("自启动设置成功")
                else:
                    winreg.DeleteValue(key, "CampusNetworkHelper")
                    self.log("自启动已取消")
        except FileNotFoundError:
            self.log("警告：注册表路径不存在，可能系统不支持")
        except PermissionError:
            self.log("错误：需要管理员权限才能修改自启动设置")
        except Exception as e:
            self.log(f"自启动设置失败: {str(e)}")

        self.running = True
        self.stop_event.clear()
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.log("启动校园网保活监控...")
        self.thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.thread.start()

    def stop_monitor(self):
        """停止监控（强制中断睡眠并清理资源）"""
        self.running = False
        self.stop_event.set()  # 触发事件中断当前睡眠
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.log("已停止监控，等待线程退出...")

        # 新增：重置开启时间和重连计数显示
        self.root.after(0, lambda: self.duration_label.config(text="开启时间：未启动"))
        self.root.after(0, lambda: self.reconnect_label.config(text="重连次数：0"))  # 重置显示
        self.start_time = None  # 清空时间戳
        self.reconnect_count = 0  # 清空计数

        # 等待线程完全退出（最多等待2秒）
        if self.thread is not None:
            self.thread.join(timeout=2)
            self.thread = None  # 彻底清空线程引用
            self.stop_event.clear()  # 重置事件状态

if __name__ == "__main__":
    root = Tk()
    app = CampusNetworkApp(root)
    root.mainloop()
