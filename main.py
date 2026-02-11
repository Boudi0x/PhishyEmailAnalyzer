import customtkinter as ctk
import webbrowser
import time
import hashlib
import re
import base64
import tkinter as tk
from datetime import datetime
from urllib.parse import urlparse, unquote
import urllib.parse
import json
import os
import threading
import sys

ctk.set_appearance_mode("dark")

BLUE_MAIN = "#3b82f6"
BLUE_DARK = "#1e3a8a"
BG_DEEP = "#020617"
CARD_BG = "#0f172a"


def resource_path(relative_path):
    if getattr(sys, "frozen", False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)


# ------------------------------------------------------------------------------------------ Regex.json ------------------------------------------------------------------------------------


def load_regex_rules():
    rules_path = resource_path("regex.json")
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: regex.json not found!")
        return {}


REGEX = load_regex_rules()

# ------------------------------------------------------------------------------------------ Regex.json ------------------------------------------------------------------------------------


def load_links():
    links_path = resource_path("links.json")
    try:
        with open(links_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: links.json not found!")
        return {}


LINKS = load_links()

# ------------------------------------------------------------------------------------------ Tooltip Class ------------------------------------------------------------------------------------


class ToolTip:
    def __init__(self, widget, text, side="right"):
        self.widget = widget
        self.text = text
        self.side = side
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.attributes("-topmost", True)
        x_orig = self.widget.winfo_pointerx()
        y_orig = self.widget.winfo_pointery()
        x = x_orig - 250 if self.side == "left" else x_orig + 15
        y = y_orig + 15
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            justify="left",
            background=BLUE_DARK,
            foreground="white",
            relief="flat",
            borderwidth=1,
            font=("Consolas", 10),
            padx=8,
            pady=4,
        )
        tw.configure(background=BLUE_MAIN)
        label.pack(padx=1)

    def hide_tip(self, event=None):
        if self.tip_window:
            tw = self.tip_window
            self.tip_window = None
            tw.destroy()


# -------------------------------------------------------------------------------------- Engine Class --------------------------------------------------------------------------------------


class EmailAnalzerEngine:
    def __init__(self, data):
        self.raw_data = data
        self.cleaned_data = self._smart_prepare(data)

    def _smart_prepare(self, data):
        text = re.sub(REGEX["prepare"]["qp_soft_break"], "", data)
        combined = text
        b64_blocks = re.findall(REGEX["prepare"]["base64_block"], data)
        for block in b64_blocks:
            try:
                pure_block = re.sub(REGEX["prepare"]["multi_space"], "", block)
                missing_padding = len(pure_block) % 4
                if missing_padding:
                    pure_block += "=" * (4 - missing_padding)
                decoded = base64.b64decode(pure_block).decode("utf-8", errors="ignore")
                combined += "\n" + decoded.replace("=\n", "").replace("=\r\n", "")
            except:
                continue
        return combined

    def get_full_headers(self):
        headers = {}
        target_keys = REGEX["target_keys"]

        for key in target_keys:
            pattern = REGEX["headers"]["main"].replace("{key}", key)
            match = re.search(pattern, self.raw_data, re.M | re.I)

            if match:
                raw_value = match.group(1)
                clean_value = re.sub(
                    REGEX["prepare"]["multi_space"], " ", raw_value
                ).strip()
                headers[key] = clean_value
            else:
                headers[key] = "N/A"

        if headers["From"] == "N/A" or "<" not in headers["From"]:
            backup_match = re.search(
                REGEX["headers"]["from_fallback"], self.raw_data, re.S | re.I
            )
            if backup_match:
                headers["From"] = (
                    f"{headers.get('From', '')} <{backup_match.group(1)}>".replace(
                        "N/A ", ""
                    )
                )

        return headers

    def check_authentication(self):
        auth = {"SPF": "FAIL", "DKIM": "FAIL", "DMARC": "FAIL"}
        low = self.raw_data.lower()
        if "spf=pass" in low:
            auth["SPF"] = "PASS"
        elif "spf=fail" in low:
            auth["SPF"] = "FAIL"
        if "dkim=pass" in low:
            auth["DKIM"] = "PASS"
        elif "dkim=fail" in low:
            auth["DKIM"] = "FAIL"
        if "dmarc=pass" in low:
            auth["DMARC"] = "PASS"
        elif "dmarc=fail" in low:
            auth["DMARC"] = "FAIL"
        return auth

    def extract_urls(self):
        url_pattern = REGEX["urls"]["extract"]

        found = re.findall(url_pattern, self.cleaned_data)
        unique_urls = []
        seen = set()

        for u in found:
            clean_u = u.replace("=3D", "=")
            clean_u = clean_u.strip().rstrip(".,;<()")
            clean_u = urllib.parse.unquote(clean_u)

            if clean_u not in seen and len(clean_u) > 10:
                unique_urls.append({"original": clean_u})
                seen.add(clean_u)
        return unique_urls

    def get_attachments_info(self):
        attachments = []

        pattern_b64 = REGEX["attachments"].get("content_b64")
        pattern_fname = REGEX["attachments"].get("filename")

        fname_matches = []
        if pattern_fname:
            fname_matches = re.findall(pattern_fname, self.raw_data, re.I)

        matches = re.findall(pattern_b64, self.raw_data, re.S | re.I)
        for i, raw_b64 in enumerate(matches, start=1):
            raw_b64_clean = "".join(raw_b64.split())
            file_hash = "N/A"
            filename = f"attachment_{i}"
            fname_pattern = REGEX["attachments"].get("filename")

            if i - 1 < len(fname_matches):
                filename = fname_matches[i - 1]
            else:
                filename = f"attachment_{i}"

            try:
                file_bytes = base64.b64decode(raw_b64_clean)
                file_hash = hashlib.sha256(file_bytes).hexdigest()
            except:
                pass
            attachments.append(
                {
                    "filename": filename,
                    "hash": file_hash,
                    "raw_b64": raw_b64_clean,
                }
            )

        return attachments


# -------------------------------------------------------------------------------------- SplashScreen --------------------------------------------------------------------------------------


class SplashScreen(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.overrideredirect(True)  # إخفاء شريط العنوان
        self.configure(fg_color=BG_DEEP)

        icon_path = resource_path("icon.ico")
        self.iconbitmap(icon_path)

        self.config(background="#000001")
        self.attributes("-transparentcolor", "#000001")

        self.configure(fg_color="#000001")

        width, height = 600, 400
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

        self.frame = ctk.CTkFrame(
            self,
            fg_color=CARD_BG,
            corner_radius=20,
            border_width=2,
            border_color=BLUE_MAIN,
        )
        self.frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.title_label = ctk.CTkLabel(
            self.frame, text="     🛡️", font=("Segoe UI", 80)
        )
        self.title_label.pack(pady=(60, 10))

        self.brand_label = ctk.CTkLabel(
            self.frame,
            text="Email Analyzer",
            font=("Impact", 40),
            text_color=BLUE_MAIN,
        )
        self.brand_label.pack()

        self.tagline = ctk.CTkLabel(
            self.frame,
            text="ADVANCED EMAIL THREAT INTELLIGENCE",
            font=("Consolas", 12),
            text_color="#64748b",
        )
        self.tagline.pack(pady=(0, 30))

        self.progress = ctk.CTkProgressBar(
            self.frame,
            width=400,
            height=12,
            progress_color=BLUE_MAIN,
            fg_color="#1e293b",
        )
        self.progress.pack(pady=20)
        self.progress.set(0)

        self.status_label = ctk.CTkLabel(
            self.frame,
            text="Loading Engine",
            font=("Consolas", 10),
            text_color=BLUE_MAIN,
        )
        self.status_label.pack()

    def start(self):
        steps = [
            "Loading Engine.",
            "Loading Engine..",
            "Loading Engine...",
            "System Ready!",
        ]
        for i in range(1, 101):
            time.sleep(0.04)
            self.progress.set(i / 100)
            if i % 25 == 0:
                self.status_label.configure(text=steps[(i // 25) - 1])
            self.update()
        self.destroy()


# ------------------------------------------------------------------------------------------- Main App -------------------------------------------------------------------------------------


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        icon_path = resource_path("icon.ico")
        self.iconbitmap(icon_path)
        self.title("Email Analyzer")
        self.geometry("1400x900")
        self.configure(fg_color=BG_DEEP)

        self.after(0, lambda: self.wm_state("zoomed"))
        self.sidebar = ctk.CTkFrame(self, width=90, fg_color=CARD_BG, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.content_area = ctk.CTkFrame(self, fg_color="transparent")
        self.content_area.pack(side="right", fill="both", expand=True)

        self.top_bar = ctk.CTkFrame(
            self.content_area, height=70, fg_color=CARD_BG, corner_radius=0
        )
        self.top_bar.pack(side="top", fill="x")
        self.status_title = ctk.CTkLabel(
            self.top_bar,
            text="DASHBOARD",
            font=("Segoe UI", 16, "bold"),
            text_color=BLUE_MAIN,
        )
        self.status_title.pack(side="left", padx=35)

        self.main_container = ctk.CTkFrame(self.content_area, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=25, pady=25)

        self.nav_buttons = {}
        self.pages = {
            name: ctk.CTkFrame(self.main_container, fg_color="transparent")
            for name in ["Input", "Results"]
        }

        self.setup_input_page()
        self.create_nav_menu()
        self.show_page("Input")

    def create_nav_menu(self):
        for icon, page_id in [("📥", "Input"), ("📊", "Results")]:
            btn = ctk.CTkButton(
                self.sidebar,
                text=icon,
                width=65,
                height=65,
                corner_radius=18,
                fg_color="transparent",
                font=("Segoe UI", 26),
                hover_color=BLUE_DARK,
                command=lambda p=page_id: self.show_page(p),
            )
            btn.pack(pady=20, padx=12)
            self.nav_buttons[page_id] = btn

    def show_page(self, name):
        for page_id, btn in self.nav_buttons.items():
            if page_id == name:
                btn.configure(fg_color=BLUE_MAIN, text_color="white")
                self.status_title.configure(text=f"{page_id.upper()}")
            else:
                btn.configure(fg_color="transparent", text_color=BLUE_MAIN)
        for page in self.pages.values():
            page.pack_forget()
        self.pages[name].pack(fill="both", expand=True)

    def copy_and_open(self, b64_content):
        if not b64_content or b64_content == "N/A":
            print("No content found to copy!")
            return

        clean_b64 = "".join(b64_content.split())
        self.clipboard_clear()
        self.clipboard_append(clean_b64)
        self.update_idletasks()
        webbrowser.open(LINKS["attachments"]["download"])

    def setup_input_page(self):
        page = self.pages["Input"]
        card = ctk.CTkFrame(
            page,
            fg_color=CARD_BG,
            corner_radius=35,
            border_width=1,
            border_color="#1e293b",
        )
        card.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.85, relheight=0.85)
        ctk.CTkLabel(
            card,
            text="EMAIL SOURCE CODE",
            font=("Segoe UI", 26, "bold"),
            text_color="#f8fafc",
        ).pack(pady=(45, 5))
        self.input_text = ctk.CTkTextbox(
            card,
            fg_color=BG_DEEP,
            corner_radius=20,
            border_width=1,
            border_color="#334155",
            font=("Consolas", 14),
            text_color=BLUE_MAIN,
        )
        self.input_text.pack(fill="both", expand=True, padx=50, pady=10)
        self.input_text.bind("<Control-KeyPress>", self.handle_control_shortcuts)
        ctk.CTkButton(
            card,
            text="START SCAN",
            height=65,
            fg_color=BLUE_MAIN,
            font=("Segoe UI", 17, "bold"),
            command=self.run_analysis,
        ).pack(pady=45, padx=50, fill="x")

    def handle_control_shortcuts(self, event):
        if event.keycode == 86 or event.keysym.lower() == "v":
            try:
                self.input_text.insert("insert", self.clipboard_get())
                return "break"
            except:
                pass
        elif event.keycode == 67 or event.keysym.lower() == "c":
            try:
                self.clipboard_clear()
                self.clipboard_append(self.input_text.get("sel.first", "sel.last"))
                return "break"
            except:
                pass
        elif event.keycode == 65 or event.keysym.lower() == "a":
            self.input_text.tag_add("sel", "1.0", "end")
            return "break"

    def run_analysis(self):
        data = self.input_text.get("0.0", "end").strip()
        if len(data) < 10:
            return

        self.status_title.configure(text="ANALYZING...")

        def task():
            engine = EmailAnalzerEngine(data)

            self.after(0, lambda: self.render_unified_results(engine, data))
            self.after(0, lambda: self.show_page("Results"))

        threading.Thread(target=task, daemon=True).start()

    def extract_auth_domain(self, auth_type, data):
        try:
            auth_type = auth_type.upper()

            pattern = REGEX["auth"].get(auth_type)
            if not pattern:
                return None

            match = re.search(pattern, data, re.I | re.S)
            if not match:
                return None

            if auth_type == "SPF":
                return match.group(2)

            return match.group(1)

        except Exception:
            return None

    def render_unified_results(self, engine, raw_data):
        page = self.pages["Results"]
        for w in page.winfo_children():
            w.destroy()
        scroll = ctk.CTkScrollableFrame(page, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        headers = engine.get_full_headers()

        # --- METADATA & AUTH ---
        row1 = ctk.CTkFrame(scroll, fg_color="transparent")
        row1.pack(fill="x", pady=(10, 20))

        meta_card = ctk.CTkFrame(
            row1,
            fg_color=CARD_BG,
            corner_radius=20,
            border_width=1,
            border_color="#1e293b",
        )
        meta_card.pack(side="left", fill="both", expand=True, padx=10)
        self.create_section_header(meta_card, "CORE METADATA", BLUE_MAIN)
        for key in ["Subject", "From", "To", "Date", "Reply-To", "Return-Path"]:
            val = headers.get(key)
            if val:
                self.create_info_row(meta_card, key, val, BLUE_MAIN)
        ctk.CTkLabel(meta_card, text="", height=10).pack()

        auth_card = ctk.CTkFrame(
            row1,
            fg_color=CARD_BG,
            corner_radius=20,
            border_width=1,
            border_color="#1e293b",
        )
        auth_card.pack(side="left", fill="both", expand=True, padx=10)
        self.create_section_header(auth_card, "AUTHENTICATION", BLUE_MAIN)
        auth = engine.check_authentication()
        for k, v in auth.items():
            status_clean = v.split("(")[0].strip()
            color = "#10b981" if "PASS" in status_clean.upper() else "#f43f5e"
            row = ctk.CTkFrame(auth_card, fg_color="transparent")
            row.pack(fill="x", pady=5, padx=30)
            ctk.CTkLabel(
                row,
                text=k.upper(),
                font=("Segoe UI", 11, "bold"),
                text_color=BLUE_MAIN,
                width=80,
                anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                row, text=status_clean, font=("Consolas", 13, "bold"), text_color=color
            ).pack(side="left", padx=10)
            if k.upper() in ["SPF", "DKIM"]:
                dom_auth = self.extract_auth_domain(k, raw_data)
                d_lbl = ctk.CTkLabel(
                    row,
                    text="[Domain]",
                    font=("Segoe UI", 10, "italic"),
                    text_color="#64748b",
                    cursor="hand2",
                )
                d_lbl.pack(side="right", padx=10)
                ToolTip(
                    d_lbl, dom_auth if dom_auth else "No domain detected", side="left"
                )

        # --- IP SECTION ---
        ip_card = ctk.CTkFrame(
            scroll,
            fg_color=CARD_BG,
            corner_radius=20,
            border_width=1,
            border_color="#1e293b",
        )
        ip_card.pack(fill="x", pady=10, padx=10)
        ip_row = ctk.CTkFrame(ip_card, fg_color="transparent")
        ip_row.pack(fill="x", padx=30, pady=20)
        mta_ip = self.extract_spf_ip(raw_data)
        ctk.CTkLabel(
            ip_row,
            text="LAST MTA IP:",
            font=("Segoe UI", 15, "bold"),
            text_color=BLUE_MAIN,
        ).pack(side="left")
        ctk.CTkLabel(
            ip_row, text=mta_ip, font=("Consolas", 18, "bold"), text_color="#ffffff"
        ).pack(side="left", padx=25)
        if mta_ip != "N/A":
            ctk.CTkButton(
                ip_row,
                text="AbuseIPDB",
                width=95,
                height=32,
                fg_color=BLUE_DARK,
                font=("Segoe UI", 11, "bold"),
                command=lambda: webbrowser.open(
                    LINKS["ip_section"]["abuseipdb"].replace("{ip}", mta_ip)
                ),
            ).pack(side="right")

        # --- DOMAIN INTELLIGENCE ---
        target_domains = set()
        for key in ["From", "Return-Path", "Reply-To"]:
            val = headers.get(key)
            if val:
                match = re.search(REGEX["domain"]["email"], str(val))
                if match:
                    target_domains.add(match.group(1).lower().strip(">"))

        if target_domains:
            self.create_section_header(scroll, "DOMAIN INTELLIGENCE", BLUE_MAIN)
            dom_card = ctk.CTkFrame(
                scroll,
                fg_color=CARD_BG,
                corner_radius=20,
                border_width=1,
                border_color="#1e293b",
            )
            dom_card.pack(fill="x", padx=10, pady=5)
            for dom in target_domains:
                dr = ctk.CTkFrame(dom_card, fg_color="transparent")
                dr.pack(fill="x", padx=30, pady=15)
                ctk.CTkLabel(
                    dr, text=dom, font=("Consolas", 14, "bold"), text_color="#ffffff"
                ).pack(side="left")
                bf = ctk.CTkFrame(dr, fg_color="transparent")
                bf.pack(side="right")
                for bt, bu in [
                    ("Check Age", LINKS["domain_intelligence"]["check_age"]),
                    ("VirusTotal", LINKS["domain_intelligence"]["virustotal"]),
                    ("Browserling", LINKS["domain_intelligence"]["browserling"]),
                ]:
                    ctk.CTkButton(
                        bf,
                        text=bt,
                        width=95,
                        height=32,
                        fg_color=BLUE_DARK,
                        font=("Segoe UI", 11, "bold"),
                        command=lambda u=bu.replace("{domain}", dom): webbrowser.open(
                            u
                        ),
                    ).pack(side="left", padx=3)

        # --- ATTACHMENTS ---
        self.create_section_header(scroll, "ATTACHMENTS", BLUE_MAIN)
        at_container = ctk.CTkFrame(
            scroll,
            fg_color=CARD_BG,
            corner_radius=20,
            border_width=1,
            border_color="#1e293b",
        )
        at_container.pack(fill="x", padx=10, pady=5)
        attachments = engine.get_attachments_info()
        if not attachments:
            ctk.CTkLabel(
                at_container, text="No attachments detected.", text_color="#64748b"
            ).pack(pady=25)
        else:
            for att in attachments:
                row = ctk.CTkFrame(at_container, fg_color="transparent")
                row.pack(fill="x", pady=12, padx=30)
                ctk.CTkLabel(
                    row,
                    text=att["filename"],
                    font=("Consolas", 14, "bold"),
                    text_color="#ffffff",
                ).pack(side="left", pady=(7, 7))
                btn_f = ctk.CTkFrame(row, fg_color="transparent")
                btn_f.pack(side="right")
                ctk.CTkButton(
                    btn_f,
                    text="VirusTotal",
                    width=95,
                    height=32,
                    fg_color=BLUE_DARK,
                    font=("Segoe UI", 11, "bold"),
                    command=lambda h=att["hash"]: webbrowser.open(
                        LINKS["attachments"]["virustotal"].replace("{hash}", h)
                    ),
                ).pack(side="left", padx=3)

                ctk.CTkButton(
                    btn_f,
                    text="Download",
                    width=95,
                    height=32,
                    fg_color=BLUE_DARK,
                    font=("Segoe UI", 11, "bold"),
                    command=lambda b=att.get("raw_b64", ""): self.copy_and_open(b),
                ).pack(side="left", padx=3)

        # --- URLS ---
        self.create_section_header(scroll, "URLS", BLUE_MAIN)
        u_card = ctk.CTkFrame(
            scroll,
            fg_color=CARD_BG,
            corner_radius=20,
            border_width=1,
            border_color="#1e293b",
        )
        u_card.pack(fill="x", padx=10, pady=5)
        for url_obj in engine.extract_urls():
            final_u = self.extract_final_url(url_obj["original"])
            u_row = ctk.CTkFrame(
                u_card,
                fg_color="#1e293b" if final_u != url_obj["original"] else "transparent",
                corner_radius=12,
            )
            u_row.pack(fill="x", pady=5, padx=20)
            disp = self.smart_truncate(final_u, 75)
            lbl = ctk.CTkLabel(
                u_row,
                text=disp,
                font=("Consolas", 11),
                text_color="#cbd5e1",
                cursor="hand2",
            )
            lbl.pack(side="left", padx=20, pady=15)
            ToolTip(lbl, final_u, side="right")
            bf = ctk.CTkFrame(u_row, fg_color="transparent")
            bf.pack(side="right", padx=15)

            ctk.CTkButton(
                bf,
                text="VirusTotal",
                width=95,
                height=32,
                fg_color=BLUE_DARK,
                font=("Segoe UI", 11, "bold"),
                command=lambda t=final_u: webbrowser.open(
                    LINKS["urls"]["virustotal"].replace(
                        "{domain}", self.get_domain_only(t)
                    )
                ),
            ).pack(side="left", padx=3)

            ctk.CTkButton(
                bf,
                text="Browserling",
                width=95,
                height=32,
                fg_color=BLUE_DARK,
                font=("Segoe UI", 11, "bold"),
                command=lambda t=final_u: webbrowser.open(
                    LINKS["urls"]["browserling"].replace("{url}", final_u)
                ),
            ).pack(side="left", padx=3)

            ctk.CTkButton(
                bf,
                text="Unshorten IT",
                width=95,
                height=32,
                fg_color=BLUE_DARK,
                font=("Segoe UI", 11, "bold"),
                command=lambda t=final_u: webbrowser.open(
                    LINKS["urls"]["unshorten"].replace("{url}", final_u)
                ),
            ).pack(side="left", padx=3)

    # --- Helpers ---
    def create_section_header(self, master, text, color):
        ctk.CTkLabel(
            master, text=text, font=("Segoe UI", 15, "bold"), text_color=color
        ).pack(pady=(25, 12), padx=30, anchor="w")

    def create_info_row(self, master, key, value, k_color):
        row = ctk.CTkFrame(master, fg_color="transparent")
        row.pack(fill="x", pady=5, padx=30)
        ctk.CTkLabel(
            row,
            text=key.upper(),
            font=("Segoe UI", 11, "bold"),
            text_color=k_color,
            width=110,
            anchor="w",
        ).pack(side="left")
        ctk.CTkLabel(
            row,
            text=value,
            font=("Consolas", 13),
            text_color="#cbd5e1",
            wraplength=450,
            justify="left",
        ).pack(side="left", padx=15)

    def extract_spf_ip(self, data):
        try:
            section = data[:5000]

            ip_rules = REGEX.get("ip")
            if not ip_rules:
                return "N/A"

            ip_base = ip_rules.get("base")
            if not ip_base:
                return "N/A"

            patterns = [
                ip_rules["client"].replace("{ip}", ip_base),
                ip_rules["spf"].replace("{ip}", ip_base),
            ]

            for p in patterns:
                m = re.search(p, section, re.I)
                if m:
                    return m.group(1)

            return "N/A"

        except Exception:
            return "N/A"

    def get_domain_only(self, url):
        try:
            return urlparse(url).netloc if urlparse(url).netloc else url
        except:
            return url

    def extract_final_url(self, url):
        decoded = urllib.parse.unquote(url)
        match = re.search(REGEX["urls"]["nested"], decoded, re.I)
        return match.group(1).strip() if match else url

    def smart_truncate(self, text, length=75):
        return text[:length] + "..." if len(text) > length else text


if __name__ == "__main__":
    splash = SplashScreen()
    splash.start()
    app = App()
    app.mainloop()
