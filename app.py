from flask import Flask, request, send_file, jsonify
import requests
from PIL import Image, ImageDraw, ImageFont
import io
import base64
import json
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import json_format, message
from google.protobuf.message import Message

import FreeFire_pb2
import main_pb2
import zitado_pb2

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB51"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}
API_KEY = "your_api_key_here"
TIMEOUT = 10

# === Flask App Setup ===
app = Flask(__name__)

# Global cache for tokens
cached_tokens = {}

# === Helper Functions ===
def pad_data(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad_data(plaintext))

def decode_protobuf(encoded_data: bytes, message_type) -> Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3939412237&password=74C35008C7E8BE5B618F6B482EC73D840F863E2AF750C1317CA66D4CD74F19FB"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17"
    else:
        return "uid=3939507748&password=55A6E86C5A338D133BAD02964EFB905C7C35A86440496BC210A682146DCE9F32"

# === Token Generation ===
def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip", 
        'Content-Type': "application/x-www-form-urlencoded"
    }
    
    response = requests.post(url, data=payload, headers=headers)
    data = response.json()
    return data.get("access_token", "0"), data.get("open_id", "0")

def create_jwt(region: str):
    try:
        account = get_account_credentials(region)
        token_val, open_id = get_access_token(account)
        body = json.dumps({
            "open_id": open_id, 
            "open_id_type": "4", 
            "login_token": token_val, 
            "orign_platform_type": "4"
        })
        
        proto_bytes = json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        
        headers = {
            'User-Agent': USERAGENT, 
            'Connection': "Keep-Alive", 
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream", 
            'Expect': "100-continue", 
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1", 
            'ReleaseVersion': RELEASEVERSION
        }
        
        response = requests.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(response.content, FreeFire_pb2.LoginRes)))
        
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200  # 7 hours
        }
        
    except Exception as e:
        print(f"Error creating JWT for {region}: {e}")

def initialize_tokens():
    for region in SUPPORTED_REGIONS:
        create_jwt(region)

def get_token_info(region: str):
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    create_jwt(region)
    info = cached_tokens.get(region)
    if info:
        return info['token'], info['region'], info['server_url']
    
    return "0", "0", "0"

def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    
    payload = json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = get_token_info(region)
    
    headers = {
        'User-Agent': USERAGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'Authorization': token, 
        'X-Unity-Version': "2018.4.11f1", 
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    response = requests.post(server + endpoint, data=data_enc, headers=headers)
    return json.loads(json_format.MessageToJson(decode_protobuf(response.content, zitado_pb2.Users)))

def fetch_player_info(uid, region):
    try:
        # You'll need to provide the actual endpoint here
        result = GetAccountInformation(uid, 0, region, "/GetPlayerPersonalShow")
        return result
    except Exception as e:
        return {"error": f"Failed to fetch player info: {str(e)}"}

def fetch_images(banner_id, avatar_id):
    try:
        banner_url = f"https://pika-ffitmes-api.vercel.app/?item_id={banner_id}&key=PikaApis"
        avatar_url = f"https://pika-ffitmes-api.vercel.app/?item_id={avatar_id}&key=PikaApis"

        banner_response = requests.get(banner_url, timeout=TIMEOUT)
        avatar_response = requests.get(avatar_url, timeout=TIMEOUT)

        if banner_response.status_code == 200 and avatar_response.status_code == 200:
            return banner_response.content, avatar_response.content
        return None, None
    except Exception:
        return None, None

def load_font(font_path, size):
    try:
        return ImageFont.truetype(font_path, size)
    except:
        return ImageFont.load_default()

def overlay_images(banner_img, avatar_img, player_name, guild_name=None, level=None):
    try:
        banner = Image.open(io.BytesIO(banner_img)).convert("RGBA")
        avatar = Image.open(io.BytesIO(avatar_img)).convert("RGBA").resize((55, 60))
        banner.paste(avatar, (0, 0), avatar)

        draw = ImageDraw.Draw(banner)
        bold_font = load_font("arialbd.ttf", 19)
        guild_font = load_font("arialbd.ttf", 22)
        level_font = load_font("arialbd.ttf", 20)

        draw.text((57, 2), player_name, fill="white", font=bold_font)
        if guild_name:
            draw.text((73, 48), guild_name, fill="#DDDDDD", font=guild_font)
        if level:
            banner_w, banner_h = banner.size
            draw.text((banner_w - 35, banner_h - 12), f"Lvl - {level}", fill="white", font=level_font, stroke_width=1, stroke_fill="black")

        return banner
    except Exception as e:
        print(f"Error overlaying images: {e}")
        return None

@app.route('/avatar-banner', methods=['GET'])
def generate_image():
    uid = request.args.get('uid')
    region = request.args.get('region')
    key = request.args.get('key')

    if key != API_KEY:
        return jsonify({"error": "Invalid API key"}), 403
    if not uid or not region:
        return jsonify({"error": "Missing uid or region in parameter"}), 400

    player_data = fetch_player_info(uid, region)
    if "error" in player_data:
        return jsonify(player_data), 400

    # Extract data from player data
    basic_info = player_data.get("basicinfo", [{}])[0] if player_data.get("basicinfo") else {}
    clan_info = player_data.get("claninfo", [{}])[0] if player_data.get("claninfo") else {}

    banner_id = basic_info.get("banner", 0)
    avatar_id = basic_info.get("avatar", 0)
    player_name = basic_info.get("username", "Player")
    level = str(basic_info.get("level", 0))
    guild_name = clan_info.get("clanname")

    banner_img, avatar_img = fetch_images(banner_id, avatar_id)
    if not banner_img or not avatar_img:
        return jsonify({"error": "Failed to fetch avatar or banner image"}), 500

    final_image = overlay_images(banner_img, avatar_img, player_name, guild_name, level)
    if not final_image:
        return jsonify({"error": "Failed to generate image"}), 500

    img_buffer = io.BytesIO()
    final_image.save(img_buffer, format="PNG")
    img_buffer.seek(0)

    return send_file(img_buffer, mimetype="image/png")

@app.route('/check_key', methods=['GET'])
def check_key():
    return jsonify({"status": "valid" if request.args.get('key') == API_KEY else "invalid"})

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "regions_initialized": len(cached_tokens)})

# Initialize tokens when app starts
@app.before_first_request
def initialize():
    initialize_tokens()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)