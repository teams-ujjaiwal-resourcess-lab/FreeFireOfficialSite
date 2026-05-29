import os
import sys
import json
import time
import urllib3
import base64
import requests
import ssl
import aiohttp
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, request, jsonify
from flask_caching import Cache
import asyncio

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# SimpleProtobuf class for parsing
class SimpleProtobuf:
    @staticmethod
    def parse_protobuf(data):
        """Simple protobuf parser"""
        result = {}
        i = 0
        while i < len(data):
            if i >= len(data):
                break
            tag = data[i]
            field_num = tag >> 3
            wire_type = tag & 0x07
            
            i += 1
            
            if wire_type == 0:  # Varint
                value = 0
                shift = 0
                while i < len(data):
                    byte = data[i]
                    i += 1
                    value |= (byte & 0x7F) << shift
                    shift += 7
                    if not (byte & 0x80):
                        break
                result[field_num] = value
            elif wire_type == 2:  # Length-delimited
                # Read length
                length = 0
                shift = 0
                while i < len(data):
                    byte = data[i]
                    i += 1
                    length |= (byte & 0x7F) << shift
                    shift += 7
                    if not (byte & 0x80):
                        break
                
                # Read string data
                if i + length <= len(data):
                    string_data = data[i:i+length]
                    try:
                        result[field_num] = string_data.decode('utf-8')
                    except:
                        result[field_num] = string_data.hex()
                    i += length
            else:
                # Skip unknown wire types
                break
        return result

def AutoUpdate():
    """Auto update function to get all server URLs and versions"""
    try:
        # First API call to get version info
        url = f'https://version.ggwhitehawk.com/live/ver.php?version=1.123.9&lang=en&device=android&channel=android&appstore=googleplay&region=IND&whitelist_version=1.3.0&whitelist_sp_version=1.0.0'
        
        print("[*] Fetching server configuration...")
        r = requests.get(url, timeout=10)
        data = r.json()
        
        # Extract all required values
        server_url = data.get('server_url', 'https://loginbp.ggpolarbear.com/')
        latest_release_version = data.get('latest_release_version', 'OB53')
        version = data.get('remote_version', '1.123.15')
        
        # Get GOP URL from the response
        gop_url = data.get('gop_url', 'https://ffmconnect.live.gop.garenanow.com;https://ffmmsdk.live.gop.garenanow.com')
        # Split GOP URLs and take the first one
        gop_urls = gop_url.split(';')
        primary_gop_url = gop_urls[0] if gop_urls else 'https://ffmconnect.live.gop.garenanow.com'
        
        print(f"[✓] Server URL: {server_url}")
        print(f"[✓] GOP URL: {primary_gop_url}")
        print(f"[✓] Latest Version: {latest_release_version}")
        print(f"[✓] Remote Version: {version}")
        
        return server_url, primary_gop_url, latest_release_version, version
        
    except Exception as e:
        print(f"[!] Error fetching version info: {e}")
        print("[!] Using fallback values...")
        # Fallback values
        return "https://loginbp.ggpolarbear.com/", "https://ffmconnect.live.gop.garenanow.com", "OB53", "1.123.15"

# Get all configuration from auto-update
login_url, gop_url, latest_release_version, version = AutoUpdate()

headers = {
    'User-Agent': "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/octet-stream",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': latest_release_version
}

async def get_token(uid, password):
    """Get token using GOP URL"""
    token_url = f"{gop_url}/oauth/guest/token/grant"
    
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    
    try:
        print(f"[*] Getting token from: {token_url}")
        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, headers=headers, data=data, ssl=False, timeout=15) as response:
                if response.status != 200:
                    print(f"[!] Token request failed with status: {response.status}")
                    return (None, None)
                resp_data = await response.json()
                open_id = resp_data.get("open_id")
                access_token = resp_data.get("access_token")
                if open_id and access_token:
                    print(f"[✓] Token obtained successfully")
                    return (open_id, access_token)
                else:
                    print(f"[!] No open_id or access_token in response")
                    return (None, None)
    except Exception as e:
        print(f"[!] Token error: {e}")
        return (None, None)

def _encode_varint(value):
    out = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def _encode_length_delimited(field_num, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    tag = (field_num << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(data)) + data

def _encode_varint_field(field_num, value):
    tag = (field_num << 3) | 0
    return _encode_varint(tag) + _encode_varint(value)

def build_major_login_packet(access_token, open_id, region="IND", lang_code="en"):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        ip = requests.get('https://api.ipify.org', timeout=5).text
    except:
        ip = "0.0.0.0"
    
    packet = b''
    packet += _encode_length_delimited(3, now_str)
    packet += _encode_length_delimited(4, "free fire")
    packet += _encode_length_delimited(7, version)
    packet += _encode_length_delimited(20, ip)
    packet += _encode_length_delimited(21, lang_code)
    packet += _encode_length_delimited(22, open_id)
    packet += _encode_length_delimited(26, region.upper())
    packet += _encode_length_delimited(29, access_token)
    packet += _encode_varint_field(76, 2)
    packet += _encode_varint_field(78, 2)
    packet += _encode_varint_field(79, 2)
    packet += _encode_varint_field(88, 4)
    packet += _encode_varint_field(97, 1)
    packet += _encode_varint_field(98, 1)
    packet += _encode_length_delimited(99, "4")
    packet += _encode_length_delimited(100, "4")
    return packet

async def EncRypTMajoRLoGin(open_id, access_token, region="IND", lang_code="en"):
    plain_packet = build_major_login_packet(access_token, open_id, region, lang_code)
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - (len(plain_packet) % 16)
    if pad_len == 0:
        pad_len = 16
    plaintext_padded = plain_packet + bytes([pad_len]) * pad_len
    encrypted_payload = cipher.encrypt(plaintext_padded)
    return encrypted_payload

async def major_login(payload):
    url = f"{login_url}MajorLogin"
    print(f"[*] Sending major login to: {url}")
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, headers=headers, ssl=ssl_context, timeout=15) as response:
                if response.status == 200:
                    print(f"[✓] Major login successful")
                    return await response.read()
                else:
                    print(f"[!] Major login failed with status: {response.status}")
                    return None
    except Exception as e:
        print(f"[!] Major login error: {e}")
        return None

@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Both uid and password parameters are required"}), 400

    try:
        print(f"[*] Processing request for UID: {uid}")
        
        # Get token
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        open_id, access_token = loop.run_until_complete(get_token(uid, password))
        loop.close()
        
        if not open_id or not access_token:
            return jsonify({
                "status": "invalid",
                "message": "Wrong UID or Password. Please check and try again.",
                "credit": "@Ujjaiwal"
            }), 401
        
        # Encrypt and perform major login
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        encrypted_payload = loop.run_until_complete(EncRypTMajoRLoGin(open_id, access_token))
        response_data = loop.run_until_complete(major_login(encrypted_payload))
        loop.close()
        
        if response_data:
            parsed_response = SimpleProtobuf.parse_protobuf(response_data)
            
            # Extract fields from parsed response
            status_field = parsed_response.get(5, "N/A")
            token_field = parsed_response.get(8, "N/A")
            region_field = parsed_response.get(2, "N/A")
            
            response_json = {
                "status": status_field if not isinstance(status_field, dict) else status_field.get("5", "N/A"),
                "token": token_field if not isinstance(token_field, dict) else token_field.get("8", "N/A"),
                "region": region_field if not isinstance(region_field, dict) else region_field.get("2", "N/A"), 
                "access_token": access_token, 
                "open_id": open_id
            }
            
            print(f"[✓] Response sent successfully")
            return jsonify(response_json)
        else:
            return jsonify({
                "status": "error",
                "error": "Failed to get response from server"
            }), 400
            
    except Exception as e:
        print(f"[!] Internal error: {e}")
        return jsonify({
            "status": "error",
            "error": f"Internal error occurred: {str(e)}"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "server_url": login_url,
        "gop_url": gop_url,
        "version": version,
        "release_version": latest_release_version
    })

if __name__ == '__main__':
    print("="*50)
    print("FreeFire Authentication Server")
    print("="*50)
    print(f"[✓] Server URL: {login_url}")
    print(f"[✓] GOP URL: {gop_url}")
    print(f"[✓] Version: {version}")
    print(f"[✓] Release Version: {latest_release_version}")
    print("="*50)
    print("[*] Starting Flask server on http://0.0.0.0:5000")
    print("[*] API Endpoint: http://localhost:5000/token?uid=YOUR_UID&password=YOUR_PASSWORD")
    print("[*] Health Check: http://localhost:5000/health")
    print("="*50)
    app.run(host='0.0.0.0', port=5000, debug=False)