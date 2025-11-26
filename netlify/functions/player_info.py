import json
import time
import asyncio
import httpx
import base64
from Crypto.Cipher import AES
from google.protobuf import json_format, message
import FreeFire_pb2
import main_pb2
import AccountPersonalShow_pb2

# ==== CONSTANTS ====
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB51"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

SUPPORTED_REGIONS = {"IND","BR","US","SAC","NA","SG","RU","ID","TW","VN","TH","ME","PK","CIS","BD","EUROPE"}

# Helper functions
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(body: dict, proto):
    json_format.ParseDict(body, proto)
    return proto.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3939412237&password=74C35008C7E8BE5B618F6B482EC73D840F863E2AF750C1317CA66D4CD74F19FB"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17"
    else:
        return "uid=3939507748&password=55A6E86C5A338D133BAD02964EFB905C7C35A86440496BC210A682146DCE9F32"

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token","0"), data.get("open_id","0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)

    body = {
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    }

    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
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

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))

        return {
            "token": f"Bearer {msg.get('token','0')}",
            "region": msg.get('lockRegion','0'),
            "server_url": msg.get('serverUrl','0')
        }

async def GetAccountInformation(uid, unk, region):
    region = region.upper()

    jwt_info = await create_jwt(region)

    payload = await json_to_proto({"a": uid, "b": unk}, main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': jwt_info["token"],
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(jwt_info["server_url"] + "/GetPlayerPersonalShow", data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))


# ==== NETLIFY HANDLER ====
def handler(event, context):
    params = event.get("queryStringParameters") or {}

    uid = params.get("uid")
    region = params.get("region")

    if not uid or not region:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Please pass uid & region"})
        }

    try:
        result = asyncio.run(GetAccountInformation(uid, "7", region))
        return {
            "statusCode": 200,
            "body": json.dumps(result, indent=2)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Invalid UID or Region"})
        }