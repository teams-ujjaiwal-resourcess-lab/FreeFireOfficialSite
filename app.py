from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import CSLikeProfile_pb2 as like_pb2
import CSLikeProfile_count_pb2 as like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from datetime import datetime, timedelta
import pg8000.native
from urllib.parse import urlparse
import secrets
import string
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

app = Flask(__name__)

# ---------------------------------------------------------
#  PostgreSQL + pg8000 Connection
# ---------------------------------------------------------

DATABASE_URL = "postgresql://neondb_owner:npg_Y9yimA8vNXDu@ep-bold-voice-adb8shfq-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"

def get_conn():
    url = urlparse(DATABASE_URL)

    return pg8000.native.Connection(
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port or 5432,   # FIXED ✅
        database=url.path[1:],   # remove "/"
        ssl_context=True
    )

# ---------------------------------------------------------
#  Create Table on Startup (if not exists)
# ---------------------------------------------------------

def ensure_tables():
    conn = None
    try:
        conn = get_conn()
        conn.run(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                key VARCHAR(128) UNIQUE NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                total_requests INT NOT NULL,
                remaining_requests INT NOT NULL,
                notes TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                last_reset TIMESTAMP,
                last_used TIMESTAMP
            );
            """
        )
    except Exception as e:
        print("Error creating tables:", e)
    finally:
        if conn:
            conn.close()

ensure_tables()

# ---------------------------------------------------------
# Scheduler (Daily Reset)
# ---------------------------------------------------------

scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

def reset_remaining_requests():
    """Reset remaining requests for all active keys"""
    now = datetime.utcnow()
    conn = None

    try:
        conn = get_conn()
        keys = conn.run(
            "SELECT * FROM api_keys WHERE is_active = TRUE AND expires_at > :t",
            t=now
        )
        for key in keys:
            conn.run(
                """
                UPDATE api_keys
                SET remaining_requests = :tot,
                    last_reset = :now
                WHERE id = :kid
                """,
                tot=key["total_requests"],
                now=now,
                kid=key["id"]
            )
    except Exception as e:
        print("Reset error:", e)
    finally:
        if conn:
            conn.close()

scheduler.add_job(reset_remaining_requests, 'cron', hour=0, minute=0, timezone='UTC')

# ---------------------------------------------------------
#  TOKEN Loader + Encryption + Protobuf Helpers
# ---------------------------------------------------------

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                return json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                return json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                return json.load(f)
    except:
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode()
    except:
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except:
        return None

# ---------------------------------------------------------
#  ASYNC HTTP REQUEST FUNCTIONS
# ---------------------------------------------------------

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as resp:
                if resp.status != 200:
                    return None
                return await resp.text()
    except:
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        msg = create_protobuf_message(uid, region)
        if msg is None:
            return None

        encrypted_uid = encrypt_message(msg)
        if encrypted_uid is None:
            return None

        tokens = load_tokens(server_name)
        if tokens is None:
            return None

        tasks = []
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except:
        return None


# ---------------------------------------------------------
#  UID Encrypt + Request to Garena
# ---------------------------------------------------------

def create_protobuf(uid):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.ujjaiwal_ = int(uid)
        msg.garena = 1
        return msg.SerializeToString()
    except:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }

        r = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = r.content.hex()
        binary = bytes.fromhex(hex_data)

        obj = like_count_pb2.Info()
        obj.ParseFromString(binary)
        return obj
    except:
        return None

def authenticate_key(api_key):
    try:
        conn = get_conn()

        rows = conn.run(
            "SELECT * FROM api_keys WHERE key = :k",
            k=api_key
        )
        conn.close()

        if not rows:
            return None

        key = rows[0]
        now = datetime.utcnow()

        if key["expires_at"] < now:
            conn = get_conn()
            conn.run(
                "UPDATE api_keys SET is_active = FALSE WHERE key = :k",
                k=api_key
            )
            conn.close()
            return None

        if not key["is_active"]:
            return None

        if key["last_reset"] is not None:
            if key["last_reset"].date() < now.date():
                conn = get_conn()
                conn.run(
                    """
                    UPDATE api_keys
                    SET remaining_requests = :tot,
                        last_reset = :now
                    WHERE key = :k
                    """,
                    tot=key["total_requests"],
                    now=now,
                    k=api_key
                )
                conn.close()
                key["remaining_requests"] = key["total_requests"]
                key["last_reset"] = now

        return key

    except Exception as e:
        print("Auth key error:", e)
        return None


def update_key_usage(api_key, dec=1):
    try:
        now = datetime.utcnow()
        conn = get_conn()
        conn.run(
            """
            UPDATE api_keys
            SET remaining_requests = remaining_requests - :d,
                last_used = :t
            WHERE key = :k
            """,
            d=dec,
            t=now,
            k=api_key
        )
        conn.close()
    except:
        pass


# ---------------------------------------------------------
#  API KEY – CREATE
# ---------------------------------------------------------

@app.route('/api/key/create', methods=['POST'])
def create_key():
    try:
        data = request.get_json() or {}

        custom_key = data.get("custom_key")
        total_requests = int(data.get("total_requests", 1000))
        expiry_days = int(data.get("expiry_days", 30))
        notes = data.get("notes", "")

        # If custom key exists?
        if custom_key:
            conn = get_conn()
            exist = conn.run(
                "SELECT * FROM api_keys WHERE key = :k",
                k=custom_key
            )
            conn.close()
            if exist:
                return jsonify({"error": "Custom key already exists"}), 400

            api_key = custom_key
        else:
            chars = string.ascii_letters + string.digits
            api_key = ''.join(secrets.choice(chars) for _ in range(32))

        expires = datetime.utcnow() + timedelta(days=expiry_days)

        conn = get_conn()
        conn.run(
            """
            INSERT INTO api_keys
            (key, created_at, expires_at, total_requests, remaining_requests, notes, is_active, last_reset)
            VALUES (:k, :c, :e, :t, :r, :n, TRUE, :l)
            """,
            k=api_key,
            c=datetime.utcnow(),
            e=expires,
            t=total_requests,
            r=total_requests,
            n=notes,
            l=datetime.utcnow()
        )
        conn.close()

        return jsonify({
            "message": "Key created",
            "key": api_key,
            "expires_at": expires.isoformat(),
            "total_requests": total_requests
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------------------------------------------------
#  API KEY – CHECK
# ---------------------------------------------------------

@app.route('/api/key/check', methods=['GET'])
def check_key():
    api_key = request.headers.get('X-API-KEY') or request.args.get('key')

    if not api_key:
        return jsonify({"error": "API key required"}), 401

    key = authenticate_key(api_key)
    if not key:
        return jsonify({"error": "Invalid or expired API key"}), 403

    # Convert datetime to ISO
    for k in ("created_at", "expires_at", "last_reset", "last_used"):
        if key.get(k) and hasattr(key[k], "isoformat"):
            key[k] = key[k].isoformat()

    key.pop("id", None)   # Optional: hide internal ID

    return jsonify(key)


# ---------------------------------------------------------
#  API KEY – REMOVE / DEACTIVATE
# ---------------------------------------------------------

@app.route('/api/key/remove', methods=['DELETE'])
def remove_key():
    api_key = request.headers.get('X-API-KEY') or request.args.get('key')

    if not api_key:
        return jsonify({"error": "API key required"}), 401

    if not authenticate_key(api_key):
        return jsonify({"error": "Invalid or expired API key"}), 403

    conn = get_conn()
    conn.run("UPDATE api_keys SET is_active = FALSE WHERE key = :k", k=api_key)
    conn.close()

    return jsonify({"message": "API key deactivated"})


# ---------------------------------------------------------
#  API KEY – UPDATE
# ---------------------------------------------------------

@app.route('/api/key/update', methods=['PUT'])
def update_key():
    api_key = request.headers.get('X-API-KEY') or request.args.get('key')

    if not api_key:
        return jsonify({"error": "API key required"}), 401

    key_data = authenticate_key(api_key)
    if not key_data:
        return jsonify({"error": "Invalid or expired API key"}), 403

    data = request.get_json() or {}
    updates = []
    params = {}

    # update: total_requests
    if "total_requests" in data:
        try:
            tr = int(data["total_requests"])
            updates.append("total_requests = :tr")
            params["tr"] = tr

            # adjust remaining
            oldTR = key_data["total_requests"]
            oldRem = key_data["remaining_requests"]
            if tr > oldTR:
                newRem = tr - (oldTR - oldRem)
                updates.append("remaining_requests = :nr")
                params["nr"] = newRem
        except:
            return jsonify({"error": "total_requests must be int"}), 400

    # update: expiry_days
    if "expiry_days" in data:
        try:
            days = int(data["expiry_days"])
            new_exp = datetime.utcnow() + timedelta(days=days)
            updates.append("expires_at = :exp")
            params["exp"] = new_exp
        except:
            return jsonify({"error": "expiry_days must be int"}), 400

    # update: is_active
    if "is_active" in data:
        updates.append("is_active = :ia")
        params["ia"] = bool(data["is_active"])

    # update: notes
    if "notes" in data:
        updates.append("notes = :nts")
        params["nts"] = str(data["notes"])

    if not updates:
        return jsonify({"error": "Nothing to update"}), 400

    params["k"] = api_key
    sql = "UPDATE api_keys SET " + ", ".join(updates) + " WHERE key = :k"

    conn = get_conn()
    conn.run(sql, **params)
    conn.close()

    return jsonify({"message": "Key updated"})


# ---------------------------------------------------------
#  MAIN LIKE ENDPOINT
# ---------------------------------------------------------

@app.route('/like', methods=['GET'])
def like_handler():
    api_key = request.headers.get('X-API-KEY') or request.args.get('key')

    if not api_key:
        return jsonify({"error": "API key is required"}), 401

    key_data = authenticate_key(api_key)
    if not key_data:
        return jsonify({"error": "Invalid or expired API key"}), 403

    # request limit check
    if key_data["remaining_requests"] <= 0:
        next_reset = (datetime.utcnow().replace(hour=0, minute=0, second=0)
                      + timedelta(days=1))

        return jsonify({
            "error": "No remaining requests",
            "status": 0,
            "next_reset": next_reset.isoformat()
        }), 429

    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()

    if not uid or not server_name:
        return jsonify({"error": "uid and server_name required"}), 400

    try:
        # Load tokens
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify({"error": "Token load failed"}), 500

        token = tokens[0]["token"]
        encrypted = enc(uid)

        if encrypted is None:
            return jsonify({"error": "Encryption failed"}), 500

        # FIRST REQUEST (before likes)
        before = make_request(encrypted, server_name, token)
        if before is None:
            return jsonify({"error": "Failed to fetch player info"}), 500

        before_json = json.loads(MessageToJson(before))
        acc_before = before_json.get("AccountInfo", {})
        before_likes = int(acc_before.get("Likes", 0))

        # URL for LIKE REQUESTS
        if server_name == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send multiple likes
        asyncio.run(send_multiple_requests(uid, server_name, like_url))

        # SECOND REQUEST (after likes)
        after = make_request(encrypted, server_name, token)
        if after is None:
            return jsonify({"error": "Failed to fetch after-like info"}), 500

        after_json = json.loads(MessageToJson(after))
        acc_after = after_json.get("AccountInfo", {})

        after_likes = int(acc_after.get("Likes", 0))
        player_name = acc_after.get("PlayerNickname", "")
        player_uid = acc_after.get("UID", "")

        likes_given = after_likes - before_likes

        # Update key usage
        if likes_given > 0:
            update_key_usage(api_key)
            status = 1
        else:
            status = 2

        updated = authenticate_key(api_key)

        return jsonify({
            "status": status,
            "response": {
                "KeyExpiresAt": updated["expires_at"].isoformat(),
                "KeyRemainingRequests": f"{updated['remaining_requests']}/{updated['total_requests']}",
                "PlayerNickname": player_name,
                "UID": player_uid,
                "LikesbeforeCommand": before_likes,
                "LikesafterCommand": after_likes,
                "LikesGivenByAPI": likes_given
            }
        })

    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500


# ---------------------------------------------------------
#  FLASK RUN
# ---------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)