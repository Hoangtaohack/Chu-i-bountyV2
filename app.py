from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from flask import Flask, request, jsonify
import requests
import random
from datetime import datetime
import uid_generator_pb2
from zitado_pb2 import Users
from secret import key, iv

app = Flask(__name__)

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(akiru_, aditya):
    message = uid_generator_pb2.uid_generator()
    message.akiru_ = akiru_
    message.aditya = aditya
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def get_credentials(region):
    region = region.upper()
    if region == "VN":
        return "3988398641", "CF2B0302A7635BB971BF098F4531F123C6DE4A06B3842EAC5A91F1508A2E56E2"

def get_jwt_token(region):
    uid, password = get_credentials(region)
    jwt_url = f"https://aditya-jwt-v11op.onrender.com/token?uid={uid}&password={password}
    
    response = requests.get(jwt_url)
    if response.status_code != 200:
        return None
    return response.json()


@app.route('/player', methods=['GET'])
def main():
    uid = request.args.get('uid')
    region = request.args.get('region', '').upper()

    if region != 'VN':
        return jsonify({"error": "Chỉ hỗ trợ server Việt Nam"}), 400

    if not uid:
        return jsonify({"error": "Thiếu tham số 'UID'"}), 400

    try:
        saturn_ = int(uid)
    except ValueError:
        return jsonify({"error": "UID phải là số"}), 400

    jwt_info = get_jwt_token(region)
    if not jwt_info or 'token' not in jwt_info:
        return jsonify({"error": "Không thể lấy token từ máy chủ, vui lòng báo cho admin"}), 500

    token = jwt_info['token']
    hex_data = protobuf_to_hex(create_protobuf(saturn_, 1))
    encrypted_hex = encrypt_aes(hex_data, key, iv)

    headers = {
        'User-Agent': 'Dalvik/2.1.0',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB49',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        response = requests.post(
            "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
            headers=headers,
            data=bytes.fromhex(encrypted_hex)
        )
        response.raise_for_status()
    except requests.RequestException:
        return jsonify({"error": "Không thể kết nối server game"}), 502

    try:
        users = decode_hex(response.content.hex())
    except Exception as e:
        return jsonify({"error": f"Không thể giải mã dữ liệu trả về"}), 500

    result = {}

    if users.basicinfo:
        result['basicinfo'] = [{
            'name': u.username,
            'region': u.region,
            'level': u.level,
            'likes': u.likes,
            'bio': users.bioinfo[0].bio if users.bioinfo else None,
            'brrankscore': u.brrankscore,
            'BadgeCount': u.BadgeCount,
            'csrankpoint': u.csrankpoint,
            'csrankscore': u.csrankscore,
            'brrankpoint': u.brrankpoint,
            'createat': datetime.utcfromtimestamp(u.createat).strftime('%Y-%m-%d %H:%M:%S') if u.createat else None,
            'lastlogin': datetime.utcfromtimestamp(u.lastlogin).strftime('%Y-%m-%d %H:%M:%S') if u.lastlogin else None,
        } for u in users.basicinfo]

    if users.claninfo:
        result['claninfo'] = [{
            'clanid': c.clanid,
            'clanname': c.clanname,
            'guildlevel': c.guildlevel,
            'livemember': c.livemember
        } for c in users.claninfo]

    if users.clanadmin:
        result['clanadmin'] = [{
            'idadmin': a.idadmin,
            'adminname': a.adminname,
            'level': a.level,
            'exp': a.exp,
            'brpoint': a.brpoint,
            'cspoint': a.cspoint,
            'lastlogin': datetime.utcfromtimestamp(a.lastlogin).strftime('%Y-%m-%d %H:%M:%S') if a.lastlogin else None
        } for a in users.clanadmin]

    result['credit'] = 'FB: Dinh Hoang(amdts)'
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
