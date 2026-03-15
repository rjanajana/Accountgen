# app.py - Free Fire Bio Update API
# JWT generation is handled internally (no external converter needed)

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
from urllib.parse import urlparse, parse_qs
import requests
import jwt
import time
import logging
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==================== LOGGING ====================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== CONSTANTS ====================

# AES keys (same as Garena client)
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

# FreeFire version
FREEFIRE_VERSION = "OB52"

# Region → Server URL mapping (per-region exact URLs)
REGION_URLS = {
    'IND': 'https://client.ind.freefiremobile.com',
    'BR':  'https://client.us.freefiremobile.com',
    'US':  'https://client.us.freefiremobile.com',
    'SAC': 'https://client.us.freefiremobile.com',
    'NA':  'https://client.us.freefiremobile.com',
    'EU':  'https://clientbp.ggblueshark.com',
    'ME':  'https://clientbp.ggblueshark.com',
    'ID':  'https://clientbp.ggblueshark.com',
    'TH':  'https://clientbp.ggblueshark.com',
    'VN':  'https://clientbp.ggblueshark.com',
    'SG':  'https://clientbp.ggblueshark.com',
    'BD':  'https://clientbp.ggwhitehawk.com',
    'PK':  'https://clientbp.ggblueshark.com',
    'MY':  'https://clientbp.ggblueshark.com',
    'PH':  'https://clientbp.ggblueshark.com',
    'RU':  'https://clientbp.ggblueshark.com',
    'AFR': 'https://clientbp.ggblueshark.com',
    'TW':  'https://clientbp.ggblueshark.com',
}
DEFAULT_URL = 'https://clientbp.ggblueshark.com'

# ==================== PROTOBUF SETUP (INLINE) ====================
# Bio update protobuf — defined inline, no external .pb2 file needed

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05'
    b'\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6'
    b'\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f'
    b'\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r'
    b'.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n'
    b'\x0c\x45mptyMessageb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data_pb2', _globals)

if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals['_DATA']._serialized_start = 15
    _globals['_DATA']._serialized_end   = 202
    _globals['_EMPTYMESSAGE']._serialized_start = 204
    _globals['_EMPTYMESSAGE']._serialized_end   = 218

Data         = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')

# JWT generation protobuf — external pb2 files (same as before)
try:
    import my_pb2
    import output_pb2
except ImportError as e:
    logger.error(f"Protobuf import error: {e}")
    print("Make sure my_pb2.py and output_pb2.py are in the same directory")
    exit(1)

# ==================== HELPER: AES ENCRYPT ====================

def encrypt_aes(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

# ==================== JWT AUTH FUNCTIONS ====================

def decode_jwt_token(jwt_token: str) -> dict:
    """JWT decode karo bina signature verify kiye"""
    try:
        if jwt_token.startswith('Bearer '):
            jwt_token = jwt_token[7:]
        return jwt.decode(jwt_token, options={"verify_signature": False})
    except Exception as e:
        logger.error(f"JWT decode error: {e}")
        return None

def get_access_token_from_uid(uid: str, password: str) -> dict:
    """UID + password se Garena OAuth access token lo"""
    try:
        response = requests.post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            data={
                'uid':           uid,
                'password':      password,
                'response_type': "token",
                'client_type':   "2",
                'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                'client_id':     "100067"
            },
            headers={
                'User-Agent':      "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
                'Connection':      "Keep-Alive",
                'Accept-Encoding': "gzip"
            },
            timeout=10
        )
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        return None

def get_token_inspect_data(access_token: str) -> dict:
    """Access token inspect karo — open_id aur platform type milega"""
    try:
        resp = requests.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
            timeout=15,
            verify=False
        )
        return resp.json() if resp.status_code == 200 else None
    except Exception as e:
        logger.error(f"Token inspect error: {e}")
        return None

def generate_jwt_token(access_token: str, open_id: str, platform_type: int) -> str:
    """Access token se game JWT generate karo — Garena MajorLogin ke through"""
    try:
        game_data = my_pb2.GameData()
        game_data.timestamp        = time.strftime("%Y-%m-%d %H:%M:%S")
        game_data.game_name        = "Free Fire"
        game_data.game_version     = 1
        game_data.version_code     = "1.120.1"
        game_data.os_info          = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type      = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type  = "WIFI"
        game_data.screen_width     = 1280
        game_data.screen_height    = 960
        game_data.dpi              = "240"
        game_data.cpu_info         = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram        = 5951
        game_data.gpu_name         = "Adreno (TM) 640"
        game_data.gpu_version      = "OpenGL ES 3.0"
        game_data.user_id          = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
        game_data.ip_address       = "172.190.111.97"
        game_data.language         = "en"
        game_data.open_id          = open_id
        game_data.access_token     = access_token
        game_data.platform_type    = platform_type
        game_data.field_99         = str(platform_type)
        game_data.field_100        = str(platform_type)

        encrypted = encrypt_aes(game_data.SerializeToString())

        response = requests.post(
            "https://loginbp.ggpolarbear.com/MajorLogin",
            data=encrypted,
            headers={
                "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                "Connection":      "Keep-Alive",
                "Accept-Encoding": "gzip",
                "Content-Type":    "application/octet-stream",
                "Expect":          "100-continue",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA":            "v1 1",
                "ReleaseVersion":  FREEFIRE_VERSION
            },
            verify=False,
            timeout=10
        )

        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            return jwt_msg.token if jwt_msg.token else None

    except Exception as e:
        logger.error(f"JWT generate error: {e}")
    return None

def eat_to_access_token(eat_token: str) -> dict:
    """EAT token ko access_token mein convert karo"""
    try:
        response = requests.get(
            f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}",
            allow_redirects=True,
            timeout=30,
            verify=False
        )
        if 'help.garena.com' in response.url:
            params = parse_qs(urlparse(response.url).query)
            if 'access_token' in params:
                return {
                    'success':      True,
                    'access_token': params['access_token'][0],
                    'region':       params.get('region', [None])[0],
                    'game_uid':     params.get('account_id', [None])[0],
                    'nickname':     params.get('nickname', [None])[0]
                }
        return {'success': False, 'error': 'Invalid EAT token'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def process_to_jwt(uid=None, password=None, token=None, access_token=None, eat_token=None) -> dict:
    """
    Kisi bhi auth method se JWT token banao.
    Priority: JWT → access_token → EAT token → UID+password
    """
    try:
        # 1. Direct JWT
        if token:
            decoded = decode_jwt_token(token)
            if not decoded:
                return {"success": False, "error": "Invalid JWT token"}
            return {
                "success":    True,
                "jwt_token":  token,
                "account_id": decoded.get('account_id') or decoded.get('uid'),
                "region":     decoded.get('lock_region', 'OTHERS'),
                "nickname":   decoded.get('nickname')
            }

        # 2. Access token → JWT
        elif access_token:
            token_info = get_token_inspect_data(access_token)
            if not token_info:
                return {"success": False, "error": "Invalid or expired access token"}

            jwt_token = generate_jwt_token(
                access_token,
                token_info.get('open_id'),
                token_info.get('platform', 4)
            )
            if not jwt_token:
                return {"success": False, "error": "Failed to generate JWT from access token"}

            decoded = decode_jwt_token(jwt_token)
            if not decoded:
                return {"success": False, "error": "Failed to decode generated JWT"}

            return {
                "success":    True,
                "jwt_token":  jwt_token,
                "account_id": decoded.get('account_id') or decoded.get('uid'),
                "region":     decoded.get('lock_region', 'OTHERS'),
                "nickname":   decoded.get('nickname')
            }

        # 3. EAT token → access_token → JWT
        elif eat_token:
            eat_result = eat_to_access_token(eat_token)
            if not eat_result.get('success'):
                return {"success": False, "error": eat_result.get('error', 'Invalid EAT token')}
            return process_to_jwt(access_token=eat_result['access_token'])

        # 4. UID + Password → access_token → JWT
        elif uid and password:
            oauth_data = get_access_token_from_uid(uid, password)
            if not oauth_data or not oauth_data.get('access_token'):
                return {"success": False, "error": "Invalid UID or password"}
            return process_to_jwt(access_token=oauth_data['access_token'])

        else:
            return {"success": False, "error": "No valid authentication provided"}

    except Exception as e:
        logger.error(f"Auth processing error: {e}")
        return {"success": False, "error": str(e)}

# ==================== BIO HELPER ====================

def build_bio_payload(bio_text: str) -> bytes:
    """Bio text ka AES encrypted protobuf payload banao"""
    data = Data()
    data.field_2  = 17
    data.field_5.CopyFrom(EmptyMessage())
    data.field_6.CopyFrom(EmptyMessage())
    data.field_8  = bio_text
    data.field_9  = 1
    data.field_11.CopyFrom(EmptyMessage())
    data.field_12.CopyFrom(EmptyMessage())
    return encrypt_aes(data.SerializeToString())

# ==================== FLASK ROUTES ====================

@app.route('/')
def home():
    return jsonify({
        "status":    "active",
        "service":   "Free Fire Bio Update API",
        "version":   "2.0",
        "endpoints": {
            "update_bio":        "/upbio?uid=UID&password=PASSWORD&text=BIO",
            "update_bio_token":  "/upbio?access_token=TOKEN&text=BIO",
            "update_bio_eat":    "/upbio?eat_token=EAT&text=BIO",
            "update_bio_jwt":    "/upbio?token=JWT&text=BIO",
            "legacy_jwt":        "/update_bio?jwt=JWT&text=BIO&region=IND",
            "regions":           "/regions",
            "health":            "/health"
        },
        "auth_methods": ["uid+password", "access_token", "eat_token", "jwt_token"]
    })


@app.route('/upbio', methods=['GET'])
def update_bio_new():
    """
    Bio update — 4 auth methods support karta hai:
    ?uid=&password=  |  ?access_token=  |  ?eat_token=  |  ?token=
    """
    uid          = request.args.get('uid')
    password     = request.args.get('password')
    token        = request.args.get('token')
    access_token = request.args.get('access_token')
    eat_token    = request.args.get('eat_token')
    bio_text     = request.args.get('text')

    if not bio_text:
        return jsonify({"status": "error", "message": "text parameter required"}), 400

    if len(bio_text) > 120:
        return jsonify({"status": "error", "message": "Bio max 120 characters allowed"}), 400

    # Auth → JWT
    auth_result = process_to_jwt(
        uid=uid, password=password,
        token=token, access_token=access_token,
        eat_token=eat_token
    )

    if not auth_result.get('success'):
        return jsonify({"status": "error", "message": auth_result.get('error')}), 400

    jwt_token = auth_result['jwt_token']
    region    = auth_result.get('region', 'OTHERS').upper()

    try:
        base_url  = REGION_URLS.get(region, DEFAULT_URL)
        encrypted = build_bio_payload(bio_text)

        headers = {
            "Expect":          "100-continue",
            "Authorization":   f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA":            "v1 1",
            "ReleaseVersion":  FREEFIRE_VERSION,
            "Content-Type":    "application/x-www-form-urlencoded",
            "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Connection":      "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        res = requests.post(
            f"{base_url}/UpdateSocialBasicInfo",
            headers=headers,
            data=encrypted,
            timeout=10,
            verify=False
        )

        if res.status_code == 200:
            return jsonify({
                "status":       "success",
                "message":      f"Bio updated: {bio_text}",
                "region":       region,
                "uid":          auth_result.get('account_id'),
                "nickname":     auth_result.get('nickname'),
                "status_code":  res.status_code
            })
        else:
            return jsonify({
                "status":      "error",
                "message":     "FF server request failed",
                "status_code": res.status_code,
                "region":      region,
                "response":    res.text[:300]
            }), res.status_code

    except Exception as e:
        logger.error(f"Bio update error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/update_bio', methods=['GET'])
def update_bio_legacy():
    """Legacy endpoint — direct JWT se bio update (backward compatibility)"""
    jwt_token = request.args.get('jwt')
    bio_text  = request.args.get('text')
    region    = request.args.get('region', 'IND').upper()

    if not jwt_token or not bio_text:
        return jsonify({
            "status":  "error",
            "message": "jwt and text parameters required"
        }), 400

    try:
        base_url  = REGION_URLS.get(region, DEFAULT_URL)
        encrypted = build_bio_payload(bio_text)

        headers = {
            "Expect":          "100-continue",
            "Authorization":   f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA":            "v1 1",
            "ReleaseVersion":  FREEFIRE_VERSION,
            "Content-Type":    "application/x-www-form-urlencoded",
            "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Connection":      "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        res = requests.post(
            f"{base_url}/UpdateSocialBasicInfo",
            headers=headers,
            data=encrypted,
            timeout=10,
            verify=False
        )

        if res.status_code == 200:
            return jsonify({
                "status":      "success",
                "message":     f"Bio updated: {bio_text}",
                "region":      region,
                "status_code": res.status_code
            })
        else:
            return jsonify({
                "status":      "error",
                "message":     "FF server request failed",
                "status_code": res.status_code,
                "region":      region
            }), 400

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/regions', methods=['GET'])
def get_regions():
    return jsonify({
        "regions":     list(REGION_URLS.keys()),
        "default_url": DEFAULT_URL
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status":    "healthy",
        "service":   "Free Fire Bio Update API",
        "version":   "2.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })


# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  FREE FIRE BIO UPDATE API  v2.0")
    print("="*55)
    print("  Running on: http://localhost:5000")
    print("\n  ENDPOINTS:")
    print("  POST /upbio?uid=UID&password=PASS&text=BIO")
    print("  POST /upbio?access_token=TOKEN&text=BIO")
    print("  POST /upbio?eat_token=EAT&text=BIO")
    print("  POST /upbio?token=JWT&text=BIO")
    print("  POST /update_bio?jwt=JWT&text=BIO&region=IND  [legacy]")
    print("="*55 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
