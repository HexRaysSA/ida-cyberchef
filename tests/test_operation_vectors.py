import base64
import bz2
import calendar
import gzip
import hashlib
import hmac
import io
import json
import ipaddress
import math
import re
import struct
import tarfile
import time
import uuid
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import product
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from ida_cyberchef.cyberchef import bake

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BRAILLE_ASCII = " A1B'K2L@CIF/MSP\"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)="
BRAILLE_DOT6 = "⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⠚⠛⠜⠝⠞⠟⠠⠡⠢⠣⠤⠥⠦⠧⠨⠩⠪⠫⠬⠭⠮⠯⠰⠱⠲⠳⠴⠵⠶⠷⠸⠹⠺⠻⠼⠽⠾⠿"


@dataclass(frozen=True)
class BakeVector:
    name: str
    input_data: bytes | str
    recipe: list[str | dict[str, object]]
    expected: object | Callable[[object], None]


@dataclass(frozen=True)
class BlockedBakeVector:
    name: str
    input_data: bytes | str
    recipe: list[str | dict[str, object]]
    error_message: str


EMPTY_BSON_DOCUMENT = b"\x05\x00\x00\x00\x00"
HELLO_WORLD_BSON_DOCUMENT = bytes.fromhex("160000000268656c6c6f0006000000776f726c640000")
MICROSOFT_SCRIPT_SAMPLE_ENCODED = (
    "#@~^RQAAAA==-mD~sX|:/TP{~J:+dYbxL~@!F@*@!+@*@!&@*eEI@#@&@#@&.jm.raY "
    "214Wv:zms/obI0xEAAA==^#~@"
)
MICROSOFT_SCRIPT_SAMPLE_DECODED = 'var my_msg = "Testing <1><2><3>!";\r\n\r\nVScript.Echo(my_msg);'
HELLO_HELLO_HELLO_LZ4_FRAME = bytes.fromhex("04224d184070df0f0000006268656c6c6f2006005068656c6c6f00000000")
HELLO_HELLO_HELLO_LZMA_STREAM = bytes.fromhex(
    "5d00008000110000000000000000341949ee8de94f7f35c5a3ffff78a40000"
)
LZNT1_COMPRESSED_SAMPLE = b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot"
HELLO_HELLO_HELLO_RAW_DEFLATE_STREAM = bytes.fromhex("4dc4a109000010c3c0557eb94245a0fbbbd837d7c0ee29")
HELLO_HELLO_HELLO_RAW_DEFLATE_FIXED_STREAM = bytes.fromhex("cb48cdc9c957402201")
HELLO_HELLO_HELLO_RAW_DEFLATE_STORE_STREAM = bytes.fromhex(
    "011100eeff68656c6c6f2068656c6c6f2068656c6c6f"
)
HELLO_HELLO_HELLO_ZLIB_STREAM = bytes.fromhex(
    "789c4dc4a109000010c3c0557eb94245a0fbbbd837d7c0ee293a2e067d"
)
HELLO_HELLO_HELLO_ZLIB_FIXED_STREAM = bytes.fromhex("785ecb48cdc9c9574022013a2e067d")
HELLO_HELLO_HELLO_ZLIB_STORE_STREAM = bytes.fromhex(
    "7801011100eeff68656c6c6f2068656c6c6f2068656c6c6f3a2e067d"
)
AMF3_SINGLE_FIELD_OBJECT = b"\x0a\x13\x01\x03a\x06\x09test"
AMF0_SINGLE_FIELD_OBJECT = b"\x03\x00\x01a\x02\x00\x04test\x00\x00\t"
AVRO_SINGLE_RECORD_CONTAINER = (
    b"\x4f\x62\x6a\x01\x04\x16\x61\x76\x72\x6f\x2e\x73\x63\x68\x65\x6d\x61\x96\x01\x7b\x22\x74\x79\x70\x65\x22\x3a\x22\x72\x65"
    b"\x63\x6f\x72\x64\x22\x2c\x22\x6e\x61\x6d\x65\x22\x3a\x22\x73\x6d\x61\x6c\x6c\x22\x2c\x22\x66\x69\x65\x6c\x64\x73\x22\x3a"
    b"\x5b\x7b\x22\x6e\x61\x6d\x65\x22\x3a\x22\x6e\x61\x6d\x65\x22\x2c\x22\x74\x79\x70\x65\x22\x3a\x22\x73\x74\x72\x69\x6e\x67"
    b"\x22\x7d\x5d\x7d\x14\x61\x76\x72\x6f\x2e\x63\x6f\x64\x65\x63\x08\x6e\x75\x6c\x6c\x00\x4e\x02\x47\x63\x2e\x37\x02\xe5\xb7"
    b"\x5c\xda\xb9\xa6\x2f\x15\x41\x02\x0e\x0c\x6d\x79\x6e\x61\x6d\x65\x4e\x02\x47\x63\x2e\x37\x02\xe5\xb7\x5c\xda\xb9\xa6\x2f"
    b"\x15\x41"
)
CSV_COMPLEX_SAMPLE = (
    "A,B,C,D,E,F\r\n"
    "1,2,3,4,5,6\r\n"
    "\",\",;,',\"\"\"\",,\r\n"
    '"""hello""","a""1","multi\r\nline",,,end\r\n'
)
CSV_COMPLEX_ARRAY_OF_DICTS = [
    {"A": "1", "B": "2", "C": "3", "D": "4", "E": "5", "F": "6"},
    {"A": ",", "B": ";", "C": "'", "D": '"', "E": "", "F": ""},
    {"A": '"hello"', "B": 'a"1', "C": "multi\r\nline", "D": "", "E": "", "F": "end"},
]
AMF3_SINGLE_FIELD_OBJECT_DECODED = {
    "marker": 10,
    "$objectTypeIndicator": 19,
    "$traits": {
        "className": {"$lengthOrReference": 1, "$value": ""},
        "sealedMemberNames": [{"$lengthOrReference": 3, "$value": "a"}],
    },
    "_dynamicMembers": [],
    "_values": [{"marker": 6, "stringOrReference": {"$lengthOrReference": 9, "$value": "test"}}],
}
AMF0_SINGLE_FIELD_OBJECT_DECODED = {
    "marker": 3,
    "properties": [{"keyLength": 1, "key": "a", "value": {"marker": 2, "length": 4, "$value": "test"}}],
}
SIMPLE_DER_HEX = "3003020105"
SIMPLE_CERTIFICATE_PEM = "-----BEGIN CERTIFICATE-----\r\nMAMCAQU=\r\n-----END CERTIFICATE-----\r\n"
SIMPLE_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\r\nMAMCAQU=\r\n-----END PUBLIC KEY-----\r\n"
ECDSA_TEST_MESSAGE = (
    "A common mistake that people make when trying to design something completely foolproof is to "
    "underestimate the ingenuity of complete fools."
)
ECDSA_P256_PRIVATE_KEY_PKCS1_PEM = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINtTjwUkgfAiSwqgcGAXWyE0ueIW6n2k395dmQZ3vGr4oAoGCCqGSM49
AwEHoUQDQgAEDUc8A0EDNKoCYIPWMHz1yUzqE5mJgusgcAE8H6810fkJ8ZmTNiCC
a6sLgR2vD1VNh2diirWgKPH4PVMKav5e6Q==
-----END EC PRIVATE KEY-----"""
ECDSA_P256_PRIVATE_KEY_PKCS8_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg21OPBSSB8CJLCqBw
YBdbITS54hbqfaTf3l2ZBne8avihRANCAAQNRzwDQQM0qgJgg9YwfPXJTOoTmYmC
6yBwATwfrzXR+QnxmZM2IIJrqwuBHa8PVU2HZ2KKtaAo8fg9Uwpq/l7p
-----END PRIVATE KEY-----"""
ECDSA_P256_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDUc8A0EDNKoCYIPWMHz1yUzqE5mJ
gusgcAE8H6810fkJ8ZmTNiCCa6sLgR2vD1VNh2diirWgKPH4PVMKav5e6Q==
-----END PUBLIC KEY-----"""
ECDSA_P256_PUBLIC_KEY_PEM_CRLF = ECDSA_P256_PUBLIC_KEY_PEM.replace("\n", "\r\n") + "\r\n"
ECDSA_P256_PRIVATE_KEY_PKCS8_PEM_CRLF = ECDSA_P256_PRIVATE_KEY_PKCS8_PEM.replace("\n", "\r\n") + "\r\n"
ECDSA_P256_SIGNATURE_SHA256_ASN1 = (
    "3046022100e06905608a2fa7dbda9e284c2a7959dfb68fb527a5f003b2d7975ff135145127"
    "022100b6baa253793334f8b93ea1dd622bc600124d8090babd807efe3f77b8b324388d"
)
ECDSA_P256_SIGNATURE_SHA256_P1363 = (
    "e06905608a2fa7dbda9e284c2a7959dfb68fb527a5f003b2d7975ff135145127"
    "b6baa253793334f8b93ea1dd622bc600124d8090babd807efe3f77b8b324388d"
)
ECDSA_P256_SIGNATURE_SHA256_JWS = (
    "4GkFYIovp9vanihMKnlZ37aPtSel8AOy15df8TUUUSe2uqJTeTM0-Lk-od1iK8YAEk2AkLq9gH7-P3e4syQ4jQ"
)
ECDSA_P256_SIGNATURE_SHA256_JSON_OBJECT = {
    "r": "00e06905608a2fa7dbda9e284c2a7959dfb68fb527a5f003b2d7975ff135145127",
    "s": "00b6baa253793334f8b93ea1dd622bc600124d8090babd807efe3f77b8b324388d",
}
ECDSA_P256_SIGNATURE_SHA256_JSON = json.dumps(ECDSA_P256_SIGNATURE_SHA256_JSON_OBJECT, separators=(",", ":"))
ECDSA_P256_PUBLIC_JWK_OBJECT = {
    "kty": "EC",
    "crv": "P-256",
    "x": "DUc8A0EDNKoCYIPWMHz1yUzqE5mJgusgcAE8H6810fk",
    "y": "CfGZkzYggmurC4Edrw9VTYdnYoq1oCjx-D1TCmr-Xuk",
}
ECDSA_P256_PRIVATE_JWK_OBJECT = {
    **ECDSA_P256_PUBLIC_JWK_OBJECT,
    "d": "21OPBSSB8CJLCqBwYBdbITS54hbqfaTf3l2ZBne8avg",
}
ECDSA_P256_PUBLIC_JWK = json.dumps(ECDSA_P256_PUBLIC_JWK_OBJECT, separators=(",", ":"))
ECDSA_P256_PRIVATE_JWK = json.dumps(ECDSA_P256_PRIVATE_JWK_OBJECT, separators=(",", ":"))
SIMPLE_TLV_HI = bytes.fromhex("01024869")
SIMPLE_LV_SEQUENCE = bytes.fromhex("02486903627965")
SIMPLE_TWO_BYTE_LENGTH_TLV = bytes.fromhex("0102004869")
SIMPLE_BER_TLV = bytes.fromhex("01024142")
MINIMAL_EXIF_JPEG = bytes.fromhex(
    "ffd8"
    "ffe10028457869660000"
    "4d4d002a00000008"
    "0001"
    "010f0002000000060000001a"
    "00000000"
    "43616e6f6e00"
    "ffd9"
)
MINIMAL_ID3_TAG = bytes.fromhex("4944330300000000001054543200000000060000005469746c65")
FERNET_TEST_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
FERNET_PHASE21_TOKEN = "gAAAAABpq-NaiTYSdio-mpGASNZAteHn6Q-ga8cYUUzCsmHyy73m1QsCRsqj0i-4QbAMBD6rIshNSOicC5CVLLIBXtg64AnOPw=="
JWT_PHASE22_PAYLOAD = {"sub": "123", "name": "John Doe", "admin": True, "iat": 1_700_000_000}
HASSH_CLIENT_SAMPLE_HEX = (
    "000003140814c639665f5425dcb80bf9f0a048380a410000007e6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c"
    "6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d736861312c6469666669652d68656c6c6d616e2d67726f757031342d736861312c"
    "6469666669652d68656c6c6d616e2d67726f7570312d736861310000000f7373682d7273612c7373682d6473730000009d6165733132382d6374722c61657331"
    "39322d6374722c6165733235362d6374722c617263666f75723235362c617263666f75723132382c6165733132382d6362632c336465732d6362632c626c6f"
    "77666973682d6362632c636173743132382d6362632c6165733139322d6362632c6165733235362d6362632c617263666f75722c72696a6e6461656c2d6362"
    "63406c797361746f722e6c69752e73650000009d6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c617263666f7572323536"
    "2c617263666f75723132382c6165733132382d6362632c336465732d6362632c626c6f77666973682d6362632c636173743132382d6362632c616573313932"
    "2d6362632c6165733235362d6362632c617263666f75722c72696a6e6461656c2d636263406c797361746f722e6c69752e736500000069686d61632d6d6435"
    "2c686d61632d736861312c756d61632d3634406f70656e7373682e636f6d2c686d61632d726970656d643136302c686d61632d726970656d64313630406f70"
    "656e7373682e636f6d2c686d61632d736861312d39362c686d61632d6d64352d393600000069686d61632d6d64352c686d61632d736861312c756d61632d36"
    "34406f70656e7373682e636f6d2c686d61632d726970656d643136302c686d61632d726970656d64313630406f70656e7373682e636f6d2c686d61632d7368"
    "61312d39362c686d61632d6d64352d39360000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70"
    "656e7373682e636f6d2c7a6c6962000000000000000000000000000000000000000000"
)
HASSH_CLIENT_ALGORITHMS = (
    "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,"
    "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;"
    "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,"
    "blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se;"
    "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,"
    "hmac-sha1-96,hmac-md5-96;none,zlib@openssh.com,zlib"
)
HASSH_SERVER_SAMPLE_HEX = (
    "0000027c0b142c7bb93a1da21c9e54f5862e60a5597c000000596469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d736861312c"
    "6469666669652d68656c6c6d616e2d67726f757031342d736861312c6469666669652d68656c6c6d616e2d67726f7570312d736861310000000f7373682d"
    "7273612c7373682d647373000000876165733132382d6362632c336465732d6362632c626c6f77666973682d6362632c636173743132382d6362632c6172"
    "63666f75722c6165733139322d6362632c6165733235362d6362632c72696a6e6461656c2d636263406c797361746f722e6c69752e73652c616573313238"
    "2d6374722c6165733139322d6374722c6165733235362d637472000000876165733132382d6362632c336465732d6362632c626c6f77666973682d636263"
    "2c636173743132382d6362632c617263666f75722c6165733139322d6362632c6165733235362d6362632c72696a6e6461656c2d636263406c797361746f"
    "722e6c69752e73652c6165733132382d6374722c6165733139322d6374722c6165733235362d63747200000055686d61632d6d64352c686d61632d736861"
    "312c686d61632d726970656d643136302c686d61632d726970656d64313630406f70656e7373682e636f6d2c686d61632d736861312d39362c686d61632d"
    "6d64352d393600000055686d61632d6d64352c686d61632d736861312c686d61632d726970656d643136302c686d61632d726970656d64313630406f7065"
    "6e7373682e636f6d2c686d61632d736861312d39362c686d61632d6d64352d3936000000096e6f6e652c7a6c6962000000096e6f6e652c7a6c6962000000"
    "000000000000000000000000000000000000000000"
)
HASSH_SERVER_SAMPLE_BASE64 = base64.b64encode(bytes.fromhex(HASSH_SERVER_SAMPLE_HEX)).decode()
HASSH_SERVER_ALGORITHMS = (
    "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;"
    "aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,"
    "rijndael-cbc@lysator.liu.se,aes128-ctr,aes192-ctr,aes256-ctr;"
    "hmac-md5,hmac-sha1,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96;"
    "none,zlib"
)
JA3_TLS12_SAMPLE_HEX = (
    "1603010102010000fe0303543dd3283283692d85f9416b5ccc65d2aafca45c6530b3c6eafbf6d371b6a015000094c030c02cc028c024c014c00a00a3009f"
    "006b006a0039003800880087c032c02ec02ac026c00fc005009d003d00350084c012c00800160013c00dc003000ac02fc02bc027c023c013c00900a2009e"
    "0067004000330032009a009900450044c031c02dc029c025c00ec004009c003c002f009600410007c011c007c00cc0020005000400150012000900140011"
    "00080006000300ff01000041000b000403000102000a000600040018001700230000000d0022002006010602060305010502050304010402040303010302"
    "03030201020202030101000f000101"
)
JA3_TLS12_SAMPLE_BASE64 = base64.b64encode(bytes.fromhex(JA3_TLS12_SAMPLE_HEX)).decode()
JA3_TLS12_STRING = (
    "771,49200-49196-49192-49188-49172-49162-163-159-107-106-57-56-136-135-49202-49198-49194-49190-49167-49157-157-61-53-132-49170-49160"
    "-22-19-49165-49155-10-49199-49195-49191-49187-49171-49161-162-158-103-64-51-50-154-153-69-68-49201-49197-49193-49189-49166-49156"
    "-156-60-47-150-65-7-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,11-10-35-13-15,24-23,0-1-2"
)
JA3S_TLS12_SAMPLE_HEX = "160303003d020000390303543dd328b38b445686739d58fab733fa23838f575e0e5ad9a1b9baace6cc3b4100c02f000011ff01000100000b00040300010200230000"
JA3S_TLS12_STRING = "771,49199,65281-11-35"
JA4_TLS13_SAMPLE_HEX = "1603010200010001fc0303b2c03e7ba990ef540c316a665d4d925f8e9079ac4b15687e587dc99016e75a6c20d0b0099243c9296a0c84153ea4ada7d87ad017f4211c2ea1350b0b3cc5514d5f00205a5a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000193fafa000000000024002200001f636f6e74656e742d6175746f66696c6c2e676f6f676c65617069732e636f6d0033002b00293a3a000100001d0020fb2cd8ef3d605b96ab03119ec4f30a6e2088cb1af86c41a81feace8706068c50000d001200100403080404010503080505010806060100230000000b00020100ff01000100000a000a00083a3a001d00170018001b000302000244690005000302683200120000002d000201010010000e000c02683208687474702f312e31000500050100000000002b0007060a0a03040303001700001a1a000100001500b800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
JA4_TLS13_ALL_OUTPUT = (
    "JA4:    t13d1516h2_8daaf6152771_e5627efa2ab1\n"
    "JA4_o:  t13d1516h2_acb858a92679_5276cb03a33b\n"
    "JA4_r:  t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601\n"
    "JA4_ro: t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_0000,0033,000d,0023,000b,ff01,000a,001b,4469,0012,002d,0010,0005,002b,0017,0015_0403,0804,0401,0503,0805,0501,0806,0601"
)
JA4_TLS12_SAMPLE_HEX = "1603010200010001fc0303ecb2691addb2bf6c599c7aaae23de5f42561cc04eb41029acc6fc050a16ac1d22046f8617b580ac9358e2aa44e306d52466bcc989c87c8ca64309f5faf50ba7b4d0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100019100000021001f00001c636f6e74696c652e73657276696365732e6d6f7a696c6c612e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b0069001d00208909858fbeb6ed2f1248ba5b9e2978bead0e840110192c61daed0096798b184400170041044d183d91f5eed35791fa982464e3b0214aaa5f5d1b78616d9b9fbebc22d11f535b2f94c686143136aa795e6e5a875d6c08064ad5b76d44caad766e2483012748002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c000240010015007a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
JA4S_TLS12_SAMPLE_HEX = "16030300640200006003035f0236c07f47bfb12dc2da706ecb3fe7f9eeac9968cc2ddf444f574e4752440120b89ff1ab695278c69b8a73f76242ef755e0b13dc6d459aaaa784fec9c2dfce34cca900001800000000ff01000100000b00020100001000050003026832"
JA4S_TLS12_SAMPLE_BASE64 = base64.b64encode(bytes.fromhex(JA4S_TLS12_SAMPLE_HEX)).decode()
JA4S_TLS13_SAMPLE_HEX = "160303007a020000760303236d214556452c55a0754487e64b1a8b0262c50ba23004c9d504166a6de3439920d0b0099243c9296a0c84153ea4ada7d87ad017f4211c2ea1350b0b3cc5514d5f130100002e00330024001d002099e3cc43a2c9941ae75af1b2c7a629bee3ee7031973cad85c82f2f23677fb244002b00020304"
IPV4_HEADER_SAMPLE_HEX = "45 c0 00 c4 02 89 00 00 ff 11 1e 8c c0 a8 0c 01 c0 a8 0c 02"
PARSE_TCP_NO_OPTIONS_HEX = "c2eb0050a138132e70dc9fb9501804025ea70000"
PARSE_TCP_OPTIONS_HEX = "c2eb0050a1380c1f000000008002faf080950000020405b40103030801010402"
PARSE_UDP_NO_DATA_HEX = "04 89 00 35 00 2c 01 01"
PARSE_UDP_WITH_DATA_HEX = "04 89 00 35 00 2c 01 01 02 02"
PARSE_TLS_ALERT_HEX = "150303001411770b5b5d11078535823266ec79671ed402bced"
PARSE_TLS_CHANGE_CIPHER_SPEC_HEX = "140303000101"
PARSE_TLS_CLIENT_HELLO_HEX = (
    "16030300320100002e030345cd3a31beaebd2934dd4ec2a151d7a054eab8bc0e4e5b9d4b9abdaacd051076000004123443210200010000"
)
PROTOBUF_SAMPLE_BYTES = bytes.fromhex("0d1c0000001203596f751a024d65202b2a0a0a066162633132331200")
PROTOBUF_TYPED_SCHEMA = """message Test {
    optional string Banana = 2;
    repeated string Carrot = 3;
    optional int32 Date = 4;
    optional Options Imbe = 7;
}

enum Options {
    Option0 = 0;
    Option1 = 1;
    Option2 = 2;
}
"""
PROTOBUF_FULL_SCHEMA = """message Test {
    repeated fixed32 Apple = 1;
    optional string Banana = 2;
    repeated string Carrot = 3;
    optional int32 Date = 4;
    optional subTest Elderberry = 5;
    repeated fixed64 Huckleberry = 6;
    optional Options Imbe = 7;
}

message subTest {
    optional string Fig = 1;
    optional subSubTest Grape = 2;
}

message subSubTest {}

enum Options {
    Option0 = 0;
    Option1 = 1;
    Option2 = 2;
}
"""
TYPEX_PHASE25_CUSTOM_ARGS = {
    "1st (left-hand) rotor": "KHWENRCBISXJQGOFMAPVYZDLTU<BFHNQUW",
    "1st rotor reversed": True,
    "1st rotor ring setting": "B",
    "1st rotor initial value": "C",
    "2nd rotor": "BYPDZMGIKQCUSATREHOJNLFWXV<BFHNQUW",
    "2nd rotor reversed": False,
    "2nd rotor ring setting": "D",
    "2nd rotor initial value": "E",
    "3rd (middle) rotor": "ZANJCGDLVHIXOBRPMSWQUKFYET<BFHNQUW",
    "3rd rotor reversed": True,
    "3rd rotor ring setting": "F",
    "3rd rotor initial value": "G",
    "4th (static) rotor": "QXBGUTOVFCZPJIHSWERYNDAMLK<BFHNQUW",
    "4th rotor reversed": False,
    "4th rotor ring setting": "H",
    "4th rotor initial value": "I",
    "5th (right-hand, static) rotor": "BDCNWUEIQVFTSXALOGZJYMHKPR<BFHNQUW",
    "5th rotor reversed": True,
    "5th rotor ring setting": "J",
    "5th rotor initial value": "K",
    "Reflector": "AN BC FG IE KD LU MH OR TS VZ WQ XJ YP",
    "Plugboard": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "Typex keyboard emulation": "None",
    "Strict output": False,
}
CYBERCHEF_SAMPLE_EXIF_JPEG = (
    Path(__file__).resolve().parents[1] / "deps" / "CyberChef" / "tests" / "node" / "sampleData" / "pic.jpg"
).read_bytes()
MINIMAL_ELF64 = bytes.fromhex(
    "7f454c46"
    "02"
    "01"
    "01"
    "00"
    "00"
    "00000000000000"
    "0200"
    "3e00"
    "01000000"
    "0000000000000000"
    "0000000000000000"
    "0000000000000000"
    "00000000"
    "4000"
    "0000"
    "0000"
    "0000"
    "0000"
    "0000"
)
MINIMAL_ELF64_INFO_OUTPUT = (
    "============================== ELF Header ==============================\n"
    "Magic:                        \x7fELF\n"
    "Format:                       64-bit\n"
    "Endianness:                   Little\n"
    "Version:                      1\n"
    "ABI:                          System V\n"
    "ABI Version:                  0\n"
    "Type:                         Executable File\n"
    "Instruction Set Architecture: AMD x86-64\n"
    "ELF Version:                  1\n"
    "Entry Point:                  0x00\n"
    "Entry PHOFF:                  0x00\n"
    "Entry SHOFF:                  0x00\n"
    "Flags:                        00000000\n"
    "ELF Header Size:              64 bytes\n"
    "Program Header Size:          0 bytes\n"
    "Program Header Entries:       0\n"
    "Section Header Size:          0 bytes\n"
    "Section Header Entries:       0\n"
    "Section Header Names:         0\n\n"
    "============================== Program Header ==============================\n"
    "============================== Section Header ==============================\n"
    "============================== Symbol Table =============================="
)


def build_base45(value: bytes, alphabet: str = BASE45_ALPHABET) -> str:
    if not value:
        return ""

    encoded = []

    for index in range(0, len(value), 2):
        pair = value[index : index + 2]
        number = 0

        for element in pair:
            number = (number * 256) + element

        chars = 0
        while True:
            encoded.append(alphabet[number % 45])
            chars += 1
            number //= 45
            if number == 0:
                break

        if chars < 2:
            encoded.append("0")
            chars += 1

        if len(pair) > 1 and chars < 3:
            encoded.append("0")

    return "".join(encoded)


def build_expanded_alphabet(pattern: str) -> str:
    expanded = []
    index = 0

    while index < len(pattern):
        character = pattern[index]

        if character == "\\" and index + 1 < len(pattern):
            expanded.append(pattern[index + 1])
            index += 2
            continue

        if index + 2 < len(pattern) and pattern[index + 1] == "-":
            start = ord(character)
            end = ord(pattern[index + 2])
            step = 1 if start <= end else -1
            expanded.extend(chr(code_point) for code_point in range(start, end + step, step))
            index += 3
            continue

        expanded.append(character)
        index += 1

    return "".join(expanded)


def build_line_numbered_text(value: str, *, offset: int = 0) -> str:
    lines = value.split("\n")
    width = len(str(len(lines)))
    return "\n".join(
        f"{str(index + 1 + offset).rjust(width)} {line}" for index, line in enumerate(lines)
    )


def build_alternating_caps(value: str) -> str:
    output = []
    previous_caps = True

    for character in value:
        if not character.isalpha():
            output.append(character)
        elif previous_caps:
            output.append(character.lower())
            previous_caps = False
        else:
            output.append(character.upper())
            previous_caps = True

    return "".join(output)


def build_base58(value: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    if not value:
        return ""

    leading_zero_count = len(value) - len(value.lstrip(b"\x00"))
    number = int.from_bytes(value, byteorder="big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded

    return (alphabet[0] * leading_zero_count) + encoded


def build_base58_bitcoin(value: bytes) -> str:
    return build_base58(value, BASE58_ALPHABET)


def build_base62(value: bytes, alphabet: str = BASE62_ALPHABET) -> str:
    if not value:
        return ""

    number = int.from_bytes(value, byteorder="big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 62)
        encoded = alphabet[remainder] + encoded

    return encoded or alphabet[0]


def build_base_string(value: int, radix: int) -> str:
    if value == 0:
        return "0"

    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    encoded = ""

    while value:
        value, remainder = divmod(value, radix)
        encoded = digits[remainder] + encoded

    return encoded


def build_base92_character(value: int) -> str:
    if value == 0:
        return "!"

    if value <= 61:
        return chr(ord("#") + value - 1)

    return chr(ord("a") + value - 62)


def build_base92(value: bytes) -> str:
    encoded = []
    bit_string = ""
    remaining = bytes(value)

    while remaining:
        while len(bit_string) < 13 and remaining:
            bit_string += format(remaining[0], "08b")
            remaining = remaining[1:]

        if len(bit_string) < 13:
            break

        number = int(bit_string[:13], 2)
        encoded.append(build_base92_character(number // 91))
        encoded.append(build_base92_character(number % 91))
        bit_string = bit_string[13:]

    if bit_string:
        if len(bit_string) < 7:
            bit_string = bit_string.ljust(6, "0")
            encoded.append(build_base92_character(int(bit_string, 2)))
        else:
            bit_string = bit_string.ljust(13, "0")
            number = int(bit_string[:13], 2)
            encoded.append(build_base92_character(number // 91))
            encoded.append(build_base92_character(number % 91))

    return "".join(encoded)


def build_base64_with_alphabet(value: bytes, alphabet: str) -> str:
    expanded_alphabet = build_expanded_alphabet(alphabet)
    encoded = base64.b64encode(value).decode()
    translated = encoded.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            expanded_alphabet[:64],
        )
    )

    if len(expanded_alphabet) == 64:
        return translated.rstrip("=")

    return translated.replace("=", expanded_alphabet[64])


def build_png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + chunk_type
        + data
        + struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    )


def build_png_rgba_bytes(rows: list[list[tuple[int, int, int, int]]]) -> bytes:
    height = len(rows)
    width = len(rows[0]) if rows else 0
    raw = b"".join(b"\x00" + bytes(channel for pixel in row for channel in pixel) for row in rows)
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + build_png_chunk(b"IHDR", header)
        + build_png_chunk(b"IDAT", zlib.compress(raw))
        + build_png_chunk(b"IEND", b"")
    )


def build_extract_rgba_text(rows: list[list[tuple[int, int, int, int]]]) -> str:
    return ",".join(str(channel) for row in rows for pixel in row for channel in pixel)


def build_randomized_palette_rgba_text(
    rows: list[list[tuple[int, int, int, int]]],
    *,
    seed: str,
) -> str:
    output = []

    for row in rows:
        for red, green, blue, _ in row:
            hash_prefix = hashlib.md5(f"{seed}{red}.{green}.{blue}".encode()).hexdigest()[:6]
            output.extend(str(int(hash_prefix[index : index + 2], 16)) for index in range(0, 6, 2))
            output.append("255")

    return ",".join(output)


FORENSICS_RGBA_ROWS = [[(0, 255, 0, 255), (255, 0, 255, 0)]]
FORENSICS_RGBA_PNG = build_png_rgba_bytes(FORENSICS_RGBA_ROWS)
FORENSICS_LSB_PNG = build_png_rgba_bytes([[(int(bit), 0, 0, 255) for bit in "01000001"]])
FORENSICS_EMBEDDED_PNG_SAMPLE = b"ABCD" + build_png_rgba_bytes([[(1, 2, 3, 255)]]) + b"XYZ"
MULTIMEDIA_SOURCE_ROWS = [
    [(255, 0, 0, 255), (0, 255, 0, 255)],
    [(0, 0, 255, 255), (255, 255, 255, 255)],
]
MULTIMEDIA_SOURCE_PNG = build_png_rgba_bytes(MULTIMEDIA_SOURCE_ROWS)
MULTIMEDIA_AUTOCROP_PNG = build_png_rgba_bytes(
    [
        [(0, 0, 0, 255), (0, 0, 0, 255), (0, 0, 0, 255)],
        [(0, 0, 0, 255), (255, 0, 0, 255), (0, 0, 0, 255)],
        [(0, 0, 0, 255), (0, 0, 0, 255), (0, 0, 0, 255)],
    ]
)
MULTIMEDIA_NORMALISE_SOURCE_ROWS = [
    [(10, 20, 30, 255), (110, 120, 130, 255)],
    [(210, 220, 230, 255), (60, 70, 80, 255)],
]
MULTIMEDIA_NORMALISE_SOURCE_PNG = build_png_rgba_bytes(MULTIMEDIA_NORMALISE_SOURCE_ROWS)
MINIMAL_WAV = bytes.fromhex("524946462800000057415645666d74201000000001000100401f0000401f000001000800646174610400000080817f80")


def assert_heatmap_chart_with_headers(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("<svg ")
    assert 'class="bins"' in result
    assert 'stroke="rgba(0, 0, 0, 0.5)"' in result
    assert ">x</text>" in result
    assert ">y</text>" in result
    assert "Count: 2" in result
    assert "Count: 1" in result


def assert_heatmap_chart_with_custom_labels(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("<svg ")
    assert 'class="bins"' in result
    assert 'stroke="none"' in result
    assert ">X value</text>" in result
    assert ">Y value</text>" in result
    assert "Count: 2" in result
    assert "Count: 1" in result


def assert_hex_density_chart_with_headers_and_empty_hexagons(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("<svg ")
    assert 'class="hexagon"' in result
    assert 'class="empty-hexagon"' in result
    assert 'stroke="black"' in result
    assert ">x</text>" in result
    assert ">y</text>" in result
    assert "Count: 0" in result
    assert "Count: 3" in result


def assert_scatter_chart_with_headers(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("<svg ")
    assert 'class="points"' in result
    assert result.count("<circle") == 3
    assert 'fill="black"' in result
    assert 'r="10"' in result
    assert '>x</text>' in result
    assert '>y</text>' in result
    assert 'X: 0' in result
    assert 'Y: 2' in result


def assert_scatter_chart_with_input_colours(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("<svg ")
    assert 'class="points"' in result
    assert result.count("<circle") == 2
    assert 'fill="red"' in result
    assert 'fill="blue"' in result
    assert 'r="5"' in result
    assert '>Horizontal</text>' in result
    assert '>Vertical</text>' in result
    assert 'fill="green"' not in result


def assert_series_chart_with_custom_colours(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("<svg ")
    assert result.count("<circle") == 6
    assert result.count("<rect") == 3
    assert 'stroke="red"' in result
    assert 'stroke="blue"' in result
    assert 'fill="red"' in result
    assert 'fill="blue"' in result
    assert 'r="3"' in result
    assert '>Time</text>' in result
    assert '>temp</text>' in result
    assert '>humidity</text>' in result
    assert 'temp: 10' in result
    assert 'humidity: 30' in result


def assert_split_colour_channels_files(result: object) -> None:
    assert isinstance(result, list)
    assert [item["name"] for item in result] == ["red.png", "green.png", "blue.png"]
    assert all(item["type"] == "image/png" for item in result)
    expected_channels = {
        "red.png": build_extract_rgba_text(
            [
                [(255, 0, 0, 255), (0, 0, 0, 255)],
                [(0, 0, 0, 255), (255, 0, 0, 255)],
            ]
        ),
        "green.png": build_extract_rgba_text(
            [
                [(0, 0, 0, 255), (0, 255, 0, 255)],
                [(0, 0, 0, 255), (0, 255, 0, 255)],
            ]
        ),
        "blue.png": build_extract_rgba_text(
            [
                [(0, 0, 0, 255), (0, 0, 0, 255)],
                [(0, 0, 255, 255), (0, 0, 255, 255)],
            ]
        ),
    }
    for item in result:
        assert item["data"]
        assert bake(item["data"], ["Extract RGBA"]) == expected_channels[item["name"]]


def get_delimiter_text(name: str) -> str:
    return {
        "Space": " ",
        "Comma": ",",
        "Semi-colon": ";",
        "Colon": ":",
        "Line feed": "\n",
        "CRLF": "\r\n",
        "None": "",
    }[name]


def build_a1z26_encode_string(value: str, delimiter: str) -> str:
    separator = get_delimiter_text(delimiter)
    encoded = []

    for character in value.lower():
        if "a" <= character <= "z":
            encoded.append(str(ord(character) - 96))

    return separator.join(encoded)


def build_a1z26_decode_string(value: str, delimiter: str) -> str:
    if not value:
        return ""

    separator = get_delimiter_text(delimiter)
    return "".join(chr(int(part) + 96) for part in value.split(separator))


def build_affine_encode_string(value: str, *, a: int, b: int) -> str:
    result = []

    for character in value:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            offset = ord(character.lower()) - ord("a")
            result.append(chr((((a * offset) + b) % 26) + base))
            continue

        result.append(character)

    return "".join(result)


def build_affine_decode_string(value: str, *, a: int, b: int) -> str:
    inverse = pow(a, -1, 26)
    result = []

    for character in value:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            offset = ord(character.lower()) - ord("a")
            result.append(chr((inverse * (offset - b) % 26) + base))
            continue

        result.append(character)

    return "".join(result)


def build_atbash_string(value: str) -> str:
    return build_affine_encode_string(value, a=25, b=25)


def build_vigenere_encode_string(value: str, *, key: str) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    key_lower = key.lower()
    output = []
    skipped = 0

    for index, character in enumerate(value):
        lower_character = character.lower()
        if lower_character not in alphabet:
            output.append(character)
            skipped += 1
            continue

        key_character = key_lower[(index - skipped) % len(key_lower)]
        key_index = alphabet.index(key_character)
        message_index = alphabet.index(lower_character)
        encoded = alphabet[(key_index + message_index) % 26]
        output.append(encoded.upper() if character.isupper() else encoded)

    return "".join(output)


def build_vigenere_decode_string(value: str, *, key: str) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    key_lower = key.lower()
    output = []
    skipped = 0

    for index, character in enumerate(value):
        lower_character = character.lower()
        if lower_character not in alphabet:
            output.append(character)
            skipped += 1
            continue

        key_character = key_lower[(index - skipped) % len(key_lower)]
        key_index = alphabet.index(key_character)
        message_index = alphabet.index(lower_character)
        decoded = alphabet[(message_index - key_index + len(alphabet)) % len(alphabet)]
        output.append(decoded.upper() if character.isupper() else decoded)

    return "".join(output)


def build_bacon_encode_string(
    value: str,
    *,
    alphabet: str,
    translation: str,
    keep_extra_characters: bool,
    invert_translation: bool,
) -> str:
    output = []

    for character in value:
        uppercase_character = character.upper()
        if "A" <= uppercase_character <= "Z":
            letter = uppercase_character
            if alphabet == "Standard (I=J and U=V)":
                letter = {"J": "I", "V": "U"}.get(letter, letter)
                code = "ABCDEFGHIKLMNOPQRSTUWXYZ".index(letter)
            else:
                code = ord(letter) - ord("A")
            output.append(format(code, "05b"))
            continue

        output.append(character)

    result = "".join(output)

    if invert_translation:
        result = result.translate(str.maketrans({"0": "1", "1": "0"}))

    if not keep_extra_characters:
        digits = re.sub(r"[^01]", "", result)
        result = " ".join(
            digits[index : index + 5]
            for index in range(0, len(digits), 5)
            if len(digits[index : index + 5]) == 5
        )

    if translation == "A/B":
        result = result.translate(str.maketrans({"0": "A", "1": "B"}))

    return result


def build_bacon_decode_string(
    value: str,
    *,
    alphabet: str,
    translation: str,
    invert_translation: bool,
) -> str:
    if translation == "0/1":
        digits = re.sub(r"[^01]", "", value)
    elif translation == "A/B":
        digits = re.sub(r"[^ABab]", "", value).translate(
            str.maketrans({"A": "0", "B": "1", "a": "0", "b": "1"})
        )
    elif translation == "Case":
        letters = re.sub(r"[^A-Za-z]", "", value)
        digits = "".join("1" if character.isupper() else "0" for character in letters)
    elif translation == "A-M/N-Z first letter":
        digits = "".join(
            "1" if word[0].upper() >= "N" else "0"
            for word in value.split()
            if word
        )
    else:
        raise ValueError(f"Unsupported Bacon translation: {translation}")

    if invert_translation:
        digits = digits.translate(str.maketrans({"0": "1", "1": "0"}))

    if alphabet == "Standard (I=J and U=V)":
        output_alphabet = "ABCDEFGHIKLMNOPQRSTUWXYZ"
    else:
        output_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    result = []
    for index in range(0, len(digits), 5):
        group = digits[index : index + 5]
        if len(group) < 5:
            continue
        decoded_index = int(group, 2)
        if decoded_index < len(output_alphabet):
            result.append(output_alphabet[decoded_index])
        else:
            result.append("?")

    return "".join(result)


def build_polybius_square(keyword: str) -> list[list[str]]:
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    combined = f"{keyword.upper().replace('J', 'I')}{alpha}"
    unique_characters = []

    for character in combined:
        if character not in unique_characters:
            unique_characters.append(character)

    return [unique_characters[index : index + 5] for index in range(0, 25, 5)]


def build_bifid_encode_string(value: str, *, keyword: str) -> str:
    polybius = build_polybius_square(keyword)
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    x_coordinates = []
    y_coordinates = []
    structure: list[bool | str] = []

    for character in value.replace("J", "I"):
        uppercase_character = character.upper()
        if uppercase_character in alpha:
            for row_index, row in enumerate(polybius):
                if uppercase_character in row:
                    x_coordinates.append(row.index(uppercase_character))
                    y_coordinates.append(row_index)
                    break
            structure.append(character in alpha)
            continue

        structure.append(character)

    transposed = f"{''.join(str(value) for value in y_coordinates)}{''.join(str(value) for value in x_coordinates)}"
    output = []
    count = 0

    for position in structure:
        if isinstance(position, bool):
            row_index = int(transposed[2 * count])
            column_index = int(transposed[(2 * count) + 1])
            character = polybius[row_index][column_index]
            output.append(character if position else character.lower())
            count += 1
            continue

        output.append(position)

    return "".join(output)


def build_bifid_decode_string(value: str, *, keyword: str) -> str:
    polybius = build_polybius_square(keyword)
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    structure: list[bool | str] = []
    transposed = ""

    for character in value.replace("J", "I"):
        uppercase_character = character.upper()
        if uppercase_character in alpha:
            for row_index, row in enumerate(polybius):
                if uppercase_character in row:
                    transposed += f"{row_index}{row.index(uppercase_character)}"
                    break
            structure.append(character in alpha)
            continue

        structure.append(character)

    output = []
    count = 0
    half_length = len(transposed) // 2

    for position in structure:
        if isinstance(position, bool):
            row_index = int(transposed[count])
            column_index = int(transposed[count + half_length])
            character = polybius[row_index][column_index]
            output.append(character if position else character.lower())
            count += 1
            continue

        output.append(position)

    return "".join(output)


def build_caesar_box_string(value: str, box_height: int) -> str:
    if not value:
        return ""

    table_width = -(-len(value) // box_height)
    normalized = value.replace(" ", "")
    normalized += "\x00" * ((box_height * table_width) - len(normalized))
    result = []

    for row_index in range(box_height):
        for column_index in range(row_index, len(normalized), box_height):
            if normalized[column_index] != "\x00":
                result.append(normalized[column_index])

    return "".join(result)


def build_cetacean_encode_string(value: str) -> str:
    return "".join(
        " " if character == " " else format(ord(character), "016b").translate(str.maketrans({"0": "E", "1": "e"}))
        for character in value
    )


def build_cetacean_decode_string(value: str) -> str:
    bits = []

    for character in value:
        if character == " ":
            bits.extend("0000000000100000")
            continue
        bits.append("1" if character == "e" else "0")

    return "".join(
        chr(int("".join(bits[index : index + 16]), 2))
        for index in range(0, len(bits), 16)
    )


def build_ciphersaber2_bytes(temp_ivp: bytes, key: bytes, rounds: int, input_data: bytes) -> bytes:
    ivp = list(key + temp_ivp)
    state = list(range(256))
    j = 0

    for _ in range(rounds):
        for index in range(256):
            j = (j + state[index] + ivp[index % len(ivp)]) % 256
            state[index], state[j] = state[j], state[index]

    j = 0
    i = 0
    result = bytearray()

    for value in input_data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        result.append(state[(state[i] + state[j]) % 256] ^ value)

    return bytes(result)


def build_rc4_bytes(data: bytes, key: bytes, *, drop_dwords: int = 0) -> bytes:
    state = list(range(256))
    j = 0

    for index in range(256):
        j = (j + state[index] + key[index % len(key)]) % 256
        state[index], state[j] = state[j], state[index]

    i = 0
    j = 0

    for _ in range(drop_dwords * 4):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]

    result = bytearray()

    for value in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        result.append(value ^ state[(state[i] + state[j]) % 256])

    return bytes(result)


def build_rot13_bytes(
    data: bytes,
    *,
    rotate_lower_case_chars: bool = True,
    rotate_upper_case_chars: bool = True,
    rotate_numbers: bool = False,
    amount: int = 13,
) -> bytes:
    result = bytearray(data)
    amount_numbers = amount

    if amount < 0:
        amount = 26 - (abs(amount) % 26)
        amount_numbers = 10 - (abs(amount_numbers) % 10)

    for index, value in enumerate(result):
        if rotate_upper_case_chars and 65 <= value <= 90:
            result[index] = ((value - 65 + amount) % 26) + 65
        elif rotate_lower_case_chars and 97 <= value <= 122:
            result[index] = ((value - 97 + amount) % 26) + 97
        elif rotate_numbers and 48 <= value <= 57:
            result[index] = ((value - 48 + amount_numbers) % 10) + 48

    return bytes(result)


def build_escaped_whitespace_string(value: str) -> str:
    return "".join(chr(0xE000 + ord(character)) if 9 <= ord(character) <= 16 else character for character in value)


def build_rot13_brute_force_string(
    data: bytes,
    *,
    rotate_lower_case_chars: bool = True,
    rotate_upper_case_chars: bool = True,
    rotate_numbers: bool = False,
    sample_length: int = 100,
    sample_offset: int = 0,
    print_amount: bool = True,
    crib: str = "",
) -> str:
    sample = data[sample_offset : sample_offset + sample_length]
    crib_lower = crib.lower()
    result = []

    for amount in range(1, 26):
        rotated = build_rot13_bytes(
            sample,
            rotate_lower_case_chars=rotate_lower_case_chars,
            rotate_upper_case_chars=rotate_upper_case_chars,
            rotate_numbers=rotate_numbers,
            amount=amount,
        ).decode()
        if crib_lower in rotated.lower():
            escaped = build_escaped_whitespace_string(rotated)
            result.append(f"Amount = {amount:2d}: {escaped}" if print_amount else escaped)

    return "\n".join(result)


def build_rot47_bytes(data: bytes, *, amount: int = 47) -> bytes:
    result = bytearray(data)

    if amount < 0:
        amount = 94 - (abs(amount) % 94)

    for index, value in enumerate(result):
        if 33 <= value <= 126:
            result[index] = ((value - 33 + amount) % 94) + 33

    return bytes(result)


def build_rot47_brute_force_string(
    data: bytes,
    *,
    sample_length: int = 100,
    sample_offset: int = 0,
    print_amount: bool = True,
    crib: str = "",
) -> str:
    sample = data[sample_offset : sample_offset + sample_length]
    crib_lower = crib.lower()
    result = []

    for amount in range(1, 94):
        rotated = build_rot47_bytes(sample, amount=amount).decode()
        if crib_lower in rotated.lower():
            escaped = build_escaped_whitespace_string(rotated)
            result.append(f"Amount = {amount:2d}: {escaped}" if print_amount else escaped)

    return "\n".join(result)


def build_rail_fence_encode_string(value: str, *, key: int, offset: int) -> str:
    cycle = (key - 1) * 2
    rows = [""] * key

    for position, character in enumerate(value):
        row_index = key - 1 - abs((cycle // 2) - ((position + offset) % cycle))
        rows[row_index] += character

    return "".join(rows)


def build_rail_fence_decode_string(value: str, *, key: int, offset: int) -> str:
    cycle = (key - 1) * 2
    plaintext = [""] * len(value)
    cipher_index = 0

    for row_index in range(key):
        for column_index in range(len(value)):
            if ((row_index + column_index + offset) % cycle == 0) or (
                (row_index - column_index - offset) % cycle == 0
            ):
                plaintext[column_index] = value[cipher_index]
                cipher_index += 1

    return "".join(plaintext)


def build_citrix_ctx1_bytes(value: str) -> bytes:
    result = bytearray()
    temp = 0

    for byte in value.encode("utf-16le"):
        temp = byte ^ 0xA5 ^ temp
        result.append(((temp >> 4) & 0xF) + 0x41)
        result.append((temp & 0xF) + 0x41)

    return bytes(result)


def build_citrix_ctx1_string(value: bytes) -> str:
    if len(value) % 4 != 0:
        raise ValueError("Incorrect hash length")

    reversed_value = bytearray(value)
    reversed_value.reverse()
    result = bytearray()
    temp = 0

    for index in range(0, len(reversed_value), 2):
        if index + 2 >= len(reversed_value):
            temp = 0
        else:
            temp = ((reversed_value[index + 2] - 0x41) & 0xF) ^ (
                ((reversed_value[index + 3] - 0x41) << 4) & 0xF0
            )

        temp = (
            ((reversed_value[index] - 0x41) & 0xF)
            ^ (((reversed_value[index + 1] - 0x41) << 4) & 0xF0)
            ^ 0xA5
            ^ temp
        )
        result.append(temp)

    result.reverse()
    return bytes(result).decode("utf-16le")


def build_evp_key_hex(
    passphrase: bytes,
    salt: bytes,
    *,
    key_size_bits: int,
    iterations: int,
    hash_name: str,
) -> str:
    key_size_bytes = key_size_bits // 8
    derived = b""
    block = b""
    algorithm = hash_name.lower()

    while len(derived) < key_size_bytes:
        block = hashlib.new(algorithm, block + passphrase + salt).digest()

        for _ in range(iterations - 1):
            block = hashlib.new(algorithm, block).digest()

        derived += block

    return derived[:key_size_bytes].hex()


def build_hkdf_hex(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    *,
    length: int,
    hash_name: str,
    extract_mode: str,
) -> str:
    algorithm = hash_name.lower().replace("/", "")
    hash_length = hashlib.new(algorithm).digest_size

    if extract_mode == "skip":
        pseudo_random_key = ikm
    else:
        effective_salt = salt if extract_mode == "with salt" else b"\x00" * hash_length
        pseudo_random_key = hmac.new(effective_salt, ikm, algorithm).digest()

    output_key_material = b""
    block = b""
    counter = 1

    while len(output_key_material) < length:
        block = hmac.new(pseudo_random_key, block + info + bytes([counter]), algorithm).digest()
        output_key_material += block
        counter += 1

    return output_key_material[:length].hex()


def build_colossus_args(program_to_run: str) -> dict[str, object]:
    return {
        "Input": "",
        "Pattern": "KH Pattern",
        "QBusZ": "",
        "QBusΧ": "",
        "QBusΨ": "",
        "Limitation": "None",
        "K Rack Option": "Select Program",
        "Program to run": program_to_run,
        "K Rack: Conditional": "",
        "R1-Q1": "",
        "R1-Q2": "",
        "R1-Q3": "",
        "R1-Q4": "",
        "R1-Q5": "",
        "R1-Negate": False,
        "R1-Counter": "",
        "R2-Q1": "",
        "R2-Q2": "",
        "R2-Q3": "",
        "R2-Q4": "",
        "R2-Q5": "",
        "R2-Negate": False,
        "R2-Counter": "",
        "R3-Q1": "",
        "R3-Q2": "",
        "R3-Q3": "",
        "R3-Q4": "",
        "R3-Q5": "",
        "R3-Negate": False,
        "R3-Counter": "",
        "Negate All": False,
        "K Rack: Addition": "",
        "Add-Q1": False,
        "Add-Q2": False,
        "Add-Q3": False,
        "Add-Q4": False,
        "Add-Q5": False,
        "Add-Equals": "",
        "Add-Counter1": False,
        "Add Negate All": False,
        "Total Motor": "",
        "Master Control Panel": "",
        "Set Total": 0,
        "Fast Step": "",
        "Slow Step": "",
        "Start Χ1": 1,
        "Start Χ2": 1,
        "Start Χ3": 1,
        "Start Χ4": 1,
        "Start Χ5": 1,
        "Start M61": 1,
        "Start M37": 1,
        "Start Ψ1": 1,
        "Start Ψ2": 1,
        "Start Ψ3": 1,
        "Start Ψ4": 1,
        "Start Ψ5": 1,
    }


def build_enigma_four_rotor_args() -> dict[str, object]:
    return {
        "Model": "4-rotor",
        "Left-most (4th) rotor": "FSOKANUERHMBTIYCWLQPZXVGJD",
        "Left-most rotor ring setting": "B",
        "Left-most rotor initial value": "D",
        "Left-hand rotor": "ESOVPZJAYQUIRHXLNFTGKDCMWB<K",
        "Left-hand rotor ring setting": "C",
        "Left-hand rotor initial value": "M",
        "Middle rotor": "VZBRGITYUPSDNHLXAWMJQOFECK<A",
        "Middle rotor ring setting": "D",
        "Middle rotor initial value": "C",
        "Right-hand rotor": "BDFHJLCPRTXVZNYEIWGAKMUSQO<W",
        "Right-hand rotor ring setting": "E",
        "Right-hand rotor initial value": "K",
        "Reflector": "AE BN CK DQ FU GY HW IJ LO MP RX SZ TV",
        "Plugboard": "PO ML IU KJ NH YT GB VF RE DC",
        "Strict output": False,
    }


def build_fernet_encrypt_verifier(expected_plaintext: str) -> Callable[[object], None]:
    def verify(result: object) -> None:
        assert isinstance(result, str)
        assert re.fullmatch(r"gAAAAA[A-Za-z0-9_-]+=*", result)
        assert bake(result, [{"op": "Fernet Decrypt", "args": {"Key": FERNET_TEST_KEY}}]) == expected_plaintext

    return verify


def build_gost_cipher_args(
    *,
    key_hex: str,
    algorithm: str,
    input_type: str,
    output_type: str,
    iv_hex: str = "",
    s_box: str | None = None,
    block_mode: str = "ECB",
    key_meshing_mode: str = "NO",
    padding: str = "NO",
) -> dict[str, object]:
    args: dict[str, object] = {
        "Key": {"string": key_hex, "option": "Hex"},
        "IV": {"string": iv_hex, "option": "Hex"},
        "Input type": input_type,
        "Output type": output_type,
        "Algorithm": algorithm,
        "Block mode": block_mode,
        "Key meshing mode": key_meshing_mode,
        "Padding": padding,
    }

    if s_box is not None:
        args["sBox"] = s_box

    return args


def build_gost_key_wrap_args(
    *,
    key_hex: str,
    ukm_hex: str,
    algorithm: str,
    input_type: str,
    output_type: str,
    s_box: str | None = None,
    key_wrapping: str = "NO",
) -> dict[str, object]:
    args: dict[str, object] = {
        "Key": {"string": key_hex, "option": "Hex"},
        "User Key Material": {"string": ukm_hex, "option": "Hex"},
        "Input type": input_type,
        "Output type": output_type,
        "Algorithm": algorithm,
        "Key wrapping": key_wrapping,
    }

    if s_box is not None:
        args["sBox"] = s_box

    return args


def build_gost_mac_args(
    *,
    key_hex: str,
    algorithm: str,
    input_type: str,
    iv_hex: str = "",
    s_box: str | None = None,
    output_type: str | None = None,
    mac_length: int | None = None,
    mac_hex: str | None = None,
) -> dict[str, object]:
    args: dict[str, object] = {
        "Key": {"string": key_hex, "option": "Hex"},
        "IV": {"string": iv_hex, "option": "Hex"},
        "Input type": input_type,
        "Algorithm": algorithm,
    }

    if output_type is not None:
        args["Output type"] = output_type

    if mac_length is not None:
        args["MAC length"] = mac_length

    if mac_hex is not None:
        args["MAC"] = {"string": mac_hex, "option": "Hex"}

    if s_box is not None:
        args["sBox"] = s_box

    return args


def build_salsa20_args(
    *,
    key_string: str,
    key_option: str,
    nonce_string: str,
    nonce_option: str,
    counter: int,
    rounds: str,
    input_type: str,
    output_type: str,
) -> dict[str, object]:
    return {
        "Key": {"string": key_string, "option": key_option},
        "Nonce": {"string": nonce_string, "option": nonce_option},
        "Counter": counter,
        "Rounds": rounds,
        "Input": input_type,
        "Output": output_type,
    }


def build_sm4_args(
    *,
    key_string: str,
    key_option: str,
    mode: str,
    input_type: str,
    output_type: str,
    iv_string: str = "",
    iv_option: str = "Hex",
) -> dict[str, object]:
    return {
        "Key": {"string": key_string, "option": key_option},
        "IV": {"string": iv_string, "option": iv_option},
        "Mode": mode,
        "Input": input_type,
        "Output": output_type,
    }


def build_triple_des_args(
    *,
    key_string: str,
    key_option: str,
    mode: str,
    input_type: str,
    output_type: str,
    iv_string: str = "",
    iv_option: str = "Hex",
) -> dict[str, object]:
    return {
        "Key": {"string": key_string, "option": key_option},
        "IV": {"string": iv_string, "option": iv_option},
        "Mode": mode,
        "Input": input_type,
        "Output": output_type,
    }


def build_xxtea_words(data: bytes, *, include_length: bool) -> list[int]:
    length = len(data)
    word_count = length >> 2
    if length & 3:
        word_count += 1

    words = [0] * (word_count + 1 if include_length else word_count)
    if include_length:
        words[word_count] = length

    for index, value in enumerate(data):
        words[index >> 2] |= value << ((index & 3) << 3)

    return words


def build_xxtea_bytes(words: list[int], *, include_length: bool) -> bytes:
    length = len(words)
    byte_count = length << 2

    if include_length:
        message_length = words[-1]
        byte_count -= 4
        if message_length < byte_count - 3 or message_length > byte_count:
            raise ValueError("Invalid XXTEA message length")
        byte_count = message_length

    return bytes((words[index >> 2] >> ((index & 3) << 3)) & 0xFF for index in range(byte_count))


def build_xxtea_mix(sum_value: int, y: int, z: int, position: int, e_value: int, key_words: list[int]) -> int:
    return (
        ((z >> 5 ^ (y << 2)) + (y >> 3 ^ (z << 4)))
        ^ ((sum_value ^ y) + (key_words[(position & 3) ^ e_value] ^ z))
    )


def build_xxtea_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    if not data:
        return data

    key_bytes = key[:16].ljust(16, b"\x00")
    words = build_xxtea_words(data, include_length=True)
    key_words = build_xxtea_words(key_bytes, include_length=False)
    delta = 0x9E3779B9
    word_count = len(words)
    last_index = word_count - 1
    z_value = words[last_index]
    sum_value = 0

    for _ in range((6 + (52 // word_count))):
        sum_value = (sum_value + delta) & 0xFFFFFFFF
        e_value = (sum_value >> 2) & 3

        for position in range(last_index):
            y_value = words[position + 1]
            words[position] = (words[position] + build_xxtea_mix(sum_value, y_value, z_value, position, e_value, key_words)) & 0xFFFFFFFF
            z_value = words[position]

        y_value = words[0]
        words[last_index] = (
            words[last_index] + build_xxtea_mix(sum_value, y_value, z_value, last_index, e_value, key_words)
        ) & 0xFFFFFFFF
        z_value = words[last_index]

    return build_xxtea_bytes(words, include_length=False)


def build_xxtea_decrypt_bytes(data: bytes, key: bytes) -> bytes:
    if not data:
        return data

    key_bytes = key[:16].ljust(16, b"\x00")
    words = build_xxtea_words(data, include_length=False)
    key_words = build_xxtea_words(key_bytes, include_length=False)
    delta = 0x9E3779B9
    word_count = len(words)
    last_index = word_count - 1
    y_value = words[0]
    rounds = 6 + (52 // word_count)
    sum_value = (rounds * delta) & 0xFFFFFFFF

    while sum_value:
        e_value = (sum_value >> 2) & 3

        for position in range(last_index, 0, -1):
            z_value = words[position - 1]
            words[position] = (
                words[position] - build_xxtea_mix(sum_value, y_value, z_value, position, e_value, key_words)
            ) & 0xFFFFFFFF
            y_value = words[position]

        z_value = words[last_index]
        words[0] = (words[0] - build_xxtea_mix(sum_value, y_value, z_value, 0, e_value, key_words)) & 0xFFFFFFFF
        y_value = words[0]
        sum_value = (sum_value - delta) & 0xFFFFFFFF

    return build_xxtea_bytes(words, include_length=True)


def build_base64url_text(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def build_jwt_hs256_token(payload: dict[str, object], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = build_base64url_text(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = build_base64url_text(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{build_base64url_text(signature)}"


def build_multiple_bombe_args() -> dict[str, object]:
    return {
        "Standard Enigmas": "User defined",
        "Main rotors": (
            "EKMFLGDQVZNTOWYHXUSPAIBRCJ<R\n"
            "AJDKSIRUXBLHWTMCQGZNPYFVOE<F\n"
            "BDFHJLCPRTXVZNYEIWGAKMUSQO<W"
        ),
        "4th rotor": "",
        "Reflectors": "AY BR CU DH EQ FS GL IP JX KN MO TZ VW",
        "Crib": "BBBB",
        "Crib offset": 0,
        "Use checking machine": True,
    }


def build_murmurhash3(value: str, seed: int = 0, *, signed: bool = False) -> int:
    remainder = len(value) & 3
    byte_count = len(value) - remainder
    hash_value = seed
    constant_one = 0xCC9E2D51
    constant_two = 0x1B873593
    index = 0

    while index < byte_count:
        block = (
            (ord(value[index]) & 0xFF)
            | ((ord(value[index + 1]) & 0xFF) << 8)
            | ((ord(value[index + 2]) & 0xFF) << 16)
            | ((ord(value[index + 3]) & 0xFF) << 24)
        )
        index += 4

        block = ((block & 0xFFFF) * constant_one + ((((block >> 16) * constant_one) & 0xFFFF) << 16)) & 0xFFFFFFFF
        block = ((block << 15) | (block >> 17)) & 0xFFFFFFFF
        block = ((block & 0xFFFF) * constant_two + ((((block >> 16) * constant_two) & 0xFFFF) << 16)) & 0xFFFFFFFF

        hash_value ^= block
        hash_value = ((hash_value << 13) | (hash_value >> 19)) & 0xFFFFFFFF
        mixed = ((hash_value & 0xFFFF) * 5 + ((((hash_value >> 16) * 5) & 0xFFFF) << 16)) & 0xFFFFFFFF
        hash_value = ((mixed & 0xFFFF) + 0x6B64 + ((((mixed >> 16) + 0xE654) & 0xFFFF) << 16)) & 0xFFFFFFFF

    block = 0

    if remainder == 3:
        block ^= (ord(value[index + 2]) & 0xFF) << 16

    if remainder in {2, 3}:
        block ^= (ord(value[index + 1]) & 0xFF) << 8

    if remainder in {1, 2, 3}:
        block ^= ord(value[index]) & 0xFF
        block = ((block & 0xFFFF) * constant_one + ((((block >> 16) * constant_one) & 0xFFFF) << 16)) & 0xFFFFFFFF
        block = ((block << 15) | (block >> 17)) & 0xFFFFFFFF
        block = ((block & 0xFFFF) * constant_two + ((((block >> 16) * constant_two) & 0xFFFF) << 16)) & 0xFFFFFFFF
        hash_value ^= block

    hash_value ^= len(value)
    hash_value ^= hash_value >> 16
    hash_value = ((hash_value & 0xFFFF) * 0x85EBCA6B + ((((hash_value >> 16) * 0x85EBCA6B) & 0xFFFF) << 16)) & 0xFFFFFFFF
    hash_value ^= hash_value >> 13
    hash_value = ((hash_value & 0xFFFF) * 0xC2B2AE35 + ((((hash_value >> 16) * 0xC2B2AE35) & 0xFFFF) << 16)) & 0xFFFFFFFF
    hash_value ^= hash_value >> 16
    hash_value &= 0xFFFFFFFF

    if signed and hash_value & 0x80000000:
        return hash_value - 0x100000000

    return hash_value


def build_hash_analysis_output(input_value: str) -> str:
    normalized = re.sub(r"\s+", "", input_value)
    bit_length = len(normalized) * 4
    hash_functions = {
        4: ["Fletcher-4", "Luhn algorithm", "Verhoeff algorithm"],
        8: ["Fletcher-8"],
        16: ["BSD checksum", "CRC-16", "SYSV checksum", "Fletcher-16"],
        32: ["CRC-32", "Fletcher-32", "Adler-32"],
        64: ["CRC-64", "RIPEMD-64", "SipHash"],
        128: ["MD5", "MD4", "MD2", "HAVAL-128", "RIPEMD-128", "Snefru", "Tiger-128"],
        160: ["SHA-1", "SHA-0", "FSB-160", "HAS-160", "HAVAL-160", "RIPEMD-160", "Tiger-160"],
        192: ["Tiger", "HAVAL-192"],
        224: ["SHA-224", "SHA3-224", "ECOH-224", "FSB-224", "HAVAL-224"],
        256: [
            "SHA-256",
            "SHA3-256",
            "BLAKE-256",
            "ECOH-256",
            "FSB-256",
            "GOST",
            "Grøstl-256",
            "HAVAL-256",
            "PANAMA",
            "RIPEMD-256",
            "Snefru",
        ],
        320: ["RIPEMD-320"],
        384: ["SHA-384", "SHA3-384", "ECOH-384", "FSB-384"],
        512: [
            "SHA-512",
            "SHA3-512",
            "BLAKE-512",
            "ECOH-512",
            "FSB-512",
            "Grøstl-512",
            "JH",
            "MD6",
            "Spectral Hash",
            "SWIFFT",
            "Whirlpool",
        ],
        1024: ["Fowler-Noll-Vo"],
    }.get(bit_length, ["Unknown"])
    return (
        f"Hash length: {len(normalized)}\n"
        f"Byte length: {len(normalized) // 2}\n"
        f"Bit length:  {bit_length}\n\n"
        "Based on the length, this hash could have been generated by one of the following hashing functions:\n"
        + "\n".join(hash_functions)
    )


def parse_named_output(text: str) -> dict[str, str]:
    return {
        name: value.strip()
        for name, value in (line.split(":", 1) for line in text.strip().splitlines())
    }


def build_luhn_checksum(value: str, radix: int) -> int:
    total = 0
    should_double = False

    for character in reversed(value):
        digit = int(character, radix)
        if should_double:
            digit *= 2
            digit = (digit // radix) + (digit % radix)
        total += digit
        should_double = not should_double

    return total % radix


def build_luhn_checksum_output(value: str, radix: int) -> str:
    if not value:
        return ""

    checksum = build_base_string(build_luhn_checksum(value, radix), radix)
    check_digit = build_luhn_checksum(f"{value}0", radix)
    check_digit = 0 if check_digit == 0 else radix - check_digit
    check_digit_text = build_base_string(check_digit, radix)
    return f"Checksum: {checksum}\nCheckdigit: {check_digit_text}\nLuhn Validated String: {value}{check_digit_text}"


def verify_generate_all_checksums_16_named_output(result: object) -> None:
    assert isinstance(result, str)
    parsed = parse_named_output(result)
    assert len(parsed) == 60
    assert parsed["CRC-16"] == "bb3d"
    assert parsed["CRC-16/IBM-SDLC"] == "906e"
    assert parsed["CRC-16/MODBUS"] == "4b37"
    assert parsed["CRC-16/XMODEM"] == "31c3"
    assert parsed["Fletcher-16"] == "1ede"


def verify_generate_all_checksums_32_named_output(result: object) -> None:
    assert isinstance(result, str)
    parsed = parse_named_output(result)
    assert len(parsed) == 30
    assert parsed["Adler-32"] == "091e01de"
    assert parsed["CRC-32"] == "cbf43926"
    assert parsed["CRC-32/CASTAGNOLI"] == "e3069283"
    assert parsed["CRC-32/MPEG-2"] == "0376e6e7"
    assert parsed["Fletcher-32"] == "df09d509"


def verify_generate_all_hashes_128_named_output(result: object) -> None:
    assert isinstance(result, str)
    assert parse_named_output(result) == {
        "MD2": "dd34716876364a02d0195e2fb9ae2d1b",
        "MD4": "db346d691d7acc4dc2625db19f9e3f52",
        "MD5": "098f6bcd4621d373cade4e832627b4f6",
        "RIPEMD-128": "f1abb5083c9ff8a9dbbca9cd2b11fead",
        "BLAKE2b-128": "44a8995dd50b6657a037a7839304535b",
        "BLAKE2s-128": "e9ddd9926b9dcb382e09be39ba403d2c",
        "LM Hash": "01FC5A6BE7BC6929AAD3B435B51404EE",
        "NT Hash": "0CB6948805F797BF2A82807973B89537",
    }


def verify_generate_all_hashes_256_unnamed_output(result: object) -> None:
    assert isinstance(result, str)
    assert result.splitlines() == [
        "93c8a7d0ff132f325138a82b2baa98c12a7c9ac982feb6c5b310a1ca713615bd",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
        "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658",
        "d3b0aa9cd8b7255622cebc631e867d4093d6f6010191a53973c45fec9b07c774",
        "fe0289110d07daeee9d9500e14c57787d9083f6ba10e6bcb256f86bb4fe7b981",
        "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202",
        "f308fc02ce9172ad02a7d75800ecfc027109bc67987ea32aba9b8dcc7b10150e",
        "12a50838191b5504f1e5f2fd078714cf6b592b9d29af99d0b10d8d02881c3857",
        "ee67303696d205ddd2b2363e8e01b4b7199a80957d94d7678eaad3fc834c5a27",
    ]


def verify_bcrypt_rounds_four_hash(result: object) -> None:
    assert isinstance(result, str)
    assert re.fullmatch(r"\$2a\$04\$[./A-Za-z0-9]{53}", result)


def verify_bombe_default_crib_bbbb(result: object) -> None:
    assert isinstance(result, dict)
    assert result["nLoops"] == 3
    assert isinstance(result["result"], list)
    assert len(result["result"]) == 267
    assert result["result"][:5] == [
        ["AFVM", "??", "VOHX"],
        ["AKSV", "??", "YYKX"],
        ["AOUM", "??", "QNXS"],
        ["AQEA", "??", "SMIW"],
        ["AYCG", "??", "IGWB"],
    ]
    assert result["result"][50] == ["GIGF", "AA BJ", "BBBB"]
    assert result["result"][100] == ["LEJP", "??", "TPOG"]
    assert result["result"][150] == ["PSWK", "??", "SGVG"]
    assert result["result"][200] == ["UJAX", "??", "EHCN"]
    assert result["result"][-1] == ["ZUNM", "AS BB", "BBBB"]


def verify_multiple_bombe_user_defined_three_rotor(result: object) -> None:
    assert isinstance(result, dict)
    assert result["nLoops"] == 3
    assert isinstance(result["bombeRuns"], list)
    assert len(result["bombeRuns"]) == 6
    assert result["bombeRuns"][0] == {
        "rotors": [
            "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
            "AJDKSIRUXBLHWTMCQGZNPYFVOE",
            "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        ],
        "reflector": "AY BR CU DH EQ FS GL IP JX KN MO TZ VW",
        "result": [
            ["ALG", "??", "EWFG"],
            ["BWX", "??", "BXEQ"],
            ["ICZ", "AA BR", "BBBB"],
            ["LND", "??", "DCBP"],
            ["PTF", "AB", "BBBB"],
            ["SFG", "??", "RGEX"],
            ["ULI", "??", "QMDO"],
            ["UVI", "??", "SIBS"],
            ["UXR", "??", "DVLV"],
            ["YTV", "??", "TKMP"],
            ["ZAY", "??", "TFZG"],
            ["ZLZ", "??", "XTEB"],
        ],
    }
    assert result["bombeRuns"][-1]["result"][-1] == ["XXZ", "AU BB", "BBBB"]


def build_binary_string(value: bytes, delimiter: str, byte_length: int) -> str:
    separator = get_delimiter_text(delimiter)
    return separator.join(format(byte, "b").zfill(byte_length) for byte in value)


def build_braille(value: str) -> str:
    lookup = dict(zip(BRAILLE_ASCII, BRAILLE_DOT6, strict=True))
    return "".join(lookup.get(character.upper(), character) for character in value)


def build_charcode_string(value: str, delimiter: str, base: int) -> str:
    separator = get_delimiter_text(delimiter)
    encoded = []

    for ordinal in map(ord, value):
        if base == 16:
            if ordinal < 256:
                padding = 2
            elif ordinal < 65536:
                padding = 4
            elif ordinal < 16777216:
                padding = 6
            elif ordinal < 4294967296:
                padding = 8
            else:
                padding = 2
            encoded.append(format(ordinal, f"0{padding}x"))
            continue

        encoded.append(build_base_string(ordinal, base))

    return separator.join(encoded)


def build_decimal_string(value: bytes, delimiter: str, *, signed: bool) -> str:
    separator = get_delimiter_text(delimiter)
    if signed:
        numbers = [byte if byte < 128 else byte - 256 for byte in value]
    else:
        numbers = list(value)
    return separator.join(str(number) for number in numbers)


def build_swap_endianness_bytes(
    data: bytes,
    word_length: int,
    *,
    pad_incomplete_words: bool,
) -> bytes:
    swapped = bytearray()

    for index in range(0, len(data), word_length):
        chunk = data[index : index + word_length]

        if len(chunk) < word_length and pad_incomplete_words:
            chunk = chunk.ljust(word_length, b"\x00")

        swapped.extend(reversed(chunk))

    return bytes(swapped)


def build_xor_bytes(
    data: bytes,
    key: bytes,
    *,
    scheme: str = "Standard",
    null_preserving: bool = False,
) -> bytes:
    result = bytearray()
    effective_key = list(key or b"\x00")

    for index, value in enumerate(data):
        key_index = index % len(effective_key)
        key_value = effective_key[key_index]

        if scheme == "Cascade":
            key_value = data[index + 1] if index + 1 < len(data) else 0

        xored_value = value ^ key_value

        if null_preserving and (value == 0 or xored_value == 0):
            result.append(value)
            continue

        result.append(xored_value)

        if scheme == "Input differential":
            effective_key[key_index] = value
        elif scheme == "Output differential":
            effective_key[key_index] = xored_value

    return bytes(result)


def build_xor_checksum(data: bytes, blocksize: int) -> str:
    result = bytearray(blocksize)

    for index, value in enumerate(data):
        result[index % blocksize] ^= value

    return result.hex()


def build_add_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data

    return bytes((value + key[index % len(key)]) % 256 for index, value in enumerate(data))


def build_and_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(0 for _ in data)

    return bytes(value & key[index % len(key)] for index, value in enumerate(data))


def build_or_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data

    return bytes(value | key[index % len(key)] for index, value in enumerate(data))


def build_sub_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data

    return bytes((value - key[index % len(key)]) % 256 for index, value in enumerate(data))


def build_left_shift_bytes(data: bytes, amount: int) -> bytes:
    return bytes((value << amount) & 0xFF for value in data)


def build_right_shift_bytes(data: bytes, amount: int, *, arithmetic: bool) -> bytes:
    result = bytearray()

    for value in data:
        shifted_value = value >> amount
        if arithmetic:
            shifted_value ^= value & 0x80
        result.append(shifted_value)

    return bytes(result)


def build_not_bytes(data: bytes) -> bytes:
    return bytes((~value) & 0xFF for value in data)


def build_rotate_left_bytes(data: bytes, amount: int) -> bytes:
    amount %= 8
    if amount == 0:
        return data

    return bytes(((value << amount) | (value >> (8 - amount))) & 0xFF for value in data)


def build_rotate_right_bytes(data: bytes, amount: int) -> bytes:
    amount %= 8
    if amount == 0:
        return data

    return bytes(((value >> amount) | ((value << (8 - amount)) & 0xFF)) for value in data)


def build_rotate_left_carry_bytes(data: bytes, amount: int) -> bytes:
    if not data:
        return b""

    amount %= 8
    result = [0] * len(data)
    carry_bits = 0

    for index in range(len(data) - 1, -1, -1):
        old_byte = data[index]
        result[index] = ((old_byte << amount) | carry_bits) & 0xFF
        carry_bits = (old_byte >> (8 - amount)) & ((1 << amount) - 1) if amount else 0

    result[-1] |= carry_bits
    return bytes(result)


def build_rotate_right_carry_bytes(data: bytes, amount: int) -> bytes:
    if not data:
        return b""

    amount %= 8
    result = []
    carry_bits = 0

    for old_byte in data:
        result.append((old_byte >> amount) | carry_bits)
        carry_bits = ((old_byte & ((1 << amount) - 1)) << (8 - amount)) if amount else 0

    result[0] |= carry_bits
    return bytes(result)


def build_drop_bytes(
    data: bytes,
    *,
    start: int,
    length: int,
    apply_to_each_line: bool = False,
) -> bytes:
    def drop_slice(chunk: bytes) -> bytes:
        slice_start = start
        slice_length = length

        if slice_start < 0:
            slice_start = len(chunk) + slice_start

        if slice_length < 0:
            slice_start += slice_length
            if slice_start < 0:
                slice_start = len(chunk) + slice_start
                slice_length = slice_start - slice_length
            else:
                slice_length = -slice_length

        return chunk[:slice_start] + chunk[slice_start + slice_length :]

    if apply_to_each_line:
        return b"\n".join(drop_slice(line) for line in data.split(b"\n"))

    return drop_slice(data)


def build_drop_nth_bytes(
    data: bytes,
    *,
    drop_every: int,
    starting_at: int,
    apply_to_each_line: bool = False,
) -> bytes:
    output = bytearray()
    offset = 0

    for index, value in enumerate(data):
        if apply_to_each_line and value == 0x0A:
            output.append(value)
            offset = index + 1
            continue

        if index - offset < starting_at or (index - (starting_at + offset)) % drop_every != 0:
            output.append(value)

    return bytes(output)


def build_file_tree(value: str, *, file_path_delimiter: str, delimiter: str) -> str:
    completed_paths: list[str] = []
    rendered_paths: list[str] = []

    for file_path in sorted(set(value.split(delimiter))):
        path_parts = file_path.split(file_path_delimiter)
        if path_parts and path_parts[0] == "":
            path_parts = path_parts[1:]

        for index, part in enumerate(path_parts):
            if index == 0:
                rendered_line = part
                key = part
            else:
                rendered_line = f"{'|   ' * (index - 1)}|---{part}"
                key = "/".join(path_parts[: index + 1])

            if key not in completed_paths:
                completed_paths.append(key)
                rendered_paths.append(rendered_line)

    return "\n".join(rendered_paths)


def build_from_case_insensitive_regex(value: str) -> str:
    return re.sub(
        r"\[[a-z]{2}\]",
        lambda match: match.group(0)[1]
        if match.group(0)[1].upper() == match.group(0)[2].upper()
        else match.group(0),
        value,
        flags=re.IGNORECASE,
    )


def build_all_casings(value: str) -> str:
    result = []
    lowercase_value = value.lower()

    for mask in range(1 << len(lowercase_value)):
        characters = list(lowercase_value)
        for index in range(len(lowercase_value)):
            if (mask >> index) & 1:
                characters[index] = characters[index].upper()
        result.append("".join(characters))

    return "\n".join(result)


def build_hamming_distance(sample_a: str, sample_b: str, *, unit: str, input_type: str) -> str:
    if input_type == "Hex":
        left = bytes.fromhex(sample_a)
        right = bytes.fromhex(sample_b)
    else:
        left = sample_a.encode()
        right = sample_b.encode()

    if unit == "Byte":
        return str(sum(left_byte != right_byte for left_byte, right_byte in zip(left, right, strict=True)))

    return str(sum((left_byte ^ right_byte).bit_count() for left_byte, right_byte in zip(left, right, strict=True)))


def build_levenshtein_distance(
    source: str,
    destination: str,
    *,
    insertion_cost: int = 1,
    deletion_cost: int = 1,
    substitution_cost: int = 1,
) -> float:
    current_cost = [deletion_cost * index for index in range(len(source) + 1)]
    next_cost = [0] * (len(source) + 1)

    for destination_character in destination:
        next_cost[0] = current_cost[0] + insertion_cost
        for index, source_character in enumerate(source):
            next_cost[index + 1] = min(
                current_cost[index + 1] + insertion_cost,
                next_cost[index] + deletion_cost,
                current_cost[index] + (0 if source_character == destination_character else substitution_cost),
            )
        current_cost, next_cost = next_cost, current_cost

    return float(current_cost[-1])


def build_pad_lines(value: str, *, position: str, length: int, character: str) -> str:
    lines = value.split("\n")
    if position == "Start":
        return "\n".join(line.rjust(len(line) + length, character) for line in lines)
    return "\n".join(line.ljust(len(line) + length, character) for line in lines)


def build_object_id_timestamp(value: str) -> str:
    return datetime.fromtimestamp(int(value[:8], 16), tz=timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def build_remove_line_numbers(value: str) -> str:
    return re.sub(r"^[ \t]{0,5}\d+[\s:|\-,.)\]]", "", value, flags=re.MULTILINE)


def build_remove_whitespace(
    value: str,
    *,
    spaces: bool = True,
    carriage_returns: bool = True,
    line_feeds: bool = True,
    tabs: bool = True,
    form_feeds: bool = True,
    full_stops: bool = False,
) -> str:
    result = value
    if spaces:
        result = result.replace(" ", "")
    if carriage_returns:
        result = result.replace("\r", "")
    if line_feeds:
        result = result.replace("\n", "")
    if tabs:
        result = result.replace("\t", "")
    if form_feeds:
        result = result.replace("\f", "")
    if full_stops:
        result = result.replace(".", "")
    return result


def assert_offset_checker_common_positions(result: object) -> None:
    assert isinstance(result, str)
    parts = result.split("\n\n")
    assert len(parts) == 3
    assert result.count("class='hl5'") == 6
    assert all("<span class='hl5'>a</span>" in part for part in parts)
    assert all("<span class='hl5'>c</span>" in part for part in parts)
    assert "b" in parts[0]
    assert "x" in parts[1]
    assert "q" in parts[2]


def assert_parse_unix_file_permissions_directory(result: object) -> None:
    assert isinstance(result, str)
    assert "Textual representation: drwxr-xr-x" in result
    assert "Octal representation:   0755" in result
    assert "File type: Directory" in result
    assert "| Execute |   X   |   X   |   X   |" in result


def assert_parse_unix_file_permissions_sticky_bit(result: object) -> None:
    assert isinstance(result, str)
    assert "Textual representation: -rwxr-xr-t" in result
    assert "Octal representation:   1755" in result
    assert "The sticky bit is set" in result
    assert "|   Write |   X   |       |       |" in result


def assert_parse_colour_code_green(result: object) -> None:
    assert isinstance(result, str)
    assert "Hex:  #00ff00" in result
    assert "RGB:  rgb(0, 255, 0)" in result
    assert "HSLA: hsla(120, 100%, 50%, 1)" in result
    assert "CMYK: cmyk(1.00, 0.00, 1.00, 0.00)" in result
    assert "colorpicker" in result
    assert "color: 'rgba(0, 255, 0, 1)'" in result


def assert_parse_colour_code_alpha_red(result: object) -> None:
    assert isinstance(result, str)
    assert "Hex:  #ff0000" in result
    assert "RGBA: rgba(255, 0, 0, 0.5)" in result
    assert "HSLA: hsla(0, 100%, 50%, 0.5)" in result
    assert "CMYK: cmyk(0.00, 1.00, 1.00, 0.00)" in result
    assert "color: 'rgba(255, 0, 0, 0.5)'" in result


def build_cartesian_product(samples: list[list[str]], item_delimiter: str) -> str:
    return item_delimiter.join(f"({','.join(items)})" for items in product(*samples))


def build_power_set(items: list[str], item_delimiter: str) -> str:
    filtered_items = [item for item in items if item]
    if not filtered_items:
        return ""

    max_binary_value = int("1" * len(filtered_items), 2)
    subsets = []

    for value in range(max_binary_value + 1):
        binary = format(value, f"0{len(filtered_items)}b")
        subset = item_delimiter.join(
            item for item, bit in zip(filtered_items, binary, strict=True) if bit == "1"
        )
        subsets.append(subset)

    subsets.sort(key=len)
    return "".join(f"{subset}\n" for subset in subsets)


def build_set_difference(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    return item_delimiter.join(item for item in sample_a if item not in sample_b)


def build_set_intersection(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    return item_delimiter.join(item for item in sample_a if item in sample_b)


def build_set_union(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    result = []
    seen = set()

    for item in [*sample_a, *sample_b]:
        if item in seen:
            continue

        seen.add(item)
        result.append(item)

    return item_delimiter.join(result)


def build_symmetric_difference(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    return item_delimiter.join([
        *[item for item in sample_a if item not in sample_b],
        *[item for item in sample_b if item not in sample_a],
    ])


def build_tar_archive(filename: str, data: bytes) -> bytes:
    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(filename)
        info.mode = 0o644
        info.mtime = 0
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    return buffer.getvalue()


def build_zip_archive(
    filename: str,
    data: bytes,
    *,
    compression: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, mode="w") as archive:
        info = zipfile.ZipInfo(filename)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = compression
        archive.writestr(info, data)

    return buffer.getvalue()


def build_file_listing(filename: str, data: bytes) -> list[dict[str, object]]:
    return [{"name": filename, "type": "application/unknown", "data": data}]


def build_ordinal_day(day: int) -> str:
    if 10 <= day % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")

    return f"{day}{suffix}"


def build_verbose_utc_datetime(value: datetime) -> str:
    return f"{value.strftime('%a')} {value.day} {value.strftime('%B %Y %H:%M:%S')} UTC"


def build_datetime_delta_string(
    value: str,
    *,
    days: int = 0,
    hours: int = 0,
    minutes: int = 0,
    seconds: int = 0,
) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return (parsed + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def build_from_unix_timestamp_string(value: str, units: str) -> str:
    divisors = {
        "Seconds (s)": 1,
        "Milliseconds (ms)": 1_000,
        "Microseconds (μs)": 1_000_000,
        "Nanoseconds (ns)": 1_000_000_000,
    }
    divisor = divisors[units]
    parsed = datetime.fromtimestamp(int(value) / divisor, tz=timezone.utc)

    if units == "Seconds (s)":
        return build_verbose_utc_datetime(parsed)

    milliseconds = parsed.strftime("%f")[:3]
    return f"{parsed.strftime('%a')} {parsed.day} {parsed.strftime('%B %Y %H:%M:%S')}.{milliseconds} UTC"


def build_parse_datetime_output(value: datetime) -> str:
    return (
        f"Date: {value.strftime('%A')} {build_ordinal_day(value.day)} {value.strftime('%B %Y')}\n"
        f"Time: {value.strftime('%H:%M:%S')}\n"
        f"Period: {value.strftime('%p')}\n"
        f"Timezone: {value.tzname()}\n"
        f"UTC offset: {value.strftime('%z')}\n\n"
        f"Daylight Saving Time: {str(bool(value.dst())).lower()}\n"
        f"Leap year: {str(calendar.isleap(value.year)).lower()}\n"
        f"Days in this month: {calendar.monthrange(value.year, value.month)[1]}\n\n"
        f"Day of year: {value.timetuple().tm_yday}\n"
        f"Week number: {value.isocalendar().week}\n"
        f"Quarter: {((value.month - 1) // 3) + 1}"
    )


def build_to_unix_timestamp_string(value: str, *, units: str, show_parsed_datetime: bool) -> str:
    parsed = datetime.strptime(value, "%a %d %B %Y %H:%M:%S").replace(tzinfo=timezone.utc)
    converters = {
        "Seconds (s)": lambda timestamp: int(timestamp),
        "Milliseconds (ms)": lambda timestamp: int(timestamp * 1_000),
        "Microseconds (μs)": lambda timestamp: int(timestamp * 1_000_000),
        "Nanoseconds (ns)": lambda timestamp: int(timestamp * 1_000_000_000),
    }
    result = converters[units](parsed.timestamp())

    if not show_parsed_datetime:
        return str(result)

    return f"{result} ({build_verbose_utc_datetime(parsed)})"


def build_translated_datetime_output(
    value: str,
    *,
    input_format: str,
    input_timezone: str,
    output_timezone: str,
) -> str:
    parsed = datetime.strptime(value, input_format).replace(tzinfo=ZoneInfo(input_timezone))
    translated = parsed.astimezone(ZoneInfo(output_timezone))
    offset = translated.strftime("%z")
    return (
        f"{translated.strftime('%Y-%m-%d %H:%M:%S')} {offset[:3]}:{offset[3:]}"
        f" {translated.tzname()}"
    )


def build_little_endian_hex(value: int) -> str:
    hex_value = format(value, "x")
    if len(hex_value) % 2:
        hex_value = f"0{hex_value}"
    return "".join(reversed([hex_value[index : index + 2] for index in range(0, len(hex_value), 2)]))


def build_windows_filetime_string(value: str, *, units: str, output_format: str) -> str:
    number = int(value)

    if units == "Seconds (s)":
        intervals = number * 10_000_000
    elif units == "Milliseconds (ms)":
        intervals = number * 10_000
    elif units == "Microseconds (μs)":
        intervals = number * 10
    else:
        intervals = number // 100

    intervals += 116_444_736_000_000_000

    if output_format == "Decimal":
        return str(intervals)

    if output_format == "Hex (big endian)":
        return format(intervals, "x")

    return build_little_endian_hex(intervals)


def build_unix_timestamp_from_windows_filetime_string(
    value: str,
    *,
    output_units: str,
    input_format: str,
) -> str:
    if input_format == "Hex (little endian)":
        chunks = [value[index : index + 2] for index in range(0, len(value), 2)]
        intervals = int("".join(reversed(chunks)), 16)
    elif input_format == "Hex (big endian)":
        intervals = int(value, 16)
    else:
        intervals = int(value)

    unix_intervals = intervals - 116_444_736_000_000_000

    if output_units == "Seconds (s)":
        return str(unix_intervals // 10_000_000)

    if output_units == "Milliseconds (ms)":
        return str(unix_intervals // 10_000)

    if output_units == "Microseconds (μs)":
        return str(unix_intervals // 10)

    return str(unix_intervals * 100)


def build_netbios_name(value: str, offset: int = 65) -> bytes:
    padded = value.encode("latin1").ljust(16, b" ")
    encoded = bytearray()

    for byte in padded:
        encoded.append((byte >> 4) + offset)
        encoded.append((byte & 0x0F) + offset)

    return bytes(encoded)


def build_group_ip_addresses_output(values: list[str], cidr: int, *, only_subnets: bool = False) -> str:
    ipv4_networks: dict[ipaddress.IPv4Network, list[ipaddress.IPv4Address]] = {}
    ipv6_networks: dict[ipaddress.IPv6Network, list[ipaddress.IPv6Address]] = {}

    for value in values:
        ip = ipaddress.ip_address(value)
        network = ipaddress.ip_network(f"{value}/{cidr}", strict=False)

        if isinstance(ip, ipaddress.IPv4Address):
            ipv4_networks.setdefault(network, []).append(ip)
        else:
            ipv6_networks.setdefault(network, []).append(ip)

    output = []

    for network, addresses in ipv4_networks.items():
        output.append(f"{network.network_address}/{cidr}\n")

        if not only_subnets:
            for address in sorted(addresses):
                output.append(f"  {address}\n")
            output.append("\n")

    for network, addresses in ipv6_networks.items():
        output.append(f"{network.network_address.compressed}/{cidr}\n")

        if not only_subnets:
            for address in addresses:
                output.append(f"  {address.compressed}\n")
            output.append("\n")

    return "".join(output)


def build_hassh_full_details(algorithms: str, *, direction: str = "Client to Server") -> str:
    digest = hashlib.md5(algorithms.encode()).hexdigest()
    kex_algorithms, encryption_algorithms, mac_algorithms, compression_algorithms = algorithms.split(";")
    return (
        f"Hash digest:\n{digest}\n\n"
        f"Full HASSH algorithms string:\n{algorithms}\n\n"
        f"Key Exchange Algorithms:\n{kex_algorithms}\n"
        f"Encryption Algorithms {direction}:\n{encryption_algorithms}\n"
        f"MAC Algorithms {direction}:\n{mac_algorithms}\n"
        f"Compression Algorithms {direction}:\n{compression_algorithms}"
    )


def build_ja3_full_details(ja3: str) -> str:
    digest = hashlib.md5(ja3.encode()).hexdigest()
    tls_version, cipher_suites, extensions, elliptic_curves, point_formats = ja3.split(",")
    return (
        f"Hash digest:\n{digest}\n\n"
        f"Full JA3 string:\n{ja3}\n\n"
        f"TLS Version:\n{tls_version}\n"
        f"Cipher Suites:\n{cipher_suites}\n"
        f"Extensions:\n{extensions}\n"
        f"Elliptic Curves:\n{elliptic_curves}\n"
        f"Elliptic Curve Point Formats:\n{point_formats}"
    )


def build_ja3s_full_details(ja3s: str) -> str:
    digest = hashlib.md5(ja3s.encode()).hexdigest()
    tls_version, cipher_suite, extensions = ja3s.split(",")
    return (
        f"Hash digest:\n{digest}\n\n"
        f"Full JA3S string:\n{ja3s}\n\n"
        f"TLS Version:\n{tls_version}\n"
        f"Cipher Suite:\n{cipher_suite}\n"
        f"Extensions:\n{extensions}"
    )


def build_udp_datagram(source_port: int, destination_port: int, payload: bytes, checksum: int) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), checksum) + payload


def build_varint_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("VarInt only supports non-negative integers")

    encoded = bytearray()
    remaining = value

    while remaining >= 0x80:
        encoded.append((remaining & 0x7F) | 0x80)
        remaining >>= 7

    encoded.append(remaining)
    return bytes(encoded)


def build_varint_string(data: bytes) -> str:
    result = 0
    shift = 0

    for byte in data:
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7

    return str(result)


def assert_parse_ipv4_header_html(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("<table ")
    assert "<td>Version</td><td>4</td>" in result
    assert "<td>Internet Header Length (IHL)</td><td>5 (20 bytes)</td>" in result
    assert "<td>Total length</td><td>196 bytes" in result
    assert "<td>Protocol</td><td>17, User Datagram (UDP)</td>" in result
    assert "<td>Header checksum</td><td>1e8c (correct)</td>" in result
    assert "<td>Source IP address</td><td>192.168.12.1</td>" in result
    assert "<td>Destination IP address</td><td>192.168.12.2</td>" in result


CODE_TIDY_VECTORS = [
    BakeVector(
        name="bson_serialise_empty_json_object",
        input_data="{}",
        recipe=["BSON serialise"],
        expected=EMPTY_BSON_DOCUMENT,
    ),
    BakeVector(
        name="bson_serialise_string_field_document",
        input_data='{"hello":"world"}',
        recipe=["BSON serialise"],
        expected=HELLO_WORLD_BSON_DOCUMENT,
    ),
    BakeVector(
        name="bson_deserialise_empty_document",
        input_data=EMPTY_BSON_DOCUMENT,
        recipe=["BSON deserialise"],
        expected="{}",
    ),
    BakeVector(
        name="bson_deserialise_string_field_document",
        input_data=HELLO_WORLD_BSON_DOCUMENT,
        recipe=["BSON deserialise"],
        expected='''{
  "hello": "world"
}''',
    ),
    BakeVector(
        name="bson_roundtrip_string_field_document",
        input_data='{"hello":"world"}',
        recipe=["BSON serialise", "BSON deserialise"],
        expected='''{
  "hello": "world"
}''',
    ),
    BakeVector(
        name="css_beautify_empty_string",
        input_data="",
        recipe=["CSS Beautify"],
        expected="",
    ),
    BakeVector(
        name="css_beautify_default_tab_indent",
        input_data="body{color:red;margin:0}",
        recipe=["CSS Beautify"],
        expected="body{\n\\tcolor:red;\n\\tmargin:0\n}\n",
    ),
    BakeVector(
        name="css_beautify_custom_space_indent",
        input_data="body{color:red}",
        recipe=[{"op": "CSS Beautify", "args": {"Indent string": "  "}}],
        expected="body{\n  color:red\n}\n",
    ),
    BakeVector(
        name="css_minify_empty_string",
        input_data="",
        recipe=["CSS Minify"],
        expected="",
    ),
    BakeVector(
        name="css_minify_default_whitespace_reduction",
        input_data="body { color: red; margin: 0; }",
        recipe=["CSS Minify"],
        expected="body {color: red;margin: 0;}",
    ),
    BakeVector(
        name="css_minify_preserve_comments",
        input_data="/*x*/ body { color: red; }",
        recipe=[{"op": "CSS Minify", "args": {"Preserve comments": True}}],
        expected="/*x*/body {color: red;}",
    ),
    BakeVector(
        name="generic_code_beautify_empty_string",
        input_data="",
        recipe=["Generic Code Beautify"],
        expected="",
    ),
    BakeVector(
        name="generic_code_beautify_if_else_block",
        input_data="if(a){b();}else{c();}",
        recipe=["Generic Code Beautify"],
        expected='''if (a)  {
    b();
} else {
    c();
}''',
    ),
    BakeVector(
        name="json_beautify_empty_object",
        input_data="{}",
        recipe=["JSON Beautify"],
        expected="{}",
    ),
    BakeVector(
        name="json_beautify_default_indent",
        input_data='{"b":1,"a":2}',
        recipe=["JSON Beautify"],
        expected='''{
    "b": 1,
    "a": 2
}''',
    ),
    BakeVector(
        name="json_beautify_sort_keys_with_custom_indent",
        input_data='{"b":1,"a":2}',
        recipe=[
            {
                "op": "JSON Beautify",
                "args": {
                    "Indent string": "  ",
                    "Sort Object Keys": True,
                    "Formatted": False,
                },
            }
        ],
        expected='''{
  "a": 2,
  "b": 1
}''',
    ),
    BakeVector(
        name="json_minify_empty_object",
        input_data="{ }",
        recipe=["JSON Minify"],
        expected="{}",
    ),
    BakeVector(
        name="json_minify_compacts_whitespace",
        input_data='''{
  "b": 1,
  "a": 2
}''',
        recipe=["JSON Minify"],
        expected='{"b":1,"a":2}',
    ),
    BakeVector(
        name="json_minify_then_beautify_roundtrip",
        input_data='''{
  "b": 1,
  "a": 2
}''',
        recipe=["JSON Minify", "JSON Beautify"],
        expected='''{
    "b": 1,
    "a": 2
}''',
    ),
    BakeVector(
        name="jq_identity_object",
        input_data='{"a":1,"b":[2,3]}',
        recipe=[{"op": "Jq", "args": {"Query": "."}}],
        expected='{"a":1,"b":[2,3]}',
    ),
    BakeVector(
        name="jq_extract_array_element",
        input_data='{"a":1,"b":[2,3]}',
        recipe=[{"op": "Jq", "args": {"Query": ".b[1]"}}],
        expected="3",
    ),
    BakeVector(
        name="jq_map_then_beautify",
        input_data='[{"a":1},{"a":2}]',
        recipe=[{"op": "Jq", "args": {"Query": "map(.a)"}}, "JSON Beautify"],
        expected='''[
    1,
    2
]''',
    ),
    BakeVector(
        name="microsoft_script_decoder_empty_string",
        input_data="",
        recipe=["Microsoft Script Decoder"],
        expected="",
    ),
    BakeVector(
        name="microsoft_script_decoder_docs_sample",
        input_data=MICROSOFT_SCRIPT_SAMPLE_ENCODED,
        recipe=["Microsoft Script Decoder"],
        expected=MICROSOFT_SCRIPT_SAMPLE_DECODED,
    ),
    BakeVector(
        name="php_deserialize_nested_array_valid_json",
        input_data='a:2:{s:1:"a";i:10;i:0;a:1:{s:2:"ab";b:1;}}',
        recipe=["PHP Deserialize"],
        expected='{"a": 10,"0": {"ab": true}}',
    ),
    BakeVector(
        name="php_deserialize_preserves_numeric_keys_when_not_valid_json",
        input_data='a:2:{s:1:"a";i:10;i:0;a:1:{s:2:"ab";b:1;}}',
        recipe=[{"op": "PHP Deserialize", "args": {"Output valid JSON": False}}],
        expected='{"a": 10,0: {"ab": true}}',
    ),
    BakeVector(
        name="php_serialize_array_docs_example",
        input_data='[5,"abc",true]',
        recipe=["PHP Serialize"],
        expected='a:3:{i:0;i:5;i:1;s:3:"abc";i:2;b:1;}',
    ),
    BakeVector(
        name="php_serialize_then_deserialize_array_roundtrip",
        input_data='[5,"abc",true]',
        recipe=["PHP Serialize", "PHP Deserialize"],
        expected='{"0": 5,"1": "abc","2": true}',
    ),
    BakeVector(
        name="render_markdown_empty_string",
        input_data="",
        recipe=["Render Markdown"],
        expected='<div style="font-family: var(--primary-font-family)"></div>',
    ),
    BakeVector(
        name="render_markdown_heading",
        input_data="# hi",
        recipe=["Render Markdown"],
        expected='<div style="font-family: var(--primary-font-family)"><h1>hi</h1>\n</div>',
    ),
    BakeVector(
        name="render_markdown_linkify_urls",
        input_data="Visit https://example.com",
        recipe=[
            {
                "op": "Render Markdown",
                "args": {
                    "Autoconvert URLs to links": True,
                    "Enable syntax highlighting": True,
                },
            }
        ],
        expected=(
            '<div style="font-family: var(--primary-font-family)"><p>Visit '
            '<a href="https://example.com">https://example.com</a></p>\n</div>'
        ),
    ),
    BakeVector(
        name="render_markdown_disables_html_rendering",
        input_data="<b>x</b>",
        recipe=["Render Markdown"],
        expected='<div style="font-family: var(--primary-font-family)"><p>&lt;b&gt;x&lt;/b&gt;</p>\n</div>',
    ),
    BakeVector(
        name="sql_beautify_empty_string",
        input_data="",
        recipe=["SQL Beautify"],
        expected="",
    ),
    BakeVector(
        name="sql_beautify_default_layout",
        input_data="select * from users where id=1",
        recipe=["SQL Beautify"],
        expected='''SELECT *
FROM users
WHERE id=1''',
    ),
    BakeVector(
        name="sql_beautify_custom_indent_string",
        input_data='select a, b from users where id=1 and name="x"',
        recipe=[{"op": "SQL Beautify", "args": {"Indent string": "  "}}],
        expected='''SELECT a,
         b
FROM users
WHERE id=1
        AND name="x"''',
    ),
    BakeVector(
        name="sql_minify_empty_string",
        input_data="",
        recipe=["SQL Minify"],
        expected="",
    ),
    BakeVector(
        name="sql_minify_multiline_query",
        input_data='''SELECT a,
       b
FROM users
WHERE id = 1 AND name = "x"''',
        recipe=["SQL Minify"],
        expected='SELECT a, b FROM users WHERE id = 1 AND name = "x"',
    ),
    BakeVector(
        name="sql_minify_then_beautify_roundtrip",
        input_data='''SELECT a,
       b
FROM users
WHERE id = 1 AND name = "x"''',
        recipe=["SQL Minify", "SQL Beautify"],
        expected='''SELECT a,
         b
FROM users
WHERE id = 1
        AND name = "x"''',
    ),
    BakeVector(
        name="strip_html_tags_empty_string",
        input_data="",
        recipe=["Strip HTML tags"],
        expected="",
    ),
    BakeVector(
        name="strip_html_tags_default_cleanup",
        input_data="<div>one</div>\n    <div>two</div>\n\n<div>three</div>",
        recipe=["Strip HTML tags"],
        expected="one\ntwo\nthree",
    ),
    BakeVector(
        name="strip_html_tags_preserve_indentation_and_line_breaks",
        input_data="<div>one</div>\n    <div>two</div>\n\n<div>three</div>",
        recipe=[
            {
                "op": "Strip HTML tags",
                "args": {
                    "Remove indentation": False,
                    "Remove excess line breaks": False,
                },
            }
        ],
        expected="one\n    two\n\nthree",
    ),
    BakeVector(
        name="to_camel_case_empty_string",
        input_data="",
        recipe=["To Camel case"],
        expected="",
    ),
    BakeVector(
        name="to_camel_case_default_transformation",
        input_data="hello_world-test value",
        recipe=["To Camel case"],
        expected="helloWorldTestValue",
    ),
    BakeVector(
        name="to_camel_case_context_aware_variable_names",
        input_data=(
            "const my_variable_name = 1;\n"
            "function another_function_name() { return my_variable_name; }"
        ),
        recipe=[{"op": "To Camel case", "args": {"Attempt to be context aware": True}}],
        expected=(
            "const myVariableName = 1;\n"
            "function anotherFunctionName() { return myVariableName; }"
        ),
    ),
    BakeVector(
        name="to_kebab_case_empty_string",
        input_data="",
        recipe=["To Kebab case"],
        expected="",
    ),
    BakeVector(
        name="to_kebab_case_default_transformation",
        input_data="hello_world-Test value",
        recipe=["To Kebab case"],
        expected="hello-world-test-value",
    ),
    BakeVector(
        name="to_kebab_case_context_aware_variable_names",
        input_data=(
            "const myVariableName = 1;\n"
            "function anotherFunctionName() { return myVariableName; }"
        ),
        recipe=[{"op": "To Kebab case", "args": {"Attempt to be context aware": True}}],
        expected=(
            "const my-variable-name = 1;\n"
            "function another-function-name() { return my-variable-name; }"
        ),
    ),
    BakeVector(
        name="to_snake_case_empty_string",
        input_data="",
        recipe=["To Snake case"],
        expected="",
    ),
    BakeVector(
        name="to_snake_case_default_transformation",
        input_data="helloWorld-Test value",
        recipe=["To Snake case"],
        expected="hello_world_test_value",
    ),
    BakeVector(
        name="to_snake_case_context_aware_variable_names",
        input_data=(
            "const myVariableName = 1;\n"
            "function anotherFunctionName() { return myVariableName; }"
        ),
        recipe=[{"op": "To Snake case", "args": {"Attempt to be context aware": True}}],
        expected=(
            "const my_variable_name = 1;\n"
            "function another_function_name() { return my_variable_name; }"
        ),
    ),
    BakeVector(
        name="xml_beautify_empty_string",
        input_data="",
        recipe=["XML Beautify"],
        expected="",
    ),
    BakeVector(
        name="xml_beautify_default_indent_string",
        input_data='<root><item id="1">x</item><item id="2"/></root>',
        recipe=["XML Beautify"],
        expected='''<root>
\\t<item id="1">x</item>
\\t<item id="2"/>
</root>''',
    ),
    BakeVector(
        name="xml_beautify_custom_indent_string",
        input_data="<root><item>1</item></root>",
        recipe=[{"op": "XML Beautify", "args": {"Indent string": "  "}}],
        expected='''<root>
  <item>1</item>
</root>''',
    ),
    BakeVector(
        name="xml_minify_empty_string",
        input_data="",
        recipe=["XML Minify"],
        expected="",
    ),
    BakeVector(
        name="xml_minify_removes_comments_and_whitespace",
        input_data='''<root>
  <!--x-->
  <item id="1">x</item>
</root>''',
        recipe=["XML Minify"],
        expected='<root><item id="1">x</item></root>',
    ),
    BakeVector(
        name="xml_minify_preserves_comments",
        input_data='''<root>
  <!--x-->
  <item id="1">x</item>
</root>''',
        recipe=[{"op": "XML Minify", "args": {"Preserve comments": True}}],
        expected='<root><!--x--><item id="1">x</item></root>',
    ),
    BakeVector(
        name="xml_minify_then_beautify_roundtrip",
        input_data='''<root>
  <item id="1">x</item>
  <item id="2"/>
</root>''',
        recipe=["XML Minify", "XML Beautify"],
        expected='''<root>
\\t<item id="1">x</item>
\\t<item id="2"/>
</root>''',
    ),
]

CODE_TIDY_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="javascript_beautify_excluded_from_node_bundle",
        input_data="const answer=42;",
        recipe=["JavaScript Beautify"],
        error_message=(
            "Sorry, the JavaScriptBeautify operation is not available in the Node.js version of CyberChef."
        ),
    ),
    BlockedBakeVector(
        name="javascript_minify_excluded_from_node_bundle",
        input_data="const answer = 42;",
        recipe=["JavaScript Minify"],
        error_message=(
            "Sorry, the JavaScriptMinify operation is not available in the Node.js version of CyberChef."
        ),
    ),
    BlockedBakeVector(
        name="javascript_parser_excluded_from_node_bundle",
        input_data="const answer = 42;",
        recipe=["JavaScript Parser"],
        error_message=(
            "Sorry, the JavaScriptParser operation is not available in the Node.js version of CyberChef."
        ),
    ),
    BlockedBakeVector(
        name="syntax_highlighter_excluded_from_node_bundle",
        input_data="const answer = 42;",
        recipe=["Syntax highlighter"],
        error_message=(
            "Sorry, the SyntaxHighlighter operation is not available in the Node.js version of CyberChef."
        ),
    ),
]

DATA_FORMAT_VECTORS = [
    BakeVector(
        name="amf_encode_amf3_single_string_field_object",
        input_data='{"a":"test"}',
        recipe=[{"op": "AMF Encode", "args": {"Format": "AMF3"}}],
        expected=AMF3_SINGLE_FIELD_OBJECT,
    ),
    BakeVector(
        name="amf_encode_amf0_single_string_field_object",
        input_data='{"a":"test"}',
        recipe=[{"op": "AMF Encode", "args": {"Format": "AMF0"}}],
        expected=AMF0_SINGLE_FIELD_OBJECT,
    ),
    BakeVector(
        name="amf_decode_amf3_single_string_field_object",
        input_data=AMF3_SINGLE_FIELD_OBJECT,
        recipe=[{"op": "AMF Decode", "args": {"Format": "AMF3"}}],
        expected=AMF3_SINGLE_FIELD_OBJECT_DECODED,
    ),
    BakeVector(
        name="amf_decode_amf0_single_string_field_object",
        input_data=AMF0_SINGLE_FIELD_OBJECT,
        recipe=[{"op": "AMF Decode", "args": {"Format": "AMF0"}}],
        expected=AMF0_SINGLE_FIELD_OBJECT_DECODED,
    ),
    BakeVector(
        name="avro_to_json_force_valid_json",
        input_data=AVRO_SINGLE_RECORD_CONTAINER,
        recipe=[{"op": "Avro to JSON", "args": {"Force Valid JSON": True}}],
        expected='''{
    "name": "myname"
}''',
    ),
    BakeVector(
        name="avro_to_json_newline_delimited_json",
        input_data=AVRO_SINGLE_RECORD_CONTAINER,
        recipe=[{"op": "Avro to JSON", "args": {"Force Valid JSON": False}}],
        expected='{"name":"myname"}\n',
    ),
    BakeVector(
        name="cbor_encode_map",
        input_data='{"a":1,"b":2,"c":3}',
        recipe=["CBOR Encode"],
        expected=bytes.fromhex("a3616101616202616303"),
    ),
    BakeVector(
        name="cbor_decode_map",
        input_data=bytes.fromhex("a3616101616202616303"),
        recipe=["CBOR Decode"],
        expected={"a": 1, "b": 2, "c": 3},
    ),
    BakeVector(
        name="cbor_roundtrip_nested_json_value",
        input_data='{"a":1,"b":false,"c":[1,2,3]}',
        recipe=["CBOR Encode", "CBOR Decode"],
        expected={"a": 1, "b": False, "c": [1, 2, 3]},
    ),
    BakeVector(
        name="csv_to_json_array_of_dictionaries",
        input_data=CSV_COMPLEX_SAMPLE,
        recipe=[
            {
                "op": "CSV to JSON",
                "args": {
                    "Cell delimiters": ",",
                    "Row delimiters": "\r\n",
                    "Format": "Array of dictionaries",
                },
            }
        ],
        expected=CSV_COMPLEX_ARRAY_OF_DICTS,
    ),
    BakeVector(
        name="csv_to_json_array_of_arrays_with_custom_delimiters",
        input_data="name;score|alice;10|bob;20",
        recipe=[
            {
                "op": "CSV to JSON",
                "args": {
                    "Cell delimiters": ";",
                    "Row delimiters": "|",
                    "Format": "Array of arrays",
                },
            }
        ],
        expected=[["name", "score"], ["alice", "10"], ["bob", "20"]],
    ),
    BakeVector(
        name="change_ip_format_dotted_decimal_to_hex",
        input_data="192.168.1.1",
        recipe=[
            {
                "op": "Change IP format",
                "args": {"Input format": "Dotted Decimal", "Output format": "Hex"},
            }
        ],
        expected=ipaddress.IPv4Address("192.168.1.1").packed.hex(),
    ),
    BakeVector(
        name="change_ip_format_hex_to_octal",
        input_data="c0a80101",
        recipe=[
            {
                "op": "Change IP format",
                "args": {"Input format": "Hex", "Output format": "Octal"},
            }
        ],
        expected=f"0{int(ipaddress.IPv4Address('192.168.1.1')):o}",
    ),
    BakeVector(
        name="change_ip_format_multiline_decimal_to_dotted_decimal",
        input_data="3232235777\n167772161",
        recipe=[
            {
                "op": "Change IP format",
                "args": {"Input format": "Decimal", "Output format": "Dotted Decimal"},
            }
        ],
        expected="\n".join([
            str(ipaddress.IPv4Address(3232235777)),
            str(ipaddress.IPv4Address(167772161)),
        ]),
    ),
    BakeVector(
        name="decode_text_utf16le_powershell_command",
        input_data=base64.b64decode("ZABpAHIAIAAiAGMAOgBcAHAAcgBvAGcAcgBhAG0AIABmAGkAbABlAHMAIgAgAA=="),
        recipe=[{"op": "Decode text", "args": {"Encoding": "UTF-16LE (1200)"}}],
        expected='dir "c:\\program files" ',
    ),
    BakeVector(
        name="decode_text_ebcdic_cp500_hello",
        input_data="hello".encode("cp500"),
        recipe=[{"op": "Decode text", "args": {"Encoding": "IBM EBCDIC International (500)"}}],
        expected="hello",
    ),
    BakeVector(
        name="encode_text_utf8_cafe",
        input_data="café",
        recipe=[{"op": "Encode text", "args": {"Encoding": "UTF-8 (65001)"}}],
        expected="café".encode("utf-8"),
    ),
    BakeVector(
        name="encode_text_ebcdic_cp500_hello",
        input_data="hello",
        recipe=[{"op": "Encode text", "args": {"Encoding": "IBM EBCDIC International (500)"}}],
        expected="hello".encode("cp500"),
    ),
    BakeVector(
        name="encode_decode_text_roundtrip_utf16le",
        input_data="pi ✓",
        recipe=[
            {"op": "Encode text", "args": {"Encoding": "UTF-16LE (1200)"}},
            {"op": "Decode text", "args": {"Encoding": "UTF-16LE (1200)"}},
        ],
        expected="pi ✓",
    ),
    BakeVector(
        name="escape_unicode_characters_default_greek_text",
        input_data="σου",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "\\u",
                    "Encode all chars": False,
                    "Padding": 4,
                    "Uppercase hex": True,
                },
            }
        ],
        expected="\\u03C3\\u03BF\\u03C5",
    ),
    BakeVector(
        name="escape_unicode_characters_preserve_ascii_with_percent_prefix",
        input_data="Aβ",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "%u",
                    "Encode all chars": False,
                    "Padding": 4,
                    "Uppercase hex": True,
                },
            }
        ],
        expected="A%u03B2",
    ),
    BakeVector(
        name="escape_unicode_characters_encode_all_with_uplus_prefix",
        input_data="A!",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "U+",
                    "Encode all chars": True,
                    "Padding": 6,
                    "Uppercase hex": False,
                },
            }
        ],
        expected="U+000041U+000021",
    ),
    BakeVector(
        name="unescape_unicode_characters_default_greek_text",
        input_data="\\u03C3\\u03BF\\u03C5",
        recipe=["Unescape Unicode Characters"],
        expected="σου",
    ),
    BakeVector(
        name="unescape_unicode_characters_percent_prefix_preserves_ascii",
        input_data="A%u03B2",
        recipe=[{"op": "Unescape Unicode Characters", "args": {"Prefix": "%u"}}],
        expected="Aβ",
    ),
    BakeVector(
        name="unescape_unicode_characters_uplus_prefix_four_digit_units",
        input_data="U+0041U+0021",
        recipe=[{"op": "Unescape Unicode Characters", "args": {"Prefix": "U+"}}],
        expected="A!",
    ),
    BakeVector(
        name="unescape_unicode_characters_surrogate_pair_forms_astral_character",
        input_data="\\uD83D\\uDE00",
        recipe=["Unescape Unicode Characters"],
        expected="😀",
    ),
    BakeVector(
        name="escape_then_unescape_unicode_characters_roundtrip",
        input_data="σου",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "\\u",
                    "Encode all chars": False,
                    "Padding": 4,
                    "Uppercase hex": True,
                },
            },
            "Unescape Unicode Characters",
        ],
        expected="σου",
    ),
    BakeVector(
        name="from_bcd_packed_nibbles_1234",
        input_data="0001 0010 0011 0100",
        recipe=[
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": False,
                    "Input format": "Nibbles",
                },
            }
        ],
        expected="1234",
    ),
    BakeVector(
        name="from_bcd_unpacked_bytes_123",
        input_data="00000001 00000010 00000011",
        recipe=[
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": False,
                    "Signed": False,
                    "Input format": "Bytes",
                },
            }
        ],
        expected="123",
    ),
    BakeVector(
        name="from_bcd_signed_negative_12",
        input_data="0001 0010 1101",
        recipe=[
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": True,
                    "Input format": "Nibbles",
                },
            }
        ],
        expected="-12",
    ),
    BakeVector(
        name="from_base_hex_ff",
        input_data="ff",
        recipe=[{"op": "From Base", "args": {"Radix": 16}}],
        expected=str(int("ff", 16)),
    ),
    BakeVector(
        name="from_base_binary_strips_whitespace",
        input_data="1 0 1 0",
        recipe=[{"op": "From Base", "args": {"Radix": 2}}],
        expected=str(int("1010", 2)),
    ),
    BakeVector(
        name="from_base32_hex_extended_binary_edge_string",
        input_data=base64.b32hexencode(b"\x00\x10\x7f\x80\xff").decode(),
        recipe=[
            {
                "op": "From Base32",
                "args": {"Alphabet": "0-9A-V=", "Remove non-alphabet chars": True},
            }
        ],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="from_base45_ascii_bytes",
        input_data=build_base45(b"AB"),
        recipe=["From Base45"],
        expected=b"AB",
    ),
    BakeVector(
        name="from_base58_ripple_alphabet_ascii_bytes",
        input_data=build_base58(b"hello", BASE58_RIPPLE_ALPHABET),
        recipe=[
            {
                "op": "From Base58",
                "args": {
                    "Alphabet": BASE58_RIPPLE_ALPHABET,
                    "Remove non-alphabet chars": True,
                },
            }
        ],
        expected=b"hello",
    ),
    BakeVector(
        name="from_base62_ascii_bytes",
        input_data=build_base62(b"hello"),
        recipe=["From Base62"],
        expected=b"hello",
    ),
    BakeVector(
        name="from_base62_custom_alphabet_ascii_bytes",
        input_data=build_base62(b"hello", BASE62_ALPHABET[::-1]),
        recipe=[{"op": "From Base62", "args": {"Alphabet": BASE62_ALPHABET[::-1]}}],
        expected=b"hello",
    ),
    BakeVector(
        name="from_base64_urlsafe_binary_edge_string",
        input_data=base64.urlsafe_b64encode(b"\xfb\xef\xff").decode(),
        recipe=[
            {
                "op": "From Base64",
                "args": {
                    "Alphabet": "A-Za-z0-9-_",
                    "Remove non-alphabet chars": True,
                    "Strict mode": False,
                },
            }
        ],
        expected=b"\xfb\xef\xff",
    ),
    BakeVector(
        name="from_base85_custom_zero_group_char",
        input_data="y",
        recipe=[
            {
                "op": "From Base85",
                "args": {
                    "Alphabet": "!-u",
                    "Remove non-alphabet chars": True,
                    "All-zero group char": "y",
                },
            }
        ],
        expected=b"\x00\x00\x00\x00",
    ),
    BakeVector(
        name="from_base92_ascii_bytes",
        input_data=build_base92(b"hello"),
        recipe=["From Base92"],
        expected=b"hello",
    ),
    BakeVector(
        name="from_binary_nibble_groups_without_delimiter",
        input_data="0001001000110100",
        recipe=[{"op": "From Binary", "args": {"Delimiter": "None", "Byte Length": 4}}],
        expected=b"\x01\x02\x03\x04",
    ),
    BakeVector(
        name="from_binary_colon_delimited_bytes",
        input_data="01001000:01101001",
        recipe=[{"op": "From Binary", "args": {"Delimiter": "Colon", "Byte Length": 8}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_braille_hello_text",
        input_data="⠓⠑⠇⠇⠕",
        recipe=["From Braille"],
        expected="HELLO",
    ),
    BakeVector(
        name="from_braille_preserves_unknown_symbols",
        input_data="⠓⠑?⠇⠕",
        recipe=["From Braille"],
        expected="HE?LO",
    ),
    BakeVector(
        name="from_charcode_base10_comma_ascii",
        input_data="72,101,108,108,111",
        recipe=[{"op": "From Charcode", "args": {"Delimiter": "Comma", "Base": 10}}],
        expected=b"Hello",
    ),
    BakeVector(
        name="from_charcode_concatenated_hex_ascii",
        input_data="48656c6c6f20776f726c64",
        recipe=[{"op": "From Charcode", "args": {"Delimiter": "Space", "Base": 16}}],
        expected=b"Hello world",
    ),
    BakeVector(
        name="from_charcode_roundtrip_colon_hex",
        input_data="Hello",
        recipe=[
            {"op": "To Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
            {"op": "From Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
        ],
        expected=b"Hello",
    ),
    BakeVector(
        name="from_decimal_colon_delimited_ascii",
        input_data="72:101:108:108:111",
        recipe=[
            {
                "op": "From Decimal",
                "args": {"Delimiter": "Colon", "Support signed values": False},
            }
        ],
        expected=b"Hello",
    ),
    BakeVector(
        name="from_decimal_signed_comma_values",
        input_data="-1,-128,127",
        recipe=[
            {
                "op": "From Decimal",
                "args": {"Delimiter": "Comma", "Support signed values": True},
            }
        ],
        expected=b"\xff\x80\x7f",
    ),
    BakeVector(
        name="from_decimal_roundtrip_signed_values",
        input_data=b"\xff\x80\x7f",
        recipe=[
            {"op": "To Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
            {"op": "From Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
        ],
        expected=b"\xff\x80\x7f",
    ),
    BakeVector(
        name="from_float_big_endian_float_one",
        input_data="1",
        recipe=[
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Big Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Space",
                },
            }
        ],
        expected=struct.pack(">f", 1.0),
    ),
    BakeVector(
        name="from_float_little_endian_double_pair",
        input_data="3.141592653589793,2.5",
        recipe=[
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Double (8 bytes)",
                    "Delimiter": "Comma",
                },
            }
        ],
        expected=struct.pack("<d", 3.141592653589793) + struct.pack("<d", 2.5),
    ),
    BakeVector(
        name="from_float_roundtrip_little_endian_float_values",
        input_data=bytes.fromhex("0000803f000020c0"),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
        ],
        expected=bytes.fromhex("0000803f000020c0"),
    ),
    BakeVector(
        name="from_html_entity_named_numeric_hex_mix",
        input_data="&amp;&lt;&#169;&#x1F600;",
        recipe=["From HTML Entity"],
        expected="&<©😀",
    ),
    BakeVector(
        name="from_html_entity_preserves_unknown_entity",
        input_data="A&bogus;B",
        recipe=["From HTML Entity"],
        expected="A&bogus;B",
    ),
    BakeVector(
        name="from_html_entity_roundtrip_named_entities",
        input_data="5 < 7 & π",
        recipe=[
            {
                "op": "To HTML Entity",
                "args": {
                    "Convert all characters": False,
                    "Convert to": "Named entities",
                },
            },
            "From HTML Entity",
        ],
        expected="5 < 7 & π",
    ),
    BakeVector(
        name="from_hex_percent_delimited_ascii",
        input_data="%48%69",
        recipe=[{"op": "From Hex", "args": {"Delimiter": "Percent"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_hex_0x_with_comma_ascii",
        input_data="0x48,0x69",
        recipe=[{"op": "From Hex", "args": {"Delimiter": "0x with comma"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_hex_content_special_chars",
        input_data="foo|3d|bar",
        recipe=["From Hex Content"],
        expected=b"foo=bar",
    ),
    BakeVector(
        name="from_hex_content_preserves_invalid_segment",
        input_data="foo|zz|bar",
        recipe=["From Hex Content"],
        expected=b"foo|zz|bar",
    ),
    BakeVector(
        name="from_hex_content_roundtrip_with_spaces",
        input_data=b"foo=bar baz",
        recipe=[
            {
                "op": "To Hex Content",
                "args": {
                    "Convert": "Only special chars including spaces",
                    "Print spaces between bytes": True,
                },
            },
            "From Hex Content",
        ],
        expected=b"foo=bar baz",
    ),
    BakeVector(
        name="from_hexdump_classic_multiline",
        input_data=(
            "00000000  68 65 6C 6C 6F 00 77 6F  |hello.wo|\n"
            "00000008  72 6C 64                 |rld|\n"
            "0000000b"
        ),
        recipe=["From Hexdump"],
        expected=b"hello\x00world",
    ),
    BakeVector(
        name="from_hexdump_roundtrip_uppercase_with_final_length",
        input_data=b"hello\x00world",
        recipe=[
            {
                "op": "To Hexdump",
                "args": {
                    "Width": 8,
                    "Upper case hex": True,
                    "Include final length": True,
                    "UNIX format": False,
                },
            },
            "From Hexdump",
        ],
        expected=b"hello\x00world",
    ),
    BakeVector(
        name="from_messagepack_single_map",
        input_data=bytes.fromhex("81a16101"),
        recipe=["From MessagePack"],
        expected={"a": 1},
    ),
    BakeVector(
        name="from_messagepack_roundtrip_nested_value",
        input_data='{"a":1,"b":[true,false]}',
        recipe=["To MessagePack", "From MessagePack"],
        expected={"a": 1, "b": [True, False]},
    ),
    BakeVector(
        name="from_modhex_auto_delimited_ascii",
        input_data="fjhk",
        recipe=["From Modhex"],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_modhex_space_delimited_ascii",
        input_data="fj hk",
        recipe=[{"op": "From Modhex", "args": {"Delimiter": "Space"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_modhex_roundtrip_colon_delimited",
        input_data=b"Hi",
        recipe=[
            {"op": "To Modhex", "args": {"Delimiter": "Colon", "Bytes per line": 0}},
            {"op": "From Modhex", "args": {"Delimiter": "Colon"}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_octal_space_delimited_ascii",
        input_data="110 151",
        recipe=[{"op": "From Octal", "args": {"Delimiter": "Space"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_octal_roundtrip_utf8_greek_text",
        input_data="Γειά",
        recipe=[
            {"op": "Encode text", "args": {"Encoding": "UTF-8 (65001)"}},
            {"op": "To Octal", "args": {"Delimiter": "Space"}},
            {"op": "From Octal", "args": {"Delimiter": "Space"}},
            {"op": "Decode text", "args": {"Encoding": "UTF-8 (65001)"}},
        ],
        expected="Γειά",
    ),
    BakeVector(
        name="from_punycode_decode_label",
        input_data="mnchen-3ya",
        recipe=["From Punycode"],
        expected="münchen",
    ),
    BakeVector(
        name="from_punycode_decode_idn_domain",
        input_data="xn--mnchen-3ya.de",
        recipe=[{"op": "From Punycode", "args": {"Internationalised domain name": True}}],
        expected="münchen.de",
    ),
    BakeVector(
        name="from_punycode_roundtrip_idn_domain",
        input_data="münchen.de",
        recipe=[
            {"op": "To Punycode", "args": {"Internationalised domain name": True}},
            {"op": "From Punycode", "args": {"Internationalised domain name": True}},
        ],
        expected="münchen.de",
    ),
    BakeVector(
        name="from_quoted_printable_decode_space_escape",
        input_data="hello=20world",
        recipe=["From Quoted Printable"],
        expected=b"hello world",
    ),
    BakeVector(
        name="from_quoted_printable_remove_soft_line_break",
        input_data="soft=\r\nbreak",
        recipe=["From Quoted Printable"],
        expected=b"softbreak",
    ),
    BakeVector(
        name="from_quoted_printable_lowercase_hex_byte",
        input_data="caf=e9",
        recipe=["From Quoted Printable"],
        expected=b"caf\xe9",
    ),
    BakeVector(
        name="hex_to_pem_default_certificate_header",
        input_data=SIMPLE_DER_HEX,
        recipe=["Hex to PEM"],
        expected=SIMPLE_CERTIFICATE_PEM,
    ),
    BakeVector(
        name="hex_to_pem_custom_public_key_header",
        input_data=SIMPLE_DER_HEX,
        recipe=[{"op": "Hex to PEM", "args": {"Header string": "PUBLIC KEY"}}],
        expected=SIMPLE_PUBLIC_KEY_PEM,
    ),
    BakeVector(
        name="json_to_csv_default_row_delimiter_uses_literal_escape_sequence",
        input_data='{"a":1,"b":2}',
        recipe=["JSON to CSV"],
        expected="a,b\\r\\n1,2\\r\\n",
    ),
    BakeVector(
        name="json_to_csv_flattens_nested_object_with_explicit_crlf",
        input_data='{"a":{"b":1},"c":2}',
        recipe=[{"op": "JSON to CSV", "args": {"Cell delimiter": ",", "Row delimiter": "\r\n"}}],
        expected="a.b,c\r\n1,2\r\n",
    ),
    BakeVector(
        name="json_to_csv_custom_delimiters_with_multiline_cell",
        input_data='[[1,2],[3,"a\\nb"]]',
        recipe=[{"op": "JSON to CSV", "args": {"Cell delimiter": ";", "Row delimiter": "|"}}],
        expected='1;2|3;"a\nb"|',
    ),
    BakeVector(
        name="json_to_yaml_nested_object",
        input_data='{"a":1,"b":[2,3]}',
        recipe=["JSON to YAML"],
        expected="a: 1\nb:\n  - 2\n  - 3\n",
    ),
    BakeVector(
        name="json_to_yaml_roundtrip_via_yaml_to_json",
        input_data='{"a":1,"b":[2,3]}',
        recipe=["JSON to YAML", "YAML to JSON"],
        expected={"a": 1, "b": [2, 3]},
    ),
    BakeVector(
        name="yaml_to_json_nested_object",
        input_data="a: 1\nb:\n  - 2\n  - 3\n",
        recipe=["YAML to JSON"],
        expected={"a": 1, "b": [2, 3]},
    ),
    BakeVector(
        name="yaml_to_json_sequence_of_mappings",
        input_data="- name: alice\n  score: 10\n- name: bob\n  score: 20\n",
        recipe=["YAML to JSON"],
        expected=[{"name": "alice", "score": 10}, {"name": "bob", "score": 20}],
    ),
    BakeVector(
        name="yaml_to_json_scalar_boolean",
        input_data="true\n",
        recipe=["YAML to JSON"],
        expected=True,
    ),
    BakeVector(
        name="yaml_to_json_then_json_beautify",
        input_data="a: 1\nb:\n  - 2\n  - 3\n",
        recipe=["YAML to JSON", "JSON Beautify"],
        expected='''{
    "a": 1,
    "b": [
        2,
        3
    ]
}''',
    ),
    BakeVector(
        name="mime_decoding_q_encoded_utf8_header",
        input_data=b"Subject: =?UTF-8?Q?caf=C3=A9?=",
        recipe=["MIME Decoding"],
        expected="Subject: café",
    ),
    BakeVector(
        name="mime_decoding_folded_adjacent_encoded_words",
        input_data=b"Subject: =?UTF-8?Q?caf=C3=A9?=\r\n =?UTF-8?Q?_au_lait?=",
        recipe=["MIME Decoding"],
        expected="Subject: café au lait",
    ),
    BakeVector(
        name="mime_decoding_base64_encoded_word",
        input_data=b"Subject: =?UTF-8?B?Y2Fmw6k=?=",
        recipe=["MIME Decoding"],
        expected="Subject: café",
    ),
    BakeVector(
        name="normalise_unicode_nfd_decomposition",
        input_data="é",
        recipe=[{"op": "Normalise Unicode", "args": {"Normal Form": "NFD"}}],
        expected="é",
    ),
    BakeVector(
        name="normalise_unicode_nfkc_compatibility_digit",
        input_data="①",
        recipe=[{"op": "Normalise Unicode", "args": {"Normal Form": "NFKC"}}],
        expected="1",
    ),
    BakeVector(
        name="normalise_unicode_nfd_then_nfc_roundtrip",
        input_data="é",
        recipe=[
            {"op": "Normalise Unicode", "args": {"Normal Form": "NFD"}},
            {"op": "Normalise Unicode", "args": {"Normal Form": "NFC"}},
        ],
        expected="é",
    ),
    BakeVector(
        name="pem_to_hex_single_certificate_block",
        input_data=SIMPLE_CERTIFICATE_PEM,
        recipe=["PEM to Hex"],
        expected=SIMPLE_DER_HEX,
    ),
    BakeVector(
        name="pem_to_hex_multiple_blocks",
        input_data=SIMPLE_CERTIFICATE_PEM + SIMPLE_PUBLIC_KEY_PEM,
        recipe=["PEM to Hex"],
        expected=f"{SIMPLE_DER_HEX}\n{SIMPLE_DER_HEX}",
    ),
    BakeVector(
        name="pem_to_hex_roundtrip_via_hex_to_pem",
        input_data=SIMPLE_DER_HEX,
        recipe=["Hex to PEM", "PEM to Hex"],
        expected=SIMPLE_DER_HEX,
    ),
    BakeVector(
        name="parse_tlv_simple_tag_length_value",
        input_data=SIMPLE_TLV_HI,
        recipe=["Parse TLV"],
        expected=[{"key": [1], "length": 2, "value": [72, 105]}],
    ),
    BakeVector(
        name="parse_tlv_length_value_sequence_without_key",
        input_data=SIMPLE_LV_SEQUENCE,
        recipe=[
            {"op": "Parse TLV", "args": {"Type/Key size": 0, "Length size": 1, "Use BER": False}}
        ],
        expected=[
            {"length": 2, "value": [72, 105]},
            {"length": 3, "value": [98, 121, 101]},
        ],
    ),
    BakeVector(
        name="parse_tlv_two_byte_length_field",
        input_data=SIMPLE_TWO_BYTE_LENGTH_TLV,
        recipe=[
            {"op": "Parse TLV", "args": {"Type/Key size": 1, "Length size": 2, "Use BER": False}}
        ],
        expected=[{"key": [1], "length": 2, "value": [72, 105]}],
    ),
    BakeVector(
        name="parse_tlv_ber_short_form_length",
        input_data=SIMPLE_BER_TLV,
        recipe=[
            {"op": "Parse TLV", "args": {"Type/Key size": 1, "Length size": 1, "Use BER": True}}
        ],
        expected=[{"key": [1], "length": 2, "value": [65, 66]}],
    ),
    BakeVector(
        name="rison_encode_default_nested_object",
        input_data='{"a":1,"b":[true,"x"]}',
        recipe=["Rison Encode"],
        expected="(a:1,b:!(!t,x))",
    ),
    BakeVector(
        name="rison_encode_uri_escapes_reserved_chars",
        input_data='{"a":"a b","b":1}',
        recipe=[{"op": "Rison Encode", "args": {"Encode Option": "Encode URI"}}],
        expected="(a:'a+b',b%3A1)",
    ),
    BakeVector(
        name="rison_decode_object_option",
        input_data="a:1",
        recipe=[{"op": "Rison Decode", "args": {"Decode Option": "Decode Object"}}],
        expected={"a": 1},
    ),
    BakeVector(
        name="rison_decode_array_option",
        input_data="1,x,!f",
        recipe=[{"op": "Rison Decode", "args": {"Decode Option": "Decode Array"}}],
        expected=[1, "x", False],
    ),
    BakeVector(
        name="rison_roundtrip_default_encode_decode",
        input_data='{"a":1,"b":[true,"x"]}',
        recipe=[
            {"op": "Rison Encode", "args": {"Encode Option": "Encode"}},
            {"op": "Rison Decode", "args": {"Decode Option": "Decode"}},
        ],
        expected={"a": 1, "b": [True, "x"]},
    ),
    BakeVector(
        name="show_base64_offsets_plain_offsets_without_variable_chars",
        input_data=b"cat",
        recipe=[
            {
                "op": "Show Base64 offsets",
                "args": {
                    "Alphabet": "A-Za-z0-9+/=",
                    "Show variable chars and padding": False,
                    "Input format": "Raw",
                },
            }
        ],
        expected="Y2F0\nNhd\njYX",
    ),
    BakeVector(
        name="show_base64_offsets_base64_input_matches_raw",
        input_data=b"Y2F0",
        recipe=[
            {
                "op": "Show Base64 offsets",
                "args": {
                    "Alphabet": "A-Za-z0-9+/=",
                    "Show variable chars and padding": False,
                    "Input format": "Base64",
                },
            }
        ],
        expected="Y2F0\nNhd\njYX",
    ),
    BakeVector(
        name="show_base64_offsets_default_html_then_strip_tags",
        input_data=b"cat",
        recipe=["Show Base64 offsets", "Strip HTML tags"],
        expected=(
            "Characters highlighted in green could change if the input is surrounded by more data.\n"
            "Characters highlighted in red are for padding purposes only.\n"
            "Unhighlighted characters are static.\n"
            "Hover over the static sections to see what they decode to on their own.\n"
            "Offset 0: Y2F0\n"
            "Offset 1: AGNhdA==\n"
            "Offset 2: AABjYXQ="
        ),
    ),
    BakeVector(
        name="swap_endianness_hex_default_word_length",
        input_data="0011223344556677",
        recipe=["Swap endianness"],
        expected=build_swap_endianness_bytes(
            bytes.fromhex("0011223344556677"),
            4,
            pad_incomplete_words=True,
        ).hex(" "),
    ),
    BakeVector(
        name="swap_endianness_raw_word_length_four",
        input_data="ABCDEFGH",
        recipe=[
            {
                "op": "Swap endianness",
                "args": {
                    "Data format": "Raw",
                    "Word length (bytes)": 4,
                    "Pad incomplete words": True,
                },
            }
        ],
        expected=build_swap_endianness_bytes(
            b"ABCDEFGH",
            4,
            pad_incomplete_words=True,
        ).decode("latin1"),
    ),
    BakeVector(
        name="swap_endianness_hex_without_padding",
        input_data="0011223344",
        recipe=[
            {
                "op": "Swap endianness",
                "args": {
                    "Data format": "Hex",
                    "Word length (bytes)": 4,
                    "Pad incomplete words": False,
                },
            }
        ],
        expected=build_swap_endianness_bytes(
            bytes.fromhex("0011223344"),
            4,
            pad_incomplete_words=False,
        ).hex(" "),
    ),
    BakeVector(
        name="text_encoding_brute_force_decode_selected_encodings",
        input_data=b"caf\xc3\xa9",
        recipe=[
            {"op": "Text Encoding Brute Force", "args": {"Mode": "Decode"}},
            {
                "op": "Jq",
                "args": {
                    "Query": '{"utf8": .["UTF-8 (65001)"], "cp500": .["IBM EBCDIC International (500)"]}'
                },
            },
        ],
        expected='{"utf8":"café","cp500":"Ä/ÃCz"}',
    ),
    BakeVector(
        name="text_encoding_brute_force_encode_selected_encodings",
        input_data="café",
        recipe=[
            {"op": "Text Encoding Brute Force", "args": {"Mode": "Encode"}},
            {
                "op": "Jq",
                "args": {
                    "Query": '{"utf8": .["UTF-8 (65001)"], "cp500": .["IBM EBCDIC International (500)"]}'
                },
            },
        ],
        expected='{"utf8":"cafÃ©","cp500":"\x83\x81\x86Q"}',
    ),
    BakeVector(
        name="to_bcd_packed_nibbles_1234",
        input_data="1234",
        recipe=["To BCD"],
        expected="0001 0010 0011 0100",
    ),
    BakeVector(
        name="to_bcd_unpacked_bytes_123",
        input_data="123",
        recipe=[
            {
                "op": "To BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": False,
                    "Signed": False,
                    "Output format": "Bytes",
                },
            }
        ],
        expected="00000001 00000010 00000011",
    ),
    BakeVector(
        name="to_bcd_signed_negative_12",
        input_data="-12",
        recipe=[
            {
                "op": "To BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": True,
                    "Output format": "Nibbles",
                },
            }
        ],
        expected="0000 0001 0010 1101",
    ),
    BakeVector(
        name="to_bcd_then_from_bcd_roundtrip",
        input_data="1234",
        recipe=[
            {
                "op": "To BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": False,
                    "Output format": "Nibbles",
                },
            },
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": False,
                    "Input format": "Nibbles",
                },
            },
        ],
        expected="1234",
    ),
    BakeVector(
        name="to_base_hex_255",
        input_data="255",
        recipe=[{"op": "To Base", "args": {"Radix": 16}}],
        expected=build_base_string(255, 16),
    ),
    BakeVector(
        name="to_base_binary_10",
        input_data="10",
        recipe=[{"op": "To Base", "args": {"Radix": 2}}],
        expected=build_base_string(10, 2),
    ),
    BakeVector(
        name="to_base_roundtrip_via_from_base",
        input_data="255",
        recipe=[
            {"op": "To Base", "args": {"Radix": 16}},
            {"op": "From Base", "args": {"Radix": 16}},
        ],
        expected="255",
    ),
    BakeVector(
        name="to_base32_hex_extended_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base32", "args": {"Alphabet": "0-9A-V="}}],
        expected=base64.b32hexencode(b"hello").decode(),
    ),
    BakeVector(
        name="to_base32_roundtrip_hex_extended_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=[
            {"op": "To Base32", "args": {"Alphabet": "0-9A-V="}},
            {
                "op": "From Base32",
                "args": {"Alphabet": "0-9A-V=", "Remove non-alphabet chars": True},
            },
        ],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="to_base45_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base45"],
        expected=build_base45(b"hello"),
    ),
    BakeVector(
        name="to_base45_custom_alphabet_pattern",
        input_data=b"AB",
        recipe=[{"op": "To Base45", "args": {"Alphabet": "A-Z0-9 $%*+\\-./:"}}],
        expected=build_base45(b"AB", build_expanded_alphabet("A-Z0-9 $%*+\\-./:")),
    ),
    BakeVector(
        name="to_base45_roundtrip_ascii_bytes",
        input_data=b"phase 13",
        recipe=["To Base45", "From Base45"],
        expected=b"phase 13",
    ),
    BakeVector(
        name="to_base58_ripple_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base58", "args": {"Alphabet": BASE58_RIPPLE_ALPHABET}}],
        expected=build_base58(b"hello", BASE58_RIPPLE_ALPHABET),
    ),
    BakeVector(
        name="to_base58_ripple_roundtrip_leading_zero_bytes",
        input_data=b"\x00\x00hello",
        recipe=[
            {"op": "To Base58", "args": {"Alphabet": BASE58_RIPPLE_ALPHABET}},
            {
                "op": "From Base58",
                "args": {
                    "Alphabet": BASE58_RIPPLE_ALPHABET,
                    "Remove non-alphabet chars": True,
                },
            },
        ],
        expected=b"\x00\x00hello",
    ),
    BakeVector(
        name="to_base62_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base62"],
        expected=build_base62(b"hello"),
    ),
    BakeVector(
        name="to_base62_custom_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base62", "args": {"Alphabet": "0-9a-zA-Z"}}],
        expected=build_base62(b"hello", build_expanded_alphabet("0-9a-zA-Z")),
    ),
    BakeVector(
        name="to_base62_roundtrip_custom_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[
            {"op": "To Base62", "args": {"Alphabet": "0-9a-zA-Z"}},
            {"op": "From Base62", "args": {"Alphabet": "0-9a-zA-Z"}},
        ],
        expected=b"hello",
    ),
    BakeVector(
        name="to_base64_urlsafe_binary_edge_bytes",
        input_data=b"\xfb\xef\xff",
        recipe=[{"op": "To Base64", "args": {"Alphabet": "A-Za-z0-9-_"}}],
        expected=build_base64_with_alphabet(b"\xfb\xef\xff", "A-Za-z0-9-_"),
    ),
    BakeVector(
        name="to_base64_rot13_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base64", "args": {"Alphabet": "N-ZA-Mn-za-m0-9+/="}}],
        expected=build_base64_with_alphabet(b"hello", "N-ZA-Mn-za-m0-9+/="),
    ),
    BakeVector(
        name="to_base64_roundtrip_urlsafe_binary_edge_bytes",
        input_data=b"\xfb\xef\xff",
        recipe=[
            {"op": "To Base64", "args": {"Alphabet": "A-Za-z0-9-_"}},
            {
                "op": "From Base64",
                "args": {
                    "Alphabet": "A-Za-z0-9-_",
                    "Remove non-alphabet chars": True,
                    "Strict mode": False,
                },
            },
        ],
        expected=b"\xfb\xef\xff",
    ),
    BakeVector(
        name="to_base85_zero_group_standard_ascii85",
        input_data=b"\x00\x00\x00\x00",
        recipe=["To Base85"],
        expected="z",
    ),
    BakeVector(
        name="to_base85_include_delimiter_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base85", "args": {"Alphabet": "!-u", "Include delimeter": True}}],
        expected=base64.a85encode(b"hello", adobe=True).decode(),
    ),
    BakeVector(
        name="to_base85_roundtrip_with_delimiter_ascii_bytes",
        input_data=b"hello",
        recipe=[
            {"op": "To Base85", "args": {"Alphabet": "!-u", "Include delimeter": True}},
            {
                "op": "From Base85",
                "args": {
                    "Alphabet": "!-u",
                    "Remove non-alphabet chars": True,
                    "All-zero group char": "z",
                },
            },
        ],
        expected=b"hello",
    ),
    BakeVector(
        name="to_base92_empty_string",
        input_data="",
        recipe=["To Base92"],
        expected=b"",
    ),
    BakeVector(
        name="to_base92_ascii_string",
        input_data="hello",
        recipe=["To Base92"],
        expected=build_base92(b"hello").encode(),
    ),
    BakeVector(
        name="to_base92_roundtrip_ascii_string",
        input_data="hello",
        recipe=["To Base92", "From Base92"],
        expected=b"hello",
    ),
    BakeVector(
        name="to_binary_default_ascii_bytes",
        input_data=b"Hi",
        recipe=["To Binary"],
        expected=build_binary_string(b"Hi", "Space", 8),
    ),
    BakeVector(
        name="to_binary_nibble_groups_without_delimiter",
        input_data=b"\x01\x02\x03\x04",
        recipe=[{"op": "To Binary", "args": {"Delimiter": "None", "Byte Length": 4}}],
        expected=build_binary_string(b"\x01\x02\x03\x04", "None", 4),
    ),
    BakeVector(
        name="to_binary_roundtrip_colon_delimited_ascii_bytes",
        input_data=b"Hi",
        recipe=[
            {"op": "To Binary", "args": {"Delimiter": "Colon", "Byte Length": 8}},
            {"op": "From Binary", "args": {"Delimiter": "Colon", "Byte Length": 8}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="to_braille_hello_text",
        input_data="Hello",
        recipe=["To Braille"],
        expected=build_braille("Hello"),
    ),
    BakeVector(
        name="to_braille_punctuation_text",
        input_data="Hi!",
        recipe=["To Braille"],
        expected=build_braille("Hi!"),
    ),
    BakeVector(
        name="to_braille_roundtrip_ascii_text_uppercases_output",
        input_data="Hello?",
        recipe=["To Braille", "From Braille"],
        expected="HELLO?",
    ),
    BakeVector(
        name="to_charcode_base10_comma_ascii",
        input_data="Hello",
        recipe=[{"op": "To Charcode", "args": {"Delimiter": "Comma", "Base": 10}}],
        expected=build_charcode_string("Hello", "Comma", 10),
    ),
    BakeVector(
        name="to_charcode_hex_greek_text",
        input_data="Γειά σου",
        recipe=["To Charcode"],
        expected=build_charcode_string("Γειά σου", "Space", 16),
    ),
    BakeVector(
        name="to_charcode_roundtrip_colon_hex_ascii",
        input_data="Hello",
        recipe=[
            {"op": "To Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
            {"op": "From Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
        ],
        expected=b"Hello",
    ),
    BakeVector(
        name="to_decimal_default_space_ascii_bytes",
        input_data=b"Hi",
        recipe=["To Decimal"],
        expected=build_decimal_string(b"Hi", "Space", signed=False),
    ),
    BakeVector(
        name="to_decimal_signed_comma_values",
        input_data=b"\xff\x80\x7f",
        recipe=[{"op": "To Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}}],
        expected=build_decimal_string(b"\xff\x80\x7f", "Comma", signed=True),
    ),
    BakeVector(
        name="to_decimal_roundtrip_signed_values",
        input_data=b"\xff\x80\x7f",
        recipe=[
            {"op": "To Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
            {"op": "From Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
        ],
        expected=b"\xff\x80\x7f",
    ),
    BakeVector(
        name="to_float_big_endian_float_one",
        input_data=struct.pack(">f", 1.0),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Big Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Space",
                },
            }
        ],
        expected="1",
    ),
    BakeVector(
        name="to_float_little_endian_double_pair",
        input_data=struct.pack("<d", 3.141592653589793) + struct.pack("<d", 2.5),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Double (8 bytes)",
                    "Delimiter": "Comma",
                },
            }
        ],
        expected="3.141592653589793,2.5",
    ),
    BakeVector(
        name="to_float_roundtrip_little_endian_float_values",
        input_data=bytes.fromhex("0000803f000020c0"),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
        ],
        expected=bytes.fromhex("0000803f000020c0"),
    ),
    BakeVector(
        name="to_html_entity_named_entities_with_astral_code_point",
        input_data="&<©😀",
        recipe=["To HTML Entity"],
        expected="&amp;&lt;&copy;&#62976;",
    ),
    BakeVector(
        name="to_html_entity_numeric_entities_for_all_characters",
        input_data="Aβ",
        recipe=[{"op": "To HTML Entity", "args": {"Convert all characters": True, "Convert to": "Numeric entities"}}],
        expected="&#65;&#946;",
    ),
    BakeVector(
        name="to_html_entity_hex_entities_preserve_ascii",
        input_data="&A😀",
        recipe=[{"op": "To HTML Entity", "args": {"Convert all characters": False, "Convert to": "Hex entities"}}],
        expected="&#x26;A&#xf600;",
    ),
    BakeVector(
        name="to_html_entity_roundtrip_named_entities",
        input_data="5 < 7 & π",
        recipe=[
            {
                "op": "To HTML Entity",
                "args": {
                    "Convert all characters": False,
                    "Convert to": "Named entities",
                },
            },
            "From HTML Entity",
        ],
        expected="5 < 7 & π",
    ),
    BakeVector(
        name="to_hex_percent_delimited_ascii_bytes",
        input_data=b"Hi",
        recipe=[{"op": "To Hex", "args": {"Delimiter": "Percent", "Bytes per line": 0}}],
        expected="48%69",
    ),
    BakeVector(
        name="to_hex_percent_roundtrip_ascii_bytes",
        input_data=b"Hi",
        recipe=[
            {"op": "To Hex", "args": {"Delimiter": "Percent", "Bytes per line": 0}},
            {"op": "From Hex", "args": {"Delimiter": "Percent"}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="to_hex_content_special_chars_including_spaces",
        input_data=b"foo=bar baz",
        recipe=[
            {
                "op": "To Hex Content",
                "args": {
                    "Convert": "Only special chars including spaces",
                    "Print spaces between bytes": False,
                },
            }
        ],
        expected="foo|3d|bar|20|baz",
    ),
    BakeVector(
        name="to_hex_content_all_chars_with_byte_spacing",
        input_data=b"Hi",
        recipe=[
            {
                "op": "To Hex Content",
                "args": {"Convert": "All chars", "Print spaces between bytes": True},
            }
        ],
        expected="|48 69|",
    ),
    BakeVector(
        name="to_hexdump_empty_bytes",
        input_data=b"",
        recipe=["To Hexdump"],
        expected="",
    ),
    BakeVector(
        name="to_hexdump_multiline_uppercase_with_final_length",
        input_data=b"hello\x00world",
        recipe=[
            {
                "op": "To Hexdump",
                "args": {
                    "Width": 8,
                    "Upper case hex": True,
                    "Include final length": True,
                    "UNIX format": True,
                },
            }
        ],
        expected=(
            "00000000  68 65 6C 6C 6F 00 77 6F  |hello.wo|\n"
            "00000008  72 6C 64                 |rld|\n"
            "0000000b"
        ),
    ),
    BakeVector(
        name="to_messagepack_empty_object",
        input_data="{}",
        recipe=["To MessagePack"],
        expected=b"\x80",
    ),
    BakeVector(
        name="to_messagepack_single_map",
        input_data='{"a":1}',
        recipe=["To MessagePack"],
        expected=bytes.fromhex("81a16101"),
    ),
    BakeVector(
        name="to_modhex_default_ascii_bytes",
        input_data=b"Hi",
        recipe=["To Modhex"],
        expected="fj hk",
    ),
    BakeVector(
        name="to_modhex_custom_colon_delimiter",
        input_data=b"Hi",
        recipe=[{"op": "To Modhex", "args": {"Delimiter": "Colon", "Bytes per line": 0}}],
        expected="fj:hk",
    ),
    BakeVector(
        name="to_octal_colon_delimited_utf8_greek_text",
        input_data="Γειά",
        recipe=[
            {"op": "Encode text", "args": {"Encoding": "UTF-8 (65001)"}},
            {"op": "To Octal", "args": {"Delimiter": "Colon"}},
        ],
        expected="316:223:316:265:316:271:316:254",
    ),
    BakeVector(
        name="to_octal_colon_roundtrip_ascii_bytes",
        input_data=b"Hi",
        recipe=[
            {"op": "To Octal", "args": {"Delimiter": "Colon"}},
            {"op": "From Octal", "args": {"Delimiter": "Colon"}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="to_punycode_label",
        input_data="münchen",
        recipe=["To Punycode"],
        expected="mnchen-3ya",
    ),
    BakeVector(
        name="to_punycode_idn_domain",
        input_data="münchen.de",
        recipe=[{"op": "To Punycode", "args": {"Internationalised domain name": True}}],
        expected="xn--mnchen-3ya.de",
    ),
    BakeVector(
        name="to_quoted_printable_empty_bytes",
        input_data=b"",
        recipe=["To Quoted Printable"],
        expected="",
    ),
    BakeVector(
        name="to_quoted_printable_latin1_bytes",
        input_data=b"caf\xe9",
        recipe=["To Quoted Printable"],
        expected="caf=E9",
    ),
    BakeVector(
        name="to_quoted_printable_wraps_long_lines_with_crlf",
        input_data=b"A" * 80,
        recipe=["To Quoted Printable"],
        expected=("A" * 75) + "=\r\nAAAAA",
    ),
    BakeVector(
        name="to_quoted_printable_roundtrip_binary_bytes",
        input_data=b"hello world=\xff",
        recipe=["To Quoted Printable", "From Quoted Printable"],
        expected=b"hello world=\xff",
    ),
    BakeVector(
        name="url_decode_plus_as_space",
        input_data="a+b%20c",
        recipe=["URL Decode"],
        expected="a b c",
    ),
    BakeVector(
        name="url_decode_preserve_plus",
        input_data="a+b%20c",
        recipe=[{"op": "URL Decode", "args": {"Treat \"+\" as space": False}}],
        expected="a+b c",
    ),
    BakeVector(
        name="url_encode_default_preserves_reserved_uri_chars",
        input_data="a/b?c=d&e=f",
        recipe=["URL Encode"],
        expected="a/b?c=d&e=f",
    ),
    BakeVector(
        name="url_encode_all_special_chars",
        input_data="a+b c=/",
        recipe=[{"op": "URL Encode", "args": {"Encode all special chars": True}}],
        expected="a%2Bb%20c%3D%2F",
    ),
    BakeVector(
        name="url_encode_decode_roundtrip_utf8_text",
        input_data="café",
        recipe=["URL Encode", "URL Decode"],
        expected="café",
    ),
]

COMPRESSION_BLOCKED_VECTORS = []

COMPRESSION_VECTORS = [
    BakeVector(
        name="bzip2_compress_python_reference_stream",
        input_data=b"hello hello hello",
        recipe=["Bzip2 Compress"],
        expected=bz2.compress(b"hello hello hello"),
    ),
    BakeVector(
        name="bzip2_decompress_python_reference_stream",
        input_data=bz2.compress(b"hello hello hello"),
        recipe=["Bzip2 Decompress"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="gzip_empty_roundtrip",
        input_data=b"",
        recipe=["Gzip", "Gunzip"],
        expected=b"",
    ),
    BakeVector(
        name="gunzip_python_reference_stream",
        input_data=gzip.compress(b"hello hello hello", mtime=0),
        recipe=["Gunzip"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="gzip_fixed_huffman_with_metadata_roundtrip",
        input_data=b"hello hello hello",
        recipe=[
            {
                "op": "Gzip",
                "args": {
                    "Compression type": "Fixed Huffman Coding",
                    "Filename (optional)": "sample.txt",
                    "Comment (optional)": "phase7",
                },
            },
            "Gunzip",
        ],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="lz4_compress_empty_bytes",
        input_data=b"",
        recipe=["LZ4 Compress"],
        expected=bytes.fromhex("04224d184070df00000000"),
    ),
    BakeVector(
        name="lz4_compress_repeated_ascii",
        input_data=b"hello hello hello",
        recipe=["LZ4 Compress"],
        expected=HELLO_HELLO_HELLO_LZ4_FRAME,
    ),
    BakeVector(
        name="lz4_decompress_repeated_ascii",
        input_data=HELLO_HELLO_HELLO_LZ4_FRAME,
        recipe=["LZ4 Decompress"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="lz4_roundtrip_binary_edge_bytes",
        input_data=bytes(range(64)),
        recipe=["LZ4 Compress", "LZ4 Decompress"],
        expected=bytes(range(64)),
    ),
    BakeVector(
        name="lzma_compress_default_mode",
        input_data=b"hello hello hello",
        recipe=["LZMA Compress"],
        expected=HELLO_HELLO_HELLO_LZMA_STREAM,
    ),
    BakeVector(
        name="lzma_decompress_known_size_stream",
        input_data=HELLO_HELLO_HELLO_LZMA_STREAM,
        recipe=["LZMA Decompress"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="lzma_roundtrip_mode_one",
        input_data=bytes(range(64)),
        recipe=[
            {"op": "LZMA Compress", "args": {"Compression Mode": "1"}},
            "LZMA Decompress",
        ],
        expected=bytes(range(64)),
    ),
    BakeVector(
        name="lznt1_decompress_empty_bytes",
        input_data=b"",
        recipe=["LZNT1 Decompress"],
        expected=b"",
    ),
    BakeVector(
        name="lznt1_decompress_upstream_reference_sample",
        input_data=LZNT1_COMPRESSED_SAMPLE,
        recipe=["LZNT1 Decompress"],
        expected=b"compressedtestdatacompressedalot",
    ),
    BakeVector(
        name="lzstring_compress_empty_string",
        input_data="",
        recipe=["LZString Compress"],
        expected="䀀",
    ),
    BakeVector(
        name="lzstring_compress_default_format",
        input_data="hello hello hello",
        recipe=["LZString Compress"],
        expected="օ〶惶J፲退",
    ),
    BakeVector(
        name="lzstring_compress_base64_format",
        input_data="hello hello hello",
        recipe=[{"op": "LZString Compress", "args": {"Compression Format": "Base64"}}],
        expected="BYUwNmD2AEoTcpA=",
    ),
    BakeVector(
        name="lzstring_decompress_empty_payload",
        input_data="䀀",
        recipe=["LZString Decompress"],
        expected="",
    ),
    BakeVector(
        name="lzstring_decompress_default_format",
        input_data="օ〶惶J፲退",
        recipe=["LZString Decompress"],
        expected="hello hello hello",
    ),
    BakeVector(
        name="lzstring_decompress_base64_format",
        input_data="BYUwNmD2AEoTcpA=",
        recipe=[{"op": "LZString Decompress", "args": {"Compression Format": "Base64"}}],
        expected="hello hello hello",
    ),
    BakeVector(
        name="lzstring_roundtrip_utf16_format",
        input_data="phase 8 ✓ café",
        recipe=[
            {"op": "LZString Compress", "args": {"Compression Format": "UTF16"}},
            {"op": "LZString Decompress", "args": {"Compression Format": "UTF16"}},
        ],
        expected="phase 8 ✓ café",
    ),
    BakeVector(
        name="raw_deflate_fixed_huffman_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Raw Deflate", "args": {"Compression type": "Fixed Huffman Coding"}}],
        expected=HELLO_HELLO_HELLO_RAW_DEFLATE_FIXED_STREAM,
    ),
    BakeVector(
        name="raw_deflate_none_store_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Raw Deflate", "args": {"Compression type": "None (Store)"}}],
        expected=HELLO_HELLO_HELLO_RAW_DEFLATE_STORE_STREAM,
    ),
    BakeVector(
        name="raw_inflate_none_store_ascii",
        input_data=HELLO_HELLO_HELLO_RAW_DEFLATE_STORE_STREAM,
        recipe=["Raw Inflate"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="raw_inflate_start_index_with_block_buffer",
        input_data=b"HEAD" + HELLO_HELLO_HELLO_RAW_DEFLATE_STREAM,
        recipe=[
            {
                "op": "Raw Inflate",
                "args": {
                    "Start index": 4,
                    "Buffer expansion type": "Block",
                    "Resize buffer after decompression": True,
                    "Verify result": True,
                },
            }
        ],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="raw_roundtrip_binary_edge_bytes",
        input_data=bytes(range(64)),
        recipe=["Raw Deflate", "Raw Inflate"],
        expected=bytes(range(64)),
    ),
    BakeVector(
        name="tar_untar_python_reference_archive",
        input_data=build_tar_archive("sample.bin", b"hello hello hello"),
        recipe=["Untar"],
        expected=build_file_listing("sample.bin", b"hello hello hello"),
    ),
    BakeVector(
        name="tar_untar_roundtrip_binary_edge_bytes",
        input_data=bytes(range(32)),
        recipe=[{"op": "Tar", "args": {"Filename": "edge.bin"}}, "Untar"],
        expected=build_file_listing("edge.bin", bytes(range(32))),
    ),
    BakeVector(
        name="unzip_python_reference_stored_archive",
        input_data=build_zip_archive("sample.bin", b"hello hello hello", compression=zipfile.ZIP_STORED),
        recipe=[{"op": "Unzip", "args": {"Verify result": True}}],
        expected=build_file_listing("sample.bin", b"hello hello hello"),
    ),
    BakeVector(
        name="zip_unzip_roundtrip_stored_bytes",
        input_data=bytes(range(32)),
        recipe=[
            {
                "op": "Zip",
                "args": {
                    "Filename": "edge.bin",
                    "Compression method": "None (Store)",
                    "Operating system": "Unix",
                },
            },
            {"op": "Unzip", "args": {"Verify result": True}},
        ],
        expected=build_file_listing("edge.bin", bytes(range(32))),
    ),
    BakeVector(
        name="zlib_deflate_fixed_huffman_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Zlib Deflate", "args": {"Compression type": "Fixed Huffman Coding"}}],
        expected=HELLO_HELLO_HELLO_ZLIB_FIXED_STREAM,
    ),
    BakeVector(
        name="zlib_deflate_none_store_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Zlib Deflate", "args": {"Compression type": "None (Store)"}}],
        expected=HELLO_HELLO_HELLO_ZLIB_STORE_STREAM,
    ),
    BakeVector(
        name="zlib_inflate_none_store_ascii",
        input_data=HELLO_HELLO_HELLO_ZLIB_STORE_STREAM,
        recipe=["Zlib Inflate"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="zlib_inflate_start_index_with_block_buffer",
        input_data=b"HEAD" + HELLO_HELLO_HELLO_ZLIB_STREAM,
        recipe=[
            {
                "op": "Zlib Inflate",
                "args": {
                    "Start index": 4,
                    "Buffer expansion type": "Block",
                    "Resize buffer after decompression": True,
                    "Verify result": True,
                },
            }
        ],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="zlib_roundtrip_binary_edge_bytes",
        input_data=bytes(range(64)),
        recipe=["Zlib Deflate", "Zlib Inflate"],
        expected=bytes(range(64)),
    ),
]

DATE_TIME_VECTORS = [
    BakeVector(
        name="datetime_delta_add_across_leap_day_boundary",
        input_data="2024-02-29 23:59:30",
        recipe=[
            {
                "op": "DateTime Delta",
                "args": {
                    "Built in formats": "International date and time",
                    "Input format string": "YYYY-MM-DD HH:mm:ss",
                    "Time Operation": "Add",
                    "Days": 1,
                    "Hours": 0,
                    "Minutes": 1,
                    "Seconds": 45,
                },
            }
        ],
        expected=build_datetime_delta_string(
            "2024-02-29 23:59:30",
            days=1,
            minutes=1,
            seconds=45,
        ),
    ),
    BakeVector(
        name="datetime_delta_subtract_across_previous_day",
        input_data="2024-03-01 00:00:00",
        recipe=[
            {
                "op": "DateTime Delta",
                "args": {
                    "Built in formats": "International date and time",
                    "Input format string": "YYYY-MM-DD HH:mm:ss",
                    "Time Operation": "Subtract",
                    "Days": 1,
                    "Hours": 0,
                    "Minutes": 0,
                    "Seconds": 1,
                },
            }
        ],
        expected=build_datetime_delta_string("2024-03-01 00:00:00", days=-1, seconds=-1),
    ),
    BakeVector(
        name="extract_dates_supported_formats",
        input_data="ignore 2024-02-29 and 03/01/2024 plus 12.31.2025",
        recipe=["Extract dates"],
        expected="2024-02-29\n03/01/2024\n12.31.2025",
    ),
    BakeVector(
        name="extract_dates_display_total",
        input_data="ignore 2024-02-29 and 03/01/2024 plus 12.31.2025",
        recipe=[{"op": "Extract dates", "args": {"Display total": True}}],
        expected="Total found: 3\n\n2024-02-29\n03/01/2024\n12.31.2025",
    ),
    BakeVector(
        name="from_unix_timestamp_seconds_epoch_example",
        input_data="978346800",
        recipe=["From UNIX Timestamp"],
        expected=build_from_unix_timestamp_string("978346800", "Seconds (s)"),
    ),
    BakeVector(
        name="from_unix_timestamp_milliseconds_epoch_example",
        input_data="978346800000",
        recipe=[{"op": "From UNIX Timestamp", "args": {"Units": "Milliseconds (ms)"}}],
        expected=build_from_unix_timestamp_string("978346800000", "Milliseconds (ms)"),
    ),
    BakeVector(
        name="parse_datetime_utc_details",
        input_data="2015-06-15 20:45:00",
        recipe=[
            {
                "op": "Parse DateTime",
                "args": {
                    "Built in formats": "International date and time",
                    "Input format string": "YYYY-MM-DD HH:mm:ss",
                    "Input timezone": "UTC",
                },
            }
        ],
        expected=build_parse_datetime_output(datetime(2015, 6, 15, 20, 45, 0, tzinfo=timezone.utc)),
    ),
    BakeVector(
        name="to_unix_timestamp_seconds_with_parsed_datetime",
        input_data="Mon 1 January 2001 11:00:00",
        recipe=["To UNIX Timestamp"],
        expected=build_to_unix_timestamp_string(
            "Mon 1 January 2001 11:00:00",
            units="Seconds (s)",
            show_parsed_datetime=True,
        ),
    ),
    BakeVector(
        name="to_unix_timestamp_milliseconds_without_parsed_datetime",
        input_data="Mon 1 January 2001 11:00:00",
        recipe=[
            {
                "op": "To UNIX Timestamp",
                "args": {
                    "Units": "Milliseconds (ms)",
                    "Treat as UTC": True,
                    "Show parsed datetime": False,
                },
            }
        ],
        expected=build_to_unix_timestamp_string(
            "Mon 1 January 2001 11:00:00",
            units="Milliseconds (ms)",
            show_parsed_datetime=False,
        ),
    ),
    BakeVector(
        name="translate_datetime_format_utc_to_queensland",
        input_data="15/06/2015 20:45:00",
        recipe=[
            {
                "op": "Translate DateTime Format",
                "args": {
                    "Built in formats": "Standard date and time",
                    "Input format string": "DD/MM/YYYY HH:mm:ss",
                    "Input timezone": "UTC",
                    "Output format string": "YYYY-MM-DD HH:mm:ss Z z",
                    "Output timezone": "Australia/Queensland",
                },
            }
        ],
        expected=build_translated_datetime_output(
            "15/06/2015 20:45:00",
            input_format="%d/%m/%Y %H:%M:%S",
            input_timezone="UTC",
            output_timezone="Australia/Queensland",
        ),
    ),
    BakeVector(
        name="unix_timestamp_to_windows_filetime_decimal_seconds",
        input_data="978346800",
        recipe=["UNIX Timestamp to Windows Filetime"],
        expected=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Decimal",
        ),
    ),
    BakeVector(
        name="unix_timestamp_to_windows_filetime_hex_little_endian",
        input_data="978346800",
        recipe=[
            {
                "op": "UNIX Timestamp to Windows Filetime",
                "args": {
                    "Input units": "Seconds (s)",
                    "Output format": "Hex (little endian)",
                },
            }
        ],
        expected=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Hex (little endian)",
        ),
    ),
    BakeVector(
        name="windows_filetime_to_unix_timestamp_decimal_seconds",
        input_data=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Decimal",
        ),
        recipe=["Windows Filetime to UNIX Timestamp"],
        expected="978346800",
    ),
    BakeVector(
        name="windows_filetime_to_unix_timestamp_hex_little_endian_milliseconds",
        input_data=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Hex (little endian)",
        ),
        recipe=[
            {
                "op": "Windows Filetime to UNIX Timestamp",
                "args": {
                    "Output units": "Milliseconds (ms)",
                    "Input format": "Hex (little endian)",
                },
            }
        ],
        expected=build_unix_timestamp_from_windows_filetime_string(
            build_windows_filetime_string(
                "978346800",
                units="Seconds (s)",
                output_format="Hex (little endian)",
            ),
            output_units="Milliseconds (ms)",
            input_format="Hex (little endian)",
        ),
    ),
]

EXTRACTOR_VECTORS = [
    BakeVector(
        name="css_selector_extracts_multiple_elements_with_custom_delimiter",
        input_data='<div><span class="x">a</span><span class="x">b</span></div>',
        recipe=[{"op": "CSS selector", "args": {"CSS selector": ".x", "Delimiter": "|"}}],
        expected='<span class="x">a</span>|<span class="x">b</span>',
    ),
    BakeVector(
        name="extract_exif_reads_minimal_make_tag",
        input_data=MINIMAL_EXIF_JPEG,
        recipe=["Extract EXIF"],
        expected="Found 1 tags.\n\nMake: Canon",
    ),
    BakeVector(
        name="extract_files_carves_embedded_zip_archive",
        input_data=b"JUNK" + build_zip_archive("a.txt", b"hello", compression=zipfile.ZIP_STORED) + b"TAIL",
        recipe=["Extract Files"],
        expected=[
            {
                "name": "extracted_at_0x4.zip",
                "type": "application/zip",
                "data": build_zip_archive("a.txt", b"hello", compression=zipfile.ZIP_STORED),
            }
        ],
    ),
    BakeVector(
        name="extract_id3_reads_minimal_title_frame",
        input_data=MINIMAL_ID3_TAG,
        recipe=["Extract ID3"],
        expected={
            "Type": "ID3",
            "Version": "3.0",
            "Flags": "0",
            "Size": "16",
            "Tags": {
                "TT2": {
                    "Size": "6",
                    "Description": "Title/Songname/Content description",
                    "Data": "Title",
                }
            },
        },
    ),
    BakeVector(
        name="extract_ip_addresses_includes_ipv6_and_removes_local_ipv4",
        input_data="10.0.0.1 xx 8.8.8.8 yy 2001:db8::1 zz 172.16.0.5 aa 127.0.0.1",
        recipe=[
            {
                "op": "Extract IP addresses",
                "args": {
                    "IPv4": True,
                    "IPv6": True,
                    "Remove local IPv4 addresses": True,
                    "Display total": True,
                },
            }
        ],
        expected="Total found: 2\n\n8.8.8.8\n2001:db8::1",
    ),
    BakeVector(
        name="extract_mac_addresses_counts_unique_results",
        input_data="AA:BB:CC:DD:EE:FF xx 11-22-33-44-55-66 yy AA:BB:CC:DD:EE:FF",
        recipe=[{"op": "Extract MAC addresses", "args": {"Display total": True, "Unique": True}}],
        expected="Total found: 2\n\nAA:BB:CC:DD:EE:FF\n11-22-33-44-55-66",
    ),
    BakeVector(
        name="extract_urls_counts_unique_results",
        input_data="ftp://b.example/file https://example.com/x https://example.com/x",
        recipe=[{"op": "Extract URLs", "args": {"Display total": True, "Unique": True}}],
        expected="Total found: 2\n\nftp://b.example/file\nhttps://example.com/x",
    ),
    BakeVector(
        name="extract_domains_supports_underscore_labels",
        input_data="mail _dmarc.example.org and selector._domainkey.example.org and plain example.com and example.com",
        recipe=[
            {
                "op": "Extract domains",
                "args": {
                    "Display total": True,
                    "Unique": True,
                    "Underscore (DMARC, DKIM, etc)": True,
                },
            }
        ],
        expected="Total found: 3\n\n_dmarc.example.org\nselector._domainkey.example.org\nexample.com",
    ),
    BakeVector(
        name="extract_email_addresses_counts_unique_results",
        input_data="z@example.com bob@example.com z@example.com",
        recipe=[{"op": "Extract email addresses", "args": {"Display total": True, "Unique": True}}],
        expected="Total found: 2\n\nz@example.com\nbob@example.com",
    ),
    BakeVector(
        name="extract_file_paths_can_limit_to_windows_paths",
        input_data=r"C:\Temp\file.txt /usr/local/bin ./rel",
        recipe=[
            {
                "op": "Extract file paths",
                "args": {
                    "Windows": True,
                    "UNIX": False,
                    "Display total": True,
                    "Unique": True,
                },
            }
        ],
        expected="Total found: 1\n\nC:\\Temp\\file.txt",
    ),
    BakeVector(
        name="extract_hashes_defaults_to_sha1_length",
        input_data="md5 9e107d9d372bb6826bd81d3542a419d6 sha1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        recipe=["Extract hashes"],
        expected="2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
    ),
    BakeVector(
        name="extract_hashes_can_find_multiple_lengths_and_count_results",
        input_data=(
            "MD5: 9e107d9d372bb6826bd81d3542a419d6\n"
            "SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n"
            "SHA256: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        ),
        recipe=[{"op": "Extract hashes", "args": {"All hashes": True, "Display Total": True}}],
        expected=(
            "Total Results: 3\n\n"
            "9e107d9d372bb6826bd81d3542a419d6\n"
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n"
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        ),
    ),
    BakeVector(
        name="jpath_expression_extracts_scalar_results_with_custom_delimiter",
        input_data=json.dumps(
            {
                "store": {
                    "book": [
                        {"author": "Nigel Rees"},
                        {"author": "Evelyn Waugh"},
                        {"author": "Herman Melville"},
                    ]
                }
            }
        ),
        recipe=[
            {
                "op": "JPath expression",
                "args": {"Query": "$.store.book[*].author", "Result delimiter": "|"},
            }
        ],
        expected='"Nigel Rees"|"Evelyn Waugh"|"Herman Melville"',
    ),
    BakeVector(
        name="jpath_expression_filters_matching_objects",
        input_data=json.dumps(
            {
                "store": {
                    "book": [
                        {"author": "Nigel Rees", "price": 8.95},
                        {"author": "Evelyn Waugh", "price": 12.99},
                        {"author": "Herman Melville", "price": 8.99},
                    ]
                }
            }
        ),
        recipe=[
            {
                "op": "JPath expression",
                "args": {"Query": "$..book[?(@.price<10)]", "Result delimiter": "\n"},
            }
        ],
        expected="\n".join(
            [
                json.dumps({"author": "Nigel Rees", "price": 8.95}, separators=(",", ":")),
                json.dumps({"author": "Herman Melville", "price": 8.99}, separators=(",", ":")),
            ]
        ),
    ),
    BakeVector(
        name="jsonata_query_filters_array_members",
        input_data=json.dumps(
            {
                "Phone": [
                    {"type": "home", "number": "0203 544 1234"},
                    {"type": "mobile", "number": "077 7700 1234"},
                ]
            }
        ),
        recipe=[{"op": "Jsonata Query", "args": {"Query": 'Phone[type="mobile"].number'}}],
        expected='"077 7700 1234"',
    ),
    BakeVector(
        name="jsonata_query_returns_empty_string_for_missing_path",
        input_data=json.dumps({"Other": {"Misc": None}}),
        recipe=[{"op": "Jsonata Query", "args": {"Query": "Other.DoesntExist"}}],
        expected='""',
    ),
    BakeVector(
        name="rake_scores_keywords_with_default_delimiters",
        input_data="test1 test2. test2",
        recipe=["RAKE"],
        expected="Scores: , Keywords: \n3.5, test1 test2\n1.5, test2",
    ),
    BakeVector(
        name="strings_extracts_utf16le_matches",
        input_data="T\x00E\x00S\x00T\x00",
        recipe=[
            {
                "op": "Strings",
                "args": {
                    "Encoding": "16-bit littleendian",
                    "Minimum length": 4,
                    "Match": "Alphanumeric + punctuation (U)",
                },
            }
        ],
        expected="T\x00E\x00S\x00T\x00",
    ),
    BakeVector(
        name="strings_counts_unique_single_byte_matches_without_sorting",
        input_data="beta\nalpha\nbeta\ngamma",
        recipe=[
            {
                "op": "Strings",
                "args": {
                    "Encoding": "Single byte",
                    "Minimum length": 4,
                    "Match": "Alphanumeric + punctuation (A)",
                    "Display total": True,
                    "Unique": True,
                },
            }
        ],
        expected="Total found: 3\n\nbeta\nalpha\ngamma",
    ),
    BakeVector(
        name="template_renders_each_blocks",
        input_data=json.dumps(
            {
                "users": [
                    {"name": "Someone", "age": 25},
                    {"name": "Someone Else", "age": 32},
                ]
            }
        ),
        recipe=[
            {
                "op": "Template",
                "args": {
                    "Template definition (.handlebars)": "{{#each users}}{{name}}:{{age}}|{{/each}}"
                },
            }
        ],
        expected="Someone:25|Someone Else:32|",
    ),
    BakeVector(
        name="template_escapes_html_from_input_data",
        input_data=json.dumps({"test": "<script></script>"}),
        recipe=[
            {
                "op": "Template",
                "args": {"Template definition (.handlebars)": "<script></script>{{ test }}"},
            }
        ],
        expected="<script></script>&lt;script&gt;&lt;/script&gt;",
    ),
    BakeVector(
        name="xpath_expression_extracts_text_nodes_with_custom_delimiter",
        input_data='<div><p class="a">hello</p><p>world</p><p class="a">again</p></div>',
        recipe=[
            {
                "op": "XPath expression",
                "args": {"XPath": '/div/p[@class="a"]/text()', "Result delimiter": "|"},
            }
        ],
        expected="hello|again",
    ),
]

FLOW_CONTROL_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="magic_raises_typeerror_under_stpyv8_runtime",
        input_data=b"hello",
        recipe=["Magic"],
        error_message="TypeError: Cannot read properties of undefined (reading 'undefined')",
    ),
]

FLOW_CONTROL_VECTORS = [
    BakeVector(
        name="comment_is_a_noop_before_to_snake_case",
        input_data="Comment Here",
        recipe=[{"op": "Comment", "args": {"": "phase28"}}, "To Snake case"],
        expected="comment_here",
    ),
    BakeVector(
        name="jump_skips_to_label_then_runs_following_operations",
        input_data="jump target",
        recipe=[
            {"op": "Jump", "args": {"Label name": "end"}},
            "To Snake case",
            {"op": "Label", "args": {"Name": "end"}},
            "To Upper case",
        ],
        expected="JUMP TARGET",
    ),
    BakeVector(
        name="conditional_jump_match_skips_to_label",
        input_data="skip me",
        recipe=[
            {"op": "Conditional Jump", "args": {"Match (regex)": "^skip", "Label name": "end"}},
            "To Snake case",
            {"op": "Label", "args": {"Name": "end"}},
            "To Upper case",
        ],
        expected="SKIP ME",
    ),
    BakeVector(
        name="conditional_jump_invert_match_skips_to_label",
        input_data="run me",
        recipe=[
            {
                "op": "Conditional Jump",
                "args": {"Match (regex)": "^skip", "Invert match": True, "Label name": "end"},
            },
            "To Snake case",
            {"op": "Label", "args": {"Name": "end"}},
            "To Upper case",
        ],
        expected="RUN ME",
    ),
    BakeVector(
        name="fork_decodes_base64_lines_and_merges_with_newlines",
        input_data="aGVsbG8=\nd29ybGQ=",
        recipe=[
            {"op": "Fork", "args": {"Split delimiter": "\n", "Merge delimiter": "\n"}},
            "From Base64",
            "Merge",
        ],
        expected="hello\nworld",
    ),
    BakeVector(
        name="merge_all_false_only_closes_nearest_nested_fork",
        input_data="a:1|b:2",
        recipe=[
            {"op": "Fork", "args": {"Split delimiter": "|", "Merge delimiter": "|"}},
            {"op": "Fork", "args": {"Split delimiter": ":", "Merge delimiter": ":"}},
            "To Upper case",
            {"op": "Merge", "args": {"Merge All": False}},
            "Reverse",
            "Merge",
        ],
        expected="1:A|2:B",
    ),
    BakeVector(
        name="return_stops_recipe_execution",
        input_data="return here",
        recipe=["To Snake case", "Return", "To Upper case"],
        expected="return_here",
    ),
    BakeVector(
        name="subsection_capture_group_only_mutates_group_contents",
        input_data="keep [one] and [two]",
        recipe=[
            {"op": "Subsection", "args": {"Section (regex)": "\\[(.*?)\\]", "Global matching": True}},
            "To Upper case",
            "Merge",
        ],
        expected="keep [ONE] and [TWO]",
    ),
    BakeVector(
        name="subsection_without_matches_skips_to_after_merge",
        input_data="plain text",
        recipe=[
            {"op": "Subsection", "args": {"Section (regex)": "\\[(.*?)\\]"}},
            "To Upper case",
            "Merge",
            "To Snake case",
        ],
        expected="plain_text",
    ),
]

FORENSICS_VECTORS = [
    BakeVector(
        name="detect_file_type_png_bytes",
        input_data=FORENSICS_RGBA_PNG,
        recipe=["Detect File Type"],
        expected="File type:   Portable Network Graphics image\nExtension:   png\nMIME type:   image/png\n",
    ),
    BakeVector(
        name="detect_file_type_png_with_images_disabled_is_unknown",
        input_data=FORENSICS_RGBA_PNG,
        recipe=[
            {
                "op": "Detect File Type",
                "args": {
                    "Images": False,
                    "Video": True,
                    "Audio": True,
                    "Documents": True,
                    "Applications": True,
                    "Archives": True,
                    "Miscellaneous": True,
                },
            }
        ],
        expected=(
            "Unknown file type. Have you tried checking the entropy of this data to determine whether it "
            "might be encrypted or compressed?"
        ),
    ),
    BakeVector(
        name="elf_info_minimal_elf64_header_only",
        input_data=MINIMAL_ELF64,
        recipe=["ELF Info"],
        expected=MINIMAL_ELF64_INFO_OUTPUT,
    ),
    BakeVector(
        name="extract_lsb_row_major_red_channel_least_significant_bits",
        input_data=FORENSICS_LSB_PNG,
        recipe=[
            {
                "op": "Extract LSB",
                "args": {
                    "Colour Pattern #1": "R",
                    "Colour Pattern #2": "",
                    "Colour Pattern #3": "",
                    "Colour Pattern #4": "",
                    "Pixel Order": "Row",
                    "Bit": 0,
                },
            }
        ],
        expected=b"A",
    ),
    BakeVector(
        name="extract_rgba_default_delimiter_includes_alpha",
        input_data=FORENSICS_RGBA_PNG,
        recipe=["Extract RGBA"],
        expected="0,255,0,255,255,0,255,0",
    ),
    BakeVector(
        name="extract_rgba_space_delimiter_without_alpha",
        input_data=FORENSICS_RGBA_PNG,
        recipe=[{"op": "Extract RGBA", "args": {"Delimiter": " ", "Include Alpha": False}}],
        expected="0 255 0 255 0 255",
    ),
    BakeVector(
        name="randomize_colour_palette_seeded_then_extract_rgba",
        input_data=FORENSICS_RGBA_PNG,
        recipe=[
            {"op": "Randomize Colour Palette", "args": {"Seed": "seed"}},
            "Extract RGBA",
        ],
        expected=build_randomized_palette_rgba_text(FORENSICS_RGBA_ROWS, seed="seed"),
    ),
    BakeVector(
        name="remove_exif_then_extract_exif_finds_zero_tags",
        input_data=CYBERCHEF_SAMPLE_EXIF_JPEG,
        recipe=["Remove EXIF", "Extract EXIF"],
        expected="Found 0 tags.\n",
    ),
    BakeVector(
        name="scan_for_embedded_files_finds_prefixed_png_and_nested_zlib",
        input_data=FORENSICS_EMBEDDED_PNG_SAMPLE,
        recipe=["Scan for Embedded Files"],
        expected=(
            "Scanning data for 'magic bytes' which may indicate embedded files. The following results may "
            "be false positives and should not be treated as reliable. Any sufficiently long file is likely "
            "to contain these magic bytes coincidentally.\n\n"
            "Offset 4 (0x04):\n"
            "  File type:   Portable Network Graphics image\n"
            "  Extension:   png\n"
            "  MIME type:   image/png\n\n"
            "Offset 45 (0x2d):\n"
            "  File type:   Zlib Deflate\n"
            "  Extension:   zlib\n"
            "  MIME type:   application/x-deflate\n"
        ),
    ),
    BakeVector(
        name="view_bit_plane_red_lsb_then_extract_rgba",
        input_data=FORENSICS_RGBA_PNG,
        recipe=[
            {"op": "View Bit Plane", "args": {"Colour": "Red", "Bit": 0}},
            "Extract RGBA",
        ],
        expected="255,255,255,255,0,0,0,255",
    ),
]

FORENSICS_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="yara_rules_simple_match_times_out_under_stpyv8",
        input_data=b"foobar foobar",
        recipe=[
            {
                "op": "YARA Rules",
                "args": {
                    "Rules": 'rule foo { strings: $re1 = /foo/ condition: $re1 }',
                    "Show strings": True,
                    "Show string lengths": True,
                    "Show metadata": False,
                    "Show counts": True,
                    "Show rule warnings": True,
                    "Show console module messages": True,
                },
            }
        ],
        error_message="Timed out waiting for CyberChef promise to settle",
    ),
]

MULTIMEDIA_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="add_text_to_image_bitmap_font_loader_requires_xhr",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[
            {
                "op": "Add Text To Image",
                "args": {
                    "Text": "A",
                    "Horizontal align": "None",
                    "Vertical align": "None",
                    "X position": 0,
                    "Y position": 0,
                    "Size": 8,
                    "Font face": "Roboto",
                    "Red": 255,
                    "Green": 255,
                    "Blue": 255,
                    "Alpha": 255,
                },
            }
        ],
        error_message="Error adding text to image. (TypeError: xhr.open is not a function)",
    ),
    BlockedBakeVector(
        name="optical_character_recognition_requires_browser_worker_runtime",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=["Optical Character Recognition"],
        error_message="Error: This operation only works in a browser",
    ),
]

HASH_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="argon2_default_hash_times_out_under_stpyv8",
        input_data="argon2password",
        recipe=[
            {
                "op": "Argon2",
                "args": {
                    "Salt": {"string": "somesalt", "option": "UTF8"},
                    "Iterations": 3,
                    "Memory (KiB)": 4096,
                    "Parallelism": 1,
                    "Hash length (bytes)": 32,
                    "Type": "Argon2i",
                    "Output format": "Encoded hash",
                },
            }
        ],
        error_message="Timed out waiting for CyberChef promise to settle",
    ),
    BlockedBakeVector(
        name="argon2_compare_known_hash_times_out_under_stpyv8",
        input_data="argon2password",
        recipe=[
            {
                "op": "Argon2 compare",
                "args": {
                    "Encoded hash": "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$s43my9eBljQADuF/LWCG8vGqwAJzOorKQ0Yog8jFvbw"
                },
            }
        ],
        error_message="Timed out waiting for CyberChef promise to settle",
    ),
]

NETWORK_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="dns_over_https_default_reference_error_under_stpyv8",
        input_data="example.com",
        recipe=["DNS over HTTPS"],
        error_message="ReferenceError: URL is not defined",
    ),
    BlockedBakeVector(
        name="http_request_requires_xmlhttprequest_under_stpyv8",
        input_data="body",
        recipe=[
            {
                "op": "HTTP request",
                "args": {
                    "Method": "GET",
                    "URL": "https://example.com",
                    "Headers": "",
                    "Mode": "Cross-Origin Resource Sharing",
                    "Show response metadata": False,
                },
            }
        ],
        error_message="ReferenceError: XMLHttpRequest is not defined",
    ),
]

BLOCKED_BAKE_VECTORS = [
    *CODE_TIDY_BLOCKED_VECTORS,
    *COMPRESSION_BLOCKED_VECTORS,
    *FLOW_CONTROL_BLOCKED_VECTORS,
    *FORENSICS_BLOCKED_VECTORS,
    *MULTIMEDIA_BLOCKED_VECTORS,
    *HASH_BLOCKED_VECTORS,
    *NETWORK_BLOCKED_VECTORS,
]

ENCODING_VECTORS = [
    BakeVector(
        name="a1z26_encode_empty_string",
        input_data="",
        recipe=[{"op": "A1Z26 Cipher Encode", "args": {"Delimiter": "Space"}}],
        expected="",
    ),
    BakeVector(
        name="a1z26_encode_comma_delimited_letters_only",
        input_data="abc xyz!",
        recipe=[{"op": "A1Z26 Cipher Encode", "args": {"Delimiter": "Comma"}}],
        expected=build_a1z26_encode_string("abc xyz!", "Comma"),
    ),
    BakeVector(
        name="a1z26_decode_line_feed_values",
        input_data="1\n2\n3\n24\n25\n26",
        recipe=[{"op": "A1Z26 Cipher Decode", "args": {"Delimiter": "Line feed"}}],
        expected=build_a1z26_decode_string("1\n2\n3\n24\n25\n26", "Line feed"),
    ),
    BakeVector(
        name="a1z26_roundtrip_crlf_delimiter",
        input_data="Phase",
        recipe=[
            {"op": "A1Z26 Cipher Encode", "args": {"Delimiter": "CRLF"}},
            {"op": "A1Z26 Cipher Decode", "args": {"Delimiter": "CRLF"}},
        ],
        expected="phase",
    ),
    BakeVector(
        name="aes_encrypt_cbc_no_padding_nist_vector",
        input_data="6bc1bee22e409f96e93d7e117393172a",
        recipe=[
            {
                "op": "AES Encrypt",
                "args": {
                    "Key": {"string": "2b7e151628aed2a6abf7158809cf4f3c", "option": "Hex"},
                    "IV": {"string": "000102030405060708090a0b0c0d0e0f", "option": "Hex"},
                    "Mode": "CBC/NoPadding",
                    "Input": "Hex",
                    "Output": "Hex",
                    "Additional Authenticated Data": {"string": "", "option": "Hex"},
                },
            }
        ],
        expected="7649abac8119b246cee98e9b12e9197d",
    ),
    BakeVector(
        name="aes_decrypt_cbc_no_padding_nist_vector",
        input_data="7649abac8119b246cee98e9b12e9197d",
        recipe=[
            {
                "op": "AES Decrypt",
                "args": {
                    "Key": {"string": "2b7e151628aed2a6abf7158809cf4f3c", "option": "Hex"},
                    "IV": {"string": "000102030405060708090a0b0c0d0e0f", "option": "Hex"},
                    "Mode": "CBC/NoPadding",
                    "Input": "Hex",
                    "Output": "Hex",
                    "GCM Tag": {"string": "", "option": "Hex"},
                    "Additional Authenticated Data": {"string": "", "option": "Hex"},
                },
            }
        ],
        expected="6bc1bee22e409f96e93d7e117393172a",
    ),
    BakeVector(
        name="aes_encrypt_decrypt_cbc_roundtrip_utf8_key",
        input_data="phase18 message",
        recipe=[
            {
                "op": "AES Encrypt",
                "args": {
                    "Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"},
                    "IV": {"string": "000102030405060708090a0b0c0d0e0f", "option": "Hex"},
                    "Mode": "CBC",
                    "Input": "Raw",
                    "Output": "Hex",
                    "Additional Authenticated Data": {"string": "", "option": "Hex"},
                },
            },
            {
                "op": "AES Decrypt",
                "args": {
                    "Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"},
                    "IV": {"string": "000102030405060708090a0b0c0d0e0f", "option": "Hex"},
                    "Mode": "CBC",
                    "Input": "Hex",
                    "Output": "Raw",
                    "GCM Tag": {"string": "", "option": "Hex"},
                    "Additional Authenticated Data": {"string": "", "option": "Hex"},
                },
            },
        ],
        expected="phase18 message",
    ),
    BakeVector(
        name="aes_key_wrap_rfc3394_vector",
        input_data="00112233445566778899aabbccddeeff",
        recipe=[
            {
                "op": "AES Key Wrap",
                "args": {
                    "Key (KEK)": {"string": "000102030405060708090a0b0c0d0e0f", "option": "Hex"},
                    "IV": {"string": "a6a6a6a6a6a6a6a6", "option": "Hex"},
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
    ),
    BakeVector(
        name="aes_key_unwrap_rfc3394_vector",
        input_data="1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
        recipe=[
            {
                "op": "AES Key Unwrap",
                "args": {
                    "Key (KEK)": {"string": "000102030405060708090a0b0c0d0e0f", "option": "Hex"},
                    "IV": {"string": "a6a6a6a6a6a6a6a6", "option": "Hex"},
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="00112233445566778899aabbccddeeff",
    ),
    BakeVector(
        name="affine_encode_identity_preserves_mixed_text",
        input_data="Affine Cipher 123!",
        recipe=[{"op": "Affine Cipher Encode", "args": {"a": 1, "b": 0}}],
        expected=build_affine_encode_string("Affine Cipher 123!", a=1, b=0),
    ),
    BakeVector(
        name="affine_encode_non_default_key",
        input_data="Affine Cipher!",
        recipe=[{"op": "Affine Cipher Encode", "args": {"a": 5, "b": 8}}],
        expected=build_affine_encode_string("Affine Cipher!", a=5, b=8),
    ),
    BakeVector(
        name="affine_decode_non_default_key",
        input_data="Ihhwvc Swfrcp!",
        recipe=[{"op": "Affine Cipher Decode", "args": {"a": 5, "b": 8}}],
        expected=build_affine_decode_string("Ihhwvc Swfrcp!", a=5, b=8),
    ),
    BakeVector(
        name="affine_roundtrip_mixed_case",
        input_data="Affine Cipher 123!",
        recipe=[
            {"op": "Affine Cipher Encode", "args": {"a": 11, "b": 6}},
            {"op": "Affine Cipher Decode", "args": {"a": 11, "b": 6}},
        ],
        expected="Affine Cipher 123!",
    ),
    BakeVector(
        name="atbash_known_phrase",
        input_data="Hello, Zebra!",
        recipe=["Atbash Cipher"],
        expected=build_atbash_string("Hello, Zebra!"),
    ),
    BakeVector(
        name="atbash_roundtrip_self_inverse",
        input_data="Attack at dawn.",
        recipe=["Atbash Cipher", "Atbash Cipher"],
        expected="Attack at dawn.",
    ),
    BakeVector(
        name="bacon_encode_standard_numeric_translation",
        input_data="HELLO",
        recipe=[
            {
                "op": "Bacon Cipher Encode",
                "args": {
                    "Alphabet": "Standard (I=J and U=V)",
                    "Translation": "0/1",
                    "Keep extra characters": False,
                    "Invert Translation": False,
                },
            }
        ],
        expected=build_bacon_encode_string(
            "HELLO",
            alphabet="Standard (I=J and U=V)",
            translation="0/1",
            keep_extra_characters=False,
            invert_translation=False,
        ),
    ),
    BakeVector(
        name="bacon_encode_complete_ab_inverted_with_extra_characters",
        input_data="abc xyz!",
        recipe=[
            {
                "op": "Bacon Cipher Encode",
                "args": {
                    "Alphabet": "Complete",
                    "Translation": "A/B",
                    "Keep extra characters": True,
                    "Invert Translation": True,
                },
            }
        ],
        expected=build_bacon_encode_string(
            "abc xyz!",
            alphabet="Complete",
            translation="A/B",
            keep_extra_characters=True,
            invert_translation=True,
        ),
    ),
    BakeVector(
        name="bacon_decode_complete_ab_translation",
        input_data="AABAA AABAB",
        recipe=[
            {
                "op": "Bacon Cipher Decode",
                "args": {
                    "Alphabet": "Complete",
                    "Translation": "A/B",
                    "Invert Translation": False,
                },
            }
        ],
        expected=build_bacon_decode_string(
            "AABAA AABAB",
            alphabet="Complete",
            translation="A/B",
            invert_translation=False,
        ),
    ),
    BakeVector(
        name="bacon_decode_case_translation",
        input_data="aaaaabbbbb",
        recipe=[
            {
                "op": "Bacon Cipher Decode",
                "args": {
                    "Alphabet": "Complete",
                    "Translation": "Case",
                    "Invert Translation": False,
                },
            }
        ],
        expected=build_bacon_decode_string(
            "aaaaabbbbb",
            alphabet="Complete",
            translation="Case",
            invert_translation=False,
        ),
    ),
    BakeVector(
        name="bcrypt_rounds_four_hash_format",
        input_data="password",
        recipe=[{"op": "Bcrypt", "args": {"Rounds": 4}}],
        expected=verify_bcrypt_rounds_four_hash,
    ),
    BakeVector(
        name="bifid_encode_keyword_roundtrip_reference",
        input_data="defend the east wall",
        recipe=[
            {
                "op": "Bifid Cipher Encode",
                "args": {"Keyword": "FORTIFICATION"},
            }
        ],
        expected=build_bifid_encode_string("defend the east wall", keyword="FORTIFICATION"),
    ),
    BakeVector(
        name="bifid_decode_keyword_roundtrip_reference",
        input_data="nrarhb inl frye osaz",
        recipe=[
            {
                "op": "Bifid Cipher Decode",
                "args": {"Keyword": "FORTIFICATION"},
            }
        ],
        expected=build_bifid_decode_string("nrarhb inl frye osaz", keyword="FORTIFICATION"),
    ),
    BakeVector(
        name="bifid_roundtrip_without_keyword",
        input_data="defend the east wall",
        recipe=[
            {"op": "Bifid Cipher Encode", "args": {"Keyword": ""}},
            {"op": "Bifid Cipher Decode", "args": {"Keyword": ""}},
        ],
        expected="defend the east wall",
    ),
    BakeVector(
        name="blowfish_encrypt_ecb_zero_key_and_plaintext",
        input_data="0000000000000000",
        recipe=[
            {
                "op": "Blowfish Encrypt",
                "args": {
                    "Key": {"string": "0000000000000000", "option": "Hex"},
                    "IV": {"string": "", "option": "Hex"},
                    "Mode": "ECB",
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="4ef997456198dd78b0d4acb28aa5ebe3",
    ),
    BakeVector(
        name="blowfish_decrypt_ecb_zero_key_and_ciphertext",
        input_data="4ef997456198dd78b0d4acb28aa5ebe3",
        recipe=[
            {
                "op": "Blowfish Decrypt",
                "args": {
                    "Key": {"string": "0000000000000000", "option": "Hex"},
                    "IV": {"string": "", "option": "Hex"},
                    "Mode": "ECB",
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="0000000000000000",
    ),
    BakeVector(
        name="blowfish_roundtrip_cfb_utf8_key",
        input_data="phase19!",
        recipe=[
            {
                "op": "Blowfish Encrypt",
                "args": {
                    "Key": {"string": "YELLOW", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Mode": "CFB",
                    "Input": "Raw",
                    "Output": "Hex",
                },
            },
            {
                "op": "Blowfish Decrypt",
                "args": {
                    "Key": {"string": "YELLOW", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Mode": "CFB",
                    "Input": "Hex",
                    "Output": "Raw",
                },
            },
        ],
        expected="phase19!",
    ),
    BakeVector(
        name="bombe_default_configuration_with_bbbb_crib",
        input_data="AAAA",
        recipe=[
            {
                "op": "Bombe",
                "args": {"Crib": "BBBB", "Use checking machine": True},
            }
        ],
        expected=verify_bombe_default_crib_bbbb,
    ),
    BakeVector(
        name="caesar_box_height_three_ignores_spaces",
        input_data="WE ARE DISCOVERED",
        recipe=[{"op": "Caesar Box Cipher", "args": {"Box Height": 3}}],
        expected=build_caesar_box_string("WE ARE DISCOVERED", 3),
    ),
    BakeVector(
        name="caesar_box_empty_string",
        input_data="",
        recipe=[{"op": "Caesar Box Cipher", "args": {"Box Height": 2}}],
        expected="",
    ),
    BakeVector(
        name="cetacean_encode_docs_example",
        input_data="hi",
        recipe=[{"op": "Cetacean Cipher Encode"}],
        expected=build_cetacean_encode_string("hi"),
    ),
    BakeVector(
        name="cetacean_decode_docs_example",
        input_data="EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe",
        recipe=[{"op": "Cetacean Cipher Decode"}],
        expected=build_cetacean_decode_string("EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe"),
    ),
    BakeVector(
        name="cetacean_roundtrip_preserves_spaces",
        input_data="hi ho",
        recipe=["Cetacean Cipher Encode", "Cetacean Cipher Decode"],
        expected="hi ho",
    ),
    BakeVector(
        name="chacha_rfc8439_encrypt_vector",
        input_data=(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
            "for the future, sunscreen would be it."
        ),
        recipe=[
            {
                "op": "ChaCha",
                "args": {
                    "Key": {
                        "string": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                        "option": "Hex",
                    },
                    "Nonce": {"string": "000000000000004a00000000", "option": "Hex"},
                    "Counter": 1,
                    "Rounds": "20",
                    "Input": "Raw",
                    "Output": "Hex",
                },
            }
        ],
        expected=(
            "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81 e9 7e 7a ec 1d 43 60 c2 "
            "0a 27 af cc fd 9f ae 0b f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57 "
            "16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8 07 ca 0d bf 50 0d 6a 61 "
            "56 a3 8e 08 8a 22 b6 5e 52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36 "
            "5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42 87 4d"
        ),
    ),
    BakeVector(
        name="chacha_roundtrip_twelve_round_eight_byte_nonce",
        input_data="phase20 roundtrip",
        recipe=[
            {
                "op": "ChaCha",
                "args": {
                    "Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"},
                    "Nonce": {"string": "12345678", "option": "UTF8"},
                    "Counter": 7,
                    "Rounds": "12",
                    "Input": "Raw",
                    "Output": "Hex",
                },
            },
            {
                "op": "ChaCha",
                "args": {
                    "Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"},
                    "Nonce": {"string": "12345678", "option": "UTF8"},
                    "Counter": 7,
                    "Rounds": "12",
                    "Input": "Hex",
                    "Output": "Raw",
                },
            },
        ],
        expected="phase20 roundtrip",
    ),
    BakeVector(
        name="ciphersaber2_decrypt_fixed_iv_vector",
        input_data=bytes(range(10)) + build_ciphersaber2_bytes(bytes(range(10)), b"secret", 5, b"hello"),
        recipe=[
            {
                "op": "CipherSaber2 Decrypt",
                "args": {
                    "Key": {"string": "secret", "option": "UTF8"},
                    "Rounds": 5,
                },
            }
        ],
        expected=b"hello",
    ),
    BakeVector(
        name="ciphersaber2_roundtrip_binary_payload",
        input_data=b"\x00phase20\xff",
        recipe=[
            {
                "op": "CipherSaber2 Encrypt",
                "args": {
                    "Key": {"string": "secret", "option": "UTF8"},
                    "Rounds": 20,
                },
            },
            {
                "op": "CipherSaber2 Decrypt",
                "args": {
                    "Key": {"string": "secret", "option": "UTF8"},
                    "Rounds": 20,
                },
            },
        ],
        expected=b"\x00phase20\xff",
    ),
    BakeVector(
        name="citrix_ctx1_encode_password1_bang",
        input_data="Password1!",
        recipe=["Citrix CTX1 Encode"],
        expected=build_citrix_ctx1_bytes("Password1!"),
    ),
    BakeVector(
        name="citrix_ctx1_decode_password1_bang",
        input_data=build_citrix_ctx1_bytes("Password1!"),
        recipe=["Citrix CTX1 Decode"],
        expected=build_citrix_ctx1_string(build_citrix_ctx1_bytes("Password1!")),
    ),
    BakeVector(
        name="citrix_ctx1_roundtrip_unicode_text",
        input_data="pi ✓",
        recipe=["Citrix CTX1 Encode", "Citrix CTX1 Decode"],
        expected="pi ✓",
    ),
    BakeVector(
        name="colossus_letter_count_program",
        input_data="AAAA",
        recipe=[
            {
                "op": "Colossus",
                "args": build_colossus_args("Letter Count"),
            }
        ],
        expected={"printout": " \n00 00 : a4 \n", "counters": [4, 0, 0, 0, 0], "runcount": 2},
    ),
    BakeVector(
        name="des_encrypt_ecb_padded_fips_example",
        input_data="0123456789ABCDEF",
        recipe=[
            {
                "op": "DES Encrypt",
                "args": {
                    "Key": {"string": "133457799BBCDFF1", "option": "Hex"},
                    "IV": {"string": "", "option": "Hex"},
                    "Mode": "ECB",
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="85e813540f0ab405fdf2e174492922f8",
    ),
    BakeVector(
        name="des_decrypt_ecb_padded_fips_example",
        input_data="85e813540f0ab405fdf2e174492922f8",
        recipe=[
            {
                "op": "DES Decrypt",
                "args": {
                    "Key": {"string": "133457799BBCDFF1", "option": "Hex"},
                    "IV": {"string": "", "option": "Hex"},
                    "Mode": "ECB",
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="0123456789abcdef",
    ),
    BakeVector(
        name="des_roundtrip_cfb_utf8_key",
        input_data="phase20!",
        recipe=[
            {
                "op": "DES Encrypt",
                "args": {
                    "Key": {"string": "YELLOW12", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Mode": "CFB",
                    "Input": "Raw",
                    "Output": "Hex",
                },
            },
            {
                "op": "DES Decrypt",
                "args": {
                    "Key": {"string": "YELLOW12", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Mode": "CFB",
                    "Input": "Hex",
                    "Output": "Raw",
                },
            },
        ],
        expected="phase20!",
    ),
    BakeVector(
        name="derive_evp_key_md5_utf8_salt",
        input_data="",
        recipe=[
            {
                "op": "Derive EVP key",
                "args": {
                    "Passphrase": {"string": "password", "option": "UTF8"},
                    "Key size": 128,
                    "Iterations": 1,
                    "Hashing function": "MD5",
                    "Salt": {"string": "12345678", "option": "UTF8"},
                },
            }
        ],
        expected=build_evp_key_hex(
            b"password",
            b"12345678",
            key_size_bits=128,
            iterations=1,
            hash_name="MD5",
        ),
    ),
    BakeVector(
        name="derive_evp_key_sha256_iterated_hex_salt",
        input_data="",
        recipe=[
            {
                "op": "Derive EVP key",
                "args": {
                    "Passphrase": {"string": "phase20", "option": "UTF8"},
                    "Key size": 256,
                    "Iterations": 2,
                    "Hashing function": "SHA256",
                    "Salt": {"string": "0001020304050607", "option": "Hex"},
                },
            }
        ],
        expected=build_evp_key_hex(
            b"phase20",
            bytes.fromhex("0001020304050607"),
            key_size_bits=256,
            iterations=2,
            hash_name="SHA256",
        ),
    ),
    BakeVector(
        name="derive_hkdf_key_rfc5869_sha256",
        input_data=b"\x0b" * 22,
        recipe=[
            {
                "op": "Derive HKDF key",
                "args": {
                    "Salt": {"string": "000102030405060708090a0b0c", "option": "Hex"},
                    "Info": {"string": "f0f1f2f3f4f5f6f7f8f9", "option": "Hex"},
                    "Hashing function": "SHA256",
                    "Extract mode": "with salt",
                    "L (number of output octets)": 42,
                },
            }
        ],
        expected=build_hkdf_hex(
            b"\x0b" * 22,
            bytes.fromhex("000102030405060708090a0b0c"),
            bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            length=42,
            hash_name="SHA256",
            extract_mode="with salt",
        ),
    ),
    BakeVector(
        name="derive_hkdf_key_skip_extract_mode",
        input_data=bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        recipe=[
            {
                "op": "Derive HKDF key",
                "args": {
                    "Salt": {"string": "", "option": "Hex"},
                    "Info": {"string": "f0f1f2f3f4f5f6f7f8f9", "option": "Hex"},
                    "Hashing function": "SHA256",
                    "Extract mode": "skip",
                    "L (number of output octets)": 42,
                },
            }
        ],
        expected=build_hkdf_hex(
            bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
            b"",
            bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            length=42,
            hash_name="SHA256",
            extract_mode="skip",
        ),
    ),
    BakeVector(
        name="derive_hkdf_key_no_salt_utf8_info",
        input_data=b"input key material",
        recipe=[
            {
                "op": "Derive HKDF key",
                "args": {
                    "Salt": {"string": "", "option": "Hex"},
                    "Info": {"string": "context", "option": "UTF8"},
                    "Hashing function": "SHA256",
                    "Extract mode": "no salt",
                    "L (number of output octets)": 16,
                },
            }
        ],
        expected=build_hkdf_hex(
            b"input key material",
            b"",
            b"context",
            length=16,
            hash_name="SHA256",
            extract_mode="no salt",
        ),
    ),
    BakeVector(
        name="derive_pbkdf2_key_sha1_rfc6070",
        input_data="",
        recipe=[
            {
                "op": "Derive PBKDF2 key",
                "args": {
                    "Passphrase": {"string": "password", "option": "UTF8"},
                    "Key size": 160,
                    "Iterations": 2,
                    "Hashing function": "SHA1",
                    "Salt": {"string": "salt", "option": "UTF8"},
                },
            }
        ],
        expected=hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 2, dklen=20).hex(),
    ),
    BakeVector(
        name="derive_pbkdf2_key_sha256_hex_passphrase_base64_salt",
        input_data="",
        recipe=[
            {
                "op": "Derive PBKDF2 key",
                "args": {
                    "Passphrase": {"string": "70686173653231", "option": "Hex"},
                    "Key size": 256,
                    "Iterations": 1000,
                    "Hashing function": "SHA256",
                    "Salt": {"string": "c2FsdCEh", "option": "Base64"},
                },
            }
        ],
        expected=hashlib.pbkdf2_hmac("sha256", b"phase21", b"salt!!", 1000, dklen=32).hex(),
    ),
    BakeVector(
        name="enigma_default_hello",
        input_data="HELLO",
        recipe=["Enigma"],
        expected="GUCNI",
    ),
    BakeVector(
        name="enigma_non_strict_preserves_punctuation",
        input_data="HELLO, WORLD!",
        recipe=[{"op": "Enigma", "args": {"Strict output": False}}],
        expected="GUCNI, DJZQG!",
    ),
    BakeVector(
        name="enigma_four_rotor_roundtrip_custom_configuration",
        input_data="PHASE TWENTYONE",
        recipe=[
            {"op": "Enigma", "args": build_enigma_four_rotor_args()},
            {"op": "Enigma", "args": build_enigma_four_rotor_args()},
        ],
        expected="PHASE TWENTYONE",
    ),
    BakeVector(
        name="fernet_encrypt_roundtrip_unicode_text",
        input_data="phase21 ✓",
        recipe=[{"op": "Fernet Encrypt", "args": {"Key": FERNET_TEST_KEY}}],
        expected=build_fernet_encrypt_verifier("phase21 ✓"),
    ),
    BakeVector(
        name="fernet_decrypt_static_token",
        input_data=FERNET_PHASE21_TOKEN,
        recipe=[{"op": "Fernet Decrypt", "args": {"Key": FERNET_TEST_KEY}}],
        expected="phase21 ✓",
    ),
    BakeVector(
        name="from_morse_code_empty_string",
        input_data="",
        recipe=["From Morse Code"],
        expected="",
    ),
    BakeVector(
        name="from_morse_code_sos_default_delimiters",
        input_data="... --- ...",
        recipe=["From Morse Code"],
        expected="SOS",
    ),
    BakeVector(
        name="from_morse_code_forward_slash_word_delimiter",
        input_data=".... . .-.. .-.. ---/.-- --- .-. .-.. -..",
        recipe=[
            {
                "op": "From Morse Code",
                "args": {"Letter delimiter": "Space", "Word delimiter": "Forward slash"},
            }
        ],
        expected="HELLO WORLD",
    ),
    BakeVector(
        name="from_morse_code_roundtrip_with_to_morse_code",
        input_data="phase 21",
        recipe=["To Morse Code", "From Morse Code"],
        expected="PHASE 21",
    ),
    BakeVector(
        name="gost_encrypt_1989_ecb_no_padding_vector",
        input_data="0123456789abcdef",
        recipe=[
            {
                "op": "GOST Encrypt",
                "args": build_gost_cipher_args(
                    key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    algorithm="GOST 28147 (1989)",
                    input_type="Hex",
                    output_type="Hex",
                    s_box="E-A",
                ),
            }
        ],
        expected="ae9300ec3ec60ca9",
    ),
    BakeVector(
        name="gost_decrypt_1989_ecb_no_padding_vector",
        input_data="ae9300ec3ec60ca9",
        recipe=[
            {
                "op": "GOST Decrypt",
                "args": build_gost_cipher_args(
                    key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    algorithm="GOST 28147 (1989)",
                    input_type="Hex",
                    output_type="Hex",
                    s_box="E-A",
                ),
            }
        ],
        expected="0123456789abcdef",
    ),
    BakeVector(
        name="gost_roundtrip_kuznyechik_ecb_no_padding",
        input_data="1122334455667700ffeeddccbbaa9988",
        recipe=[
            {
                "op": "GOST Encrypt",
                "args": build_gost_cipher_args(
                    key_hex="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
                    algorithm="GOST R 34.12 (Kuznyechik, 2015)",
                    input_type="Hex",
                    output_type="Hex",
                ),
            },
            {
                "op": "GOST Decrypt",
                "args": build_gost_cipher_args(
                    key_hex="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
                    algorithm="GOST R 34.12 (Kuznyechik, 2015)",
                    input_type="Hex",
                    output_type="Hex",
                ),
            },
        ],
        expected="1122334455667700ffeeddccbbaa9988",
    ),
    BakeVector(
        name="gost_key_wrap_1989_vector",
        input_data="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
        recipe=[
            {
                "op": "GOST Key Wrap",
                "args": build_gost_key_wrap_args(
                    key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    ukm_hex="1234567890abcdef",
                    algorithm="GOST 28147 (1989)",
                    input_type="Hex",
                    output_type="Hex",
                    s_box="E-A",
                ),
            }
        ],
        expected="7e7f3d47d98c416bd557f7c2e453bbc1520c0a12b4ac4a07ae9300ec3ec60ca9\r\n58e32eb0",
    ),
    BakeVector(
        name="gost_key_unwrap_1989_vector",
        input_data="7e7f3d47d98c416bd557f7c2e453bbc1520c0a12b4ac4a07ae9300ec3ec60ca9\r\n58e32eb0",
        recipe=[
            {
                "op": "GOST Key Unwrap",
                "args": build_gost_key_wrap_args(
                    key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    ukm_hex="1234567890abcdef",
                    algorithm="GOST 28147 (1989)",
                    input_type="Hex",
                    output_type="Hex",
                    s_box="E-A",
                ),
            }
        ],
        expected="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
    ),
    BakeVector(
        name="gost_key_wrap_roundtrip_magma",
        input_data="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
        recipe=[
            {
                "op": "GOST Key Wrap",
                "args": build_gost_key_wrap_args(
                    key_hex="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
                    ukm_hex="1234567890abcdef",
                    algorithm="GOST R 34.12 (Magma, 2015)",
                    input_type="Hex",
                    output_type="Hex",
                ),
            },
            {
                "op": "GOST Key Unwrap",
                "args": build_gost_key_wrap_args(
                    key_hex="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
                    ukm_hex="1234567890abcdef",
                    algorithm="GOST R 34.12 (Magma, 2015)",
                    input_type="Hex",
                    output_type="Hex",
                ),
            },
        ],
        expected="8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
    ),
    BakeVector(
        name="gost_sign_1989_mac_vector",
        input_data="0123456789abcdef",
        recipe=[
            {
                "op": "GOST Sign",
                "args": build_gost_mac_args(
                    key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    algorithm="GOST 28147 (1989)",
                    input_type="Hex",
                    output_type="Hex",
                    s_box="E-A",
                    mac_length=32,
                ),
            }
        ],
        expected="cb417441",
    ),
    BakeVector(
        name="gost_verify_1989_matching_mac",
        input_data="0123456789abcdef",
        recipe=[
            {
                "op": "GOST Verify",
                "args": build_gost_mac_args(
                    key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    algorithm="GOST 28147 (1989)",
                    input_type="Hex",
                    mac_hex="cb417441",
                    s_box="E-A",
                ),
            }
        ],
        expected="The signature matches",
    ),
    BakeVector(
        name="gost_verify_1989_mismatched_mac",
        input_data="0123456789abcdef",
        recipe=[
            {
                "op": "GOST Verify",
                "args": build_gost_mac_args(
                    key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                    algorithm="GOST 28147 (1989)",
                    input_type="Hex",
                    mac_hex="00000000",
                    s_box="E-A",
                ),
            }
        ],
        expected="The signature does not match",
    ),
    BakeVector(
        name="jwt_decode_static_hs256_token",
        input_data=build_jwt_hs256_token(JWT_PHASE22_PAYLOAD, "secret"),
        recipe=["JWT Decode"],
        expected=JWT_PHASE22_PAYLOAD,
    ),
    BakeVector(
        name="jwt_sign_hs256_fixed_iat_payload",
        input_data=json.dumps(JWT_PHASE22_PAYLOAD, separators=(",", ":")),
        recipe=[
            {
                "op": "JWT Sign",
                "args": {
                    "Private/Secret Key": "secret",
                    "Signing algorithm": "HS256",
                    "Header": "{}",
                },
            }
        ],
        expected=build_jwt_hs256_token(JWT_PHASE22_PAYLOAD, "secret"),
    ),
    BakeVector(
        name="jwt_verify_static_hs256_token",
        input_data=build_jwt_hs256_token(JWT_PHASE22_PAYLOAD, "secret"),
        recipe=[{"op": "JWT Verify", "args": {"Public/Secret Key": "secret"}}],
        expected=JWT_PHASE22_PAYLOAD,
    ),
    BakeVector(
        name="ls47_encrypt_zero_padding_with_signature",
        input_data="hello_world",
        recipe=[
            {
                "op": "LS47 Encrypt",
                "args": {"Password": "secret", "Padding": 0, "Signature": "pi"},
            }
        ],
        expected=")-9nmfa,/l7a54o/",
    ),
    BakeVector(
        name="ls47_decrypt_zero_padding_with_signature",
        input_data=")-9nmfa,/l7a54o/",
        recipe=[{"op": "LS47 Decrypt", "args": {"Password": "secret", "Padding": 0}}],
        expected="hello_world---pi",
    ),
    BakeVector(
        name="lorenz_sz40_send_plaintext_to_ita2",
        input_data="HELLO",
        recipe=[
            {
                "op": "Lorenz",
                "args": {
                    "Model": "SZ40",
                    "Wheel Pattern": "KH Pattern",
                    "KT-Schalter": False,
                    "Mode": "Send",
                    "Input Type": "Plaintext",
                    "Output Type": "ITA2",
                    "ITA2 Format": "5/8/9",
                },
            }
        ],
        expected="VIC3T",
    ),
    BakeVector(
        name="lorenz_sz40_send_then_receive_roundtrip",
        input_data="HELLO",
        recipe=[
            {
                "op": "Lorenz",
                "args": {
                    "Model": "SZ40",
                    "Wheel Pattern": "KH Pattern",
                    "KT-Schalter": False,
                    "Mode": "Send",
                    "Input Type": "Plaintext",
                    "Output Type": "ITA2",
                    "ITA2 Format": "5/8/9",
                },
            },
            {
                "op": "Lorenz",
                "args": {
                    "Model": "SZ40",
                    "Wheel Pattern": "KH Pattern",
                    "KT-Schalter": False,
                    "Mode": "Receive",
                    "Input Type": "ITA2",
                    "Output Type": "Plaintext",
                    "ITA2 Format": "5/8/9",
                },
            },
        ],
        expected="HELLO",
    ),
    BakeVector(
        name="lorenz_sz42b_with_kt_switch_and_alt_ita2_format",
        input_data="TEST 123",
        recipe=[
            {
                "op": "Lorenz",
                "args": {
                    "Model": "SZ42b",
                    "Wheel Pattern": "ZMUG Pattern",
                    "KT-Schalter": True,
                    "Mode": "Send",
                    "Input Type": "Plaintext",
                    "Output Type": "ITA2",
                    "ITA2 Format": "+/-/.",
                },
            },
            {
                "op": "Lorenz",
                "args": {
                    "Model": "SZ42b",
                    "Wheel Pattern": "ZMUG Pattern",
                    "KT-Schalter": True,
                    "Mode": "Receive",
                    "Input Type": "ITA2",
                    "Output Type": "Plaintext",
                    "ITA2 Format": "+/-/.",
                },
            },
        ],
        expected="TEST.123",
    ),
    BakeVector(
        name="multiple_bombe_user_defined_three_rotor_menu",
        input_data="AAAA",
        recipe=[{"op": "Multiple Bombe", "args": build_multiple_bombe_args()}],
        expected=verify_multiple_bombe_user_defined_three_rotor,
    ),
    BakeVector(
        name="rc2_encrypt_raw_to_hex_cbc",
        input_data="hello",
        recipe=[
            {
                "op": "RC2 Encrypt",
                "args": {
                    "Key": {"string": "secret12", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Input": "Raw",
                    "Output": "Hex",
                },
            }
        ],
        expected="84feeb41042de66e",
    ),
    BakeVector(
        name="rc2_encrypt_then_decrypt_cbc_roundtrip",
        input_data="phase23 message",
        recipe=[
            {
                "op": "RC2 Encrypt",
                "args": {
                    "Key": {"string": "secret12", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Input": "Raw",
                    "Output": "Hex",
                },
            },
            {
                "op": "RC2 Decrypt",
                "args": {
                    "Key": {"string": "secret12", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Input": "Hex",
                    "Output": "Raw",
                },
            },
        ],
        expected="phase23 message",
    ),
    BakeVector(
        name="rc2_decrypt_hex_to_raw_cbc",
        input_data="84feeb41042de66e",
        recipe=[
            {
                "op": "RC2 Decrypt",
                "args": {
                    "Key": {"string": "secret12", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Input": "Hex",
                    "Output": "Raw",
                },
            }
        ],
        expected="hello",
    ),
    BakeVector(
        name="rc2_decrypt_hex_to_hex_cbc",
        input_data="84feeb41042de66e",
        recipe=[
            {
                "op": "RC2 Decrypt",
                "args": {
                    "Key": {"string": "secret12", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="68656c6c6f",
    ),
    BakeVector(
        name="rc4_utf8_to_hex_reference",
        input_data="Go Out On a Limb",
        recipe=[
            {
                "op": "RC4",
                "args": {
                    "Passphrase": {"string": "Under Your Nose", "option": "UTF8"},
                    "Input format": "UTF8",
                    "Output format": "Hex",
                },
            }
        ],
        expected=build_rc4_bytes(b"Go Out On a Limb", b"Under Your Nose").hex(),
    ),
    BakeVector(
        name="rc4_hex_input_base64_output_with_base64_passphrase",
        input_data="68656c6c6f",
        recipe=[
            {
                "op": "RC4",
                "args": {
                    "Passphrase": {"string": "a2V5", "option": "Base64"},
                    "Input format": "Hex",
                    "Output format": "Base64",
                },
            }
        ],
        expected=base64.b64encode(build_rc4_bytes(b"hello", b"key")).decode(),
    ),
    BakeVector(
        name="rc4_roundtrip_utf8_hex",
        input_data="phase23 ✓",
        recipe=[
            {
                "op": "RC4",
                "args": {
                    "Passphrase": {"string": "Under Your Nose", "option": "UTF8"},
                    "Input format": "UTF8",
                    "Output format": "Hex",
                },
            },
            {
                "op": "RC4",
                "args": {
                    "Passphrase": {"string": "Under Your Nose", "option": "UTF8"},
                    "Input format": "Hex",
                    "Output format": "UTF8",
                },
            },
        ],
        expected="phase23 ✓",
    ),
    BakeVector(
        name="rc4_drop_default_192_dwords_reference",
        input_data="Go Out On a Limb",
        recipe=[
            {
                "op": "RC4 Drop",
                "args": {
                    "Passphrase": {"string": "Under Your Nose", "option": "UTF8"},
                    "Input format": "UTF8",
                    "Output format": "Hex",
                    "Number of dwords to drop": 192,
                },
            }
        ],
        expected=build_rc4_bytes(b"Go Out On a Limb", b"Under Your Nose", drop_dwords=192).hex(),
    ),
    BakeVector(
        name="rc4_drop_one_dword_reference",
        input_data="hello",
        recipe=[
            {
                "op": "RC4 Drop",
                "args": {
                    "Passphrase": {"string": "key", "option": "UTF8"},
                    "Input format": "UTF8",
                    "Output format": "Hex",
                    "Number of dwords to drop": 1,
                },
            }
        ],
        expected=build_rc4_bytes(b"hello", b"key", drop_dwords=1).hex(),
    ),
    BakeVector(
        name="rc4_drop_roundtrip_utf8_hex",
        input_data="phase23 ✓",
        recipe=[
            {
                "op": "RC4 Drop",
                "args": {
                    "Passphrase": {"string": "Under Your Nose", "option": "UTF8"},
                    "Input format": "UTF8",
                    "Output format": "Hex",
                    "Number of dwords to drop": 192,
                },
            },
            {
                "op": "RC4 Drop",
                "args": {
                    "Passphrase": {"string": "Under Your Nose", "option": "UTF8"},
                    "Input format": "Hex",
                    "Output format": "UTF8",
                    "Number of dwords to drop": 192,
                },
            },
        ],
        expected="phase23 ✓",
    ),
    BakeVector(
        name="rot13_empty_bytes",
        input_data=b"",
        recipe=["ROT13"],
        expected=b"",
    ),
    BakeVector(
        name="rot13_default_mixed_ascii",
        input_data=b"Hello-123",
        recipe=["ROT13"],
        expected=build_rot13_bytes(b"Hello-123"),
    ),
    BakeVector(
        name="rot13_amount_five_rotates_numbers",
        input_data=b"Hello-123",
        recipe=[
            {
                "op": "ROT13",
                "args": {
                    "Rotate lower case chars": True,
                    "Rotate upper case chars": True,
                    "Rotate numbers": True,
                    "Amount": 5,
                },
            }
        ],
        expected=build_rot13_bytes(
            b"Hello-123",
            rotate_numbers=True,
            amount=5,
        ),
    ),
    BakeVector(
        name="rot13_roundtrip_self_inverse",
        input_data=b"phase23",
        recipe=["ROT13", "ROT13"],
        expected=b"phase23",
    ),
    BakeVector(
        name="rot13_brute_force_default_prints_all_amounts",
        input_data=b"uryyb",
        recipe=["ROT13 Brute Force"],
        expected=build_rot13_brute_force_string(b"uryyb"),
    ),
    BakeVector(
        name="rot13_brute_force_crib_filter_without_amounts",
        input_data=b"uryyb",
        recipe=[
            {
                "op": "ROT13 Brute Force",
                "args": {
                    "Rotate lower case chars": True,
                    "Rotate upper case chars": True,
                    "Rotate numbers": False,
                    "Sample length": 100,
                    "Sample offset": 0,
                    "Print amount": False,
                    "Crib (known plaintext string)": "hello",
                },
            }
        ],
        expected=build_rot13_brute_force_string(b"uryyb", print_amount=False, crib="hello"),
    ),
    BakeVector(
        name="rot47_default_ascii",
        input_data=b"Hello!~",
        recipe=["ROT47"],
        expected=build_rot47_bytes(b"Hello!~"),
    ),
    BakeVector(
        name="rot47_amount_ten_ascii",
        input_data=b"Hello!~",
        recipe=[{"op": "ROT47", "args": {"Amount": 10}}],
        expected=build_rot47_bytes(b"Hello!~", amount=10),
    ),
    BakeVector(
        name="rot47_roundtrip_self_inverse",
        input_data=b"phase23!?*",
        recipe=["ROT47", "ROT47"],
        expected=b"phase23!?*",
    ),
    BakeVector(
        name="rot47_brute_force_default_prints_all_amounts",
        input_data=b"w6==@[",
        recipe=["ROT47 Brute Force"],
        expected=build_rot47_brute_force_string(b"w6==@["),
    ),
    BakeVector(
        name="rot47_brute_force_crib_filter_without_amounts",
        input_data=b"w6==@[",
        recipe=[
            {
                "op": "ROT47 Brute Force",
                "args": {
                    "Sample length": 100,
                    "Sample offset": 0,
                    "Print amount": False,
                    "Crib (known plaintext string)": "hello",
                },
            }
        ],
        expected=build_rot47_brute_force_string(b"w6==@[", print_amount=False, crib="hello"),
    ),
    BakeVector(
        name="rot8000_empty_string",
        input_data="",
        recipe=["ROT8000"],
        expected="",
    ),
    BakeVector(
        name="rot8000_known_phrase",
        input_data="The Quick Brown Fox Jumped Over The Lazy Dog.",
        recipe=["ROT8000"],
        expected="籝籱籮 籚籾籲籬籴 籋类籸粀籷 籏籸粁 籓籾籶籹籮籭 籘籿籮类 籝籱籮 籕籪粃粂 籍籸籰簷",
    ),
    BakeVector(
        name="rot8000_roundtrip_self_inverse",
        input_data="phase23 ✓",
        recipe=["ROT8000", "ROT8000"],
        expected="phase23 ✓",
    ),
    BakeVector(
        name="rabbit_rfc_big_endian_without_iv",
        input_data="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        recipe=[
            {
                "op": "Rabbit",
                "args": {
                    "Key": {"string": "00000000000000000000000000000000", "option": "Hex"},
                    "IV": {"string": "", "option": "Hex"},
                    "Endianness": "Big",
                    "Input": "Hex",
                    "Output": "Hex",
                },
            }
        ],
        expected="b15754f036a5d6ecf56b45261c4af70288e8d815c59c0c397b696c4789c68aa7f416a1c3700cd451da68d1881673d696",
    ),
    BakeVector(
        name="rabbit_little_endian_crypto_pp_vector",
        input_data="Rabbit stream cipher test",
        recipe=[
            {
                "op": "Rabbit",
                "args": {
                    "Key": {"string": "23c2731e8b5469fd8dabb5bc592a0f3a", "option": "Hex"},
                    "IV": {"string": "712906405ef03201", "option": "Hex"},
                    "Endianness": "Little",
                    "Input": "Raw",
                    "Output": "Hex",
                },
            }
        ],
        expected="1ae2d4edcf9b6063b00fd6fda0b223aded157e77031cf0440b",
    ),
    BakeVector(
        name="rabbit_roundtrip_big_endian_utf8_key",
        input_data="phase23 rabbit",
        recipe=[
            {
                "op": "Rabbit",
                "args": {
                    "Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Endianness": "Big",
                    "Input": "Raw",
                    "Output": "Hex",
                },
            },
            {
                "op": "Rabbit",
                "args": {
                    "Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"},
                    "IV": {"string": "12345678", "option": "UTF8"},
                    "Endianness": "Big",
                    "Input": "Hex",
                    "Output": "Raw",
                },
            },
        ],
        expected="phase23 rabbit",
    ),
    BakeVector(
        name="rail_fence_decode_two_rails_reference",
        input_data="Cytgah sTEAto rtn rsligcdsrporpyi H r fWiigo ovn oe",
        recipe=[{"op": "Rail Fence Cipher Decode", "args": {"Key": 2, "Offset": 0}}],
        expected=build_rail_fence_decode_string(
            "Cytgah sTEAto rtn rsligcdsrporpyi H r fWiigo ovn oe",
            key=2,
            offset=0,
        ),
    ),
    BakeVector(
        name="rail_fence_decode_four_rails_with_offset",
        input_data="51746026813793592840",
        recipe=[{"op": "Rail Fence Cipher Decode", "args": {"Key": 4, "Offset": 2}}],
        expected=build_rail_fence_decode_string("51746026813793592840", key=4, offset=2),
    ),
    BakeVector(
        name="rail_fence_decode_three_rails_with_spaces",
        input_data=build_rail_fence_encode_string(
            "No one expects the spanish Inquisition.",
            key=3,
            offset=2,
        ),
        recipe=[{"op": "Rail Fence Cipher Decode", "args": {"Key": 3, "Offset": 2}}],
        expected="No one expects the spanish Inquisition.",
    ),
    BakeVector(
        name="rail_fence_encode_three_rails_reference",
        input_data="WEAREDISCOVEREDFLEEATONCE",
        recipe=[{"op": "Rail Fence Cipher Encode", "args": {"Key": 3, "Offset": 0}}],
        expected=build_rail_fence_encode_string("WEAREDISCOVEREDFLEEATONCE", key=3, offset=0),
    ),
    BakeVector(
        name="rail_fence_encode_four_rails_with_offset",
        input_data="12345678901234567890",
        recipe=[{"op": "Rail Fence Cipher Encode", "args": {"Key": 4, "Offset": 2}}],
        expected=build_rail_fence_encode_string("12345678901234567890", key=4, offset=2),
    ),
    BakeVector(
        name="rail_fence_encode_decode_roundtrip_with_spaces",
        input_data="No one expects the spanish Inquisition.",
        recipe=[
            {"op": "Rail Fence Cipher Encode", "args": {"Key": 3, "Offset": 2}},
            {"op": "Rail Fence Cipher Decode", "args": {"Key": 3, "Offset": 2}},
        ],
        expected="No one expects the spanish Inquisition.",
    ),
    BakeVector(
        name="sigaba_encrypt_default_hello",
        input_data="HELLO",
        recipe=["SIGABA"],
        expected="HIPGI",
    ),
    BakeVector(
        name="sigaba_decrypt_default_hello",
        input_data="HIPGI",
        recipe=[{"op": "SIGABA", "args": {"SIGABA mode": "Decrypt"}}],
        expected="HELLO",
    ),
    BakeVector(
        name="sigaba_roundtrip_default_configuration",
        input_data="HELLOWORLD",
        recipe=["SIGABA", {"op": "SIGABA", "args": {"SIGABA mode": "Decrypt"}}],
        expected="HELLOWORLD",
    ),
    BakeVector(
        name="sm4_encrypt_ecb_padding_openssl_vector",
        input_data="0123456789abcdeffedcba9876543210",
        recipe=[
            {
                "op": "SM4 Encrypt",
                "args": build_sm4_args(
                    key_string="0123456789abcdeffedcba9876543210",
                    key_option="Hex",
                    mode="ECB",
                    input_type="Hex",
                    output_type="Hex",
                ),
            }
        ],
        expected="68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46 00 2a 8a 4e fa 86 3c ca d0 24 ac 03 00 bb 40 d2",
    ),
    BakeVector(
        name="sm4_decrypt_ecb_no_padding_standard_vector",
        input_data="681edf34d206965e86b3e94f536e4246",
        recipe=[
            {
                "op": "SM4 Decrypt",
                "args": build_sm4_args(
                    key_string="0123456789abcdeffedcba9876543210",
                    key_option="Hex",
                    mode="ECB/NoPadding",
                    input_type="Hex",
                    output_type="Hex",
                ),
            }
        ],
        expected="01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10",
    ),
    BakeVector(
        name="sm4_encrypt_decrypt_cbc_roundtrip_utf8_key",
        input_data="SM4 roundtrip",
        recipe=[
            {
                "op": "SM4 Encrypt",
                "args": build_sm4_args(
                    key_string="YELLOW SUBMARINE",
                    key_option="UTF8",
                    iv_string="0123456789ABCDEF",
                    iv_option="UTF8",
                    mode="CBC",
                    input_type="Raw",
                    output_type="Hex",
                ),
            },
            {
                "op": "SM4 Decrypt",
                "args": build_sm4_args(
                    key_string="YELLOW SUBMARINE",
                    key_option="UTF8",
                    iv_string="0123456789ABCDEF",
                    iv_option="UTF8",
                    mode="CBC",
                    input_type="Hex",
                    output_type="Raw",
                ),
            },
        ],
        expected="SM4 roundtrip",
    ),
    BakeVector(
        name="salsa20_zero_key_nonce_keystream_prefix",
        input_data="00000000000000000000000000000000",
        recipe=[
            {
                "op": "Salsa20",
                "args": build_salsa20_args(
                    key_string="00000000000000000000000000000000",
                    key_option="Hex",
                    nonce_string="0000000000000000",
                    nonce_option="Hex",
                    counter=0,
                    rounds="20",
                    input_type="Hex",
                    output_type="Hex",
                ),
            }
        ],
        expected="65 13 ad ae cf eb 12 4c 1c be 6b da ef 69 0b 4f",
    ),
    BakeVector(
        name="salsa20_roundtrip_twelve_round_utf8_nonce",
        input_data="hello salsa",
        recipe=[
            {
                "op": "Salsa20",
                "args": build_salsa20_args(
                    key_string="YELLOW SUBMARINE",
                    key_option="UTF8",
                    nonce_string="12345678",
                    nonce_option="UTF8",
                    counter=1,
                    rounds="12",
                    input_type="Raw",
                    output_type="Hex",
                ),
            },
            {
                "op": "Salsa20",
                "args": build_salsa20_args(
                    key_string="YELLOW SUBMARINE",
                    key_option="UTF8",
                    nonce_string="12345678",
                    nonce_option="UTF8",
                    counter=1,
                    rounds="12",
                    input_type="Hex",
                    output_type="Raw",
                ),
            },
        ],
        expected="hello salsa",
    ),
    BakeVector(
        name="salsa20_integer_nonce_eight_round_short_hex",
        input_data="00010203",
        recipe=[
            {
                "op": "Salsa20",
                "args": build_salsa20_args(
                    key_string="YELLOW SUBMARINE",
                    key_option="UTF8",
                    nonce_string="1",
                    nonce_option="Integer",
                    counter=0,
                    rounds="8",
                    input_type="Hex",
                    output_type="Hex",
                ),
            }
        ],
        expected="ac ed 07 76",
    ),
    BakeVector(
        name="scrypt_utf8_salt_hashlib_reference",
        input_data="password",
        recipe=[
            {
                "op": "Scrypt",
                "args": {
                    "Salt": {"string": "salt", "option": "UTF8"},
                    "Iterations (N)": 16,
                    "Memory factor (r)": 1,
                    "Parallelization factor (p)": 1,
                    "Key length": 16,
                },
            }
        ],
        expected=hashlib.scrypt(b"password", salt=b"salt", n=16, r=1, p=1, dklen=16).hex(),
    ),
    BakeVector(
        name="scrypt_base64_salt_hashlib_reference",
        input_data="password",
        recipe=[
            {
                "op": "Scrypt",
                "args": {
                    "Salt": {"string": "c2FsdA==", "option": "Base64"},
                    "Iterations (N)": 16,
                    "Memory factor (r)": 2,
                    "Parallelization factor (p)": 1,
                    "Key length": 32,
                },
            }
        ],
        expected=hashlib.scrypt(b"password", salt=b"salt", n=16, r=2, p=1, dklen=32).hex(),
    ),
    BakeVector(
        name="substitute_default_caesar_uppercase",
        input_data="ABC XYZ",
        recipe=["Substitute"],
        expected="XYZ UVW",
    ),
    BakeVector(
        name="substitute_ignore_case_preserves_input_case",
        input_data="AbCaBc",
        recipe=[
            {"op": "Substitute", "args": {"Plaintext": "ABC", "Ciphertext": "XYZ", "Ignore case": True}}
        ],
        expected="XyZxYz",
    ),
    BakeVector(
        name="substitute_warns_on_mismatched_alphabet_lengths",
        input_data="abc",
        recipe=[
            {
                "op": "Substitute",
                "args": {"Plaintext": "ABCDEF", "Ciphertext": "XYZ", "Ignore case": True},
            }
        ],
        expected="Warning: Plaintext and Ciphertext lengths differ\n\nxyz",
    ),
    BakeVector(
        name="to_morse_code_empty_string",
        input_data="",
        recipe=["To Morse Code"],
        expected="",
    ),
    BakeVector(
        name="to_morse_code_default_word_delimiter_newline",
        input_data="phase 24",
        recipe=["To Morse Code"],
        expected=".--. .... .- ... .\n..--- ....-",
    ),
    BakeVector(
        name="to_morse_code_dash_dot_comma_forward_slash",
        input_data="SOS HELP",
        recipe=[
            {
                "op": "To Morse Code",
                "args": {
                    "Format options": "Dash/Dot",
                    "Letter delimiter": "Comma",
                    "Word delimiter": "Forward slash",
                },
            }
        ],
        expected=(
            "DotDotDot,DashDashDash,DotDotDot/"
            "DotDotDotDot,Dot,DotDashDotDot,DotDashDashDot"
        ),
    ),
    BakeVector(
        name="triple_des_encrypt_ecb_padding_openssl_vector",
        input_data="0123456789abcdeffedcba9876543210",
        recipe=[
            {
                "op": "Triple DES Encrypt",
                "args": build_triple_des_args(
                    key_string="0123456789abcdeffedcba98765432100123456789abcdef",
                    key_option="Hex",
                    mode="ECB",
                    input_type="Hex",
                    output_type="Hex",
                ),
            }
        ],
        expected="1a4d672dca6cb3351fd1b02b237af9ae2e24eeb85aef49ae",
    ),
    BakeVector(
        name="triple_des_decrypt_ecb_no_padding_vector",
        input_data="1a4d672dca6cb3351fd1b02b237af9ae",
        recipe=[
            {
                "op": "Triple DES Decrypt",
                "args": build_triple_des_args(
                    key_string="0123456789abcdeffedcba98765432100123456789abcdef",
                    key_option="Hex",
                    mode="ECB/NoPadding",
                    input_type="Hex",
                    output_type="Hex",
                ),
            }
        ],
        expected="0123456789abcdeffedcba9876543210",
    ),
    BakeVector(
        name="triple_des_encrypt_decrypt_cbc_roundtrip_utf8_key",
        input_data="phase24 tdes",
        recipe=[
            {
                "op": "Triple DES Encrypt",
                "args": build_triple_des_args(
                    key_string="ABCDEFGHIJKLMNOPQRSTUVWX",
                    key_option="UTF8",
                    iv_string="12345678",
                    iv_option="UTF8",
                    mode="CBC",
                    input_type="Raw",
                    output_type="Hex",
                ),
            },
            {
                "op": "Triple DES Decrypt",
                "args": build_triple_des_args(
                    key_string="ABCDEFGHIJKLMNOPQRSTUVWX",
                    key_option="UTF8",
                    iv_string="12345678",
                    iv_option="UTF8",
                    mode="CBC",
                    input_type="Hex",
                    output_type="Raw",
                ),
            },
        ],
        expected="phase24 tdes",
    ),
    BakeVector(
        name="typex_encrypt_default_hello",
        input_data="HELLO",
        recipe=["Typex"],
        expected="PDEBF",
    ),
    BakeVector(
        name="typex_roundtrip_default_configuration",
        input_data="HELLO WORLD",
        recipe=["Typex", {"op": "Typex", "args": {"Strict output": False}}],
        expected="HELLO WORLD",
    ),
    BakeVector(
        name="typex_roundtrip_keyboard_emulation_digits_and_punctuation",
        input_data="MEET AT 9.",
        recipe=[
            {"op": "Typex", "args": {"Typex keyboard emulation": "Encrypt", "Strict output": False}},
            {"op": "Typex", "args": {"Typex keyboard emulation": "Decrypt", "Strict output": False}},
        ],
        expected="MEET AT 9.",
    ),
    BakeVector(
        name="typex_roundtrip_custom_rotors_raw_values",
        input_data="TYPEXROUNDTRIP",
        recipe=[
            {"op": "Typex", "args": TYPEX_PHASE25_CUSTOM_ARGS},
            {"op": "Typex", "args": TYPEX_PHASE25_CUSTOM_ARGS},
        ],
        expected="TYPEXROUNDTRIP",
    ),
    BakeVector(
        name="vigenere_encode_empty_string",
        input_data="",
        recipe=[{"op": "Vigenère Encode", "args": {"Key": "LEMON"}}],
        expected="",
    ),
    BakeVector(
        name="vigenere_encode_classic_reference",
        input_data="ATTACKATDAWN",
        recipe=[{"op": "Vigenère Encode", "args": {"Key": "LEMON"}}],
        expected=build_vigenere_encode_string("ATTACKATDAWN", key="LEMON"),
    ),
    BakeVector(
        name="vigenere_decode_classic_reference",
        input_data="LXFOPVEFRNHR",
        recipe=[{"op": "Vigenère Decode", "args": {"Key": "LEMON"}}],
        expected=build_vigenere_decode_string("LXFOPVEFRNHR", key="LEMON"),
    ),
    BakeVector(
        name="vigenere_roundtrip_preserves_case_and_punctuation",
        input_data="Attack at dawn!",
        recipe=[
            {"op": "Vigenère Encode", "args": {"Key": "LEMON"}},
            {"op": "Vigenère Decode", "args": {"Key": "LEMON"}},
        ],
        expected="Attack at dawn!",
    ),
    BakeVector(
        name="xor_input_differential_hex_key",
        input_data=b"ABCD",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "10", "option": "Hex"},
                    "Scheme": "Input differential",
                    "Null preserving": False,
                },
            }
        ],
        expected=build_xor_bytes(b"ABCD", b"\x10", scheme="Input differential"),
    ),
    BakeVector(
        name="xor_output_differential_hex_key",
        input_data=b"ABCD",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "10", "option": "Hex"},
                    "Scheme": "Output differential",
                    "Null preserving": False,
                },
            }
        ],
        expected=build_xor_bytes(b"ABCD", b"\x10", scheme="Output differential"),
    ),
    BakeVector(
        name="xor_cascade_ignores_supplied_key",
        input_data=b"ABCD",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "10", "option": "Hex"},
                    "Scheme": "Cascade",
                    "Null preserving": False,
                },
            }
        ],
        expected=build_xor_bytes(b"ABCD", b"\x10", scheme="Cascade"),
    ),
    BakeVector(
        name="xor_brute_force_crib_finds_single_plaintext",
        input_data=b"HELLO",
        recipe=[
            {
                "op": "XOR Brute Force",
                "args": {
                    "Key length": 1,
                    "Sample length": 5,
                    "Sample offset": 0,
                    "Scheme": "Standard",
                    "Null preserving": False,
                    "Print key": True,
                    "Output as hex": False,
                    "Crib (known plaintext string)": "hello",
                },
            }
        ],
        expected="Key = 20: hello",
    ),
    BakeVector(
        name="xor_brute_force_sample_offset_hex_output",
        input_data=b"zzHELLOzz",
        recipe=[
            {
                "op": "XOR Brute Force",
                "args": {
                    "Key length": 1,
                    "Sample length": 5,
                    "Sample offset": 2,
                    "Scheme": "Standard",
                    "Null preserving": False,
                    "Print key": True,
                    "Output as hex": True,
                    "Crib (known plaintext string)": "hello",
                },
            }
        ],
        expected="Key = 20: 68 65 6c 6c 6f",
    ),
    BakeVector(
        name="xsalsa20_zero_key_nonce_keystream_prefix",
        input_data="00000000000000000000000000000000",
        recipe=[
            {
                "op": "XSalsa20",
                "args": build_salsa20_args(
                    key_string="00000000000000000000000000000000",
                    key_option="Hex",
                    nonce_string="000000000000000000000000000000000000000000000000",
                    nonce_option="Hex",
                    counter=0,
                    rounds="20",
                    input_type="Hex",
                    output_type="Hex",
                ),
            }
        ],
        expected="37 33 27 1f c3 d0 14 a4 2a 9d ff 9f 22 d7 2b 28",
    ),
    BakeVector(
        name="xsalsa20_roundtrip_twelve_round_utf8_nonce",
        input_data="hello xsalsa",
        recipe=[
            {
                "op": "XSalsa20",
                "args": build_salsa20_args(
                    key_string="YELLOW SUBMARINE",
                    key_option="UTF8",
                    nonce_string="123456789012345678901234",
                    nonce_option="UTF8",
                    counter=1,
                    rounds="12",
                    input_type="Raw",
                    output_type="Hex",
                ),
            },
            {
                "op": "XSalsa20",
                "args": build_salsa20_args(
                    key_string="YELLOW SUBMARINE",
                    key_option="UTF8",
                    nonce_string="123456789012345678901234",
                    nonce_option="UTF8",
                    counter=1,
                    rounds="12",
                    input_type="Hex",
                    output_type="Raw",
                ),
            },
        ],
        expected="hello xsalsa",
    ),
    BakeVector(
        name="xxtea_encrypt_empty_bytes",
        input_data=b"",
        recipe=[
            {"op": "XXTEA Encrypt", "args": {"Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"}}}
        ],
        expected=b"",
    ),
    BakeVector(
        name="xxtea_encrypt_utf8_key_reference",
        input_data=b"hello!!!",
        recipe=[
            {"op": "XXTEA Encrypt", "args": {"Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"}}}
        ],
        expected=build_xxtea_encrypt_bytes(b"hello!!!", b"YELLOW SUBMARINE"),
    ),
    BakeVector(
        name="xxtea_decrypt_utf8_key_reference",
        input_data=build_xxtea_encrypt_bytes(b"hello!!!", b"YELLOW SUBMARINE"),
        recipe=[
            {"op": "XXTEA Decrypt", "args": {"Key": {"string": "YELLOW SUBMARINE", "option": "UTF8"}}}
        ],
        expected=build_xxtea_decrypt_bytes(
            build_xxtea_encrypt_bytes(b"hello!!!", b"YELLOW SUBMARINE"),
            b"YELLOW SUBMARINE",
        ),
    ),
    BakeVector(
        name="xxtea_encrypt_decrypt_base64_key_roundtrip",
        input_data=b"phase25 xxtea",
        recipe=[
            {
                "op": "XXTEA Encrypt",
                "args": {
                    "Key": {
                        "string": base64.b64encode(b"YELLOW SUBMARINE").decode(),
                        "option": "Base64",
                    }
                },
            },
            {
                "op": "XXTEA Decrypt",
                "args": {
                    "Key": {
                        "string": base64.b64encode(b"YELLOW SUBMARINE").decode(),
                        "option": "Base64",
                    }
                },
            },
        ],
        expected=b"phase25 xxtea",
    ),
    BakeVector(
        name="to_base64_empty_bytes",
        input_data=b"",
        recipe=["To Base64"],
        expected="",
    ),
    BakeVector(
        name="to_base64_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base64"],
        expected=base64.b64encode(b"hello").decode(),
    ),
    BakeVector(
        name="from_base64_empty_string",
        input_data="",
        recipe=["From Base64"],
        expected=b"",
    ),
    BakeVector(
        name="from_base64_ascii_string",
        input_data="aGVsbG8=",
        recipe=["From Base64"],
        expected=b"hello",
    ),
    BakeVector(
        name="base64_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base64", "From Base64"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_base32_empty_bytes",
        input_data=b"",
        recipe=["To Base32"],
        expected="",
    ),
    BakeVector(
        name="to_base32_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=["To Base32"],
        expected=base64.b32encode(b"\x00\x10\x7f\x80\xff").decode(),
    ),
    BakeVector(
        name="from_base32_binary_edge_string",
        input_data="AAIH7AH7",
        recipe=["From Base32"],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="base32_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base32", "From Base32"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_base58_empty_bytes",
        input_data=b"",
        recipe=["To Base58"],
        expected="",
    ),
    BakeVector(
        name="to_base58_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base58"],
        expected=build_base58_bitcoin(b"hello"),
    ),
    BakeVector(
        name="to_base58_preserves_leading_zero_bytes",
        input_data=b"\x00\x00hello",
        recipe=["To Base58"],
        expected=build_base58_bitcoin(b"\x00\x00hello"),
    ),
    BakeVector(
        name="from_base58_preserves_leading_zero_bytes",
        input_data="11Cn8eVZg",
        recipe=["From Base58"],
        expected=b"\x00\x00hello",
    ),
    BakeVector(
        name="base58_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base58", "From Base58"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_base85_empty_bytes",
        input_data=b"",
        recipe=["To Base85"],
        expected="",
    ),
    BakeVector(
        name="to_base85_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=["To Base85"],
        expected=base64.a85encode(b"\x00\x10\x7f\x80\xff").decode(),
    ),
    BakeVector(
        name="from_base85_binary_edge_string",
        input_data='!"aX1rr',
        recipe=["From Base85"],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="base85_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base85", "From Base85"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_hex_empty_bytes",
        input_data=b"",
        recipe=["To Hex"],
        expected="",
    ),
    BakeVector(
        name="to_hex_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=["To Hex"],
        expected="00 10 7f 80 ff",
    ),
    BakeVector(
        name="to_hex_no_delimiter_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Hex", "args": {"Delimiter": "None", "Bytes per line": 0}}],
        expected="68656c6c6f",
    ),
    BakeVector(
        name="from_hex_empty_string",
        input_data="",
        recipe=["From Hex"],
        expected=b"",
    ),
    BakeVector(
        name="from_hex_binary_edge_string",
        input_data="00 10 7f 80 ff",
        recipe=["From Hex"],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="from_hex_no_delimiter_string",
        input_data="68656c6c6f",
        recipe=[{"op": "From Hex", "args": {"Delimiter": "None"}}],
        expected=b"hello",
    ),
    BakeVector(
        name="hex_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Hex", "From Hex"],
        expected=bytes(range(256)),
    ),
]

HASH_VECTORS = [
    BakeVector(
        name="analyse_hash_64bit_digest",
        input_data="0123456789abcdef",
        recipe=["Analyse hash"],
        expected=build_hash_analysis_output("0123456789abcdef"),
    ),
    BakeVector(
        name="analyse_hash_after_md5_composition",
        input_data=b"hello",
        recipe=["MD5", "Analyse hash"],
        expected=build_hash_analysis_output(hashlib.md5(b"hello").hexdigest()),
    ),
    BakeVector(
        name="blake2b_512_empty_bytes",
        input_data=b"",
        recipe=[
            {
                "op": "BLAKE2b",
                "args": {
                    "Size": "512",
                    "Output Encoding": "Hex",
                    "Key": {"string": "", "option": "UTF8"},
                },
            }
        ],
        expected=hashlib.blake2b(b"", digest_size=64).hexdigest(),
    ),
    BakeVector(
        name="blake2b_160_keyed_base64",
        input_data=b"hello",
        recipe=[
            {
                "op": "BLAKE2b",
                "args": {
                    "Size": "160",
                    "Output Encoding": "Base64",
                    "Key": {"string": "key", "option": "UTF8"},
                },
            }
        ],
        expected=base64.b64encode(hashlib.blake2b(b"hello", digest_size=20, key=b"key").digest()).decode(),
    ),
    BakeVector(
        name="blake2s_256_empty_bytes",
        input_data=b"",
        recipe=[
            {
                "op": "BLAKE2s",
                "args": {
                    "Size": "256",
                    "Output Encoding": "Hex",
                    "Key": {"string": "", "option": "UTF8"},
                },
            }
        ],
        expected=hashlib.blake2s(b"", digest_size=32).hexdigest(),
    ),
    BakeVector(
        name="blake2s_128_keyed_base64",
        input_data=b"hello",
        recipe=[
            {
                "op": "BLAKE2s",
                "args": {
                    "Size": "128",
                    "Output Encoding": "Base64",
                    "Key": {"string": "key", "option": "UTF8"},
                },
            }
        ],
        expected=base64.b64encode(hashlib.blake2s(b"hello", digest_size=16, key=b"key").digest()).decode(),
    ),
    BakeVector(
        name="blake3_eight_byte_digest",
        input_data="Hello world",
        recipe=[{"op": "BLAKE3", "args": {"Size (bytes)": 8, "Key": ""}}],
        expected="e7e6fb7d2869d109",
    ),
    BakeVector(
        name="blake3_keyed_eight_byte_digest",
        input_data="Hello world",
        recipe=[
            {
                "op": "BLAKE3",
                "args": {"Size (bytes)": 8, "Key": "ThiskeyisexactlythirtytwoBytesLo"},
            }
        ],
        expected="59dd23ac9d025690",
    ),
    BakeVector(
        name="bcrypt_compare_match",
        input_data="dolphin",
        recipe=[
            {
                "op": "Bcrypt compare",
                "args": {"Hash": "$2a$10$qyon0LQCmMxpFFjwWH6Qh.dDdhqntQh./IN0RXCc3XIMILuOYZKgK"},
            }
        ],
        expected="Match: dolphin",
    ),
    BakeVector(
        name="bcrypt_compare_no_match",
        input_data="shark",
        recipe=[
            {
                "op": "Bcrypt compare",
                "args": {"Hash": "$2a$10$qyon0LQCmMxpFFjwWH6Qh.dDdhqntQh./IN0RXCc3XIMILuOYZKgK"},
            }
        ],
        expected="No match",
    ),
    BakeVector(
        name="bcrypt_parse_rounds_salt_and_hash",
        input_data="$2a$05$kXWtAIGB/R8VEzInoM5ocOTBtyc0m2YTIwFiBU/0XoW032f9QrkWW",
        recipe=["Bcrypt parse"],
        expected=(
            "Rounds: 5\n"
            "Salt: $2a$05$kXWtAIGB/R8VEzInoM5ocO\n"
            "Password hash: TBtyc0m2YTIwFiBU/0XoW032f9QrkWW\n"
            "Full hash: $2a$05$kXWtAIGB/R8VEzInoM5ocOTBtyc0m2YTIwFiBU/0XoW032f9QrkWW"
        ),
    ),
    BakeVector(
        name="cmac_aes128_empty_message_nist_vector",
        input_data=b"",
        recipe=[
            {
                "op": "CMAC",
                "args": {
                    "Key": {"string": "2b7e151628aed2a6abf7158809cf4f3c", "option": "Hex"},
                    "Encryption algorithm": "AES",
                },
            }
        ],
        expected="bb1d6929e95937287fa37d129b756746",
    ),
    BakeVector(
        name="cmac_triple_des_single_block_nist_vector",
        input_data=bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        recipe=[
            {
                "op": "CMAC",
                "args": {
                    "Key": {
                        "string": "0123456789abcdef23456789abcdef01456789abcdef0123",
                        "option": "Hex",
                    },
                    "Encryption algorithm": "Triple DES",
                },
            }
        ],
        expected="30239cf1f52e6609",
    ),
    BakeVector(
        name="crc_checksum_16_ascii_bytes",
        input_data=b"test input",
        recipe=[{"op": "CRC Checksum", "args": {"Algorithm": "CRC-16"}}],
        expected="77c7",
    ),
    BakeVector(
        name="crc_checksum_32_ascii_bytes",
        input_data=b"test input",
        recipe=[{"op": "CRC Checksum", "args": {"Algorithm": "CRC-32"}}],
        expected="29822bc8",
    ),
    BakeVector(
        name="ctph_empty_string",
        input_data="",
        recipe=["CTPH"],
        expected="A::",
    ),
    BakeVector(
        name="ctph_phrase_upstream_vector",
        input_data="If You Can't Stand the Heat, Get Out of the Kitchen",
        recipe=["CTPH"],
        expected="A:+EgFgBKAA0V0UFfClEs6:+Qk0gUFse",
    ),
    BakeVector(
        name="compare_ctph_identical_hashes_default_delimiter",
        input_data="A:E:E\nA:E:E",
        recipe=["Compare CTPH hashes"],
        expected=100.0,
    ),
    BakeVector(
        name="compare_ctph_identical_hashes_comma_delimiter",
        input_data="A:+EgFgBKAA0V0UFfClEs6:+Qk0gUFse,A:+EgFgBKAA0V0UFfClEs6:+Qk0gUFse",
        recipe=[{"op": "Compare CTPH hashes", "args": {"Delimiter": "Comma"}}],
        expected=100.0,
    ),
    BakeVector(
        name="compare_ssdeep_identical_hashes_default_delimiter",
        input_data="3:DLIXzMQCJc:XERKc\n3:DLIXzMQCJc:XERKc",
        recipe=["Compare SSDEEP hashes"],
        expected=100.0,
    ),
    BakeVector(
        name="compare_ssdeep_distinct_hashes_comma_delimiter",
        input_data="3:DLIXzMQCJc:XERKc,3:Hn:Hn",
        recipe=[{"op": "Compare SSDEEP hashes", "args": {"Delimiter": "Comma"}}],
        expected=0.0,
    ),
    BakeVector(
        name="gost_hash_1994_empty_bytes",
        input_data=b"",
        recipe=[
            {
                "op": "GOST Hash",
                "args": {"Algorithm": "GOST 28147 (1994)", "Digest length": "256", "sBox": "D-A"},
            }
        ],
        expected="981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
    ),
    BakeVector(
        name="gost_hash_streebog_512_test_bytes",
        input_data=b"test",
        recipe=[
            {
                "op": "GOST Hash",
                "args": {"Algorithm": "GOST R 34.11 (Streebog, 2012)", "Digest length": "512"},
            }
        ],
        expected="7200bf5dea560f0d7960d07fdc8874ad9f3b86ece2e45f5502ae2e176f2c928e0e581152281f5aee818318bed7cbe6aa69999589234723ceb33175598365b5c8",
    ),
    BakeVector(
        name="generate_all_checksums_16_named_check_string",
        input_data=b"123456789",
        recipe=[{"op": "Generate all checksums", "args": {"Length (bits)": "16", "Include names": True}}],
        expected=verify_generate_all_checksums_16_named_output,
    ),
    BakeVector(
        name="generate_all_checksums_32_named_check_string",
        input_data=b"123456789",
        recipe=[{"op": "Generate all checksums", "args": {"Length (bits)": "32", "Include names": True}}],
        expected=verify_generate_all_checksums_32_named_output,
    ),
    BakeVector(
        name="generate_all_hashes_128_named_test_bytes",
        input_data=b"test",
        recipe=[{"op": "Generate all hashes", "args": {"Length (bits)": "128", "Include names": True}}],
        expected=verify_generate_all_hashes_128_named_output,
    ),
    BakeVector(
        name="generate_all_hashes_256_unnamed_test_bytes",
        input_data=b"test",
        recipe=[{"op": "Generate all hashes", "args": {"Length (bits)": "256", "Include names": False}}],
        expected=verify_generate_all_hashes_256_unnamed_output,
    ),
    BakeVector(
        name="hmac_sha256_latin1_key_ascii_bytes",
        input_data=b"Hello, World!",
        recipe=[
            {
                "op": "HMAC",
                "args": {"Key": {"string": "test", "option": "Latin1"}, "Hashing function": "SHA256"},
            }
        ],
        expected=hmac.new(b"test", b"Hello, World!", hashlib.sha256).hexdigest(),
    ),
    BakeVector(
        name="hmac_sha512_rfc4231_long_hex_key",
        input_data=b"Test Using Larger Than Block-Size Key - Hash Key First",
        recipe=[
            {
                "op": "HMAC",
                "args": {
                    "Key": {
                        "string": "aa" * 131,
                        "option": "Hex",
                    },
                    "Hashing function": "SHA512",
                },
            }
        ],
        expected=hmac.new(bytes.fromhex("aa" * 131), b"Test Using Larger Than Block-Size Key - Hash Key First", hashlib.sha512).hexdigest(),
    ),
    BakeVector(
        name="keccak_256_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "Keccak", "args": {"Size": "256"}}],
        expected="acaf3289d7b601cbd114fb36c4d29c85bbfd5e133f14cb355c3fd8d99367964f",
    ),
    BakeVector(
        name="keccak_512_test_bytes",
        input_data=b"test",
        recipe=[{"op": "Keccak", "args": {"Size": "512"}}],
        expected="1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e",
    ),
    BakeVector(
        name="lm_hash_empty_string",
        input_data="",
        recipe=["LM Hash"],
        expected="AAD3B435B51404EEAAD3B435B51404EE",
    ),
    BakeVector(
        name="lm_hash_long_ascii_string",
        input_data="QWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*()_+.,?/",
        recipe=["LM Hash"],
        expected="6D9DF16655336CA75A3C13DD18BA8156",
    ),
    BakeVector(
        name="luhn_checksum_empty_string",
        input_data="",
        recipe=["Luhn Checksum"],
        expected="",
    ),
    BakeVector(
        name="luhn_checksum_standard_mod10",
        input_data="35641709012469",
        recipe=["Luhn Checksum"],
        expected=build_luhn_checksum_output("35641709012469", 10),
    ),
    BakeVector(
        name="luhn_checksum_mod16_alpha_numeric",
        input_data="ABCD",
        recipe=[{"op": "Luhn Checksum", "args": {"Radix": 16}}],
        expected=build_luhn_checksum_output("ABCD", 16),
    ),
    BakeVector(
        name="md2_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=["MD2"],
        expected="1c8f1e6a94aaa7145210bf90bb52871a",
    ),
    BakeVector(
        name="md4_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=["MD4"],
        expected="94e3cb0fa9aa7a5ee3db74b79e915989",
    ),
    BakeVector(
        name="md5_empty_bytes",
        input_data=b"",
        recipe=["MD5"],
        expected=hashlib.md5(b"").hexdigest(),
    ),
    BakeVector(
        name="md5_ascii_bytes",
        input_data=b"hello",
        recipe=["MD5"],
        expected=hashlib.md5(b"hello").hexdigest(),
    ),
    BakeVector(
        name="md5_utf8_bytes",
        input_data="ნუ პანიკას".encode(),
        recipe=["MD5"],
        expected=hashlib.md5("ნუ პანიკას".encode()).hexdigest(),
    ),
    BakeVector(
        name="md5_utf8_string",
        input_data="ნუ პანიკას",
        recipe=["MD5"],
        expected=hashlib.md5("ნუ პანიკას".encode()).hexdigest(),
    ),
    BakeVector(
        name="md6_keyed_text",
        input_data="Head Over Heels",
        recipe=[{"op": "MD6", "args": {"Size": 256, "Levels": 64, "Key": "arty"}}],
        expected="d8f7fe4931fbaa37316f76283d5f615f50ddd54afdc794b61da522556aee99ad",
    ),
    BakeVector(
        name="murmurhash3_empty_string",
        input_data="",
        recipe=["MurmurHash3"],
        expected=float(build_murmurhash3("")),
    ),
    BakeVector(
        name="murmurhash3_seeded_hello_world_string",
        input_data="Hello World!",
        recipe=[{"op": "MurmurHash3", "args": {"Seed": 1337, "Convert to Signed": False}}],
        expected=float(build_murmurhash3("Hello World!", seed=1337)),
    ),
    BakeVector(
        name="murmurhash3_signed_foo_string",
        input_data="foo",
        recipe=[{"op": "MurmurHash3", "args": {"Seed": 0, "Convert to Signed": True}}],
        expected=float(build_murmurhash3("foo", signed=True)),
    ),
    BakeVector(
        name="nt_hash_long_ascii_string",
        input_data="QWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*()_+.,?/",
        recipe=["NT Hash"],
        expected="C5FA1C40E55734A8E528DBFE21766D23",
    ),
    BakeVector(
        name="ripemd_160_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "RIPEMD", "args": {"Size": "160"}}],
        expected=hashlib.new("ripemd160", b"Hello, World!").hexdigest(),
    ),
    BakeVector(
        name="ripemd_320_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "RIPEMD", "args": {"Size": "320"}}],
        expected="f9832e5bb00576fc56c2221f404eb77addeafe49843c773f0df3fc5a996d5934f3c96e94aeb80e89",
    ),
    BakeVector(
        name="sha0_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=["SHA0"],
        expected="5a5588f0407c6ae9a988758e76965f841b299229",
    ),
    BakeVector(
        name="sha1_ascii_bytes",
        input_data=b"hello",
        recipe=["SHA1"],
        expected=hashlib.sha1(b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha1_utf8_bytes",
        input_data="ნუ პანიკას".encode(),
        recipe=["SHA1"],
        expected=hashlib.sha1("ნუ პანიკას".encode()).hexdigest(),
    ),
    BakeVector(
        name="sha2_224_utf8_bytes",
        input_data="ნუ პანიკას".encode(),
        recipe=[{"op": "SHA2", "args": {"size": "224"}}],
        expected=hashlib.sha224("ნუ პანიკას".encode()).hexdigest(),
    ),
    BakeVector(
        name="sha2_256_empty_bytes",
        input_data=b"",
        recipe=[{"op": "SHA2", "args": {"size": "256"}}],
        expected=hashlib.sha256(b"").hexdigest(),
    ),
    BakeVector(
        name="sha2_256_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "SHA2", "args": {"size": "256"}}],
        expected=hashlib.sha256(b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha2_512_256_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "SHA2", "args": {"size": "512/256"}}],
        expected=hashlib.new("sha512_256", b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha3_default_512_ascii_bytes",
        input_data=b"hello",
        recipe=["SHA3"],
        expected=hashlib.sha3_512(b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha3_224_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "SHA3", "args": {"Size": "224"}}],
        expected=hashlib.sha3_224(b"Hello, World!").hexdigest(),
    ),
    BakeVector(
        name="sha3_256_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "SHA3", "args": {"size": "256"}}],
        expected=hashlib.sha3_256(b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha3_384_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "SHA3", "args": {"Size": "384"}}],
        expected=hashlib.sha3_384(b"Hello, World!").hexdigest(),
    ),
    BakeVector(
        name="shake_default_512_ascii_bytes",
        input_data=b"hello",
        recipe=["Shake"],
        expected=hashlib.shake_256(b"hello").hexdigest(64),
    ),
    BakeVector(
        name="shake_128_256_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "Shake", "args": {"Capacity": "128", "Size": 256}}],
        expected=hashlib.shake_128(b"Hello, World!").hexdigest(32),
    ),
    BakeVector(
        name="shake_256_512_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "Shake", "args": {"Capacity": "256", "Size": 512}}],
        expected=hashlib.shake_256(b"Hello, World!").hexdigest(64),
    ),
    BakeVector(
        name="sm3_default_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=["SM3"],
        expected="7ed26cbf0bee4ca7d55c1e64714c4aa7d1f163089ef5ceb603cd102c81fbcbc5",
    ),
    BakeVector(
        name="sm3_short_rounds_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "SM3", "args": {"Length": 256, "Rounds": 16}}],
        expected="64d4c84c6efaaf512c7eb1a44bce6bef3906efa4d100d47cf420466ee1d1dfde",
    ),
    BakeVector(
        name="ssdeep_empty_string",
        input_data="",
        recipe=["SSDEEP"],
        expected="3::",
    ),
    BakeVector(
        name="ssdeep_phrase_upstream_vector",
        input_data="shotgun tyranny snugly",
        recipe=["SSDEEP"],
        expected="3:DLIXzMQCJc:XERKc",
    ),
    BakeVector(
        name="snefru_default_128_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=["Snefru"],
        expected="6f3d55b69557abb0a3c4e9de9d29ba5d",
    ),
    BakeVector(
        name="snefru_256_two_round_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "Snefru", "args": {"Size": 256, "Rounds": "2"}}],
        expected="65736daba648de28ef4c4a316b4684584ecf9f22ddb5c457729e6bf0f40113c4",
    ),
    BakeVector(
        name="streebog_default_256_test_bytes",
        input_data=b"test",
        recipe=["Streebog"],
        expected="12a50838191b5504f1e5f2fd078714cf6b592b9d29af99d0b10d8d02881c3857",
    ),
    BakeVector(
        name="streebog_512_test_bytes",
        input_data=b"test",
        recipe=[{"op": "Streebog", "args": {"Digest length": "512"}}],
        expected="7200bf5dea560f0d7960d07fdc8874ad9f3b86ece2e45f5502ae2e176f2c928e0e581152281f5aee818318bed7cbe6aa69999589234723ceb33175598365b5c8",
    ),
    BakeVector(
        name="whirlpool_default_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=["Whirlpool"],
        expected="3d837c9ef7bb291bd1dcfc05d3004af2eeb8c631dd6a6c4ba35159b8889de4b1ec44076ce7a8f7bfa497e4d9dcb7c29337173f78d06791f3c3d9e00cc6017f0b",
    ),
    BakeVector(
        name="whirlpool_t_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "Whirlpool", "args": {"Variant": "Whirlpool-T", "Rounds": 10}}],
        expected="16c581089b6a6f356ae56e16a63a4c613eecd82a2a894b293f5ee45c37a31d09d7a8b60bfa7e414bd4a7166662cea882b5cf8c96b7d583fc610ad202591bcdb1",
    ),
    BakeVector(
        name="whirlpool_zero_hello_world_bytes",
        input_data=b"Hello, World!",
        recipe=[{"op": "Whirlpool", "args": {"Variant": "Whirlpool-0", "Rounds": 10}}],
        expected="1c327026f565a0105a827efbfb3d3635cdb042c0aabb8416e96deb128e6c5c8684b13541cf31c26c1488949df050311c6999a12eb0e7002ad716350f5c7700ca",
    ),
    BakeVector(
        name="xor_checksum_default_empty_bytes",
        input_data=b"",
        recipe=["XOR Checksum"],
        expected="00000000",
    ),
    BakeVector(
        name="xor_checksum_blocksize_one_phrase",
        input_data=b"The ships hung in the sky in much the same way that bricks don't.",
        recipe=[{"op": "XOR Checksum", "args": {"Blocksize": 1}}],
        expected=build_xor_checksum(b"The ships hung in the sky in much the same way that bricks don't.", 1),
    ),
    BakeVector(
        name="xor_checksum_blocksize_four_all_bytes",
        input_data=bytes(range(256)),
        recipe=[{"op": "XOR Checksum", "args": {"Blocksize": 4}}],
        expected=build_xor_checksum(bytes(range(256)), 4),
    ),
]

LANGUAGE_VECTORS = [
    BakeVector(
        name="convert_leet_speak_empty_string",
        input_data="",
        recipe=["Convert Leet Speak"],
        expected="",
    ),
    BakeVector(
        name="convert_leet_speak_to_default_letters",
        input_data="Attack at dawn!",
        recipe=["Convert Leet Speak"],
        expected="4774ck 47 d4wn!",
    ),
    BakeVector(
        name="convert_leet_speak_from_option",
        input_data="7357",
        recipe=[{"op": "Convert Leet Speak", "args": {"Direction": "From Leet Speak"}}],
        expected="test",
    ),
    BakeVector(
        name="convert_leet_speak_roundtrip_safe_subset",
        input_data="test",
        recipe=[
            "Convert Leet Speak",
            {"op": "Convert Leet Speak", "args": {"Direction": "From Leet Speak"}},
        ],
        expected="test",
    ),
    BakeVector(
        name="convert_to_nato_alphabet_letters_digits_punctuation",
        input_data="Go,9./",
        recipe=["Convert to NATO alphabet"],
        expected="Golf Oscar Comma Nine Full stop Fraction bar ",
    ),
    BakeVector(
        name="convert_to_nato_alphabet_preserves_spacing",
        input_data="A Z",
        recipe=["Convert to NATO alphabet"],
        expected="Alfa  Zulu ",
    ),
    BakeVector(
        name="remove_diacritics_empty_string",
        input_data="",
        recipe=["Remove Diacritics"],
        expected="",
    ),
    BakeVector(
        name="remove_diacritics_accented_latin_text",
        input_data="Crème Brûlée naïve café",
        recipe=["Remove Diacritics"],
        expected="Creme Brulee naive cafe",
    ),
    BakeVector(
        name="remove_diacritics_combining_mark_sequence",
        input_data="Cafe\u0301",
        recipe=["Remove Diacritics"],
        expected="Cafe",
    ),
    BakeVector(
        name="unicode_text_format_empty_bytes",
        input_data=b"",
        recipe=[{"op": "Unicode Text Format", "args": {"Underline": False, "Strikethrough": False}}],
        expected=b"",
    ),
    BakeVector(
        name="unicode_text_format_plain_passthrough",
        input_data=b"ab",
        recipe=[{"op": "Unicode Text Format", "args": {"Underline": False, "Strikethrough": False}}],
        expected=b"ab",
    ),
    BakeVector(
        name="unicode_text_format_underline_only",
        input_data=b"ab",
        recipe=[{"op": "Unicode Text Format", "args": {"Underline": True, "Strikethrough": False}}],
        expected="a\u0332b\u0332".encode("utf-8"),
    ),
    BakeVector(
        name="unicode_text_format_strikethrough_only",
        input_data=b"ab",
        recipe=[{"op": "Unicode Text Format", "args": {"Underline": False, "Strikethrough": True}}],
        expected="a\u0336b\u0336".encode("utf-8"),
    ),
    BakeVector(
        name="unicode_text_format_both_styles",
        input_data=b"ab",
        recipe=[{"op": "Unicode Text Format", "args": {"Underline": True, "Strikethrough": True}}],
        expected="a\u0336\u0332b\u0336\u0332".encode("utf-8"),
    ),
]

MULTIMEDIA_VECTORS = [
    BakeVector(
        name="blur_image_fast_amount_one_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[{"op": "Blur Image", "args": {"Amount": 1, "Type": "Fast"}}, "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(128, 113, 113, 255), (125, 141, 113, 255)],
                [(125, 113, 141, 255), (128, 141, 141, 255)],
            ]
        ),
    ),
    BakeVector(
        name="contain_image_left_top_transparent_letterbox_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[
            {
                "op": "Contain Image",
                "args": {
                    "Width": 4,
                    "Height": 2,
                    "Horizontal align": "Left",
                    "Vertical align": "Top",
                    "Resizing algorithm": "Nearest Neighbour",
                    "Opaque background": False,
                },
            },
            "Extract RGBA",
        ],
        expected=build_extract_rgba_text(
            [
                [(255, 0, 0, 255), (0, 255, 0, 255), (0, 0, 0, 0), (0, 0, 0, 0)],
                [(0, 0, 255, 255), (255, 255, 255, 255), (0, 0, 0, 0), (0, 0, 0, 0)],
            ]
        ),
    ),
    BakeVector(
        name="convert_image_format_to_bmp_then_detect_file_type",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[
            {
                "op": "Convert Image Format",
                "args": {
                    "Output Format": "BMP",
                    "JPEG Quality": 80,
                    "PNG Filter Type": "None",
                    "PNG Deflate Level": 9,
                },
            },
            "Detect File Type",
        ],
        expected="File type:   Bitmap image\nExtension:   bmp\nMIME type:   image/bmp\n",
    ),
    BakeVector(
        name="cover_image_left_top_clips_to_single_column",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[
            {
                "op": "Cover Image",
                "args": {
                    "Width": 1,
                    "Height": 2,
                    "Horizontal align": "Left",
                    "Vertical align": "Top",
                    "Resizing algorithm": "Nearest Neighbour",
                },
            },
            "Extract RGBA",
        ],
        expected=build_extract_rgba_text([[(255, 0, 0, 255)], [(0, 0, 255, 255)]]),
    ),
    BakeVector(
        name="crop_image_autocrop_single_red_center_pixel",
        input_data=MULTIMEDIA_AUTOCROP_PNG,
        recipe=[
            {
                "op": "Crop Image",
                "args": {
                    "X Position": 0,
                    "Y Position": 0,
                    "Width": 10,
                    "Height": 10,
                    "Autocrop": True,
                    "Autocrop tolerance (%)": 0.02,
                    "Only autocrop frames": True,
                    "Symmetric autocrop": False,
                    "Autocrop keep border (px)": 0,
                },
            },
            "Extract RGBA",
        ],
        expected=build_extract_rgba_text([[(255, 0, 0, 255)]]),
    ),
    BakeVector(
        name="dither_image_small_png_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=["Dither Image", "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(255, 1, 1, 255), (9, 255, 9, 255)],
                [(13, 13, 255, 255), (255, 255, 255, 255)],
            ]
        ),
    ),
    BakeVector(
        name="flip_image_vertical_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[{"op": "Flip Image", "args": {"Axis": "Vertical"}}, "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(0, 0, 255, 255), (255, 255, 255, 255)],
                [(255, 0, 0, 255), (0, 255, 0, 255)],
            ]
        ),
    ),
    BakeVector(
        name="generate_image_rgba_mode_extract_rgba",
        input_data=bytes(
            [
                255,
                0,
                0,
                255,
                0,
                255,
                0,
                255,
                0,
                0,
                255,
                255,
                255,
                255,
                255,
                255,
            ]
        ),
        recipe=[
            {"op": "Generate Image", "args": {"Mode": "RGBA", "Pixel Scale Factor": 1, "Pixels per row": 2}},
            "Extract RGBA",
        ],
        expected=build_extract_rgba_text(MULTIMEDIA_SOURCE_ROWS),
    ),
    BakeVector(
        name="generate_image_bits_mode_extract_rgba",
        input_data=bytes([0b10100000]),
        recipe=[
            {"op": "Generate Image", "args": {"Mode": "Bits", "Pixel Scale Factor": 1, "Pixels per row": 4}},
            "Extract RGBA",
        ],
        expected=build_extract_rgba_text(
            [
                [(0, 0, 0, 255), (255, 255, 255, 255), (0, 0, 0, 255), (255, 255, 255, 255)],
                [(255, 255, 255, 255), (255, 255, 255, 255), (255, 255, 255, 255), (255, 255, 255, 255)],
            ]
        ),
    ),
    BakeVector(
        name="heatmap_chart_headers_edges_and_counts",
        input_data="x,y\n0,0\n1,1\n2,2",
        recipe=[
            {
                "op": "Heatmap chart",
                "args": {
                    "Record delimiter": "Line feed",
                    "Field delimiter": "Comma",
                    "Number of vertical bins": 2,
                    "Number of horizontal bins": 2,
                    "Use column headers as labels": True,
                    "X label": "",
                    "Y label": "",
                    "Draw bin edges": True,
                    "Min colour value": "white",
                    "Max colour value": "black",
                },
            }
        ],
        expected=assert_heatmap_chart_with_headers,
    ),
    BakeVector(
        name="heatmap_chart_custom_labels_without_headers",
        input_data="0 0\n1 1\n2 2",
        recipe=[
            {
                "op": "Heatmap chart",
                "args": {
                    "Record delimiter": "Line feed",
                    "Field delimiter": "Space",
                    "Number of vertical bins": 2,
                    "Number of horizontal bins": 2,
                    "Use column headers as labels": False,
                    "X label": "X value",
                    "Y label": "Y value",
                    "Draw bin edges": False,
                    "Min colour value": "white",
                    "Max colour value": "black",
                },
            }
        ],
        expected=assert_heatmap_chart_with_custom_labels,
    ),
    BakeVector(
        name="hex_density_chart_headers_edges_and_empty_hexagons",
        input_data="x y\n0 0\n1 1\n2 2",
        recipe=[
            {
                "op": "Hex Density chart",
                "args": {
                    "Record delimiter": "Line feed",
                    "Field delimiter": "Space",
                    "Pack radius": 25,
                    "Draw radius": 15,
                    "Use column headers as labels": True,
                    "X label": "",
                    "Y label": "",
                    "Draw hexagon edges": True,
                    "Min colour value": "white",
                    "Max colour value": "black",
                    "Draw empty hexagons within data boundaries": True,
                },
            }
        ],
        expected=assert_hex_density_chart_with_headers_and_empty_hexagons,
    ),
    BakeVector(
        name="image_filter_sepia_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[{"op": "Image Filter", "args": {"Filter type": "Sepia"}}, "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(100, 34, 45, 255), (196, 243, 183, 255)],
                [(48, 59, 78, 255), (255, 255, 255, 255)],
            ]
        ),
    ),
    BakeVector(
        name="image_opacity_half_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[{"op": "Image Opacity", "args": {"Opacity (%)": 50}}, "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(255, 0, 0, 127), (0, 255, 0, 127)],
                [(0, 0, 255, 127), (255, 255, 255, 127)],
            ]
        ),
    ),
    BakeVector(
        name="invert_image_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=["Invert Image", "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(0, 255, 255, 255), (255, 0, 255, 255)],
                [(255, 255, 0, 255), (0, 0, 0, 255)],
            ]
        ),
    ),
    BakeVector(
        name="normalise_image_stretches_channel_range_extract_rgba",
        input_data=MULTIMEDIA_NORMALISE_SOURCE_PNG,
        recipe=["Normalise Image", "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(0, 0, 0, 255), (127, 127, 127, 255)],
                [(255, 255, 255, 255), (63, 63, 63, 255)],
            ]
        ),
    ),
    BakeVector(
        name="play_media_base64_wav_roundtrip",
        input_data=base64.b64encode(MINIMAL_WAV).decode(),
        recipe=[{"op": "Play Media", "args": {"Input format": "Base64"}}],
        expected=MINIMAL_WAV,
    ),
    BakeVector(
        name="render_image_hex_png_roundtrip",
        input_data=MULTIMEDIA_SOURCE_PNG.hex(),
        recipe=[{"op": "Render Image", "args": {"Input format": "Hex"}}],
        expected=MULTIMEDIA_SOURCE_PNG,
    ),
    BakeVector(
        name="resize_image_percent_nearest_neighbour_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[
            {
                "op": "Resize Image",
                "args": {
                    "Width": 50,
                    "Height": 100,
                    "Unit type": "Percent",
                    "Maintain aspect ratio": False,
                    "Resizing algorithm": "Nearest Neighbour",
                },
            },
            "Extract RGBA",
        ],
        expected=build_extract_rgba_text([[(255, 0, 0, 255)], [(0, 0, 255, 255)]]),
    ),
    BakeVector(
        name="rotate_image_180_extract_rgba",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=[{"op": "Rotate Image", "args": {"Rotation amount (degrees)": 180}}, "Extract RGBA"],
        expected=build_extract_rgba_text(
            [
                [(255, 255, 255, 255), (0, 0, 255, 255)],
                [(0, 255, 0, 255), (255, 0, 0, 255)],
            ]
        ),
    ),
    BakeVector(
        name="scatter_chart_headers_and_default_colour",
        input_data="x,y\n0,0\n1,1\n2,2",
        recipe=[
            {
                "op": "Scatter chart",
                "args": {
                    "Record delimiter": "Line feed",
                    "Field delimiter": "Comma",
                    "Use column headers as labels": True,
                    "X label": "",
                    "Y label": "",
                    "Colour": "black",
                    "Point radius": 10,
                    "Use colour from third column": False,
                },
            }
        ],
        expected=assert_scatter_chart_with_headers,
    ),
    BakeVector(
        name="scatter_chart_colour_from_third_column",
        input_data="0;0;red\r\n1;1;blue",
        recipe=[
            {
                "op": "Scatter chart",
                "args": {
                    "Record delimiter": "CRLF",
                    "Field delimiter": "Semi-colon",
                    "Use column headers as labels": False,
                    "X label": "Horizontal",
                    "Y label": "Vertical",
                    "Colour": "green",
                    "Point radius": 5,
                    "Use colour from third column": True,
                },
            }
        ],
        expected=assert_scatter_chart_with_input_colours,
    ),
    BakeVector(
        name="series_chart_crlf_semicolon_custom_colours",
        input_data=(
            "temp;00:00;10\r\n"
            "humidity;00:00;20\r\n"
            "temp;12:00;15\r\n"
            "humidity;12:00;25\r\n"
            "temp;24:00;12\r\n"
            "humidity;24:00;30"
        ),
        recipe=[
            {
                "op": "Series chart",
                "args": {
                    "Record delimiter": "CRLF",
                    "Field delimiter": "Semi-colon",
                    "X label": "Time",
                    "Point radius": 3,
                    "Series colours": "red,blue",
                },
            }
        ],
        expected=assert_series_chart_with_custom_colours,
    ),
    BakeVector(
        name="sharpen_image_unsharp_mask_extract_rgba",
        input_data=MULTIMEDIA_NORMALISE_SOURCE_PNG,
        recipe=[
            {"op": "Sharpen Image", "args": {"Radius": 1, "Amount": 1, "Threshold": 0}},
            "Extract RGBA",
        ],
        expected=build_extract_rgba_text(
            [
                [(10, 20, 30, 255), (127, 137, 147, 255)],
                [(255, 255, 255, 255), (60, 70, 80, 255)],
            ]
        ),
    ),
    BakeVector(
        name="split_colour_channels_returns_three_png_files",
        input_data=MULTIMEDIA_SOURCE_PNG,
        recipe=["Split Colour Channels"],
        expected=assert_split_colour_channels_files,
    ),
]

NETWORK_VECTORS = [
    BakeVector(
        name="dechunk_http_response_empty_string",
        input_data="",
        recipe=["Dechunk HTTP response"],
        expected="",
    ),
    BakeVector(
        name="dechunk_http_response_crlf_chunks",
        input_data="4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        recipe=["Dechunk HTTP response"],
        expected="Wikipedia",
    ),
    BakeVector(
        name="dechunk_http_response_lf_chunks",
        input_data="4\nWiki\n0\n\n",
        recipe=["Dechunk HTTP response"],
        expected="Wiki",
    ),
    BakeVector(
        name="dechunk_http_response_md5_composition",
        input_data="4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        recipe=["Dechunk HTTP response", "MD5"],
        expected=hashlib.md5(b"Wikipedia").hexdigest(),
    ),
    BakeVector(
        name="encode_netbios_name_short_ascii",
        input_data="ABC",
        recipe=["Encode NetBIOS Name"],
        expected=build_netbios_name("ABC"),
    ),
    BakeVector(
        name="decode_netbios_name_known_string",
        input_data="FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF",
        recipe=["Decode NetBIOS Name"],
        expected=b"The NetBIOS name",
    ),
    BakeVector(
        name="netbios_roundtrip_custom_offset",
        input_data="ABC",
        recipe=[
            {"op": "Encode NetBIOS Name", "args": {"Offset": 97}},
            {"op": "Decode NetBIOS Name", "args": {"Offset": 97}},
        ],
        expected=b"ABC",
    ),
    BakeVector(
        name="defang_ip_addresses_ipv4",
        input_data="192.168.1.1",
        recipe=["Defang IP Addresses"],
        expected="192[.]168[.]1[.]1",
    ),
    BakeVector(
        name="defang_ip_addresses_ipv6_shorthand",
        input_data="2001:db8:3c4d:15::1a2f:1a2b",
        recipe=["Defang IP Addresses"],
        expected="2001[:]db8[:]3c4d[:]15[:][:]1a2f[:]1a2b",
    ),
    BakeVector(
        name="defang_ip_addresses_preserves_ipv4_cidr_suffix",
        input_data="203.0.113.0/24",
        recipe=["Defang IP Addresses"],
        expected="203[.]0[.]113[.]0/24",
    ),
    BakeVector(
        name="defang_url_domain_default_process",
        input_data="example.com",
        recipe=["Defang URL"],
        expected="example[.]com",
    ),
    BakeVector(
        name="defang_url_only_full_urls",
        input_data="example.com and http://x.y",
        recipe=[{"op": "Defang URL", "args": {"Process": "Only full URLs"}}],
        expected="example.com and hxxp[://]x[.]y",
    ),
    BakeVector(
        name="defang_url_everything_slashes_only",
        input_data="http://example.com",
        recipe=[
            {
                "op": "Defang URL",
                "args": {
                    "Escape dots": False,
                    "Escape http": False,
                    "Escape ://": True,
                    "Process": "Everything",
                },
            }
        ],
        expected="http[://]example.com",
    ),
    BakeVector(
        name="fang_url_default_restore",
        input_data="hxxp[://]example[.]com/path",
        recipe=["Fang URL"],
        expected="http://example.com/path",
    ),
    BakeVector(
        name="fang_url_partial_restore",
        input_data="hxxps[://]example[.]com",
        recipe=[
            {
                "op": "Fang URL",
                "args": {"Restore [.]": True, "Restore hxxp": False, "Restore ://": True},
            }
        ],
        expected="hxxps://example.com",
    ),
    BakeVector(
        name="defang_then_fang_url_roundtrip",
        input_data="http://example.com/path?x=1#frag",
        recipe=["Defang URL", "Fang URL"],
        expected="http://example.com/path?x=1#frag",
    ),
    BakeVector(
        name="format_mac_addresses_empty_string",
        input_data="",
        recipe=["Format MAC addresses"],
        expected="",
    ),
    BakeVector(
        name="format_mac_addresses_default_single_input",
        input_data="00-01-02-03-04-05",
        recipe=["Format MAC addresses"],
        expected=(
            "000102030405\n"
            "000102030405\n"
            "00-01-02-03-04-05\n"
            "00-01-02-03-04-05\n"
            "00:01:02:03:04:05\n"
            "00:01:02:03:04:05\n"
        ),
    ),
    BakeVector(
        name="format_mac_addresses_upper_cisco_and_ipv6",
        input_data="00-01-02-03-04-05",
        recipe=[
            {
                "op": "Format MAC addresses",
                "args": {
                    "Output case": "Upper only",
                    "No delimiter": False,
                    "Dash delimiter": False,
                    "Colon delimiter": False,
                    "Cisco style": True,
                    "IPv6 interface ID": True,
                },
            }
        ],
        expected="0001.0203.0405\n0201:02FF:FE03:0405\n",
    ),
    BakeVector(
        name="group_ip_addresses_empty_string",
        input_data="",
        recipe=["Group IP addresses"],
        expected="",
    ),
    BakeVector(
        name="group_ip_addresses_ipv4_default_subnet",
        input_data="192.168.1.1\n192.168.1.5\n192.168.2.1",
        recipe=["Group IP addresses"],
        expected=build_group_ip_addresses_output(["192.168.1.1", "192.168.1.5", "192.168.2.1"], 24),
    ),
    BakeVector(
        name="group_ip_addresses_comma_delimited_subnets_only",
        input_data="192.168.1.1,192.168.1.5,192.168.2.1",
        recipe=[
            {
                "op": "Group IP addresses",
                "args": {"Delimiter": "Comma", "Only show the subnets": True},
            }
        ],
        expected=build_group_ip_addresses_output(
            ["192.168.1.1", "192.168.1.5", "192.168.2.1"],
            24,
            only_subnets=True,
        ),
    ),
    BakeVector(
        name="group_ip_addresses_ipv6_64_subnet",
        input_data="2001:db8::1\n2001:db8::2\n2001:db9::1",
        recipe=[{"op": "Group IP addresses", "args": {"Subnet (CIDR)": 64}}],
        expected=build_group_ip_addresses_output(["2001:db8::1", "2001:db8::2", "2001:db9::1"], 64),
    ),
    BakeVector(
        name="hassh_client_fingerprint_default_hash_digest",
        input_data=HASSH_CLIENT_SAMPLE_HEX,
        recipe=["HASSH Client Fingerprint"],
        expected=hashlib.md5(HASSH_CLIENT_ALGORITHMS.encode()).hexdigest(),
    ),
    BakeVector(
        name="hassh_client_fingerprint_algorithms_string",
        input_data=HASSH_CLIENT_SAMPLE_HEX,
        recipe=[{"op": "HASSH Client Fingerprint", "args": {"Output format": "HASSH algorithms string"}}],
        expected=HASSH_CLIENT_ALGORITHMS,
    ),
    BakeVector(
        name="hassh_client_fingerprint_full_details",
        input_data=HASSH_CLIENT_SAMPLE_HEX,
        recipe=[{"op": "HASSH Client Fingerprint", "args": {"Output format": "Full details"}}],
        expected=build_hassh_full_details(HASSH_CLIENT_ALGORITHMS),
    ),
    BakeVector(
        name="hassh_server_fingerprint_default_hash_digest",
        input_data=HASSH_SERVER_SAMPLE_HEX,
        recipe=["HASSH Server Fingerprint"],
        expected=hashlib.md5(HASSH_SERVER_ALGORITHMS.encode()).hexdigest(),
    ),
    BakeVector(
        name="hassh_server_fingerprint_algorithms_string",
        input_data=HASSH_SERVER_SAMPLE_HEX,
        recipe=[{"op": "HASSH Server Fingerprint", "args": {"Output format": "HASSH algorithms string"}}],
        expected=HASSH_SERVER_ALGORITHMS,
    ),
    BakeVector(
        name="hassh_server_fingerprint_full_details_base64_input",
        input_data=HASSH_SERVER_SAMPLE_BASE64,
        recipe=[
            {
                "op": "HASSH Server Fingerprint",
                "args": {"Input format": "Base64", "Output format": "Full details"},
            }
        ],
        expected=build_hassh_full_details(HASSH_SERVER_ALGORITHMS, direction="Server to Client"),
    ),
    BakeVector(
        name="ipv6_transition_addresses_ipv4_default_output",
        input_data="198.51.100.7",
        recipe=["IPv6 Transition Addresses"],
        expected=(
            "6to4: 2002:c633:6407::/48\n"
            "IPv4 Mapped: ::ffff:c633:6407\n"
            "IPv4 Translated: ::ffff:0:c633:6407\n"
            "Nat 64: 64:ff9b::c633:6407\n"
        ),
    ),
    BakeVector(
        name="ipv6_transition_addresses_ipv4_range",
        input_data="198.51.100.0/24",
        recipe=[{"op": "IPv6 Transition Addresses", "args": {"Ignore ranges": False}}],
        expected=(
            "6to4: 2002:c633:6400::/40\n"
            "IPv4 Mapped: ::ffff:c633:6400/120\n"
            "IPv4 Translated: ::ffff:0:c633:6400/120\n"
            "Nat 64: 64:ff9b::c633:6400/120\n"
        ),
    ),
    BakeVector(
        name="ipv6_transition_addresses_remove_headers",
        input_data="198.51.100.7",
        recipe=[{"op": "IPv6 Transition Addresses", "args": {"Remove headers": True}}],
        expected="2002:c633:6407::/48\n::ffff:c633:6407\n::ffff:0:c633:6407\n64:ff9b::c633:6407\n",
    ),
    BakeVector(
        name="ipv6_transition_addresses_nat64_to_ipv4",
        input_data="64:ff9b::c633:6407",
        recipe=["IPv6 Transition Addresses"],
        expected="IPv4: 198.51.100.7\n",
    ),
    BakeVector(
        name="ipv6_transition_addresses_mac_to_eui64",
        input_data="a1:b2:c3:d4:e5:f6",
        recipe=["IPv6 Transition Addresses"],
        expected="EUI-64 Interface ID: a3b2:c3ff:fed4:e5f6",
    ),
    BakeVector(
        name="parse_ip_range_ipv4_cidr_default",
        input_data="10.0.0.0/30",
        recipe=["Parse IP range"],
        expected=(
            "Network: 10.0.0.0\n"
            "CIDR: 30\n"
            "Mask: 255.255.255.252\n"
            "Range: 10.0.0.0 - 10.0.0.3\n"
            "Total addresses in range: 4\n\n"
            "10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.3"
        ),
    ),
    BakeVector(
        name="parse_ip_range_ipv4_hyphenated_without_network_info",
        input_data="10.0.0.0 - 10.0.0.3",
        recipe=[{"op": "Parse IP range", "args": {"Include network info": False}}],
        expected="10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.3",
    ),
    BakeVector(
        name="parse_ip_range_ipv4_list_default",
        input_data="10.0.0.8\n10.0.0.5/30\n10.0.0.1\n10.0.0.3",
        recipe=["Parse IP range"],
        expected=(
            "Minimum subnet required to hold this range:\n"
            "\tNetwork: 10.0.0.0\n"
            "\tCIDR: 28\n"
            "\tMask: 255.255.255.240\n"
            "\tSubnet range: 10.0.0.0 - 10.0.0.15\n"
            "\tTotal addresses in subnet: 16\n\n"
            "Range: 10.0.0.1 - 10.0.0.8\n"
            "Total addresses in range: 8\n\n"
            "10.0.0.1\n10.0.0.2\n10.0.0.3\n10.0.0.4\n10.0.0.5\n10.0.0.6\n10.0.0.7\n10.0.0.8"
        ),
    ),
    BakeVector(
        name="parse_ip_range_ipv6_cidr_default",
        input_data="2404:6800:4001::/48",
        recipe=["Parse IP range"],
        expected=(
            "Network: 2404:6800:4001:0000:0000:0000:0000:0000\n"
            "Shorthand: 2404:6800:4001::\n"
            "CIDR: 48\n"
            "Mask: ffff:ffff:ffff:0000:0000:0000:0000:0000\n"
            "Range: 2404:6800:4001:0000:0000:0000:0000:0000 - 2404:6800:4001:ffff:ffff:ffff:ffff:ffff\n"
            "Total addresses in range: 1.2089258196146292e+24\n\n"
        ),
    ),
    BakeVector(
        name="parse_ipv4_header_hex_html_output",
        input_data=IPV4_HEADER_SAMPLE_HEX,
        recipe=["Parse IPv4 header"],
        expected=assert_parse_ipv4_header_html,
    ),
    BakeVector(
        name="parse_ipv4_header_strip_html_composition",
        input_data=IPV4_HEADER_SAMPLE_HEX,
        recipe=["Parse IPv4 header", "Strip HTML tags"],
        expected=(
            "FieldValue\n"
            "Version4\n"
            "Internet Header Length (IHL)5 (20 bytes)\n"
            "Differentiated Services Code Point (DSCP)48\n"
            "Explicit Congestion Notification (ECN)0\n"
            "Total length196 bytes\n"
            "IP header: 20 bytes\n"
            "Data: 176 bytes\n"
            "Identification0x289 (649)\n"
            "Flags0x00\n"
            "Reserved bit:0 (must be 0)\n"
            "Don't fragment:0\n"
            "More fragments:0\n"
            "Fragment offset0\n"
            "Time-To-Live255\n"
            "Protocol17, User Datagram (UDP)\n"
            "Header checksum1e8c (correct)\n"
            "Source IP address192.168.12.1\n"
            "Destination IP address192.168.12.2"
        ),
    ),
    BakeVector(
        name="parse_ipv6_address_nat64_translation",
        input_data="64:ff9b::c633:6407",
        recipe=["Parse IPv6 address"],
        expected=(
            "Longhand:  0064:ff9b:0000:0000:0000:0000:c633:6407\n"
            "Shorthand: 64:ff9b::c633:6407\n\n"
            "'Well-Known' prefix for IPv4/IPv6 translation detected. See RFC 6052 for more details.\n"
            "Translated IPv4 address: 198.51.100.7\n"
            "'Well-Known' prefix range: 64:ff9b::/96"
        ),
    ),
    BakeVector(
        name="parse_ipv6_address_teredo_sample",
        input_data="2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        recipe=["Parse IPv6 address"],
        expected=(
            "Longhand:  2001:0000:4136:e378:8000:63bf:3fff:fdd2\n"
            "Shorthand: 2001:0:4136:e378:8000:63bf:3fff:fdd2\n\n"
            "Teredo tunneling IPv6 address detected\n\n"
            "Server IPv4 address: 65.54.227.120\n"
            "Client IPv4 address: 192.0.2.45\n"
            "Client UDP port:     40000\n"
            "Flags:\n"
            "\tCone:    1 (Client is behind a cone NAT)\n"
            "\tR:       0\n"
            "\tRandom1: 0000\n"
            "\tUG:      00\n"
            "\tRandom2: 00000000\n\n"
            "This is a valid Teredo address which complies with RFC 4380, however it does not comply with RFC 5991 (Teredo Security Updates) as there are no randomised bits in the flag field.\n\n"
            "Teredo prefix range: 2001::/32"
        ),
    ),
    BakeVector(
        name="parse_ipv6_address_6to4_sample",
        input_data="2002:c633:6407::1",
        recipe=["Parse IPv6 address"],
        expected=(
            "Longhand:  2002:c633:6407:0000:0000:0000:0000:0001\n"
            "Shorthand: 2002:c633:6407::1\n\n"
            "6to4 transition IPv6 address detected. See RFC 3056 for more details.\n"
            "6to4 prefix range: 2002::/16\n\n"
            "Encapsulated IPv4 address: 198.51.100.7\n"
            "SLA ID: 0\n"
            "Interface ID (base 16): 0001\n"
            "Interface ID (base 10): 1"
        ),
    ),
    BakeVector(
        name="ja3_fingerprint_default_hash_digest",
        input_data=JA3_TLS12_SAMPLE_HEX,
        recipe=["JA3 Fingerprint"],
        expected=hashlib.md5(JA3_TLS12_STRING.encode()).hexdigest(),
    ),
    BakeVector(
        name="ja3_fingerprint_string_output",
        input_data=JA3_TLS12_SAMPLE_HEX,
        recipe=[{"op": "JA3 Fingerprint", "args": {"Output format": "JA3 string"}}],
        expected=JA3_TLS12_STRING,
    ),
    BakeVector(
        name="ja3_fingerprint_full_details_base64_input",
        input_data=JA3_TLS12_SAMPLE_BASE64,
        recipe=[
            {
                "op": "JA3 Fingerprint",
                "args": {"Input format": "Base64", "Output format": "Full details"},
            }
        ],
        expected=build_ja3_full_details(JA3_TLS12_STRING),
    ),
    BakeVector(
        name="ja3s_fingerprint_default_hash_digest",
        input_data=JA3S_TLS12_SAMPLE_HEX,
        recipe=["JA3S Fingerprint"],
        expected=hashlib.md5(JA3S_TLS12_STRING.encode()).hexdigest(),
    ),
    BakeVector(
        name="ja3s_fingerprint_string_output",
        input_data=JA3S_TLS12_SAMPLE_HEX,
        recipe=[{"op": "JA3S Fingerprint", "args": {"Output format": "JA3S string"}}],
        expected=JA3S_TLS12_STRING,
    ),
    BakeVector(
        name="ja3s_fingerprint_full_details",
        input_data=JA3S_TLS12_SAMPLE_HEX,
        recipe=[{"op": "JA3S Fingerprint", "args": {"Output format": "Full details"}}],
        expected=build_ja3s_full_details(JA3S_TLS12_STRING),
    ),
    BakeVector(
        name="ja4_fingerprint_default_output",
        input_data=JA4_TLS13_SAMPLE_HEX,
        recipe=[{"op": "JA4 Fingerprint", "args": {"Output format": "JA4"}}],
        expected="t13d1516h2_8daaf6152771_e5627efa2ab1",
    ),
    BakeVector(
        name="ja4_fingerprint_original_rendering_output",
        input_data=JA4_TLS12_SAMPLE_HEX,
        recipe=[{"op": "JA4 Fingerprint", "args": {"Output format": "JA4 Original Rendering"}}],
        expected="t13d1715h2_5b234860e130_014157ec0da2",
    ),
    BakeVector(
        name="ja4_fingerprint_all_output",
        input_data=JA4_TLS13_SAMPLE_HEX,
        recipe=[{"op": "JA4 Fingerprint", "args": {"Output format": "All"}}],
        expected=JA4_TLS13_ALL_OUTPUT,
    ),
    BakeVector(
        name="ja4server_fingerprint_default_output",
        input_data=JA4S_TLS12_SAMPLE_HEX,
        recipe=["JA4Server Fingerprint"],
        expected="t1204h2_cca9_1428ce7b4018",
    ),
    BakeVector(
        name="ja4server_fingerprint_raw_output",
        input_data=JA4S_TLS13_SAMPLE_HEX,
        recipe=[{"op": "JA4Server Fingerprint", "args": {"Output format": "JA4S Raw"}}],
        expected="t130200_1301_0033,002b",
    ),
    BakeVector(
        name="ja4server_fingerprint_both_output_base64_input",
        input_data=JA4S_TLS12_SAMPLE_BASE64,
        recipe=[
            {
                "op": "JA4Server Fingerprint",
                "args": {"Input format": "Base64", "Output format": "Both"},
            }
        ],
        expected="JA4S:   t1204h2_cca9_1428ce7b4018\nJA4S_r: t1204h2_cca9_0000,ff01,000b,0010",
    ),
    BakeVector(
        name="parse_tcp_hex_default_header_fields",
        input_data=PARSE_TCP_NO_OPTIONS_HEX,
        recipe=["Parse TCP"],
        expected={
            "Source port": 49899,
            "Destination port": 80,
            "Sequence number": "2704806702",
            "Acknowledgement number": 1893507001,
            "Data offset": "5 (20 bytes)",
            "Flags": {
                "Reserved": "000",
                "NS": 0,
                "CWR": 0,
                "ECE": 0,
                "URG": 0,
                "ACK": 1,
                "PSH": 1,
                "RST": 0,
                "SYN": 0,
                "FIN": 0,
            },
            "Window size": "1026 (Scaled: 1026)",
            "Checksum": "0x5ea7",
            "Urgent pointer": "0x0000",
        },
    ),
    BakeVector(
        name="parse_tcp_raw_bytes_with_options",
        input_data=bytes.fromhex(PARSE_TCP_OPTIONS_HEX),
        recipe=[{"op": "Parse TCP", "args": {"Input format": "Raw"}}],
        expected={
            "Source port": 49899,
            "Destination port": 80,
            "Sequence number": "2704804895",
            "Acknowledgement number": 0,
            "Data offset": "8 (32 bytes)",
            "Flags": {
                "Reserved": "000",
                "NS": 0,
                "CWR": 0,
                "ECE": 0,
                "URG": 0,
                "ACK": 0,
                "PSH": 0,
                "RST": 0,
                "SYN": 1,
                "FIN": 0,
            },
            "Window size": "64240 (Scaled: 16445440)",
            "Checksum": "0x8095",
            "Urgent pointer": "0x0000",
            "Options": {
                "Maximum Segment Size": {"Kind": 2, "Length": 4, "Value": 1460},
                "No-Operation": {"Kind": 1},
                "Window Scale": {
                    "Kind": 3,
                    "Length": 3,
                    "Value": {"Shift count": 8, "Multiplier": 256},
                },
                "SACK Permitted": {"Kind": 4, "Length": 2},
            },
        },
    ),
    BakeVector(
        name="parse_tls_record_truncated_header_returns_empty_list",
        input_data=bytes.fromhex("16030300"),
        recipe=["Parse TLS record"],
        expected=[],
    ),
    BakeVector(
        name="parse_tls_record_multiple_records",
        input_data=bytes.fromhex(PARSE_TLS_CHANGE_CIPHER_SPEC_HEX + PARSE_TLS_ALERT_HEX),
        recipe=["Parse TLS record"],
        expected=[
            {"type": "change_cipher_spec", "version": "0x0303", "length": 1, "value": "0x01"},
            {
                "type": "alert",
                "version": "0x0303",
                "length": 20,
                "value": "0x11770b5b5d11078535823266ec79671ed402bced",
            },
        ],
    ),
    BakeVector(
        name="parse_tls_record_client_hello",
        input_data=bytes.fromhex(PARSE_TLS_CLIENT_HELLO_HEX),
        recipe=["Parse TLS record"],
        expected=[
            {
                "type": "handshake",
                "version": "0x0303",
                "length": 50,
                "handshakeType": "client_hello",
                "clientVersion": "0x0303",
                "random": "0x45cd3a31beaebd2934dd4ec2a151d7a054eab8bc0e4e5b9d4b9abdaacd051076",
                "cipherSuites": {"length": 4, "values": ["0x1234", "0x4321"]},
                "compressionMethods": {"length": 2, "values": ["0x00", "0x01"]},
                "extensions": {},
            }
        ],
    ),
    BakeVector(
        name="parse_udp_hex_no_data",
        input_data=PARSE_UDP_NO_DATA_HEX,
        recipe=["Parse UDP"],
        expected={"Source port": 1161, "Destination port": 53, "Length": 44, "Checksum": "0x0101"},
    ),
    BakeVector(
        name="parse_udp_raw_bytes_with_payload",
        input_data=bytes.fromhex(PARSE_UDP_WITH_DATA_HEX.replace(" ", "")),
        recipe=[{"op": "Parse UDP", "args": {"Input format": "Raw"}}],
        expected={
            "Source port": 1161,
            "Destination port": 53,
            "Length": 44,
            "Checksum": "0x0101",
            "Data": "0x0202",
        },
    ),
    BakeVector(
        name="parse_uri_basic_query_string",
        input_data="https://www.google.co.uk/search?q=almonds",
        recipe=["Parse URI"],
        expected="Protocol:\thttps:\nHostname:\twww.google.co.uk\nPath name:\t/search\nArguments:\n\tq = almonds\n",
    ),
    BakeVector(
        name="parse_uri_auth_port_hash_and_blank_argument",
        input_data="ftp://user:pass@example.com:21/files/report.txt?download=&x=1#frag",
        recipe=["Parse URI"],
        expected=(
            "Protocol:\tftp:\n"
            "Auth:\t\tuser:pass\n"
            "Hostname:\texample.com\n"
            "Port:\t\t21\n"
            "Path name:\t/files/report.txt\n"
            "Arguments:\n"
            "\tdownload\n"
            "\tx        = 1\n"
            "Hash:\t\t#frag\n"
        ),
    ),
    BakeVector(
        name="url_decode_then_parse_uri_composition",
        input_data="https%3A%2F%2Fexample.com%2Fsearch%3Fq%3Done%2520two%26x%3D1",
        recipe=["URL Decode", "Parse URI"],
        expected=(
            "Protocol:\thttps:\n"
            "Hostname:\texample.com\n"
            "Path name:\t/search\n"
            "Arguments:\n"
            "\tq = one two\n"
            "\tx = 1\n"
        ),
    ),
    BakeVector(
        name="parse_user_agent_firefox_windows",
        input_data="Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0 ",
        recipe=["Parse User Agent"],
        expected=(
            "Browser\n"
            "    Name: Firefox\n"
            "    Version: 47.0\n"
            "Device\n"
            "    Model: unknown\n"
            "    Type: unknown\n"
            "    Vendor: unknown\n"
            "Engine\n"
            "    Name: Gecko\n"
            "    Version: 47.0\n"
            "OS\n"
            "    Name: Windows\n"
            "    Version: 7\n"
            "CPU\n"
            "    Architecture: amd64"
        ),
    ),
    BakeVector(
        name="parse_user_agent_mobile_safari",
        input_data=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
        ),
        recipe=["Parse User Agent"],
        expected=(
            "Browser\n"
            "    Name: Mobile Safari\n"
            "    Version: 16.0\n"
            "Device\n"
            "    Model: iPhone\n"
            "    Type: mobile\n"
            "    Vendor: Apple\n"
            "Engine\n"
            "    Name: WebKit\n"
            "    Version: 605.1.15\n"
            "OS\n"
            "    Name: iOS\n"
            "    Version: 16.3\n"
            "CPU\n"
            "    Architecture: unknown"
        ),
    ),
    BakeVector(
        name="protobuf_decode_without_schema",
        input_data=PROTOBUF_SAMPLE_BYTES,
        recipe=["Protobuf Decode"],
        expected={"1": 28, "2": "You", "3": "Me", "4": 43, "5": {"1": "abc123", "2": {}}},
    ),
    BakeVector(
        name="protobuf_decode_with_schema_show_types",
        input_data=bytes.fromhex("1203596f751a024d65202b3801"),
        recipe=[
            {
                "op": "Protobuf Decode",
                "args": {
                    "Schema (.proto text)": PROTOBUF_TYPED_SCHEMA,
                    "Show Unknown Fields": False,
                    "Show Types": True,
                },
            }
        ],
        expected={
            "Carrot (string)": ["Me"],
            "Banana (string)": "You",
            "Date (int32)": 43,
            "Imbe (Options)": "Option1",
        },
    ),
    BakeVector(
        name="protobuf_encode_full_schema_to_bytes",
        input_data=(
            '{"Apple":[28],"Banana":"You","Carrot":["Me"],"Date":43,'
            '"Elderberry":{"Fig":"abc123","Grape":{}},"Huckleberry":[3029774971578],"Imbe":1}'
        ),
        recipe=[{"op": "Protobuf Encode", "args": {"Schema (.proto text)": PROTOBUF_FULL_SCHEMA}}],
        expected=bytes.fromhex("0d1c0000001203596f751a024d65202b2a0a0a06616263313233120031ba32a96cc10200003801"),
    ),
    BakeVector(
        name="protobuf_encode_then_decode_roundtrip",
        input_data='{"Banana":"You","Date":43}',
        recipe=[
            {"op": "Protobuf Encode", "args": {"Schema (.proto text)": PROTOBUF_TYPED_SCHEMA}},
            {
                "op": "Protobuf Decode",
                "args": {
                    "Schema (.proto text)": PROTOBUF_TYPED_SCHEMA,
                    "Show Unknown Fields": False,
                    "Show Types": False,
                },
            },
        ],
        expected={"Banana": "You", "Date": 43, "Carrot": [], "Imbe": "Option0"},
    ),
    BakeVector(
        name="strip_http_headers_crlf_response",
        input_data="HTTP/1.1 200 OK\r\nHeader: value\r\n\r\nbody",
        recipe=["Strip HTTP headers"],
        expected="body",
    ),
    BakeVector(
        name="strip_http_headers_lf_request",
        input_data="GET / HTTP/1.1\nHost: example.com\n\npayload",
        recipe=["Strip HTTP headers"],
        expected="payload",
    ),
    BakeVector(
        name="strip_http_headers_passthrough_without_separator",
        input_data="header: value only",
        recipe=["Strip HTTP headers"],
        expected="header: value only",
    ),
    BakeVector(
        name="strip_ipv4_header_without_payload",
        input_data=bytes.fromhex("450000140005400080060000c0a80001c0a80002"),
        recipe=["Strip IPv4 header"],
        expected=b"",
    ),
    BakeVector(
        name="strip_ipv4_header_options_with_payload",
        input_data=bytes.fromhex("460000140005400080060000c0a80001c0a8000207000000ffffffffffffffff"),
        recipe=["Strip IPv4 header"],
        expected=bytes.fromhex("ffffffffffffffff"),
    ),
    BakeVector(
        name="strip_ipv4_header_then_parse_udp_raw",
        input_data=bytes.fromhex("450000140005400080060000c0a80001c0a800028111003500100000ffffffffffffffff"),
        recipe=["Strip IPv4 header", {"op": "Parse UDP", "args": {"Input format": "Raw"}}],
        expected={
            "Source port": 33041,
            "Destination port": 53,
            "Length": 16,
            "Checksum": "0x0000",
            "Data": "0xffffffffffffffff",
        },
    ),
    BakeVector(
        name="strip_tcp_header_without_payload",
        input_data=bytes.fromhex("7f900050000fa4b2000cb2a45010bff100000000"),
        recipe=["Strip TCP header"],
        expected=b"",
    ),
    BakeVector(
        name="strip_tcp_header_options_with_payload",
        input_data=bytes.fromhex("7f900050000fa4b2000cb2a47010bff100000000020405b404020000ffffffffffffffff"),
        recipe=["Strip TCP header"],
        expected=bytes.fromhex("ffffffffffffffff"),
    ),
    BakeVector(
        name="strip_tcp_header_then_decode_text",
        input_data=bytes.fromhex("7f900050000fa4b2000cb2a45010bff10000000048656c6c6f"),
        recipe=["Strip TCP header", {"op": "Decode text", "args": {"Encoding": "UTF-8 (65001)"}}],
        expected="Hello",
    ),
    BakeVector(
        name="strip_udp_header_without_payload",
        input_data=build_udp_datagram(1161, 53, b"", 0x0101),
        recipe=["Strip UDP header"],
        expected=b"",
    ),
    BakeVector(
        name="strip_udp_header_binary_payload",
        input_data=build_udp_datagram(1161, 53, b"\x00\xffpayload", 0x1A2B),
        recipe=["Strip UDP header"],
        expected=b"\x00\xffpayload",
    ),
    BakeVector(
        name="strip_udp_header_then_decode_text",
        input_data=build_udp_datagram(33041, 53, b"hello", 0x0000),
        recipe=["Strip UDP header", {"op": "Decode text", "args": {"Encoding": "UTF-8 (65001)"}}],
        expected="hello",
    ),
    BakeVector(
        name="varint_encode_zero",
        input_data="0",
        recipe=["VarInt Encode"],
        expected=build_varint_bytes(0),
    ),
    BakeVector(
        name="varint_encode_multibyte_300",
        input_data="300",
        recipe=["VarInt Encode"],
        expected=build_varint_bytes(300),
    ),
    BakeVector(
        name="varint_encode_large_uint64",
        input_data=str(2**64 - 1),
        recipe=["VarInt Encode"],
        expected=build_varint_bytes(2**64 - 1),
    ),
    BakeVector(
        name="varint_decode_empty_bytes_to_zero",
        input_data=b"",
        recipe=["VarInt Decode"],
        expected=build_varint_string(b""),
    ),
    BakeVector(
        name="varint_decode_multibyte_300",
        input_data=build_varint_bytes(300),
        recipe=["VarInt Decode"],
        expected=build_varint_string(build_varint_bytes(300)),
    ),
    BakeVector(
        name="varint_decode_large_uint64",
        input_data=build_varint_bytes(2**64 - 1),
        recipe=["VarInt Decode"],
        expected=build_varint_string(build_varint_bytes(2**64 - 1)),
    ),
    BakeVector(
        name="varint_encode_then_decode_roundtrip",
        input_data=str(2**64 - 1),
        recipe=["VarInt Encode", "VarInt Decode"],
        expected=str(2**64 - 1),
    ),
]

def build_chi_square_score(value: bytes) -> float:
    if not value:
        return 0.0

    distribution = [0] * 256
    for byte in value:
        distribution[byte] += 1

    expected = len(value) / 256
    return sum(((count - expected) ** 2) / expected for count in distribution if count > 0)


def build_entropy_value(value: bytes) -> float:
    if not value:
        return 0.0

    distribution = [0] * 256
    for byte in value:
        distribution[byte] += 1

    entropy = 0.0
    for count in distribution:
        if count == 0:
            continue
        probability = count / len(value)
        entropy -= probability * (math.log(probability, 2))

    return entropy


def build_entropy_curve(value: bytes) -> list[float]:
    if not value:
        return []

    bin_width = 8 if len(value) < 256 else 256
    return [build_entropy_value(value[index : index + bin_width]) for index in range(0, len(value), bin_width)]


def build_frequency_distribution_output(value: bytes) -> dict[str, object]:
    distribution = [0] * 256
    for byte in value:
        distribution[byte] += 1

    percentages = [(count / len(value)) * 100 for count in distribution]
    return {
        "dataLength": len(value),
        "percentages": percentages,
        "distribution": distribution,
        "bytesRepresented": sum(1 for count in distribution if count > 0),
    }


def build_de_bruijn_sequence(k: int, n: int) -> str:
    alphabet = [0] * (k * n)
    sequence: list[int] = []

    def visit(t: int = 1, p: int = 1) -> None:
        if t > n:
            if n % p != 0:
                return
            for index in range(1, p + 1):
                sequence.append(alphabet[index])
            return

        alphabet[t] = alphabet[t - p]
        visit(t + 1, p)
        for index in range(alphabet[t - p] + 1, k):
            alphabet[t] = index
            visit(t + 1, t)

    visit()
    return "".join(str(value) for value in sequence)


def build_base32_bytes(value: str) -> bytes:
    padding = (-len(value)) % 8
    return base64.b32decode(value + ("=" * padding), casefold=True)


def build_hotp_code(secret: str, *, counter: int, digits: int) -> str:
    digest = hmac.new(
        build_base32_bytes(secret),
        counter.to_bytes(8, byteorder="big"),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    truncated = int.from_bytes(digest[offset : offset + 4], byteorder="big") & 0x7FFFFFFF
    return f"{truncated % (10**digits):0{digits}d}"


def build_hotp_output(secret: str, *, digits: int, counter: int, name: str = "") -> str:
    label = f"/{name}" if name else "/"
    return (
        f"URI: otpauth://hotp{label}?secret={secret}&algorithm=SHA1&digits={digits}&counter={counter}"
        f"\n\nPassword: {build_hotp_code(secret, counter=counter, digits=digits)}"
    )


def build_totp_output(
    secret: str,
    *,
    digits: int,
    epoch_offset: int,
    interval: int,
    at_time: int,
    name: str = "",
) -> str:
    counter = (at_time - epoch_offset) // interval
    label = f"/{name}" if name else "/"
    return (
        f"URI: otpauth://totp{label}?secret={secret}&algorithm=SHA1&digits={digits}&period={interval}"
        f"\n\nPassword: {build_hotp_code(secret, counter=counter, digits=digits)}"
    )


def assert_qr_code_png_hello(result: object) -> None:
    assert isinstance(result, bytes)
    assert result.startswith(b"\x89PNG\r\n\x1a\n")
    assert result[12:16] == b"IHDR"
    assert struct.unpack(">II", result[16:24]) == (145, 145)


def assert_qr_code_svg_hello(result: object) -> None:
    assert isinstance(result, bytes)
    assert result.startswith(b"<svg ")
    assert b'width="21"' in result
    assert b'height="21"' in result
    assert b'viewBox="0 0 21 21"' in result
    assert b"<path d=\"" in result


def build_uuid_version_assertion(expected_version: int) -> Callable[[object], None]:
    def assert_uuid_version(result: object) -> None:
        assert isinstance(result, str)
        parsed = uuid.UUID(result)
        assert str(parsed) == result
        assert parsed.version == expected_version

    return assert_uuid_version


def build_haversine_distance(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    to_radians = math.pi / 180
    delta_latitude = (lat2 - lat1) * to_radians
    delta_longitude = (lng2 - lng1) * to_radians
    a_value = (
        math.sin(delta_latitude / 2) ** 2
        + math.cos(lat1 * to_radians) * math.cos(lat2 * to_radians) * math.sin(delta_longitude / 2) ** 2
    )
    return 6371000 * 2 * math.atan2(math.sqrt(a_value), math.sqrt(1 - a_value))


def build_index_of_coincidence(text: str) -> float:
    frequencies = [0] * 26

    for character in text.lower():
        if "a" <= character <= "z":
            frequencies[ord(character) - ord("a")] += 1

    coincidence = sum(frequency * (frequency - 1) for frequency in frequencies)
    density = max(sum(frequencies), 2)
    return coincidence / (density * (density - 1))


def build_numberwang_assertion(expected_prefix: str) -> Callable[[object], None]:
    def assert_numberwang(result: object) -> None:
        assert isinstance(result, str)
        assert result.startswith(expected_prefix)
        assert "\n\nDid you know: " in result
        fact = result.split("\n\nDid you know: ", maxsplit=1)[1]
        assert fact

    return assert_numberwang


def build_float_approx_assertion(expected: float, *, rel: float = 1e-12, abs: float = 0.0) -> Callable[[object], None]:
    def assert_float(result: object) -> None:
        assert isinstance(result, float)
        assert result == pytest.approx(expected, rel=rel, abs=abs)

    return assert_float


def assert_html_to_text_preserves_raw_parse_ipv4_markup(result: object) -> None:
    assert isinstance(result, str)
    decoded = base64.b64decode(result).decode()
    assert decoded.startswith("<table ")
    assert "<td>Version</td><td>4</td>" in decoded
    assert "<td>Total length</td><td>196 bytes" in decoded
    assert "<td>Protocol</td><td>17, User Datagram (UDP)</td>" in decoded
    assert decoded.endswith("</table>")


def extract_js_string_constant(source: str, name: str) -> str:
    match = re.search(rf'export const {re.escape(name)} = "(.*?)";', source, re.S)
    if not match:
        raise ValueError(f"Could not find JS string constant {name}")
    return match.group(1)


def extract_js_template_constant(source: str, name: str) -> str:
    match = re.search(rf"const {re.escape(name)} = `(.*?)`;", source, re.S)
    if not match:
        raise ValueError(f"Could not find JS template constant {name}")
    return match.group(1)


def extract_pgp_case_input(source: str, case_name: str) -> str:
    match = re.search(
        rf'name: "{re.escape(case_name)}",\s*input: `(.*?)`,\s*expectedOutput:',
        source,
        re.S,
    )
    if not match:
        raise ValueError(f"Could not find PGP case input {case_name}")
    return match.group(1)


def extract_pgp_case_expected_literal(source: str, case_name: str) -> str:
    match = re.search(
        rf'name: "{re.escape(case_name)}",\s*input: `.*?`,\s*expectedOutput: `(.*?)`,\s*recipeConfig:',
        source,
        re.S,
    )
    if not match:
        raise ValueError(f"Could not find literal expected output for PGP case {case_name}")
    return match.group(1)


REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_DATA_DIR = REPO_ROOT / "tests" / "data"
UPSTREAM_PGP_TESTS_TEXT = (REPO_ROOT / "deps" / "CyberChef" / "tests" / "operations" / "tests" / "PGP.mjs").read_text()
UPSTREAM_CIPHER_SAMPLES_TEXT = (REPO_ROOT / "deps" / "CyberChef" / "tests" / "samples" / "Ciphers.mjs").read_text()
PGP_ALICE_PRIVATE_KEY = extract_js_template_constant(UPSTREAM_PGP_TESTS_TEXT, "ALICE_PRIVATE")
PGP_ALICE_PUBLIC_KEY = extract_js_template_constant(UPSTREAM_PGP_TESTS_TEXT, "ALICE_PUBLIC")
PGP_BOB_PRIVATE_KEY = extract_js_template_constant(UPSTREAM_PGP_TESTS_TEXT, "BOB_PRIVATE")
PGP_BOB_PUBLIC_KEY = extract_js_template_constant(UPSTREAM_PGP_TESTS_TEXT, "BOB_PUBLIC")
PGP_ASCII_TEXT = extract_js_string_constant(UPSTREAM_CIPHER_SAMPLES_TEXT, "ASCII_TEXT")
PGP_UTF8_TEXT = extract_js_string_constant(UPSTREAM_CIPHER_SAMPLES_TEXT, "UTF8_TEXT")
PGP_VERIFY_INPUT = extract_pgp_case_input(UPSTREAM_PGP_TESTS_TEXT, "PGP Verify: ASCII, Alice")
PGP_VERIFY_EXPECTED = extract_pgp_case_expected_literal(UPSTREAM_PGP_TESTS_TEXT, "PGP Verify: ASCII, Alice")
PGP_DECRYPT_INPUT = extract_pgp_case_input(UPSTREAM_PGP_TESTS_TEXT, "PGP Decrypt: ASCII, Alice -> Bob")
PGP_DECRYPT_AND_VERIFY_INPUT = extract_pgp_case_input(
    UPSTREAM_PGP_TESTS_TEXT, "PGP Decrypt and Verify: UTF8, Alice -> Bob"
)
PGP_DECRYPT_AND_VERIFY_EXPECTED = extract_pgp_case_expected_literal(
    UPSTREAM_PGP_TESTS_TEXT, "PGP Decrypt and Verify: UTF8, Alice -> Bob"
).replace("${UTF8_TEXT}", PGP_UTF8_TEXT)
RSA_TEST_PRIVATE_KEY_PEM = (TEST_DATA_DIR / "public_key_phase45_rsa_private.pem").read_text()
RSA_TEST_PUBLIC_KEY_PEM = (TEST_DATA_DIR / "public_key_phase45_rsa_public.pem").read_text()
RSA_TEST_CSR_PEM = (TEST_DATA_DIR / "public_key_phase45_parse_csr.pem").read_text()
SSH_RSA_HOST_KEY_PUBLIC = (TEST_DATA_DIR / "public_key_phase45_ssh_host_key.pub").read_text()
RSA_TEST_SHA256_SIGNATURE = bytes.fromhex(
    "38015b89cac4dc16ccedf3d7ffbeb81521af828f9298dfcf613d268d0ec673fac4b115f203a8c0ccb00800bbcd2af2c81f14a8ef5cf6d3251eba94828ba2b770a938f03230b490234d6c70da9d73a0a0c013195b20ffc7adc7e25d1717e3218f21b31361e023dca9426761c587ad8f044c91e9fecc96abfbbdbe5a028e51ec47"
)
SM2_TEST_PRIVATE_KEY = "b714695bb3344da7fb8f5ca4524213b31ec946c5feeddcf86d11ea88827e667b"
SM2_TEST_PUBLIC_KEY_X = "a3a4faf374e0f1fe63c95c951a63cd6dc08a4b500ece0a433f463fa4b7a4764d"
SM2_TEST_PUBLIC_KEY_Y = "3e88d2372b5853f578cb46b8a870f6e057a130298c977a3986a2f3165aada482"
SM2_TEST_MESSAGE = bytes.fromhex("0001534d32ff")
SM2_TEST_C1C3C2_CIPHERTEXT = (
    "4f251a9946d8999eb999076430b37e1f10092585c4a41544ad1f73d2e4849805"
    "ba75046968a80f282c36ea7b4e3c829e17f62212a485e70da544da361913b4ac"
    "ffed6ed8d6a0261a21a6bd19995b3482bd605ba8834d3e968a8cbebc5516e250"
    "16793be6068f"
)
SM2_TEST_C1C2C3_CIPHERTEXT = (
    "088580fa1d0ca161d4411f48d0684919aa0e69b7e1a3276211f295e52ef6b4bd"
    "57ad35110273fbdf9536efbf7b89cf3c979c8cf382554936b67063605b0fea20"
    "3dfcfdbf42ad039f0c18c608d93a4faffa0619528367545df63f2e762293b9b2"
    "727a8d1d54b1"
)


def parse_json_lines(value: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in value.splitlines() if line.strip()]


def assert_pgp_signed_output(result: object, expected_message: str) -> None:
    assert isinstance(result, str)
    assert result.startswith("Signed by PGP key ID: DF98E485\n")
    assert "PGP fingerprint: e94e06dd0b3744a0e970de9d84246548df98e485\n" in result
    assert re.search(r"^Signed by PGP key ID: DF98E485\nPGP fingerprint: e94e06dd0b3744a0e970de9d84246548df98e485\nSigned on .+ GMT\n----------------------------------\n", result)
    assert result.endswith(expected_message)


def assert_parse_csr_output(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("Subject\n")
    assert "  CN = example.test\n" in result
    assert "  O  = Example Org\n" in result
    assert "  C  = US\n" in result
    assert "  Algorithm:      RSA\n" in result
    assert "  Length:         1024 bits\n" in result
    assert "  Exponent:       65537 (0x10001)\n" in result
    assert "  Key Usage:\n    Digital Signature\n    Key encipherment\n" in result
    assert "  Extended Key Usage:\n    TLS Web Server Authentication\n    TLS Web Client Authentication\n" in result
    assert "  Subject Alternative Name:\n    DNS: example.test\n    DNS: www.example.test" in result


def assert_generated_ecdsa_pem_key_pair(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert "\n\n-----BEGIN PRIVATE KEY-----\n" in result
    keys = parse_json_lines(bake(result, ["PEM to JWK"]))
    assert len(keys) == 2
    assert all(key["kty"] == "EC" for key in keys)
    assert {key["crv"] for key in keys} == {"P-256"}
    assert sum("d" in key for key in keys) == 1


def assert_generated_ecdsa_jwk_key_pair(result: object) -> None:
    assert isinstance(result, str)
    parsed = json.loads(result)
    assert list(parsed) == ["keys"]
    assert len(parsed["keys"]) == 2
    private_key, public_key = parsed["keys"]
    assert private_key["kty"] == "EC"
    assert private_key["crv"] == "P-256"
    assert private_key["kid"] == "PrivateKey"
    assert private_key["key_ops"] == ["sign"]
    assert "d" in private_key
    assert public_key["kty"] == "EC"
    assert public_key["crv"] == "P-256"
    assert public_key["kid"] == "PublicKey"
    assert public_key["key_ops"] == ["verify"]
    assert "d" not in public_key
    pem_output = bake(result, ["JWK to PEM"])
    assert isinstance(pem_output, str)
    assert "-----BEGIN PRIVATE KEY-----\r\n" in pem_output
    assert "-----BEGIN PUBLIC KEY-----\r\n" in pem_output


def assert_generated_rsa_pem_key_pair(result: object) -> None:
    assert isinstance(result, str)
    assert result.startswith("-----BEGIN PUBLIC KEY-----\r\n")
    assert "-----BEGIN RSA PRIVATE KEY-----\r\n" in result
    keys = parse_json_lines(bake(result, ["PEM to JWK"]))
    assert len(keys) == 2
    assert all(key["kty"] == "RSA" for key in keys)
    assert all("n" in key and "e" in key for key in keys)
    assert sum("d" in key for key in keys) == 1


PUBLIC_KEY_VECTORS = [
    BakeVector(
        name="ecdsa_sign_verify_pkcs1_asn1_roundtrip",
        input_data=ECDSA_TEST_MESSAGE,
        recipe=[
            {
                "op": "ECDSA Sign",
                "args": {
                    "ECDSA Private Key (PEM)": ECDSA_P256_PRIVATE_KEY_PKCS1_PEM,
                    "Message Digest Algorithm": "SHA-256",
                    "Output Format": "ASN.1 HEX",
                },
            },
            {
                "op": "ECDSA Verify",
                "args": {
                    "Input Format": "ASN.1 HEX",
                    "Message Digest Algorithm": "SHA-256",
                    "ECDSA Public Key (PEM)": ECDSA_P256_PUBLIC_KEY_PEM,
                    "Message": ECDSA_TEST_MESSAGE,
                    "Message format": "Raw",
                },
            },
        ],
        expected="Verified OK",
    ),
    BakeVector(
        name="ecdsa_sign_verify_hex_message_format_roundtrip",
        input_data="cdb23f958e018418621d9e489b7bba0f0c481f604eba2eb1ea35e38f99490cc0",
        recipe=[
            {"op": "From Hex", "args": {"Delimiter": "Auto"}},
            {
                "op": "ECDSA Sign",
                "args": {
                    "ECDSA Private Key (PEM)": ECDSA_P256_PRIVATE_KEY_PKCS1_PEM,
                    "Message Digest Algorithm": "SHA-256",
                    "Output Format": "ASN.1 HEX",
                },
            },
            {
                "op": "ECDSA Verify",
                "args": {
                    "Input Format": "ASN.1 HEX",
                    "Message Digest Algorithm": "SHA-256",
                    "ECDSA Public Key (PEM)": ECDSA_P256_PUBLIC_KEY_PEM,
                    "Message": "cdb23f958e018418621d9e489b7bba0f0c481f604eba2eb1ea35e38f99490cc0",
                    "Message format": "Hex",
                },
            },
        ],
        expected="Verified OK",
    ),
    BakeVector(
        name="ecdsa_verify_known_jws_signature",
        input_data=ECDSA_P256_SIGNATURE_SHA256_JWS,
        recipe=[
            {
                "op": "ECDSA Verify",
                "args": {
                    "Input Format": "Auto",
                    "Message Digest Algorithm": "SHA-256",
                    "ECDSA Public Key (PEM)": ECDSA_P256_PUBLIC_KEY_PEM,
                    "Message": ECDSA_TEST_MESSAGE,
                    "Message format": "Raw",
                },
            }
        ],
        expected="Verified OK",
    ),
    BakeVector(
        name="ecdsa_signature_conversion_asn1_to_jws",
        input_data=ECDSA_P256_SIGNATURE_SHA256_ASN1,
        recipe=[
            {
                "op": "ECDSA Signature Conversion",
                "args": {"Input Format": "Auto", "Output Format": "JSON Web Signature"},
            }
        ],
        expected=ECDSA_P256_SIGNATURE_SHA256_JWS,
    ),
    BakeVector(
        name="ecdsa_signature_conversion_json_to_p1363",
        input_data=ECDSA_P256_SIGNATURE_SHA256_JSON,
        recipe=[
            {
                "op": "ECDSA Signature Conversion",
                "args": {"Input Format": "Auto", "Output Format": "P1363 HEX"},
            }
        ],
        expected=ECDSA_P256_SIGNATURE_SHA256_P1363,
    ),
    BakeVector(
        name="generate_ecdsa_key_pair_pem_structure",
        input_data="",
        recipe=[
            {
                "op": "Generate ECDSA Key Pair",
                "args": {"Elliptic Curve": "P-256", "Output Format": "PEM"},
            }
        ],
        expected=assert_generated_ecdsa_pem_key_pair,
    ),
    BakeVector(
        name="generate_ecdsa_key_pair_jwk_roundtrip_to_pem",
        input_data="",
        recipe=[
            {
                "op": "Generate ECDSA Key Pair",
                "args": {"Elliptic Curve": "P-256", "Output Format": "JWK"},
            }
        ],
        expected=assert_generated_ecdsa_jwk_key_pair,
    ),
    BakeVector(
        name="generate_rsa_key_pair_pem_roundtrip_to_jwk",
        input_data="",
        recipe=[
            {
                "op": "Generate RSA Key Pair",
                "args": {"RSA Key Length": "1024", "Output Format": "PEM"},
            }
        ],
        expected=assert_generated_rsa_pem_key_pair,
    ),
    BakeVector(
        name="pgp_encrypt_decrypt_rsa_roundtrip",
        input_data=PGP_ASCII_TEXT,
        recipe=[
            {"op": "PGP Encrypt", "args": {"Public key of recipient": PGP_ALICE_PUBLIC_KEY}},
            {
                "op": "PGP Decrypt",
                "args": {
                    "Private key of recipient": PGP_ALICE_PRIVATE_KEY,
                    "Private key passphrase": "",
                },
            },
        ],
        expected=PGP_ASCII_TEXT,
    ),
    BakeVector(
        name="pgp_decrypt_upstream_ascii_ciphertext",
        input_data=PGP_DECRYPT_INPUT,
        recipe=[
            {
                "op": "PGP Decrypt",
                "args": {
                    "Private key of recipient": PGP_ALICE_PRIVATE_KEY,
                    "Private key passphrase": "",
                },
            }
        ],
        expected=PGP_ASCII_TEXT,
    ),
    BakeVector(
        name="pgp_verify_upstream_ascii_signed_message",
        input_data=PGP_VERIFY_INPUT,
        recipe=[{"op": "PGP Verify", "args": {"Public key of signer": PGP_ALICE_PUBLIC_KEY}}],
        expected=PGP_VERIFY_EXPECTED,
    ),
    BakeVector(
        name="pgp_encrypt_and_sign_decrypt_and_verify_roundtrip",
        input_data="hello",
        recipe=[
            {
                "op": "PGP Encrypt and Sign",
                "args": {
                    "Private key of signer": PGP_ALICE_PRIVATE_KEY,
                    "Private key passphrase": "",
                    "Public key of recipient": PGP_BOB_PUBLIC_KEY,
                },
            },
            {
                "op": "PGP Decrypt and Verify",
                "args": {
                    "Public key of signer": PGP_ALICE_PUBLIC_KEY,
                    "Private key of recipient": PGP_BOB_PRIVATE_KEY,
                    "Private key password": "",
                },
            },
        ],
        expected=lambda result: assert_pgp_signed_output(result, "hello"),
    ),
    BakeVector(
        name="pgp_decrypt_and_verify_upstream_utf8_message",
        input_data=PGP_DECRYPT_AND_VERIFY_INPUT,
        recipe=[
            {
                "op": "PGP Decrypt and Verify",
                "args": {
                    "Public key of signer": PGP_ALICE_PUBLIC_KEY,
                    "Private key of recipient": PGP_BOB_PRIVATE_KEY,
                    "Private key password": "",
                },
            }
        ],
        expected=PGP_DECRYPT_AND_VERIFY_EXPECTED,
    ),
    BakeVector(
        name="parse_csr_rsa_with_requested_extensions",
        input_data=RSA_TEST_CSR_PEM,
        recipe=["Parse CSR"],
        expected=assert_parse_csr_output,
    ),
    BakeVector(
        name="parse_ssh_host_key_rsa_public_key",
        input_data=SSH_RSA_HOST_KEY_PUBLIC,
        recipe=["Parse SSH Host Key"],
        expected=(
            "Key type: ssh-rsa\n"
            "Exponent: 0x010001\n"
            "Modulus: "
            "0x00a67f62b1a9f27aee5a6e0b51331b39e70807a6f0a8c5ee73399f3cad601681afc0763205fbfd6dbe5d5bffbb59e8eccbb29630c50d76fada242a43e9a8b2d994e2e6047a0df7060c3960bf8e5c5c3e947e1c03e935f1a6ece6bb88b2ef061a8e9e1686de3066b5c62e5b7c6e4d9a4f1e1a5a5e4ab35b8a3f7e23cab32875c0c5"
        ),
    ),
    BakeVector(
        name="rsa_encrypt_decrypt_oaep_sha256_roundtrip",
        input_data="hello rsa",
        recipe=[
            {
                "op": "RSA Encrypt",
                "args": {
                    "RSA Public Key (PEM)": RSA_TEST_PUBLIC_KEY_PEM,
                    "Encryption Scheme": "RSA-OAEP",
                    "Message Digest Algorithm": "SHA-256",
                },
            },
            {
                "op": "RSA Decrypt",
                "args": {
                    "RSA Private Key (PEM)": RSA_TEST_PRIVATE_KEY_PEM,
                    "Key Password": "",
                    "Encryption Scheme": "RSA-OAEP",
                    "Message Digest Algorithm": "SHA-256",
                },
            },
        ],
        expected="hello rsa",
    ),
    BakeVector(
        name="rsa_sign_verify_sha256_roundtrip",
        input_data="hello rsa",
        recipe=[
            {
                "op": "RSA Sign",
                "args": {
                    "RSA Private Key (PEM)": RSA_TEST_PRIVATE_KEY_PEM,
                    "Key Password": "",
                    "Message Digest Algorithm": "SHA-256",
                },
            },
            {
                "op": "RSA Verify",
                "args": {
                    "RSA Public Key (PEM)": RSA_TEST_PUBLIC_KEY_PEM,
                    "Message": "hello rsa",
                    "Message format": "Raw",
                    "Message Digest Algorithm": "SHA-256",
                },
            },
        ],
        expected="Verified OK",
    ),
    BakeVector(
        name="rsa_verify_known_signature_raw_message",
        input_data=RSA_TEST_SHA256_SIGNATURE,
        recipe=[
            {
                "op": "RSA Verify",
                "args": {
                    "RSA Public Key (PEM)": RSA_TEST_PUBLIC_KEY_PEM,
                    "Message": "hello rsa",
                    "Message format": "Raw",
                    "Message Digest Algorithm": "SHA-256",
                },
            }
        ],
        expected="Verified OK",
    ),
    BakeVector(
        name="rsa_verify_known_signature_hex_message",
        input_data=RSA_TEST_SHA256_SIGNATURE,
        recipe=[
            {
                "op": "RSA Verify",
                "args": {
                    "RSA Public Key (PEM)": RSA_TEST_PUBLIC_KEY_PEM,
                    "Message": "68656c6c6f20727361",
                    "Message format": "Hex",
                    "Message Digest Algorithm": "SHA-256",
                },
            }
        ],
        expected="Verified OK",
    ),
    BakeVector(
        name="rsa_verify_known_signature_base64_message",
        input_data=RSA_TEST_SHA256_SIGNATURE,
        recipe=[
            {
                "op": "RSA Verify",
                "args": {
                    "RSA Public Key (PEM)": RSA_TEST_PUBLIC_KEY_PEM,
                    "Message": "aGVsbG8gcnNh",
                    "Message format": "Base64",
                    "Message Digest Algorithm": "SHA-256",
                },
            }
        ],
        expected="Verified OK",
    ),
    BakeVector(
        name="rsa_verify_rejects_wrong_message",
        input_data=RSA_TEST_SHA256_SIGNATURE,
        recipe=[
            {
                "op": "RSA Verify",
                "args": {
                    "RSA Public Key (PEM)": RSA_TEST_PUBLIC_KEY_PEM,
                    "Message": "goodbye rsa",
                    "Message format": "Raw",
                    "Message Digest Algorithm": "SHA-256",
                },
            }
        ],
        expected="Verification Failure",
    ),
    BakeVector(
        name="sm2_encrypt_decrypt_c1c3c2_binary_roundtrip",
        input_data=SM2_TEST_MESSAGE,
        recipe=[
            {
                "op": "SM2 Encrypt",
                "args": {
                    "Public Key X": SM2_TEST_PUBLIC_KEY_X,
                    "Public Key Y": SM2_TEST_PUBLIC_KEY_Y,
                    "Output Format": "C1C3C2",
                    "Curve": "sm2p256v1",
                },
            },
            {
                "op": "SM2 Decrypt",
                "args": {
                    "Private Key": SM2_TEST_PRIVATE_KEY,
                    "Input Format": "C1C3C2",
                    "Curve": "sm2p256v1",
                },
            },
        ],
        expected=SM2_TEST_MESSAGE,
    ),
    BakeVector(
        name="sm2_encrypt_decrypt_c1c2c3_binary_roundtrip",
        input_data=SM2_TEST_MESSAGE,
        recipe=[
            {
                "op": "SM2 Encrypt",
                "args": {
                    "Public Key X": SM2_TEST_PUBLIC_KEY_X,
                    "Public Key Y": SM2_TEST_PUBLIC_KEY_Y,
                    "Output Format": "C1C2C3",
                    "Curve": "sm2p256v1",
                },
            },
            {
                "op": "SM2 Decrypt",
                "args": {
                    "Private Key": SM2_TEST_PRIVATE_KEY,
                    "Input Format": "C1C2C3",
                    "Curve": "sm2p256v1",
                },
            },
        ],
        expected=SM2_TEST_MESSAGE,
    ),
    BakeVector(
        name="sm2_decrypt_known_c1c3c2_ciphertext",
        input_data=SM2_TEST_C1C3C2_CIPHERTEXT,
        recipe=[
            {
                "op": "SM2 Decrypt",
                "args": {
                    "Private Key": SM2_TEST_PRIVATE_KEY,
                    "Input Format": "C1C3C2",
                    "Curve": "sm2p256v1",
                },
            }
        ],
        expected=SM2_TEST_MESSAGE,
    ),
    BakeVector(
        name="sm2_decrypt_known_c1c2c3_ciphertext",
        input_data=SM2_TEST_C1C2C3_CIPHERTEXT,
        recipe=[
            {
                "op": "SM2 Decrypt",
                "args": {
                    "Private Key": SM2_TEST_PRIVATE_KEY,
                    "Input Format": "C1C2C3",
                    "Curve": "sm2p256v1",
                },
            }
        ],
        expected=SM2_TEST_MESSAGE,
    ),
    BakeVector(
        name="hex_to_object_identifier_server_auth_oid",
        input_data="2b06010505070301",
        recipe=["Hex to Object Identifier"],
        expected="1.3.6.1.5.5.7.3.1",
    ),
    BakeVector(
        name="object_identifier_to_hex_server_auth_oid",
        input_data="1.3.6.1.5.5.7.3.1",
        recipe=["Object Identifier to Hex"],
        expected="2b06010505070301",
    ),
    BakeVector(
        name="pem_to_jwk_ec_public_key_exact",
        input_data=ECDSA_P256_PUBLIC_KEY_PEM,
        recipe=["PEM to JWK"],
        expected=ECDSA_P256_PUBLIC_JWK,
    ),
    BakeVector(
        name="pem_to_jwk_ec_private_key_exact",
        input_data=ECDSA_P256_PRIVATE_KEY_PKCS1_PEM,
        recipe=["PEM to JWK"],
        expected=ECDSA_P256_PRIVATE_JWK,
    ),
    BakeVector(
        name="jwk_to_pem_ec_public_key_exact",
        input_data=ECDSA_P256_PUBLIC_JWK,
        recipe=["JWK to PEM"],
        expected=ECDSA_P256_PUBLIC_KEY_PEM_CRLF,
    ),
    BakeVector(
        name="jwk_to_pem_ec_private_key_exact",
        input_data=ECDSA_P256_PRIVATE_JWK,
        recipe=["JWK to PEM"],
        expected=ECDSA_P256_PRIVATE_KEY_PKCS8_PEM_CRLF,
    ),
]


OTHER_VECTORS = [
    BakeVector(
        name="analyse_uuid_version_1_namespace_dns",
        input_data="6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        recipe=["Analyse UUID"],
        expected="UUID version: 1",
    ),
    BakeVector(
        name="analyse_uuid_version_4_random",
        input_data="550e8400-e29b-41d4-a716-446655440000",
        recipe=["Analyse UUID"],
        expected="UUID version: 4",
    ),
    BakeVector(
        name="chi_square_empty_bytes",
        input_data=b"",
        recipe=["Chi Square"],
        expected=build_chi_square_score(b""),
    ),
    BakeVector(
        name="chi_square_uniform_byte_range",
        input_data=bytes(range(256)),
        recipe=["Chi Square"],
        expected=build_chi_square_score(bytes(range(256))),
    ),
    BakeVector(
        name="disassemble_x86_64_nop_ret",
        input_data="90 c3",
        recipe=["Disassemble x86"],
        expected=(
            "0000000000000000 90                              NOP\r\n"
            "0000000000000001 C3                              RET\r\n"
        ),
    ),
    BakeVector(
        name="disassemble_x86_32_without_hex_or_position",
        input_data="B800000000C3",
        recipe=[
            {
                "op": "Disassemble x86",
                "args": {
                    "Bit mode": "32",
                    "Compatibility": "Full x86 architecture",
                    "Code Segment (CS)": 16,
                    "Offset (IP)": 4096,
                    "Show instruction hex": False,
                    "Show instruction position": False,
                },
            }
        ],
        expected="MOV EAX,00000000\r\nRET\r\n",
    ),
    BakeVector(
        name="entropy_single_bit_of_information",
        input_data=b"\x00\x01",
        recipe=["Entropy"],
        expected=build_entropy_value(b"\x00\x01"),
    ),
    BakeVector(
        name="entropy_curve_two_equal_blocks",
        input_data=bytes(range(16)),
        recipe=[{"op": "Entropy", "args": {"Visualisation": "Curve"}}],
        expected=build_entropy_curve(bytes(range(16))),
    ),
    BakeVector(
        name="frequency_distribution_repeated_ascii_bytes",
        input_data=b"ABCA",
        recipe=["Frequency distribution"],
        expected=build_frequency_distribution_output(b"ABCA"),
    ),
    BakeVector(
        name="generate_de_bruijn_sequence_default_parameters",
        input_data="",
        recipe=["Generate De Bruijn Sequence"],
        expected=build_de_bruijn_sequence(2, 3),
    ),
    BakeVector(
        name="generate_de_bruijn_sequence_ternary_pairs",
        input_data="",
        recipe=[{"op": "Generate De Bruijn Sequence", "args": {"Alphabet size (k)": 3, "Key length (n)": 2}}],
        expected=build_de_bruijn_sequence(3, 2),
    ),
    BakeVector(
        name="generate_hotp_rfc_base32_secret",
        input_data=b"JBSWY3DPEHPK3PXP",
        recipe=[{"op": "Generate HOTP", "args": {"Code length": 6, "Counter": 0}}],
        expected=build_hotp_output("JBSWY3DPEHPK3PXP", digits=6, counter=0),
    ),
    BakeVector(
        name="generate_lorem_ipsum_five_words",
        input_data="",
        recipe=[{"op": "Generate Lorem Ipsum", "args": {"Length": 5, "Length in": "Words"}}],
        expected="Lorem ipsum dolor sit amet.",
    ),
    BakeVector(
        name="generate_lorem_ipsum_eleven_bytes",
        input_data="",
        recipe=[{"op": "Generate Lorem Ipsum", "args": {"Length": 11, "Length in": "Bytes"}}],
        expected="Lorem ipsum",
    ),
    BakeVector(
        name="generate_qr_code_default_png_hello",
        input_data="hello",
        recipe=["Generate QR Code"],
        expected=assert_qr_code_png_hello,
    ),
    BakeVector(
        name="generate_qr_code_svg_without_margin",
        input_data="hello",
        recipe=[
            {
                "op": "Generate QR Code",
                "args": {
                    "Image Format": "SVG",
                    "Module size (px)": 1,
                    "Margin (num modules)": 0,
                    "Error correction": "Low",
                },
            }
        ],
        expected=assert_qr_code_svg_hello,
    ),
    BakeVector(
        name="generate_uuid_default_v4_shape",
        input_data="",
        recipe=["Generate UUID"],
        expected=build_uuid_version_assertion(4),
    ),
    BakeVector(
        name="generate_uuid_v1_shape",
        input_data="",
        recipe=[{"op": "Generate UUID", "args": {"Version": "v1"}}],
        expected=build_uuid_version_assertion(1),
    ),
    BakeVector(
        name="generate_uuid_v3_dns_hello",
        input_data="hello",
        recipe=[{"op": "Generate UUID", "args": {"Version": "v3", "Namespace": str(uuid.NAMESPACE_DNS)}}],
        expected=str(uuid.uuid3(uuid.NAMESPACE_DNS, "hello")),
    ),
    BakeVector(
        name="generate_uuid_v5_dns_hello",
        input_data="hello",
        recipe=[{"op": "Generate UUID", "args": {"Version": "v5", "Namespace": str(uuid.NAMESPACE_DNS)}}],
        expected=str(uuid.uuid5(uuid.NAMESPACE_DNS, "hello")),
    ),
    BakeVector(
        name="generate_uuid_v6_shape",
        input_data="",
        recipe=[{"op": "Generate UUID", "args": {"Version": "v6"}}],
        expected=build_uuid_version_assertion(6),
    ),
    BakeVector(
        name="generate_uuid_v7_shape",
        input_data="",
        recipe=[{"op": "Generate UUID", "args": {"Version": "v7"}}],
        expected=build_uuid_version_assertion(7),
    ),
    BakeVector(
        name="html_to_text_preserves_parse_ipv4_markup_for_base64",
        input_data=IPV4_HEADER_SAMPLE_HEX,
        recipe=["Parse IPv4 header", "HTML To Text", "To Base64"],
        expected=assert_html_to_text_preserves_raw_parse_ipv4_markup,
    ),
    BakeVector(
        name="haversine_distance_same_coordinates_zero_metres",
        input_data="51.487263,-0.124323, 51.487263,-0.124323",
        recipe=["Haversine distance"],
        expected=0.0,
    ),
    BakeVector(
        name="haversine_distance_docs_example",
        input_data="51.487263,-0.124323, 38.9517,-77.1467",
        recipe=["Haversine distance"],
        expected=build_float_approx_assertion(build_haversine_distance(51.487263, -0.124323, 38.9517, -77.1467)),
    ),
    BakeVector(
        name="index_of_coincidence_empty_string",
        input_data="",
        recipe=["Index of Coincidence"],
        expected=build_index_of_coincidence(""),
    ),
    BakeVector(
        name="index_of_coincidence_ignores_non_letters",
        input_data="Attack at dawn! 123",
        recipe=["Index of Coincidence"],
        expected=build_index_of_coincidence("Attack at dawn! 123"),
    ),
    BakeVector(
        name="numberwang_empty_input_prompt",
        input_data="",
        recipe=["Numberwang"],
        expected=build_numberwang_assertion("Let's play Wangernumb!"),
    ),
    BakeVector(
        name="numberwang_numeric_hit",
        input_data="46",
        recipe=["Numberwang"],
        expected=build_numberwang_assertion("46! That's Numberwang!"),
    ),
    BakeVector(
        name="numberwang_alphanumeric_hit",
        input_data="46x",
        recipe=["Numberwang"],
        expected=build_numberwang_assertion("46x! That's AlphaNumericWang!"),
    ),
    BakeVector(
        name="numberwang_miss_rotates_board",
        input_data="hello world",
        recipe=["Numberwang"],
        expected=build_numberwang_assertion("Sorry, that's not Numberwang. Let's rotate the board!"),
    ),
    BakeVector(
        name="parse_qr_code_roundtrip_generated_png",
        input_data="hello",
        recipe=["Generate QR Code", "Parse QR Code"],
        expected="hello",
    ),
    BakeVector(
        name="parse_qr_code_roundtrip_generated_png_with_normalise",
        input_data="hello",
        recipe=["Generate QR Code", {"op": "Parse QR Code", "args": {"Normalise image": True}}],
        expected="hello",
    ),
    BakeVector(
        name="xkcd_random_number_is_four",
        input_data="",
        recipe=["XKCD Random Number"],
        expected=4.0,
    ),
    BakeVector(
        name="generate_totp_large_period_exact_code",
        input_data=b"JBSWY3DPEHPK3PXP",
        recipe=[
            {
                "op": "Generate TOTP",
                "args": {
                    "Code length": 8,
                    "Epoch offset (T0)": 0,
                    "Interval (T1)": 1_000_000_000,
                },
            }
        ],
        expected=build_totp_output(
            "JBSWY3DPEHPK3PXP",
            digits=8,
            epoch_offset=0,
            interval=1_000_000_000,
            at_time=int(time.time()),
        ),
    ),
]


UTILS_VECTORS = [
    BakeVector(
        name="add_line_numbers_empty_string",
        input_data="",
        recipe=["Add line numbers"],
        expected=build_line_numbered_text(""),
    ),
    BakeVector(
        name="add_line_numbers_with_offset",
        input_data="alpha\nbeta",
        recipe=[{"op": "Add line numbers", "args": {"Offset": 8}}],
        expected=build_line_numbered_text("alpha\nbeta", offset=8),
    ),
    BakeVector(
        name="alternating_caps_empty_string",
        input_data="",
        recipe=["Alternating Caps"],
        expected="",
    ),
    BakeVector(
        name="alternating_caps_unicode_and_punctuation",
        input_data="Ångström, hello! 123",
        recipe=["Alternating Caps"],
        expected=build_alternating_caps("Ångström, hello! 123"),
    ),
    BakeVector(
        name="convert_area_default_identity",
        input_data="1",
        recipe=["Convert area"],
        expected="1",
    ),
    BakeVector(
        name="convert_area_square_kilometres_to_hectares",
        input_data="1",
        recipe=[
            {
                "op": "Convert area",
                "args": {
                    "Input units": "Square kilometre (sq km)",
                    "Output units": "Hectare (ha)",
                },
            }
        ],
        expected="100",
    ),
    BakeVector(
        name="convert_data_units_default_identity",
        input_data="1",
        recipe=["Convert data units"],
        expected="1",
    ),
    BakeVector(
        name="convert_data_units_kibibytes_to_bytes",
        input_data="1",
        recipe=[
            {
                "op": "Convert data units",
                "args": {
                    "Input units": "Kibibytes (KiB)",
                    "Output units": "Bytes (B)",
                },
            }
        ],
        expected="1024",
    ),
    BakeVector(
        name="convert_distance_default_identity",
        input_data="1",
        recipe=["Convert distance"],
        expected="1",
    ),
    BakeVector(
        name="convert_distance_feet_to_inches",
        input_data="3",
        recipe=[
            {
                "op": "Convert distance",
                "args": {
                    "Input units": "Feet (ft)",
                    "Output units": "Inches (in)",
                },
            }
        ],
        expected="36",
    ),
    BakeVector(
        name="convert_mass_default_identity",
        input_data="1",
        recipe=["Convert mass"],
        expected="1",
    ),
    BakeVector(
        name="convert_mass_tonnes_to_kilograms",
        input_data="2",
        recipe=[
            {
                "op": "Convert mass",
                "args": {
                    "Input units": "Tonne (t)",
                    "Output units": "Kilogram (kg)",
                },
            }
        ],
        expected="2000",
    ),
    BakeVector(
        name="convert_speed_default_identity",
        input_data="1",
        recipe=["Convert speed"],
        expected="1",
    ),
    BakeVector(
        name="convert_speed_kilometres_per_hour_to_metres_per_second",
        input_data="1",
        recipe=[
            {
                "op": "Convert speed",
                "args": {
                    "Input units": "Kilometres per hour (km/h)",
                    "Output units": "Metres per second (m/s)",
                },
            }
        ],
        expected="0.2778",
    ),
    BakeVector(
        name="count_occurrences_default_empty_search",
        input_data="banana",
        recipe=["Count occurrences"],
        expected=0.0,
    ),
    BakeVector(
        name="count_occurrences_simple_substring",
        input_data="banana",
        recipe=[
            {
                "op": "Count occurrences",
                "args": {"Search string": {"string": "an", "option": "Simple string"}},
            }
        ],
        expected=2.0,
    ),
    BakeVector(
        name="count_occurrences_regex_case_insensitive",
        input_data="Alpha alpha ALPHA",
        recipe=[
            {
                "op": "Count occurrences",
                "args": {"Search string": {"string": "alpha", "option": "Regex"}},
            }
        ],
        expected=3.0,
    ),
    BakeVector(
        name="count_occurrences_extended_newline_escape",
        input_data="a\nb\na\n",
        recipe=[
            {
                "op": "Count occurrences",
                "args": {
                    "Search string": {
                        "string": "\\n",
                        "option": "Extended (\\n, \\t, \\x...)",
                    }
                },
            }
        ],
        expected=3.0,
    ),
    BakeVector(
        name="diff_character_custom_delimiter",
        input_data="cat|cut",
        recipe=[
            {
                "op": "Diff",
                "args": {
                    "Sample delimiter": "|",
                    "Diff by": "Character",
                    "Show added": True,
                    "Show removed": True,
                    "Show subtraction": False,
                    "Ignore whitespace": False,
                },
            }
        ],
        expected="c<del>a</del><ins>u</ins>t",
    ),
    BakeVector(
        name="diff_word_ignore_whitespace",
        input_data="hello world|hello  world",
        recipe=[
            {
                "op": "Diff",
                "args": {
                    "Sample delimiter": "|",
                    "Diff by": "Word",
                    "Show added": True,
                    "Show removed": True,
                    "Show subtraction": False,
                    "Ignore whitespace": True,
                },
            }
        ],
        expected="hello  world",
    ),
    BakeVector(
        name="diff_json_escapes_html",
        input_data='{"a":1}|{"a":2}',
        recipe=[
            {
                "op": "Diff",
                "args": {
                    "Sample delimiter": "|",
                    "Diff by": "JSON",
                    "Show added": True,
                    "Show removed": True,
                    "Show subtraction": False,
                    "Ignore whitespace": False,
                },
            }
        ],
        expected="<del>{&quot;a&quot;:1}</del><ins>{&quot;a&quot;:2}</ins>",
    ),
    BakeVector(
        name="drop_bytes_empty_input",
        input_data=b"",
        recipe=["Drop bytes"],
        expected=b"",
    ),
    BakeVector(
        name="drop_bytes_middle_slice",
        input_data=b"abcdef",
        recipe=[{"op": "Drop bytes", "args": {"Start": 1, "Length": 2, "Apply to each line": False}}],
        expected=build_drop_bytes(b"abcdef", start=1, length=2),
    ),
    BakeVector(
        name="drop_bytes_negative_length",
        input_data=b"abcdef",
        recipe=[{"op": "Drop bytes", "args": {"Start": 4, "Length": -2, "Apply to each line": False}}],
        expected=build_drop_bytes(b"abcdef", start=4, length=-2),
    ),
    BakeVector(
        name="drop_bytes_apply_to_each_line",
        input_data=b"abc\ndef\n",
        recipe=[{"op": "Drop bytes", "args": {"Start": 1, "Length": 1, "Apply to each line": True}}],
        expected=build_drop_bytes(b"abc\ndef\n", start=1, length=1, apply_to_each_line=True),
    ),
    BakeVector(
        name="drop_nth_bytes_default_every_fourth_byte",
        input_data=b"abcdefghi",
        recipe=["Drop nth bytes"],
        expected=build_drop_nth_bytes(b"abcdefghi", drop_every=4, starting_at=0),
    ),
    BakeVector(
        name="drop_nth_bytes_apply_to_each_line_with_offset",
        input_data=b"abcdef\nuvwxyz\n",
        recipe=[
            {
                "op": "Drop nth bytes",
                "args": {
                    "Drop every": 2,
                    "Starting at": 1,
                    "Apply to each line": True,
                },
            }
        ],
        expected=build_drop_nth_bytes(
            b"abcdef\nuvwxyz\n",
            drop_every=2,
            starting_at=1,
            apply_to_each_line=True,
        ),
    ),
    BakeVector(
        name="escape_string_default_quotes_newline_and_apostrophe",
        input_data="Don't\nstop",
        recipe=["Escape string"],
        expected="Don\\'t\\nstop",
    ),
    BakeVector(
        name="escape_string_everything_json_and_uppercase_hex",
        input_data='é"',
        recipe=[
            {
                "op": "Escape string",
                "args": {
                    "Escape level": "Everything",
                    "Escape quote": "Double",
                    "JSON compatible": True,
                    "ES6 compatible": True,
                    "Uppercase hex": True,
                },
            }
        ],
        expected='"\\u00E9\\""',
    ),
    BakeVector(
        name="expand_alphabet_range_multiple_ranges",
        input_data="a-cx-z",
        recipe=["Expand alphabet range"],
        expected=build_expanded_alphabet("a-cx-z"),
    ),
    BakeVector(
        name="expand_alphabet_range_custom_delimiter",
        input_data="a-c",
        recipe=[{"op": "Expand alphabet range", "args": {"Delimiter": ","}}],
        expected="a,b,c",
    ),
    BakeVector(
        name="file_tree_default_line_feed_paths",
        input_data="src/main.py\nsrc/lib/util.py\nREADME.md",
        recipe=["File Tree"],
        expected=build_file_tree(
            "src/main.py\nsrc/lib/util.py\nREADME.md",
            file_path_delimiter="/",
            delimiter="\n",
        ),
    ),
    BakeVector(
        name="file_tree_custom_path_and_entry_delimiters",
        input_data="root>sub>file.txt,root>other.txt",
        recipe=[{"op": "File Tree", "args": {"File Path Delimiter": ">", "Delimiter": "Comma"}}],
        expected=build_file_tree(
            "root>sub>file.txt,root>other.txt",
            file_path_delimiter=">",
            delimiter=",",
        ),
    ),
    BakeVector(
        name="filter_line_feed_regex_match",
        input_data="apple\npear\napricot",
        recipe=[{"op": "Filter", "args": {"Regex": "^ap"}}],
        expected="apple\napricot",
    ),
    BakeVector(
        name="filter_comma_delimited_invert_condition",
        input_data="apple,pear,apricot",
        recipe=[{"op": "Filter", "args": {"Delimiter": "Comma", "Regex": "^ap", "Invert condition": True}}],
        expected="pear",
    ),
    BakeVector(
        name="from_case_insensitive_regex_collapses_letter_pairs",
        input_data="[mM][oO][zZ]illa",
        recipe=["From Case Insensitive Regex"],
        expected=build_from_case_insensitive_regex("[mM][oO][zZ]illa"),
    ),
    BakeVector(
        name="from_case_insensitive_regex_preserves_non_case_pairs",
        input_data="[ab][cC][dE]",
        recipe=["From Case Insensitive Regex"],
        expected=build_from_case_insensitive_regex("[ab][cC][dE]"),
    ),
    BakeVector(
        name="fuzzy_match_docs_example_highlights_disjoint_ranges",
        input_data="Don't Panic",
        recipe=[{"op": "Fuzzy Match", "args": {"Search": "dpan"}}],
        expected='<span class="hl1"><b>D</b>on&#x27;t <b>Pan</b></span>ic',
    ),
    BakeVector(
        name="fuzzy_match_no_match_returns_escaped_input",
        input_data="<alpha>",
        recipe=[{"op": "Fuzzy Match", "args": {"Search": "zzz"}}],
        expected="&lt;alpha&gt;",
    ),
    BakeVector(
        name="get_all_casings_two_letters",
        input_data="ab",
        recipe=["Get All Casings"],
        expected=build_all_casings("ab"),
    ),
    BakeVector(
        name="get_all_casings_non_letters_produce_duplicate_rows",
        input_data="a1",
        recipe=["Get All Casings"],
        expected=build_all_casings("a1"),
    ),
    BakeVector(
        name="hamming_distance_raw_string_bytes",
        input_data="karolin|kathrin",
        recipe=[
            {
                "op": "Hamming Distance",
                "args": {
                    "Delimiter": "|",
                    "Unit": "Byte",
                    "Input type": "Raw string",
                },
            }
        ],
        expected=build_hamming_distance("karolin", "kathrin", unit="Byte", input_type="Raw string"),
    ),
    BakeVector(
        name="hamming_distance_hex_bits",
        input_data="ff00|0f0f",
        recipe=[
            {
                "op": "Hamming Distance",
                "args": {
                    "Delimiter": "|",
                    "Unit": "Bit",
                    "Input type": "Hex",
                },
            }
        ],
        expected=build_hamming_distance("ff00", "0f0f", unit="Bit", input_type="Hex"),
    ),
    BakeVector(
        name="head_default_keeps_all_short_input",
        input_data="a\nb\nc",
        recipe=["Head"],
        expected="a\nb\nc",
    ),
    BakeVector(
        name="head_negative_number_drops_last_field",
        input_data="a,b,c,d",
        recipe=[{"op": "Head", "args": {"Delimiter": "Comma", "Number": -1}}],
        expected="a,b,c",
    ),
    BakeVector(
        name="levenshtein_distance_explicit_newline_delimiter",
        input_data="kitten\nsitting",
        recipe=[
            {
                "op": "Levenshtein Distance",
                "args": {
                    "Sample delimiter": "\n",
                    "Insertion cost": 1,
                    "Deletion cost": 1,
                    "Substitution cost": 1,
                },
            }
        ],
        expected=build_levenshtein_distance("kitten", "sitting"),
    ),
    BakeVector(
        name="levenshtein_distance_custom_substitution_cost",
        input_data="abc|adc",
        recipe=[
            {
                "op": "Levenshtein Distance",
                "args": {
                    "Sample delimiter": "|",
                    "Insertion cost": 1,
                    "Deletion cost": 1,
                    "Substitution cost": 2,
                },
            }
        ],
        expected=build_levenshtein_distance(
            "abc",
            "adc",
            insertion_cost=1,
            deletion_cost=1,
            substitution_cost=2,
        ),
    ),
    BakeVector(
        name="offset_checker_highlights_common_positions",
        input_data="abc\n\naxc\n\naqc",
        recipe=[{"op": "Offset checker", "args": {"Sample delimiter": "\n\n"}}],
        expected=assert_offset_checker_common_positions,
    ),
    BakeVector(
        name="pad_lines_default_start_padding",
        input_data="a\nbb",
        recipe=["Pad lines"],
        expected=build_pad_lines("a\nbb", position="Start", length=5, character=" "),
    ),
    BakeVector(
        name="pad_lines_end_padding_with_zeroes",
        input_data="a\nbb",
        recipe=[{"op": "Pad lines", "args": {"Position": "End", "Length": 4, "Character": "0"}}],
        expected=build_pad_lines("a\nbb", position="End", length=4, character="0"),
    ),
    BakeVector(
        name="parse_objectid_timestamp_known_example",
        input_data="507f1f77bcf86cd799439011",
        recipe=["Parse ObjectID timestamp"],
        expected=build_object_id_timestamp("507f1f77bcf86cd799439011"),
    ),
    BakeVector(
        name="parse_objectid_timestamp_zero_epoch",
        input_data="000000000000000000000000",
        recipe=["Parse ObjectID timestamp"],
        expected=build_object_id_timestamp("000000000000000000000000"),
    ),
    BakeVector(
        name="parse_unix_file_permissions_textual_directory",
        input_data="drwxr-xr-x",
        recipe=["Parse UNIX file permissions"],
        expected=assert_parse_unix_file_permissions_directory,
    ),
    BakeVector(
        name="parse_unix_file_permissions_octal_sticky_bit",
        input_data="1755",
        recipe=["Parse UNIX file permissions"],
        expected=assert_parse_unix_file_permissions_sticky_bit,
    ),
    BakeVector(
        name="parse_colour_code_hex_green",
        input_data="#00ff00",
        recipe=["Parse colour code"],
        expected=assert_parse_colour_code_green,
    ),
    BakeVector(
        name="parse_colour_code_rgba_preserves_alpha",
        input_data="rgba(255,0,0,0.5)",
        recipe=["Parse colour code"],
        expected=assert_parse_colour_code_alpha_red,
    ),
    BakeVector(
        name="regular_expression_highlight_matches",
        input_data="abc123def456",
        recipe=[
            {
                "op": "Regular expression",
                "args": {
                    "Regex": "\\d+",
                    "Case insensitive": True,
                    "^ and $ match at newlines": True,
                    "Dot matches all": False,
                    "Unicode support": False,
                    "Astral support": False,
                    "Display total": False,
                    "Output format": "Highlight matches",
                },
            }
        ],
        expected="abc<span class='hl2' title='Offset: 3\n'>123</span>def<span class='hl1' title='Offset: 9\n'>456</span>",
    ),
    BakeVector(
        name="regular_expression_lists_capture_groups_with_total",
        input_data="abc123def456",
        recipe=[
            {
                "op": "Regular expression",
                "args": {
                    "Regex": "([a-z]+)(\\d+)",
                    "Case insensitive": True,
                    "^ and $ match at newlines": True,
                    "Dot matches all": False,
                    "Unicode support": False,
                    "Astral support": False,
                    "Display total": True,
                    "Output format": "List capture groups",
                },
            }
        ],
        expected="Total found: 2\n\nabc\n123\ndef\n456",
    ),
    BakeVector(
        name="remove_line_numbers_simple_prefixes",
        input_data="1 alpha\n2 beta",
        recipe=["Remove line numbers"],
        expected=build_remove_line_numbers("1 alpha\n2 beta"),
    ),
    BakeVector(
        name="remove_line_numbers_roundtrip_add_line_numbers",
        input_data="alpha\nbeta",
        recipe=["Add line numbers", "Remove line numbers"],
        expected="alpha\nbeta",
    ),
    BakeVector(
        name="remove_null_bytes_empty_input",
        input_data=b"",
        recipe=["Remove null bytes"],
        expected=b"",
    ),
    BakeVector(
        name="remove_null_bytes_interspersed_bytes",
        input_data=b"a\x00b\x00\x00c",
        recipe=["Remove null bytes"],
        expected=b"abc",
    ),
    BakeVector(
        name="remove_whitespace_default_categories",
        input_data=" a\r\n\tb\f. c ",
        recipe=["Remove whitespace"],
        expected=build_remove_whitespace(" a\r\n\tb\f. c "),
    ),
    BakeVector(
        name="remove_whitespace_full_stops_only",
        input_data="a . b",
        recipe=[
            {
                "op": "Remove whitespace",
                "args": {
                    "Spaces": False,
                    "Carriage returns (\\r)": False,
                    "Line feeds (\\n)": False,
                    "Tabs": False,
                    "Form feeds (\\f)": False,
                    "Full stops": True,
                },
            }
        ],
        expected=build_remove_whitespace(
            "a . b",
            spaces=False,
            carriage_returns=False,
            line_feeds=False,
            tabs=False,
            form_feeds=False,
            full_stops=True,
        ),
    ),
]


TEXT_VECTORS = [
    BakeVector(
        name="url_encode_empty_string",
        input_data="",
        recipe=["URL Encode"],
        expected="",
    ),
    BakeVector(
        name="url_encode_ascii_text",
        input_data="Hello World!",
        recipe=["URL Encode"],
        expected="Hello%20World!",
    ),
    BakeVector(
        name="to_upper_case_all_scope",
        input_data="Hello world!",
        recipe=["To Upper case"],
        expected="HELLO WORLD!",
    ),
    BakeVector(
        name="to_upper_case_word_scope",
        input_data="hello world",
        recipe=[{"op": "To Upper case", "args": {"Scope": "Word"}}],
        expected="Hello World",
    ),
    BakeVector(
        name="to_lower_case_ascii_text",
        input_data="Hello WORLD!",
        recipe=["To Lower case"],
        expected="hello world!",
    ),
]

BINARY_VECTORS = [
    BakeVector(
        name="xor_hex_key_ascii_bytes",
        input_data=b"hello",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "ff", "option": "Hex"},
                    "Scheme": "Standard",
                    "Null preserving": False,
                },
            }
        ],
        expected=build_xor_bytes(b"hello", b"\xff"),
    ),
    BakeVector(
        name="xor_utf8_key_without_null_preserving",
        input_data=b"A\x00B",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "A", "option": "UTF8"},
                    "Scheme": "Standard",
                    "Null preserving": False,
                },
            }
        ],
        expected=build_xor_bytes(b"A\x00B", b"A"),
    ),
    BakeVector(
        name="xor_utf8_key_with_null_preserving",
        input_data=b"A\x00B",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "A", "option": "UTF8"},
                    "Scheme": "Standard",
                    "Null preserving": True,
                },
            }
        ],
        expected=build_xor_bytes(b"A\x00B", b"A", null_preserving=True),
    ),
]

ARITHMETIC_LOGIC_VECTORS = [
    BakeVector(
        name="add_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "ADD", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="add_wraparound_with_repeating_hex_key",
        input_data=b"\x00\xfe\xff\x10",
        recipe=[
            {
                "op": "ADD",
                "args": {"Key": {"string": "0102", "option": "Hex"}},
            }
        ],
        expected=build_add_bytes(b"\x00\xfe\xff\x10", b"\x01\x02"),
    ),
    BakeVector(
        name="add_utf8_key_option",
        input_data=b"A\xff",
        recipe=[
            {
                "op": "ADD",
                "args": {"Key": {"string": "A", "option": "UTF8"}},
            }
        ],
        expected=build_add_bytes(b"A\xff", b"A"),
    ),
    BakeVector(
        name="and_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "AND", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="and_binary_key_option",
        input_data=b"\xff\x0f\xf0",
        recipe=[
            {
                "op": "AND",
                "args": {"Key": {"string": "10100001", "option": "Binary"}},
            }
        ],
        expected=build_and_bytes(b"\xff\x0f\xf0", b"\xa1"),
    ),
    BakeVector(
        name="and_utf8_key_option",
        input_data=b"Az",
        recipe=[
            {
                "op": "AND",
                "args": {"Key": {"string": "A", "option": "UTF8"}},
            }
        ],
        expected=build_and_bytes(b"Az", b"A"),
    ),
    BakeVector(
        name="bit_shift_left_empty_bytes",
        input_data=b"",
        recipe=[{"op": "Bit shift left", "args": {"Amount": 1}}],
        expected=b"",
    ),
    BakeVector(
        name="bit_shift_left_amount_one",
        input_data=b"\x01\x80\x7f",
        recipe=[{"op": "Bit shift left", "args": {"Amount": 1}}],
        expected=build_left_shift_bytes(b"\x01\x80\x7f", 1),
    ),
    BakeVector(
        name="bit_shift_left_amount_seven",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Bit shift left", "args": {"Amount": 7}}],
        expected=build_left_shift_bytes(b"\x81\x7f", 7),
    ),
    BakeVector(
        name="bit_shift_right_logical",
        input_data=b"\x81\x7f",
        recipe=[
            {
                "op": "Bit shift right",
                "args": {"Amount": 1, "Type": "Logical shift"},
            }
        ],
        expected=build_right_shift_bytes(b"\x81\x7f", 1, arithmetic=False),
    ),
    BakeVector(
        name="bit_shift_right_arithmetic",
        input_data=b"\x81\x7f",
        recipe=[
            {
                "op": "Bit shift right",
                "args": {"Amount": 1, "Type": "Arithmetic shift"},
            }
        ],
        expected=build_right_shift_bytes(b"\x81\x7f", 1, arithmetic=True),
    ),
    BakeVector(
        name="bit_shift_right_amount_two_arithmetic",
        input_data=b"\xff\x40\x20",
        recipe=[
            {
                "op": "Bit shift right",
                "args": {"Amount": 2, "Type": "Arithmetic shift"},
            }
        ],
        expected=build_right_shift_bytes(b"\xff\x40\x20", 2, arithmetic=True),
    ),
    BakeVector(
        name="cartesian_product_two_sets_default_delimiters",
        input_data="red,blue\n\ncircle,square",
        recipe=[
            {
                "op": "Cartesian Product",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_cartesian_product(
            [["red", "blue"], ["circle", "square"]],
            ",",
        ),
    ),
    BakeVector(
        name="cartesian_product_custom_sample_delimiter",
        input_data="a,b|1,2|X,Y",
        recipe=[
            {
                "op": "Cartesian Product",
                "args": {"Sample delimiter": "|", "Item delimiter": ","},
            }
        ],
        expected=build_cartesian_product(
            [["a", "b"], ["1", "2"], ["X", "Y"]],
            ",",
        ),
    ),
    BakeVector(
        name="cartesian_product_custom_item_delimiter",
        input_data="north/south\n\neast/west",
        recipe=[
            {
                "op": "Cartesian Product",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": "/"},
            }
        ],
        expected=build_cartesian_product(
            [["north", "south"], ["east", "west"]],
            "/",
        ),
    ),
    BakeVector(
        name="divide_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Divide", "args": {"Delimiter": "Space"}}],
        expected="2.5",
    ),
    BakeVector(
        name="divide_excludes_invalid_tokens",
        input_data="20 nope 5",
        recipe=[{"op": "Divide", "args": {"Delimiter": "Space"}}],
        expected="4",
    ),
    BakeVector(
        name="mean_space_delimited_docs_example",
        input_data="0x0a 8 .5 .5",
        recipe=[{"op": "Mean", "args": {"Delimiter": "Space"}}],
        expected="4.75",
    ),
    BakeVector(
        name="mean_comma_delimited_values",
        input_data="1,2,3,4",
        recipe=[{"op": "Mean", "args": {"Delimiter": "Comma"}}],
        expected="2.5",
    ),
    BakeVector(
        name="median_space_delimited_docs_example",
        input_data="0x0a 8 1 .5",
        recipe=[{"op": "Median", "args": {"Delimiter": "Space"}}],
        expected="4.5",
    ),
    BakeVector(
        name="median_sorted_odd_values",
        input_data="1,2,10",
        recipe=[{"op": "Median", "args": {"Delimiter": "Comma"}}],
        expected="2",
    ),
    BakeVector(
        name="multiply_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Multiply", "args": {"Delimiter": "Space"}}],
        expected="40",
    ),
    BakeVector(
        name="multiply_excludes_invalid_tokens",
        input_data="3 nope 2 0.5",
        recipe=[{"op": "Multiply", "args": {"Delimiter": "Space"}}],
        expected="3",
    ),
    BakeVector(
        name="not_empty_bytes",
        input_data=b"",
        recipe=["NOT"],
        expected=b"",
    ),
    BakeVector(
        name="not_binary_edge_bytes",
        input_data=b"\x00\x01\x7f\x80\xff",
        recipe=["NOT"],
        expected=build_not_bytes(b"\x00\x01\x7f\x80\xff"),
    ),
    BakeVector(
        name="not_roundtrip_double_not",
        input_data=bytes(range(32)),
        recipe=["NOT", "NOT"],
        expected=bytes(range(32)),
    ),
    BakeVector(
        name="or_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "OR", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="or_binary_key_option",
        input_data=b"\x0f\xf0U",
        recipe=[
            {
                "op": "OR",
                "args": {"Key": {"string": "10100001", "option": "Binary"}},
            }
        ],
        expected=build_or_bytes(b"\x0f\xf0U", b"\xa1"),
    ),
    BakeVector(
        name="or_utf8_key_option",
        input_data=b"Az",
        recipe=[
            {
                "op": "OR",
                "args": {"Key": {"string": "A", "option": "UTF8"}},
            }
        ],
        expected=build_or_bytes(b"Az", b"A"),
    ),
    BakeVector(
        name="power_set_empty_string",
        input_data="",
        recipe=[{"op": "Power Set", "args": {"Item delimiter": ","}}],
        expected="",
    ),
    BakeVector(
        name="power_set_comma_delimited_values",
        input_data="red,blue",
        recipe=[{"op": "Power Set", "args": {"Item delimiter": ","}}],
        expected=build_power_set(["red", "blue"], ","),
    ),
    BakeVector(
        name="power_set_custom_item_delimiter",
        input_data="north|south",
        recipe=[{"op": "Power Set", "args": {"Item delimiter": "|"}}],
        expected=build_power_set(["north", "south"], "|"),
    ),
    BakeVector(
        name="rotate_left_empty_bytes",
        input_data=b"",
        recipe=[{"op": "Rotate left", "args": {"Amount": 1, "Carry through": False}}],
        expected=b"",
    ),
    BakeVector(
        name="rotate_left_amount_two",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate left", "args": {"Amount": 2, "Carry through": False}}],
        expected=build_rotate_left_bytes(b"\x81\x7f", 2),
    ),
    BakeVector(
        name="rotate_left_carry_through",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate left", "args": {"Amount": 1, "Carry through": True}}],
        expected=build_rotate_left_carry_bytes(b"\x81\x7f", 1),
    ),
    BakeVector(
        name="rotate_right_empty_bytes",
        input_data=b"",
        recipe=[{"op": "Rotate right", "args": {"Amount": 1, "Carry through": False}}],
        expected=b"",
    ),
    BakeVector(
        name="rotate_right_amount_two",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate right", "args": {"Amount": 2, "Carry through": False}}],
        expected=build_rotate_right_bytes(b"\x81\x7f", 2),
    ),
    BakeVector(
        name="rotate_right_carry_through",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate right", "args": {"Amount": 1, "Carry through": True}}],
        expected=build_rotate_right_carry_bytes(b"\x81\x7f", 1),
    ),
    BakeVector(
        name="rotate_roundtrip_left_then_right",
        input_data=bytes(range(32)),
        recipe=[
            {"op": "Rotate left", "args": {"Amount": 3, "Carry through": False}},
            {"op": "Rotate right", "args": {"Amount": 3, "Carry through": False}},
        ],
        expected=bytes(range(32)),
    ),
    BakeVector(
        name="sub_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "SUB", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="sub_wraparound_with_repeating_hex_key",
        input_data=b"\x00\x01\xff\x10",
        recipe=[
            {
                "op": "SUB",
                "args": {"Key": {"string": "0102", "option": "Hex"}},
            }
        ],
        expected=build_sub_bytes(b"\x00\x01\xff\x10", b"\x01\x02"),
    ),
    BakeVector(
        name="sub_base64_key_option",
        input_data=b"A\xff",
        recipe=[
            {
                "op": "SUB",
                "args": {"Key": {"string": "QQ==", "option": "Base64"}},
            }
        ],
        expected=build_sub_bytes(b"A\xff", b"A"),
    ),
    BakeVector(
        name="set_difference_default_delimiters",
        input_data="red,blue\n\nblue,green",
        recipe=[
            {
                "op": "Set Difference",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_set_difference(["red", "blue"], ["blue", "green"], ","),
    ),
    BakeVector(
        name="set_difference_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Set Difference",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_set_difference(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="set_intersection_default_delimiters",
        input_data="red,blue\n\nblue,green",
        recipe=[
            {
                "op": "Set Intersection",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_set_intersection(["red", "blue"], ["blue", "green"], ","),
    ),
    BakeVector(
        name="set_intersection_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Set Intersection",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_set_intersection(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="set_union_default_delimiters",
        input_data="red,blue\n\nblue,green",
        recipe=[
            {
                "op": "Set Union",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_set_union(["red", "blue"], ["blue", "green"], ","),
    ),
    BakeVector(
        name="set_union_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Set Union",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_set_union(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="standard_deviation_population_example",
        input_data="2,4,4,4,5,5,7,9",
        recipe=[{"op": "Standard Deviation", "args": {"Delimiter": "Comma"}}],
        expected="2",
    ),
    BakeVector(
        name="standard_deviation_excludes_invalid_tokens",
        input_data="1:3:nope",
        recipe=[{"op": "Standard Deviation", "args": {"Delimiter": "Colon"}}],
        expected="1",
    ),
    BakeVector(
        name="subtract_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Subtract", "args": {"Delimiter": "Space"}}],
        expected="1.5",
    ),
    BakeVector(
        name="subtract_excludes_invalid_tokens",
        input_data="20 nope 5",
        recipe=[{"op": "Subtract", "args": {"Delimiter": "Space"}}],
        expected="15",
    ),
    BakeVector(
        name="subtract_comma_delimited_values",
        input_data="10,1,2,3",
        recipe=[{"op": "Subtract", "args": {"Delimiter": "Comma"}}],
        expected="4",
    ),
    BakeVector(
        name="sum_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Sum", "args": {"Delimiter": "Space"}}],
        expected="18.5",
    ),
    BakeVector(
        name="sum_excludes_invalid_tokens",
        input_data="20 nope 5",
        recipe=[{"op": "Sum", "args": {"Delimiter": "Space"}}],
        expected="25",
    ),
    BakeVector(
        name="sum_colon_delimited_values",
        input_data="1:2:3:4",
        recipe=[{"op": "Sum", "args": {"Delimiter": "Colon"}}],
        expected="10",
    ),
    BakeVector(
        name="symmetric_difference_default_delimiters",
        input_data="red,blue\n\ngreen,blue",
        recipe=[
            {
                "op": "Symmetric Difference",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_symmetric_difference(["red", "blue"], ["green", "blue"], ","),
    ),
    BakeVector(
        name="symmetric_difference_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Symmetric Difference",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_symmetric_difference(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="symmetric_difference_preserves_duplicates_per_sample_order",
        input_data="red,red,blue\n\ngreen,green,blue",
        recipe=[
            {
                "op": "Symmetric Difference",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_symmetric_difference(
            ["red", "red", "blue"],
            ["green", "green", "blue"],
            ",",
        ),
    ),
]

BITE_SIZED_BAKE_VECTORS = [
    *CODE_TIDY_VECTORS,
    *DATA_FORMAT_VECTORS,
    *COMPRESSION_VECTORS,
    *DATE_TIME_VECTORS,
    *EXTRACTOR_VECTORS,
    *FLOW_CONTROL_VECTORS,
    *FORENSICS_VECTORS,
    *ENCODING_VECTORS,
    *HASH_VECTORS,
    *LANGUAGE_VECTORS,
    *MULTIMEDIA_VECTORS,
    *NETWORK_VECTORS,
    *PUBLIC_KEY_VECTORS,
    *OTHER_VECTORS,
    *UTILS_VECTORS,
    *TEXT_VECTORS,
    *BINARY_VECTORS,
    *ARITHMETIC_LOGIC_VECTORS,
]

GET_TIME_GRANULARITIES = [
    ("Seconds (s)", 1_000_000_000, 1),
    ("Milliseconds (ms)", 1_000_000, 1),
    ("Microseconds (μs)", 1_000, 1_000),
    ("Nanoseconds (ns)", 1, 1_000_000),
]


@pytest.mark.parametrize(
    ("granularity", "divisor", "slack"),
    GET_TIME_GRANULARITIES,
    ids=[granularity for granularity, _, _ in GET_TIME_GRANULARITIES],
)
def test_get_time_returns_current_epoch(granularity: str, divisor: int, slack: int):
    lower_bound = time.time_ns() // divisor
    result = bake("", [{"op": "Get Time", "args": {"Granularity": granularity}}])
    upper_bound = time.time_ns() // divisor

    assert lower_bound - slack <= int(result) <= upper_bound + slack


@pytest.mark.parametrize(
    "vector",
    BITE_SIZED_BAKE_VECTORS,
    ids=[vector.name for vector in BITE_SIZED_BAKE_VECTORS],
)
def test_bake_vectors(vector: BakeVector):
    result = bake(vector.input_data, vector.recipe)

    if callable(vector.expected):
        vector.expected(result)
        return

    assert result == vector.expected


@pytest.mark.parametrize(
    "vector",
    BLOCKED_BAKE_VECTORS,
    ids=[vector.name for vector in BLOCKED_BAKE_VECTORS],
)
def test_bake_vectors_blocked_operations(vector: BlockedBakeVector):
    with pytest.raises(Exception, match=re.escape(vector.error_message)):
        bake(vector.input_data, vector.recipe)
