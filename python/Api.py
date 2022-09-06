#! /usr/bin/env python3

from hashlib import md5
import time
import random
import requests
import json
from Protobuf import ProtoBuf
from urllib.parse import quote, urlencode

class Api: 
    URL = "http://47.98.221.30:666/aweme_service/result"
    TOKEN = "b2fa2a3688b33c7324217f7c4380aa8e" 
    TIKTOK_APPID = 1233  #appId 根据TikTok的美版或欧版或国内版抖音来区分 或者为1180 1233 1128

    @staticmethod
    def send(funcname:str, params:list[str]) -> str:
        resp = requests.post(Api.URL, json={
            'token': Api.TOKEN,
            'appId': Api.TIKTOK_APPID,
            'function': funcname,
            'params': params
        })
        if resp.status_code != 200:
            return None

        jsonObj:dict = json.loads(resp.content)
        if 'error' in jsonObj:
            return jsonObj['error']
            
        return jsonObj['data']


class XLadon:
    @staticmethod
    def encrypt(x_khronos:int, lc_id:str) -> str:
        """
        加密X-Ladon字符串
        """
        return Api.send('XLadon_encrypt', [
            "{}-{}-{}".format(x_khronos, lc_id, Api.TIKTOK_APPID),
            str(Api.TIKTOK_APPID)
        ])

    @staticmethod
    def decrypt(xladon:str) -> str:
        """
        解密X-Ladon字符串
        """
        return Api.send('XLadon_decrypt', [
            xladon,
            str(Api.TIKTOK_APPID)
        ])

class XGorgon:
    @staticmethod
    def build(url_query_md5_hex:str, x_ss_stub:str, sdkver:int, x_khronos:int) -> str:
        default_str = '00000000'
        if url_query_md5_hex == None or len(url_query_md5_hex) == 0:
            url_query_md5_hex = md5('').hexdigest()[0:8]
        else:
            url_query_md5_hex = url_query_md5_hex[0:8]
        
        if x_ss_stub == None or len(x_ss_stub) == 0:
            x_ss_stub = default_str
        else:
            x_ss_stub = x_ss_stub[0:8]

        sdkver_hex = sdkver.to_bytes(4, 'little').hex()
        time_hex = x_khronos.to_bytes(4, 'big').hex()
        buildstr = url_query_md5_hex + x_ss_stub + default_str + sdkver_hex + time_hex
        return XGorgon.encrypt(buildstr)

    @staticmethod
    def encrypt(buildstr:str) -> str:
        return Api.send('XGorgon_encrypt', [
            buildstr
        ])
    
    @staticmethod
    def decrypt(xgorgon:str) -> str:
        return Api.send('XGorgon_decrypt', [
            xgorgon
        ])


class XCylons:
    @staticmethod
    def encrypt(query_md5_hex:str, lc_id:str, timestamp:int) -> str:
        return Api.send('XCylons_encrypt', [
            query_md5_hex,
            lc_id,
            str(timestamp)
        ])

    @staticmethod
    def decrypt(xcylons:str) -> str:
        return Api.send('XCylons_decrypt', [
            xcylons
        ])
        

class XArgus:
    @staticmethod
    def build(xargus_simple_bean:dict) -> str:
        return Api.send('XArgus_build', [
            json.dumps(xargus_simple_bean).encode('utf-8').hex()
        ])
    
    @staticmethod
    def decrypt(xargus:str) -> ProtoBuf:
        resp = Api.send('XArgus_decrypt', [ xargus ])
        return ProtoBuf(bytes.fromhex(resp))

    @staticmethod
    def encrypt(xargus:ProtoBuf) -> str:
        return Api.send('XArgus_encrypt', [ xargus.toBuf().hex() ])

class TokenReqCryptor:
    def encrypt(hex:str) -> str:
        """
        加密/sdi/get_token请求body中的部分数据
        """
        return Api.send('TokenReq_encrypt', [hex])

    def decrypt(hex:str) -> str:
        """
        解密/sdi/get_token请求body中的部分数据
        """
        return Api.send('TokenReq_decrypt', [hex])


class TCCryptor:
    def encrypt(hex:str) -> str:
        """
        加密/service/2/device_register/请求body
        """
        return Api.send('TCCryptor_encrypt', [hex])

    def decrypt(hex:str) -> str:
        """
        解密/service/2/device_register/请求body
        """
        return Api.send('TCCryptor_decrypt', [hex])


def testXLadon():
    ss1 = XLadon.decrypt("ltCyalMN4I88MKaornPKU+LSy5Tl6jDZcJFrMF3eokqTucfp")
    print(ss1)
    
    ss2 = XLadon.encrypt(1646098215, "1225625952")
    print(ss2)
    
    ss3 = XLadon.decrypt(ss2)
    print(ss3 == ss1)
    
    
def testXGorgon() :
    ss1 = XGorgon.decrypt("8404008900006d2495919861ae80fbdfc51b0161d0ded28ac70e")
    print(ss1)
    
    ss2 = XGorgon.encrypt(ss1)
    print(ss2)
    
    ss3 = XGorgon.decrypt(ss2)
    print(ss3 == (ss1))


def testXArgus() :
    ss1 = XArgus.decrypt("vJD5fL7pD9FjIAcvqRcdUppx7WMUrMYE+nZei85Ax6AWKc7CPzAtqx0H2N8FjZbEujResKXhHiahPcFD0hXL37rvZVrMmSSFanIs709vQczszNEzCB3IckOW3/sU/lsnVCOvjKdPpeA1ftVosroyHeNYDyavkgjTWCKzwER6yohr9b4axDUHDOvDAOJKAWUkWQJ21i4EA+FUGBHo7zc9MqqnGwVMYkrvNanT8smw6MedRSa7T9+zGHYT6vb1myTkJzp+7qzCUlmtU/bVhLssNu+z")
    print(ss1)

    print('bodyhash:', ss1[13].hex())
    print('queryhash:', ss1[14].hex())
    
    ss2 = XArgus.encrypt(ss1)
    print(ss2)
    
    ss3 = XArgus.decrypt(ss2)
    print(ss3)
    print(ss3 == ss1)


def testXArgusBuild():
    xargus_simple_bean = {
        'deviceID': "",
        'licenseID': "",
        'appVersion': "",
        'sdkVersionStr': "",
        'sdkVersion': 0,
        'x_khronos': 0,
        'x_ss_stub': "", #可为空
        'secDeviceToken': "", #可为空
        'queryHex': "",
    }

    ss = XArgus.build(xargus_simple_bean)
    print(ss)


def testXCylons() :
    xcylons = "vCzcLbH1humC6lstWfdp4Cfl"
    ss1 = XCylons.decrypt(xcylons)
    print(ss1)

    l = ss1.split(',')
    
    ss2 = XCylons.encrypt(l[1].strip(' '), l[0].strip(' '), l[2].strip(' '))
    print(ss2)
    print(ss2 == (xcylons))

def read_file(filename:str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()
    return None

def testTCCryptor():
    #读取/service/2/device_register/请求内容
    data = read_file("~/Desktop/device_register.req")
    ss1 = TCCryptor.decrypt(data.hex())
    print(bytes.fromhex(ss1).decode('utf-8'))
    
    ss2 = TCCryptor.encrypt(ss1)
    print(ss2)
    
    ss3 = TCCryptor.decrypt(ss2)
    print(ss3 == ss1)

def testTokenRequestDecrypt():
    #读取/sdi/get_token请求内容
    filedata = read_file('~/Desktop/get_token.req')
    endata = ProtoBuf(filedata).getBytes(4)
    dedata = TokenReqCryptor.decrypt(endata.hex())
    ProtoBuf(bytes.fromhex(dedata)).dump()

def testTokenResponseDecrypt():
    #读取/sdi/get_token返回内容
    filedata = read_file('~/Desktop/get_token.resp')
    endata = ProtoBuf(filedata).getBytes(6)
    dedata = TokenReqCryptor.decrypt(endata.hex())
    ProtoBuf(bytes.fromhex(dedata)).dump()

def aweme_v1_commit_follow_user(user_id:str, sec_user_id:str, item_id:str):
    lc_id = '466012054'
    device_id = '7128672643347531265'
    app_version = '25.3.0'
    aid = '1233'
    sdk_ver = 0x04030921
    sdk_ver_str = 'v04.03.09-ov-iOS'

    path = 'https://api22-normal-c-alisg.tiktokv.com/aweme/v1/commit/follow/user/'
    query = {
        'version_code': app_version,
        'language': 'en',
        'app_name': 'musical_ly',
        'app_version': app_version,
        'op_region': 'TW',
        'residence': 'TW',
        'device_id': device_id,
        'channel': 'App Store',
        'mcc_mnc': '',
        'tz_offset': '28800',
        'account_region': 'sg',
        'sys_region': 'TW',
        'aid': aid,
        'locale': 'en',
        'screen_width': '750',
        'uoo': '1',
        'openudid': '84d2027fd3628acd5507b2186811de22d31cd68c',
        'cdid': 'CC536710-1298-4725-8540-C5105EFFD5F8',
        'os_api': '18',
        'ac': 'WIFI',
        'os_version': '13.5.1',
        'app_language': 'en',
        'content_language': '',
        'tz_name': 'Asia/Taipei',
        'current_region': 'TW',
        'device_platform': 'iphone',
        'build_number': '253012',
        'iid': '7128673685729396482',
        'device_type': 'iPhone8,1',
        'idfv': '00000000-0000-0000-0000-000000000000',
        'idfa': '00000000-0000-0000-0000-000000000000',
    }
    body = 'channel_id=0&from=18&from_pre=0&item_id='+item_id+'&sec_user_id='+sec_user_id+'&type=1&user_id='+user_id

    x_ss_stub = md5(body.encode('utf-8')).hexdigest().upper()
    query_str = urlencode(query, safe='/,', quote_via=quote)
    query_md5_hex = md5(query_str.encode('utf-8')).hexdigest()

    x_khronos = int(time.time())
    x_ladon = XLadon.encrypt(x_khronos, lc_id)
    x_gorgon = XGorgon.build(query_md5_hex, None, sdk_ver, x_khronos)
    
    xargus_simple_bean = {
        'deviceID': device_id,  #可为空
        'licenseID': lc_id,
        'appVersion': app_version,
        'sdkVersionStr': sdk_ver_str,
        'sdkVersion': sdk_ver,
        'x_khronos': x_khronos,
        'x_ss_stub': x_ss_stub, #get请求可为空
        'secDeviceToken': "AnPPIveUCQlIiFroHGG17nXK6", #可为空
        'queryHex': query_str.encode('utf-8').hex(),
        'x_bd_lanusk': '', #/passport/user/login/ 返回头 关注、点赞必需
    }
    x_argus = XArgus.build(xargus_simple_bean)

    headers = {
        'x-tt-token': '01bd4c9642f7dcae9d0cbf7155034ae023042ecd45dbec587565ccc4c19ecc6bd05a3c99e05a88d9ba52474d45eab70f360d2d965cc1d4c073600868d687a9be22678ddf76e55f19c5cce23c03eb689ec97d696f1bf93525cdb2e1776ed4787450148-CkA3ZjNhZjBlZWQ3M2NkMWNjZWRiNzYyZjgzZDBiMjYwOWM0NDA1ZDMxOTgxOGRjMjhkOTdhNGM0ZDIxMzEwMjRm-2.0.0',
        'x-tt-dm-status': 'login=1;ct=1;rt=1',
        'x-vc-bdturing-sdk-version': '2.2.0',
        'content-type': 'application/x-www-form-urlencoded',
        'user-agent': 'TikTok 25.3.0 rv:253012 (iPhone; iOS 13.5.1; en_TW) Cronet',
        'x-tt-cmpl-token': 'AgQQAPO8F-RPsLLVyLMePJ07-I-4zF1Zf4MMYMWxEw',
        'sdk-version': '2',
        'passport-sdk-version': '5.12.1',
        'x-tt-store-idc': 'alisg',
        'x-tt-store-region': 'sg',
        'x-tt-store-region-src': 'uid',
        'x-bd-kmsv': '0',
        'x-ss-dp': '1233',
        'x-tt-trace-id': '00-80a567071062ee21fff2c646018f04d1-80a567071062ee21-01',
        'accept-encoding': 'gzip, deflate, br',
        'cookie': 'passport_csrf_token=f8667b0a9ad62546d8f08ce257abc93b',
        'cookie': 'passport_csrf_token_default=f8667b0a9ad62546d8f08ce257abc93b',
        'cookie': 'tt_webid=4d6fa65da0302c5f8dc07e636ad3a12c',
        'cookie': 'cmpl_token=AgQQAPO8F-RPsLLVyLMePJ07-I-4zF1Zf4M3YMWCxQ',
        'cookie': 'd_ticket=78fc698a8f94c1dc91589a84d1135d422a8aa',
        'cookie': 'multi_sids=7127832705102660610%3Abd4c9642f7dcae9d0cbf7155034ae023',
        'cookie': 'install_id=7128673685729396482',
        'cookie': 'ttreq=1$e8c9766828ea95b93ba3e2f26a4f3a5860dc1258',
        'cookie': 'sessionid=bd4c9642f7dcae9d0cbf7155034ae023',
        'cookie': 'sessionid_ss=bd4c9642f7dcae9d0cbf7155034ae023',
        'cookie': 'sid_guard=bd4c9642f7dcae9d0cbf7155034ae023%7C1659945173%7C15552000%7CSat%2C+04-Feb-2023+07%3A52%3A53+GMT',
        'cookie': 'sid_tt=bd4c9642f7dcae9d0cbf7155034ae023',
        'cookie': 'uid_tt=4fb0f0d0674aad4b2a49f6f8f7aac7054923022c85da0363c269d06aaf4489bc',
        'cookie': 'uid_tt_ss=4fb0f0d0674aad4b2a49f6f8f7aac7054923022c85da0363c269d06aaf4489bc',
        'cookie': 'odin_tt=e0b6fbf208d9456f48fecd170d0867d535d97eb9c3e16e8eda3a42ce4cd2dafd1e43fd92cdee2ef7ad914505456d9e127816d71c6096f340719b42b2932c96e77f4201bb5b6c231531813269383ec304',
        'cookie': 'store-idc=alisg',
        'cookie': 'store-country-code=sg',
        'cookie': 'tt-target-idc=alisg',
        'cookie': 'msToken=MAcPZrb2Vq03dovlAJSeL8n6XGP3u0oTFdirdVWMOZHQSeUBu-bvtpg4-jw2zUAyujD4Op8ngCsSO8whjqjQgRTwQFrYmR8TTpApK-HVUeg=',
        'x-ss-stub': x_ss_stub,
        'x-argus': x_argus,
        'x-gorgon': x_gorgon,
        'x-khronos': x_khronos,
        'x-ladon': x_ladon,
    }
    print('request.url:', path + '?' + query_str)
    print('request.headers:', headers)

    resp = requests.get(path + '?' + query_str, headers=headers)
    print(resp.status_code, resp.content)

if __name__ == '__main__':
    aweme_v1_commit_follow_user(None, None, None)

