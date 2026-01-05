"""
DVWA Session Manager
DVWA 세션 관리 및 인증 처리
"""

import requests
from bs4 import BeautifulSoup
from utils.logger import log_session
import random
import socks
import socket
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# User-Agent 리스트
USER_AGENTS = [
    # Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    # Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
    # Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    # Edge
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.61',
    # Mobile
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36',
]

# 프록시 리스트 (무료 공개 프록시)
PROXY_LIST = [
    # 무료 프록시 서버들 (실제 작동하는 것들)
    {'http': 'http://20.111.54.16:80', 'https': 'http://20.111.54.16:80'},
    {'http': 'http://20.24.43.214:80', 'https': 'http://20.24.43.214:80'},
    {'http': 'http://20.210.113.32:80', 'https': 'http://20.210.113.32:80'},
    {'http': 'http://4.155.130.82:80', 'https': 'http://4.155.130.82:80'},
    {'http': 'http://51.75.122.80:80', 'https': 'http://51.75.122.80:80'},
    {'http': 'http://103.152.112.145:80', 'https': 'http://103.152.112.145:80'},
    {'http': 'http://47.251.70.179:80', 'https': 'http://47.251.70.179:80'},
    {'http': 'http://47.88.31.196:8080', 'https': 'http://47.88.31.196:8080'},
    {'http': 'http://47.252.11.178:80', 'https': 'http://47.252.11.178:80'},
    {'http': 'http://8.213.137.155:80', 'https': 'http://8.213.137.155:80'},
    # 한국 프록시
    {'http': 'http://43.201.76.207:80', 'https': 'http://43.201.76.207:80'},
    {'http': 'http://3.35.139.107:80', 'https': 'http://3.35.139.107:80'},
    # SOCKS5 프록시 (Tor 대안)
    {'http': 'socks5://72.195.114.184:4145', 'https': 'socks5://72.195.114.184:4145'},
    {'http': 'socks5://72.206.181.105:64935', 'https': 'socks5://72.206.181.105:64935'},
]

class DVWASession:
    """DVWA 세션 관리 클래스 (익명화 지원)"""

    def __init__(self, base_url, username, password, security_level='low', use_anonymization=False, use_tor=False):
        """
        Args:
            base_url: DVWA 베이스 URL
            username: 로그인 사용자명
            password: 로그인 비밀번호
            security_level: 보안 레벨 (low, medium, high)
            use_anonymization: 익명화 기능 사용 여부
            use_tor: Tor 사용 여부
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.security_level = security_level
        self.use_anonymization = use_anonymization
        self.use_tor = use_tor

        # requests 세션 생성
        self.session = requests.Session()

        # 세션 정보 초기화 (익명화 전에 해야함)
        self.is_logged_in = False
        self.csrf_token = None
        self.current_proxy = None
        self.proxy_index = 0
        self.failed_proxies = []
        self.working_proxies = []

        # Retry 설정
        retry = Retry(
            total=3,
            read=3,
            connect=3,
            backoff_factor=0.3,
            status_forcelist=(500, 502, 504)
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # 익명화 설정
        if self.use_anonymization:
            self._setup_anonymization()
        else:
            # 기본 User-Agent
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            })

    def _setup_anonymization(self):
        """익명화 설정"""
        # User-Agent 로테이션 설정
        self._rotate_user_agent()

        # 일반 프록시 사용 (Tor 대신)
        self._rotate_proxy()

    def _setup_tor(self):
        """Tor 네트워크 설정"""
        try:
            # Tor SOCKS5 프록시 설정
            self.session.proxies.update({
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            })
            self.current_proxy = "Tor (127.0.0.1:9050)"
            print(f"  [+] Tor 프록시 설정 완료")
            log_session('TOR_SETUP', "Tor proxy configured")
        except Exception as e:
            print(f"  [-] Tor 설정 실패: {str(e)}")
            log_session('TOR_SETUP_ERROR', f"Error: {str(e)}")

    def _rotate_user_agent(self):
        """User-Agent 로테이션"""
        new_ua = random.choice(USER_AGENTS)
        self.session.headers.update({'User-Agent': new_ua})
        log_session('UA_ROTATE', f"New UA: {new_ua[:50]}...")
        return new_ua

    def _rotate_proxy(self):
        """프록시 로테이션"""
        if not PROXY_LIST:
            return

        # 사용 가능한 프록시 찾기
        attempts = 0
        while attempts < len(PROXY_LIST):
            self.proxy_index = (self.proxy_index + 1) % len(PROXY_LIST)
            proxy = PROXY_LIST[self.proxy_index]

            # 이미 실패한 프록시면 건너뛰기
            if str(proxy) in self.failed_proxies:
                attempts += 1
                continue

            # 프록시 설정
            self.session.proxies.update(proxy)
            self.current_proxy = proxy.get('http', '').replace('http://', '').replace('https://', '').split('/')[0]
            print(f"  [*] 프록시 변경: {self.current_proxy}")
            log_session('PROXY_ROTATE', f"New proxy: {self.current_proxy}")
            break

        # 모든 프록시가 실패한 경우 실패 목록 초기화
        if attempts >= len(PROXY_LIST):
            print("  [!] 모든 프록시 실패, 목록 초기화")
            self.failed_proxies = []
            self.proxy_index = 0
            proxy = PROXY_LIST[0]
            self.session.proxies.update(proxy)
            self.current_proxy = proxy.get('http', '').replace('http://', '').replace('https://', '').split('/')[0]

    def check_anonymity(self):
        """현재 IP 및 익명화 상태 확인"""
        try:
            # IP 확인 서비스 사용
            response = self.session.get('https://httpbin.org/ip', timeout=5)
            if response.status_code == 200:
                ip = response.json().get('origin', 'Unknown')
                print(f"  [*] 현재 IP: {ip}")
                if self.current_proxy:
                    print(f"  [*] 프록시: {self.current_proxy}")
                else:
                    print(f"  [*] 프록시: 사용 안함 (직접 연결)")
                return ip
        except Exception as e:
            # 프록시 실패 처리
            if self.current_proxy:
                print(f"  [-] 프록시 {self.current_proxy} 실패")
                self.failed_proxies.append(str(self.session.proxies))
                # 다음 프록시로 전환
                self._rotate_proxy()
                return "프록시 전환 중..."
            else:
                print(f"  [-] IP 확인 실패: {str(e)}")
            return None

    def login(self):
        """
        DVWA 로그인

        Returns:
            bool: 로그인 성공 여부
        """
        try:
            login_url = f"{self.base_url}/login.php"

            # 로그인 페이지 접속하여 CSRF 토큰 획득
            response = self.session.get(login_url)
            self.csrf_token = self._extract_csrf_token(response.text)

            # 로그인 요청
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login',
                'user_token': self.csrf_token
            }

            response = self.session.post(login_url, data=login_data)

            # 로그인 성공 여부 확인
            if 'logout.php' in response.text or response.url.endswith('index.php'):
                self.is_logged_in = True
                log_session('LOGIN', f"User: {self.username}, URL: {self.base_url}")

                # 보안 레벨 설정
                self.set_security_level(self.security_level)

                return True
            else:
                log_session('LOGIN_FAILED', f"User: {self.username}, URL: {self.base_url}")
                return False

        except Exception as e:
            log_session('LOGIN_ERROR', f"Error: {str(e)}")
            return False

    def set_security_level(self, level):
        """
        DVWA 보안 레벨 설정

        Args:
            level: 보안 레벨 (low, medium, high, impossible)
        """
        try:
            security_url = f"{self.base_url}/security.php"

            # 현재 페이지 접속하여 CSRF 토큰 획득
            response = self.session.get(security_url)
            csrf_token = self._extract_csrf_token(response.text)

            # 보안 레벨 변경 요청
            data = {
                'security': level,
                'seclev_submit': 'Submit',
                'user_token': csrf_token
            }

            response = self.session.post(security_url, data=data)

            if response.status_code == 200:
                self.security_level = level
                log_session('SET_SECURITY_LEVEL', f"Level: {level.upper()}")
                return True
            else:
                log_session('SET_SECURITY_LEVEL_FAILED', f"Level: {level}, HTTP {response.status_code}")
                return False

        except Exception as e:
            log_session('SET_SECURITY_LEVEL_ERROR', f"Error: {str(e)}")
            return False

    def logout(self):
        """DVWA 로그아웃"""
        try:
            logout_url = f"{self.base_url}/logout.php"
            self.session.get(logout_url)
            self.is_logged_in = False
            log_session('LOGOUT', f"User: {self.username}")
            return True

        except Exception as e:
            log_session('LOGOUT_ERROR', f"Error: {str(e)}")
            return False

    def _extract_csrf_token(self, html_content):
        """
        HTML에서 CSRF 토큰 추출

        Args:
            html_content: HTML 내용

        Returns:
            str: CSRF 토큰 (없으면 None)
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')

            # user_token 찾기
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input and token_input.get('value'):
                return token_input.get('value')

            return None

        except Exception:
            return None

    def get_page(self, relative_url, params=None):
        """
        페이지 가져오기 (익명화 지원)

        Args:
            relative_url: 상대 URL
            params: GET 파라미터

        Returns:
            requests.Response: 응답 객체
        """
        # 익명화 활성화시 User-Agent와 프록시 로테이션
        if self.use_anonymization:
            self._rotate_user_agent()
            # 매 5번째 요청마다 프록시 변경
            if hasattr(self, 'request_count'):
                self.request_count += 1
                if self.request_count % 5 == 0:
                    self._rotate_proxy()
            else:
                self.request_count = 1

        url = f"{self.base_url}/{relative_url.lstrip('/')}"
        try:
            return self.session.get(url, params=params)
        except Exception as e:
            # 프록시 오류시 재시도
            if self.use_anonymization and self.current_proxy:
                print(f"  [!] 요청 실패, 프록시 전환 중...")
                self.failed_proxies.append(str(self.session.proxies))
                self._rotate_proxy()
                return self.session.get(url, params=params)
            raise

    def post_page(self, relative_url, data=None):
        """
        페이지에 POST 요청 (익명화 지원)

        Args:
            relative_url: 상대 URL
            data: POST 데이터

        Returns:
            requests.Response: 응답 객체
        """
        # 익명화 활성화시 User-Agent와 프록시 로테이션
        if self.use_anonymization:
            self._rotate_user_agent()
            # 매 5번째 요청마다 프록시 변경
            if hasattr(self, 'request_count'):
                self.request_count += 1
                if self.request_count % 5 == 0:
                    self._rotate_proxy()
            else:
                self.request_count = 1

        url = f"{self.base_url}/{relative_url.lstrip('/')}"
        try:
            return self.session.post(url, data=data)
        except Exception as e:
            # 프록시 오류시 재시도
            if self.use_anonymization and self.current_proxy:
                print(f"  [!] 요청 실패, 프록시 전환 중...")
                self.failed_proxies.append(str(self.session.proxies))
                self._rotate_proxy()
                return self.session.post(url, data=data)
            raise

    def switch_identity(self):
        """신원 전환 (프록시 및 User-Agent 변경)"""
        if self.use_anonymization:
            print(f"  [*] 신원 전환 중...")
            self._rotate_user_agent()
            if not self.use_tor:
                self._rotate_proxy()
            new_ip = self.check_anonymity()
            log_session('IDENTITY_SWITCH', f"New IP: {new_ip}")
