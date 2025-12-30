"""
Anonymization Module
IP 익명화 및 User-Agent 로테이션 모듈
"""

import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socks
import socket
from utils.logger import log_attack

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

    # Bot/Crawler (때때로 이상 탐지를 피하기 위해)
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
]

# 프록시 리스트 (무료 공개 프록시)
PUBLIC_PROXIES = [
    # 실제 환경에서는 신뢰할 수 있는 프록시 리스트 사용
    # 여기서는 예시용
    {'http': 'http://proxy1.example.com:8080', 'https': 'https://proxy1.example.com:8080'},
    {'http': 'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'},  # Tor
]

class ProxyRotator:
    """프록시 로테이션 관리자"""

    def __init__(self, proxy_list=None):
        self.proxies = proxy_list or []
        self.current_index = 0
        self.failed_proxies = set()

    def get_proxy(self):
        """사용 가능한 프록시 반환"""
        if not self.proxies:
            return None

        # 실패하지 않은 프록시 찾기
        attempts = 0
        while attempts < len(self.proxies):
            proxy = self.proxies[self.current_index % len(self.proxies)]
            proxy_str = str(proxy)

            if proxy_str not in self.failed_proxies:
                self.current_index += 1
                return proxy

            self.current_index += 1
            attempts += 1

        # 모든 프록시가 실패한 경우 리셋
        if self.failed_proxies:
            print("  [!] 모든 프록시 실패. 실패 리스트 초기화")
            self.failed_proxies.clear()

        return self.proxies[0] if self.proxies else None

    def mark_failed(self, proxy):
        """프록시를 실패로 표시"""
        self.failed_proxies.add(str(proxy))
        log_attack('PROXY_FAILED', 'WARNING', f"Proxy marked as failed: {proxy}", 0, 0)

class AnonymousSession:
    """익명화된 세션 클래스"""

    def __init__(self, use_tor=False, use_proxy=True, proxy_list=None):
        self.session = requests.Session()
        self.use_tor = use_tor
        self.use_proxy = use_proxy
        self.proxy_rotator = ProxyRotator(proxy_list or PUBLIC_PROXIES)
        self.user_agents = USER_AGENTS.copy()
        random.shuffle(self.user_agents)
        self.ua_index = 0

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

        # Tor 설정
        if use_tor:
            self.setup_tor()

    def setup_tor(self):
        """Tor 네트워크 설정"""
        try:
            # Tor SOCKS5 프록시 설정
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket

            # 세션에 Tor 프록시 적용
            tor_proxy = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            self.session.proxies.update(tor_proxy)

            print("  [+] Tor 네트워크 연결 성공")
            log_attack('TOR_SETUP', 'SUCCESS', "Connected to Tor network", 200, 0)

            # Tor 연결 확인
            try:
                response = self.session.get('https://check.torproject.org/api/ip')
                if response.json().get('IsTor'):
                    print(f"  [+] Tor IP: {response.json().get('IP')}")
            except:
                pass

        except Exception as e:
            print(f"  [-] Tor 연결 실패: {str(e)}")
            print("  [!] Tor 없이 계속 진행합니다.")
            log_attack('TOR_SETUP', 'ERROR', f"Tor connection failed: {str(e)}", 0, 0)
            self.use_tor = False

    def rotate_user_agent(self):
        """User-Agent 로테이션"""
        self.ua_index = (self.ua_index + 1) % len(self.user_agents)
        new_ua = self.user_agents[self.ua_index]
        self.session.headers.update({'User-Agent': new_ua})
        return new_ua

    def rotate_proxy(self):
        """프록시 로테이션"""
        if not self.use_proxy or self.use_tor:
            return None

        proxy = self.proxy_rotator.get_proxy()
        if proxy:
            self.session.proxies.update(proxy)
        return proxy

    def make_request(self, method, url, **kwargs):
        """익명화된 요청 수행"""
        # User-Agent 로테이션
        ua = self.rotate_user_agent()

        # 프록시 로테이션 (Tor 사용 중이 아닐 때)
        proxy = None
        if self.use_proxy and not self.use_tor:
            proxy = self.rotate_proxy()

        try:
            # 요청 수행
            response = self.session.request(method, url, **kwargs)

            # 성공 로그
            proxy_info = "Tor" if self.use_tor else (str(proxy) if proxy else "Direct")
            log_attack(
                'ANONYMOUS_REQUEST',
                'SUCCESS',
                f"Method: {method}, URL: {url}, Proxy: {proxy_info}",
                response.status_code,
                len(response.content)
            )

            return response

        except Exception as e:
            # 프록시 실패 시 마킹
            if proxy and not self.use_tor:
                self.proxy_rotator.mark_failed(proxy)

            # 재시도 또는 직접 연결
            if not self.use_tor and self.use_proxy:
                print(f"  [!] 프록시 실패, 직접 연결 시도...")
                self.session.proxies.clear()
                try:
                    response = self.session.request(method, url, **kwargs)
                    return response
                except:
                    pass

            raise e

    def get(self, url, **kwargs):
        """GET 요청"""
        return self.make_request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        """POST 요청"""
        return self.make_request('POST', url, **kwargs)

    def get_current_ip(self):
        """현재 IP 주소 확인"""
        try:
            # 여러 IP 확인 서비스 중 하나 사용
            services = [
                'https://api.ipify.org?format=json',
                'https://ipinfo.io/json',
                'https://httpbin.org/ip'
            ]

            for service in services:
                try:
                    response = self.make_request('GET', service, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        ip = data.get('ip') or data.get('origin', '알 수 없음')
                        return ip
                except:
                    continue

            return "IP 확인 실패"

        except Exception as e:
            return f"오류: {str(e)}"

    def new_identity(self):
        """새로운 신원 생성 (Tor 사용 시)"""
        if self.use_tor:
            try:
                # Tor 컨트롤러를 통한 새 회로 요청
                # (torctl 또는 stem 라이브러리 필요)
                print("  [*] Tor 새 회로 요청...")
                # 실제 구현은 Tor 컨트롤러 설정에 따라 다름
                log_attack('TOR_NEW_IDENTITY', 'INFO', "Requested new Tor circuit", 0, 0)
            except:
                pass

def get_anonymous_session(use_tor=False):
    """익명 세션 생성 헬퍼 함수"""
    return AnonymousSession(use_tor=use_tor)

# 익명화 테스트
def test_anonymization():
    """익명화 기능 테스트"""
    print("\n[*] 익명화 기능 테스트")
    print("="*50)

    # 일반 세션
    print("\n[1] 일반 세션 (익명화 없음)")
    normal_session = requests.Session()
    try:
        response = normal_session.get('https://httpbin.org/headers')
        print(f"  IP: {normal_session.get('https://api.ipify.org').text}")
        print(f"  User-Agent: {response.json()['headers'].get('User-Agent', 'Unknown')}")
    except Exception as e:
        print(f"  오류: {str(e)}")

    # 익명 세션 (프록시)
    print("\n[2] 익명 세션 (프록시 + UA 로테이션)")
    anon_session = AnonymousSession(use_proxy=True)
    try:
        print(f"  IP: {anon_session.get_current_ip()}")
        response = anon_session.get('https://httpbin.org/headers')
        print(f"  User-Agent: {response.json()['headers'].get('User-Agent', 'Unknown')}")
    except Exception as e:
        print(f"  오류: {str(e)}")

    # Tor 세션
    print("\n[3] Tor 세션")
    tor_session = AnonymousSession(use_tor=True)
    try:
        print(f"  IP: {tor_session.get_current_ip()}")
        response = tor_session.get('https://httpbin.org/headers')
        print(f"  User-Agent: {response.json()['headers'].get('User-Agent', 'Unknown')}")
    except Exception as e:
        print(f"  오류: {str(e)}")

    print("\n" + "="*50)