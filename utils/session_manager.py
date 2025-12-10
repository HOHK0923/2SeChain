"""
DVWA Session Manager
DVWA 세션 관리 및 인증 처리
"""

import requests
from bs4 import BeautifulSoup
from utils.logger import log_session

class DVWASession:
    """DVWA 세션 관리 클래스"""

    def __init__(self, base_url, username, password, security_level='low'):
        """
        Args:
            base_url: DVWA 베이스 URL
            username: 로그인 사용자명
            password: 로그인 비밀번호
            security_level: 보안 레벨 (low, medium, high)
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.security_level = security_level

        # requests 세션 생성
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

        # 세션 정보
        self.is_logged_in = False
        self.csrf_token = None

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
        페이지 가져오기

        Args:
            relative_url: 상대 URL
            params: GET 파라미터

        Returns:
            requests.Response: 응답 객체
        """
        url = f"{self.base_url}/{relative_url.lstrip('/')}"
        return self.session.get(url, params=params)

    def post_page(self, relative_url, data=None):
        """
        페이지에 POST 요청

        Args:
            relative_url: 상대 URL
            data: POST 데이터

        Returns:
            requests.Response: 응답 객체
        """
        url = f"{self.base_url}/{relative_url.lstrip('/')}"
        return self.session.post(url, data=data)
