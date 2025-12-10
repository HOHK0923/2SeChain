#!/bin/bash
# 2SeC Attack Automation Tool - Installation Script
# 칼리 리눅스 환경에 전역 명령어로 설치

set -e

echo "=========================================="
echo "2SeC Attack Automation Tool 설치"
echo "=========================================="
echo ""

# 현재 디렉토리
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 설치 확인
if [ "$EUID" -ne 0 ]; then
    echo "[!] root 권한이 필요합니다. sudo를 사용해주세요."
    exit 1
fi

echo "[*] Python 패키지 설치 중..."
# 칼리 리눅스 시스템 패키지 먼저 시도
apt install -y python3-requests python3-bs4 python3-lxml >/dev/null 2>&1 && \
echo "[+] 시스템 패키지 설치 완료" || \
{
    # apt 실패 시 pip3로 시도
    pip3 install -q --break-system-packages requests beautifulsoup4 lxml 2>/dev/null && \
    echo "[+] pip3 패키지 설치 완료" || \
    echo "[!] 경고: 일부 패키지 설치 실패. 수동 설치가 필요할 수 있습니다."
}

echo "[*] 실행 권한 부여 중..."
chmod +x "$SCRIPT_DIR/dvwa_attacker.py"

echo "[*] 심볼릭 링크 생성 중..."
# /usr/local/bin에 심볼릭 링크 생성
ln -sf "$SCRIPT_DIR/dvwa_attacker.py" /usr/local/bin/2sechain

echo "[*] 설정 완료!"
echo ""
echo "=========================================="
echo "설치가 완료되었습니다!"
echo "이제 어디서든 '2sechain' 명령어를 사용할 수 있습니다."
echo "=========================================="
echo ""
echo "사용 방법:"
echo "  1. 도구 실행: 2sechain"
echo "  2. 프롬프트에서 명령어 입력"
echo ""
echo "사용 예시:"
echo "  \$ 2sechain"
echo "  2sechain> connect http://192.168.1.100/dvwa admin password"
echo "  2sechain (http://...)> attack sqli"
echo "  2sechain (http://...)> post-exploit"
echo "  2sechain (http://...)> exit"
echo ""
echo "도움말:"
echo "  2sechain 실행 후 'help' 명령어 입력"
echo ""
