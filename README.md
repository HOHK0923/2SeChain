# 2SeChain - DVWA Attack Automation Tool

> SIEM 로그 생성을 위한 대화형 DVWA 침투테스트 자동화 도구

## 프로젝트 소개

2SeC 팀의 SIEM 프로젝트를 위한 공격 로그 생성 도구입니다.
DVWA(Damn Vulnerable Web Application)를 대상으로 다양한 웹 취약점 공격을 자동화하여
실제 침투테스트 로그를 생성하고, 이를 통해 SIEM 시스템의 탐지 규칙을 테스트할 수 있습니다.

**대화형 CLI 인터페이스**를 제공하여 Metasploit처럼 프롬프트에서 명령어를 입력하는 방식으로 동작합니다.

## 주요 기능

### 지원하는 공격 유형

- **SQL Injection** - 다양한 SQLi 페이로드를 통한 데이터베이스 공격
- **XSS (Cross-Site Scripting)** - Reflected/Stored XSS 공격
- **Command Injection** - 시스템 명령어 인젝션
- **File Upload** - 악성 파일 업로드 및 웹셸 배포
- **Post-Exploitation** - 시스템 정보 수집, 권한 상승 시도
- **Pivoting & Data Exfiltration** - 내부 네트워크 탐색 및 데이터 탈취

### 특징

- **대화형 CLI 인터페이스** - Metasploit 스타일의 프롬프트 기반 인터페이스
- 실시간 연결 상태 표시
- 상세한 공격 로그 자동 생성
- SIEM 로그 수집 테스트용 최적화
- 칼리 리눅스 환경 지원
- 모듈화된 구조로 확장 가능

## 설치 방법

### 요구사항

- Kali Linux (권장) 또는 다른 리눅스 배포판
- Python 3.7 이상
- root 권한 (전역 설치 시)

### 자동 설치

```bash
cd attack-automation
sudo bash install.sh
```

설치가 완료되면 `2sechain` 명령어를 어디서든 사용할 수 있습니다.

### 수동 설치

```bash
# 필요한 패키지 설치
pip3 install requests beautifulsoup4 lxml

# 실행 권한 부여
chmod +x dvwa_attacker.py

# 심볼릭 링크 생성 (선택사항)
sudo ln -s $(pwd)/dvwa_attacker.py /usr/local/bin/2sechain
```

## 사용법

### 기본 사용 흐름

1. `2sechain` 명령어로 도구 실행
2. `connect` 명령어로 DVWA 타겟에 연결
3. 원하는 공격 모듈 실행
4. `exit`로 종료

### 실제 사용 예시

```bash
# 1. 도구 실행
$ 2sechain

# 프롬프트가 나타남
2sechain>

# 2. 타겟에 연결
2sechain> connect http://192.168.1.100/dvwa admin password
[*] http://192.168.1.100/dvwa에 연결 중...
[+] 연결 성공!
[+] 로그인: admin
[+] 보안 레벨: LOW
[*] 로그 파일: logs/attack_20240315_143052.log

# 프롬프트가 변경됨 (연결 상태 표시)
2sechain (http://192.168.1.100/dvwa)>

# 3. 현재 상태 확인
2sechain (http://192.168.1.100/dvwa)> status
[현재 상태]
  타겟: http://192.168.1.100/dvwa
  사용자: admin
  보안 레벨: LOW
  지연 시간: 1초
  상세 모드: OFF
  로그 디렉토리: logs/

# 4. SQL Injection 공격 실행
2sechain (http://192.168.1.100/dvwa)> attack sqli
[*] SQL Injection 공격 시작...
  [+] 성공: ' OR '1'='1
  [+] 성공: ' OR '1'='1' --
  ...
[+] 공격 성공: 15/20

# 5. XSS 공격 실행
2sechain (http://192.168.1.100/dvwa)> attack xss
[*] XSS 공격 시작...
  [*] Reflected XSS 테스트 중...
    [+] Reflected XSS 성공: <script>alert('XSS')</script>
  ...

# 6. 모든 공격 실행
2sechain (http://192.168.1.100/dvwa)> attack all
[*] 모든 공격 모듈 실행...
...

# 7. Post-exploitation
2sechain (http://192.168.1.100/dvwa)> post-exploit
[*] Post-Exploitation 시작...
  [*] system_info 수집 중...
  [*] user_enum 수집 중...
  ...

# 8. 피버팅
2sechain (http://192.168.1.100/dvwa)> pivoting
[*] 피버팅 및 데이터 탈취 시작...
  [1/3] 네트워크 정보 수집 중...
  [2/3] 중요 파일 탐색 중...
  [3/3] 데이터 탈취 시도 중...

# 9. 로그 확인
2sechain (http://192.168.1.100/dvwa)> logs
[로그 파일 목록]
  1. attack_20240315_143052.log (23456 bytes)
  2. attack_20240315_145230.log (18923 bytes)

# 10. 마지막 로그 보기
2sechain (http://192.168.1.100/dvwa)> show last-log
[attack_20240315_143052.log]
2024-03-15 14:30:52 | INFO     | SQL_INJECTION        | SUCCESS    | ...
...

# 11. 종료
2sechain (http://192.168.1.100/dvwa)> exit
[+] 연결 해제됨
[*] 종료합니다.
```

## 명령어 레퍼런스

### 연결 관리

```bash
connect <url> <username> <password>  # DVWA에 연결
disconnect                           # 연결 해제
status                              # 현재 상태 확인
set security <level>                # 보안 레벨 설정 (low/medium/high)
set delay <seconds>                 # 요청 간 지연 시간 설정
```

### 공격 모듈

```bash
attack sqli                         # SQL Injection 공격
attack xss                          # XSS 공격
attack cmdi                         # Command Injection 공격
attack upload                       # File Upload 공격
attack all                          # 모든 기본 공격 실행
```

### 고급 공격

```bash
post-exploit                        # Post-Exploitation
pivoting                            # 피버팅 및 데이터 탈취
```

### 기타

```bash
logs                                # 로그 파일 목록
show last-log                       # 마지막 로그 내용 보기
verbose <on/off>                    # 상세 출력 모드
clear                               # 화면 지우기
help                                # 도움말
exit, quit                          # 종료
```

## 프로젝트 구조

```
attack-automation/
├── dvwa_attacker.py          # 메인 대화형 CLI 스크립트
├── install.sh                # 설치 스크립트
├── modules/                  # 공격 모듈
│   ├── sql_injection.py      # SQL Injection 모듈
│   ├── xss_attack.py         # XSS 공격 모듈
│   ├── cmd_injection.py      # Command Injection 모듈
│   ├── file_upload.py        # File Upload 모듈
│   ├── post_exploit.py       # Post-Exploitation 모듈
│   └── pivoting.py           # 피버팅 및 데이터 탈취 모듈
├── utils/                    # 유틸리티
│   ├── logger.py             # 로그 관리
│   └── session_manager.py    # 세션 관리
├── payloads/                 # 페이로드 저장소 (자동 생성)
└── logs/                     # 로그 저장 디렉토리 (자동 생성)
```

## 로그 파일

공격 실행 시 `logs/` 디렉토리에 다음과 같은 형식으로 로그가 저장됩니다:

```
logs/attack_20240315_143052.log
```

로그 형식 예시:
```
2024-03-15 14:30:52 | INFO     | SESSION | LOGIN                | User: admin, URL: http://192.168.1.100/dvwa
2024-03-15 14:30:53 | INFO     | SQL_INJECTION        | SUCCESS    | Payload: ' OR '1'='1 | HTTP 200 | 2458 bytes
2024-03-15 14:30:54 | INFO     | XSS_REFLECTED        | SUCCESS    | Payload: <script>alert('XSS')</script> | HTTP 200 | 1823 bytes
```

## 주의사항

**법적 경고**

이 도구는 오직 **교육 목적** 및 **승인된 침투테스트 환경**에서만 사용해야 합니다.

- 본인이 소유하거나 명시적인 승인을 받은 시스템에만 사용
- 무단으로 타인의 시스템을 공격하는 것은 불법입니다
- 이 도구 사용으로 인한 모든 책임은 사용자에게 있습니다

## 사용 시나리오

### 시나리오 1: SIEM 로그 수집 테스트

```bash
$ 2sechain
2sechain> connect http://dvwa.local/dvwa admin password
2sechain (http://dvwa.local/dvwa)> set delay 2
2sechain (http://dvwa.local/dvwa)> attack all
# SIEM에서 로그 수집 확인
```

### 시나리오 2: 특정 공격 패턴 테스트

```bash
$ 2sechain
2sechain> connect http://dvwa.local/dvwa admin password
2sechain (http://dvwa.local/dvwa)> verbose on
2sechain (http://dvwa.local/dvwa)> attack sqli
# SQL Injection 탐지 룰 테스트
```

### 시나리오 3: 전체 침투 시나리오

```bash
$ 2sechain
2sechain> connect http://dvwa.local/dvwa admin password
2sechain (http://dvwa.local/dvwa)> attack all
2sechain (http://dvwa.local/dvwa)> post-exploit
2sechain (http://dvwa.local/dvwa)> pivoting
2sechain (http://dvwa.local/dvwa)> logs
2sechain (http://dvwa.local/dvwa)> exit
```

## 팁

1. **상세 모드**: `verbose on`을 사용하면 더 자세한 로그를 볼 수 있습니다
2. **지연 시간**: SIEM 테스트 시 `set delay 2`를 사용하여 로그 수집 확인
3. **상태 확인**: `status` 명령어로 현재 설정을 언제든지 확인
4. **로그 관리**: `logs` 명령어로 생성된 로그 파일 확인

## 트러블슈팅

### 연결 실패

```bash
2sechain> connect http://192.168.1.100/dvwa admin password
[!] 연결 실패: Connection refused

# 해결: 타겟 URL과 자격증명 확인
```

### 권한 오류

```bash
# install.sh 실행 시 sudo 사용
sudo bash install.sh
```

## 개발 정보

- **프로젝트**: 2SeC - 2초만에방어
- **팀원**: 황준하, 김민지, 정완우, 허예은, 이영원
- **개발자**: 황준하
- **버전**: 1.0
- **목적**: SIEM 환경 구축 및 공격 로그 생성

## 향후 계획

- [ ] Tor/프록시 연동을 통한 IP 익명화
- [ ] 명령어 자동완성 기능
- [ ] 공격 시나리오 스크립트 기능
- [ ] OWASP Juice Shop 지원
- [ ] 멀티 타겟 지원

## 라이선스

이 프로젝트는 교육 목적으로 개발되었습니다.

---

**Made by 2SeC Team**
