# 2SeChain 사용 가이드

## 빠른 시작

### 1. 설치

칼리 리눅스에서:

```bash
cd attack-automation
sudo bash install.sh
```

### 2. 기본 사용법

```bash
# DVWA 타겟에 대한 모든 공격 실행
2sechain -t http://192.168.1.100/dvwa -u admin -p password --all
```

## 상세 사용법

### 공격 모듈별 실행

#### SQL Injection

```bash
2sechain -t http://192.168.1.100/dvwa --sqli

# 상세 로그와 함께
2sechain -t http://192.168.1.100/dvwa --sqli --verbose
```

#### XSS (Cross-Site Scripting)

```bash
2sechain -t http://192.168.1.100/dvwa --xss
```

#### Command Injection

```bash
2sechain -t http://192.168.1.100/dvwa --cmdi
```

#### File Upload

```bash
2sechain -t http://192.168.1.100/dvwa --upload
```

### 보안 레벨 지정

DVWA의 보안 레벨에 따라 테스트:

```bash
# Low (기본값)
2sechain -t http://192.168.1.100/dvwa --security low --all

# Medium
2sechain -t http://192.168.1.100/dvwa --security medium --all

# High
2sechain -t http://192.168.1.100/dvwa --security high --all
```

### 내부 침투 시나리오

#### Post-Exploitation

시스템 정보 수집, 권한 확인, 파일 탐색 등:

```bash
2sechain -t http://192.168.1.100/dvwa --post-exploit
```

#### 피버팅 및 데이터 탈취

내부 네트워크 탐색 및 중요 데이터 수집:

```bash
2sechain -t http://192.168.1.100/dvwa --pivoting
```

### 전체 침투 시나리오

실제 공격자의 행동 패턴을 시뮬레이션:

```bash
# 1단계: 초기 침투 (웹 취약점 공격)
2sechain -t http://192.168.1.100/dvwa --all --delay 2

# 2단계: 시스템 정보 수집
2sechain -t http://192.168.1.100/dvwa --post-exploit --delay 2

# 3단계: 내부 네트워크 탐색 및 데이터 탈취
2sechain -t http://192.168.1.100/dvwa --pivoting --delay 2
```

## 고급 옵션

### 요청 간 지연 시간 조정

```bash
# 2초 지연 (SIEM 로그 확인에 유용)
2sechain -t http://192.168.1.100/dvwa --all --delay 2

# 지연 없이 빠르게
2sechain -t http://192.168.1.100/dvwa --all --delay 0
```

### 로그 저장 경로 지정

```bash
2sechain -t http://192.168.1.100/dvwa --all -o /tmp/my-attack-logs
```

### 상세 로그 출력

```bash
2sechain -t http://192.168.1.100/dvwa --all --verbose
```

## 로그 분석

생성된 로그는 `logs/` 디렉토리에 저장됩니다:

```bash
# 로그 파일 확인
ls -lh logs/

# 최근 로그 보기
tail -f logs/attack_*.log

# 성공한 공격만 필터링
grep "SUCCESS" logs/attack_*.log

# SQL Injection 로그만 보기
grep "SQL_INJECTION" logs/attack_*.log
```

## SIEM 연동 예제

### Filebeat 설정 예시

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /path/to/attack-automation/logs/*.log
  fields:
    log_type: penetration_test
    source: 2sechain
```

### 로그 형식

```
2024-03-15 14:30:52 | INFO     | SQL_INJECTION        | SUCCESS    | Payload: ' OR '1'='1 | HTTP 200 | 2458 bytes
2024-03-15 14:30:53 | INFO     | XSS_REFLECTED        | SUCCESS    | Payload: <script>alert('XSS')</script> | HTTP 200 | 1823 bytes
2024-03-15 14:30:54 | WARNING  | COMMAND_INJECTION    | FAILED     | Payload: ; ls | HTTP 403 | 342 bytes
```

## 트러블슈팅

### 로그인 실패

```bash
# 타겟 URL 확인
curl http://192.168.1.100/dvwa/login.php

# 올바른 자격증명 사용
2sechain -t http://192.168.1.100/dvwa -u admin -p password --sqli
```

### 권한 오류

```bash
# install.sh 실행 시 sudo 사용
sudo bash install.sh

# 로그 디렉토리 권한 확인
chmod 755 logs/
```

### 모듈 import 오류

```bash
# Python 패키지 재설치
pip3 install -r requirements.txt
```

## 팁

1. **SIEM 테스트 시**: `--delay 2` 옵션을 사용하여 로그가 제대로 수집되는지 확인
2. **탐지 룰 테스트**: 특정 공격만 반복 실행하여 탐지 정확도 확인
3. **로그 분석 연습**: 생성된 로그를 ELK Stack이나 OpenSearch에 업로드하여 분석

## 보안 주의사항

- 승인된 환경에서만 사용하세요
- 실습용 DVWA 인스턴스를 대상으로만 테스트하세요
- 프로덕션 환경에서는 절대 사용하지 마세요
- 로그에 민감한 정보가 포함될 수 있으니 주의하세요

## 참고

- 예제 스크립트: `examples.sh` 실행
- 도움말: `2sechain --help`
- 프로젝트 README: `README.md`

---

문제가 있거나 개선 사항이 있으면 2SeC 팀에게 알려주세요!
