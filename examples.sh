#!/bin/bash
# 2SeChain 사용 예제 스크립트

echo "=========================================="
echo "2SeChain - 사용 예제"
echo "=========================================="
echo ""
echo "주의: 실제 실행하려면 타겟 URL을 수정하세요"
echo ""

TARGET="http://192.168.1.100/dvwa"

echo "1. 모든 공격 모듈 실행 (기본)"
echo "   2sechain -t $TARGET -u admin -p password --all"
echo ""

echo "2. SQL Injection만 실행"
echo "   2sechain -t $TARGET --sqli"
echo ""

echo "3. XSS 공격 (상세 로그)"
echo "   2sechain -t $TARGET --xss --verbose"
echo ""

echo "4. 보안 레벨 Medium에서 Command Injection"
echo "   2sechain -t $TARGET --security medium --cmdi"
echo ""

echo "5. Post-Exploitation (내부 침투)"
echo "   2sechain -t $TARGET --post-exploit --delay 2"
echo ""

echo "6. 피버팅 및 데이터 탈취"
echo "   2sechain -t $TARGET --pivoting"
echo ""

echo "7. 전체 시나리오 (초기 침투 → Post-exploit → 피버팅)"
echo "   2sechain -t $TARGET --all"
echo "   2sechain -t $TARGET --post-exploit"
echo "   2sechain -t $TARGET --pivoting"
echo ""

echo "8. 커스텀 로그 경로 지정"
echo "   2sechain -t $TARGET --all -o /tmp/attack-logs"
echo ""

echo "=========================================="
echo "도움말: 2sechain --help"
echo "=========================================="
