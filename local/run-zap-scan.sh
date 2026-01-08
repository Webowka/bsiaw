#!/bin/bash

set -e

echo "=========================================="
echo "ZAP Authenticated Security Scan"
echo "=========================================="

# Kolory
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Sprawdź czy aplikacja działa
echo -e "\n${YELLOW}[1/3]${NC} Sprawdzanie czy aplikacja jest dostępna..."
if ! curl -s -f http://localhost:8000 > /dev/null; then
    echo -e "${RED}✗ Aplikacja nie odpowiada na http://localhost:8000${NC}"
    echo "Uruchom najpierw aplikację z folderu local/:"
    echo "  cd local && docker-compose up -d"
    exit 1
fi
echo -e "${GREEN}✓ Aplikacja jest dostępna${NC}"
echo -e "${GREEN}✓ Użytkownik testowy: admin / Admin@123${NC}"

# Utwórz katalog na raporty w root projektu
cd ..
mkdir -p zap-reports
chmod 777 zap-reports

# Uruchom skan ZAP
echo -e "\n${YELLOW}[2/3]${NC} Uruchamianie ZAP Authenticated Scan..."
echo "To może potrwać 10-20 minut..."

docker run --rm --network host \
    -v "$(pwd):/zap/wrk/:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -cmd \
    -autorun /zap/wrk/zap-authenticated-scan.yaml

# Sprawdź wyniki
echo -e "\n${YELLOW}[3/3]${NC} Sprawdzanie wyników..."
if [ -f "zap-reports/zap-authenticated-report.html" ]; then
    echo -e "${GREEN}✓ Skan zakończony pomyślnie!${NC}"
    echo ""
    echo "=========================================="
    echo "Raporty wygenerowane:"
    echo "=========================================="
    echo "HTML: zap-reports/zap-authenticated-report.html"
    echo "JSON: zap-reports/zap-authenticated-report.json"
    echo "MD:   zap-reports/zap-authenticated-report.md"
    echo ""
    echo -e "${GREEN}Otwórz raport HTML w przeglądarce:${NC}"
    echo "  firefox zap-reports/zap-authenticated-report.html"
    echo "  lub"
    echo "  xdg-open zap-reports/zap-authenticated-report.html"
else
    echo -e "${RED}✗ Skan nie wygenerował raportów${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================="
echo "Skan zakończony!"
echo "==========================================${NC}"
