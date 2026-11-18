#!/usr/bin/env bash
# ============================================================
#  RUN DEMO - Phishing Email Analyzer
#  Chay trong Git Bash (VS Code) hoac Kali Linux:
#      bash run_demo.sh
# ============================================================

# Di chuyen vao thu muc chua script nay
cd "$(dirname "$0")" || exit 1
echo ">> Thu muc: $(pwd)"

# 1. Tim Python (python3 / python / py)
PY=""
for c in python3 python py; do
  if command -v "$c" >/dev/null 2>&1 && "$c" --version >/dev/null 2>&1; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then
  echo "[LOI] Chua cai Python. Tai tai python.org, tick 'Add Python to PATH', roi mo lai VS Code."
  exit 1
fi
echo ">> Dung: $($PY --version 2>&1)"

# 2. Kiem tra file
if [ ! -f phish_demo.py ]; then
  echo "[LOI] Khong thay phish_demo.py trong thu muc nay."; exit 1
fi
EML_COUNT=$(ls *.eml 2>/dev/null | wc -l)
if [ "$EML_COUNT" -eq 0 ]; then
  echo "[LOI] Khong thay file .eml nao trong thu muc nay."; exit 1
fi
echo ">> Tim thay $EML_COUNT file .eml"

# 3. Chay phan tich (ep UTF-8 de khong loi tieng Viet tren Windows)
export PYTHONIOENCODING=utf-8
"$PY" -X utf8 phish_demo.py *.eml || { echo "[LOI] Chay that bai."; exit 1; }

# 4. Mo bao cao HTML
if [ -f phishing_report.html ]; then
  echo ">> Mo bao cao phishing_report.html ..."
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) start phishing_report.html ;;
    Darwin*)              open phishing_report.html ;;
    *)                    (xdg-open phishing_report.html || firefox phishing_report.html) >/dev/null 2>&1 & ;;
  esac
fi
