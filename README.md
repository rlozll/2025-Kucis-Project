# 2025-Kucis-Project 

malware_analyzer/

├── app.py                 # 👈 메인 Flask API 서버 파일

├── analyzer/

│   ├── __init__.py        # 👈 analyzer를 파이썬 패키지로 인식시킴

│   └── static_analyzer.py # 👈 실제 ELF/파일 분석 로직이 들어갈 파일

├── cowrie_downloads/      # 👈 카우리 허니팟이 다운로드한 파일을 저장하는 위치 (가정)

├── requirements.txt       # 👈 필요한 파이썬 라이브러리 목록

└── test_log.json          # 👈 테스트용 샘플 카우리 로그 파일