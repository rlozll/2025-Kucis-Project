# app.py: 허니팟으로부터 로그를 받을 API 엔드포인트 기본 형태 
import os
from flask import Flask, request, jsonify

# analyzer 디렉토리의 static_analyzer.py에서 분석 함수를 가져옴
from analyzer.static_analyzer import analyze_artifact

app = Flask(__name__)

# 허니팟이 다운로드한 파일이 저장된 기본 경로
DOWNLOAD_DIR = 'cowrie_downloads'


@app.route('/analyze/session', methods=['POST'])
def analyze_session():
    """카우리 세션 로그를 받아 분석하고 종합 결과를 JSON으로 반환"""
    
    # 1. 허니팟으로부터 세션 로그(JSON) 받기
    session_log = request.get_json()
    if not session_log:
        return jsonify({"error": "Invalid JSON"}), 400

    # 최종 결과를 담을 딕셔너리
    analysis_result = {}

    # 2. 세션 컨텍스트 분석 (Phase 1의 핵심)
    # Cowrie 로그 형식에 따라 실제 파싱 로직은 달라질 수 있음
    analysis_result['attacker_ip'] = session_log.get('src_ip', 'N/A')
    analysis_result['session_start'] = session_log.get('timestamp', 'N/A')

    analysis_result['geoip_country'] = session_log.get('country', 'N/A') # 카우리 로그에 국가 코드가 있다면
    
    # 로그인 시도 정보 추출 (예시)
    credentials = {}
    for log in session_log.get('log', []):
        if log.get('eventid') == 'cowrie.login.success':
            credentials['username'] = log.get('username')
            credentials['password'] = log.get('password')
            break # 첫 번째 성공 기록만 저장
    analysis_result['credentials'] = credentials
    
    # 예시: 로그에서 명령어 목록과 다운로드된 파일의 해시(shasum) 추출
    commands = [log['input'] for log in session_log.get('log', []) if log.get('eventid') == 'cowrie.session.input']
    analysis_result['command_history'] = commands
    
    downloaded_shasum = None
    for log in session_log.get('log', []):
        if log.get('eventid') == 'cowrie.file_download':
            downloaded_shasum = log.get('shasum')
            break # 첫 번째 다운로드된 파일만 분석

    # 3. 다운로드된 파일이 있다면 심층 분석 수행
    analysis_result['downloaded_artifacts'] = []
    if downloaded_shasum:
        # 파일 경로 조합 (카우리는 보통 shasum을 파일명으로 저장)
        file_path = os.path.join(DOWNLOAD_DIR, downloaded_shasum)
        
        # 디버깅을 위해 파일 경로를 터미널에 출력합니다.
        print(f"DEBUG: Attempting to analyze file at path: {file_path!r}")

        if os.path.exists(file_path):
            # 별도 모듈로 분리된 분석 함수 호출
            file_report = analyze_artifact(file_path)
            analysis_result['downloaded_artifacts'].append(file_report)
        else:
            analysis_result['downloaded_artifacts'].append({"error": f"File not found: {file_path}"})

    # 4. 최종 종합 결과 반환
    return jsonify(analysis_result)


if __name__ == '__main__':
    # 테스트를 위해 디버그 모드로 실행
    app.run(debug=True, port=5000)