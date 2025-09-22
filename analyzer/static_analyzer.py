# analyzer/static_analyzer.py: 실제 파일 분석 로직을 별도의 파일로 분리
import hashlib
import magic
import os
import requests
from elftools.elf.elffile import ELFFile
import re

# 주의: 실제 운영 환경에서는 API 키를 환경변수나 별도 설정 파일로 관리해야 합니다.
VT_API_KEY = os.environ.get("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")

def analyze_artifact(file_path):
    """주어진 파일 경로의 아티팩트를 정적 분석하여 결과를 딕셔너리로 반환"""
    
    report = {
        "file_name": os.path.basename(file_path),
    }

    # 1. 파일 타입 식별
    try:
        report['file_type'] = magic.from_file(file_path)
    except Exception as e:
        report['file_type'] = f"Error: {e}"

    # 2. 해시 계산
    hashes = {}
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        report['hashes'] = hashes
    except Exception as e:
        report['hashes'] = f"Error: {e}"
        return report # 해시 계산 실패 시 이후 분석 중단

    # 3. VirusTotal 조회
    if VT_API_KEY != "YOUR_VIRUSTOTAL_API_KEY" and 'sha256' in hashes:
        url = f"https://www.virustotal.com/api/v3/files/{hashes['sha256']}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                vt_data = response.json()['data']['attributes']['last_analysis_stats']
                report['virustotal'] = {
                    "positives": vt_data['malicious'],
                    "total": sum(vt_data.values())
                }
            else:
                report['virustotal'] = {"status": "Not found or API error"}
        except Exception as e:
            report['virustotal'] = f"Error: {e}"

    # 4. ELF 구조 분석 (ELF 파일일 경우에만)
    if 'ELF' in report.get('file_type', ''):
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                report['elf_analysis'] = {
                    "architecture": elf.get_machine_arch(),
                    "imported_functions": _get_elf_imported_functions(elf)
                }
        except Exception as e:
            report['elf_analysis'] = f"Error: {e}"
            
    # 5. 내장 IOC(strings) 추출
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            # 출력 가능한 ASCII 문자열만 추출
            strings = re.findall(b"[\x20-\x7e]{4,}", content)
            decoded_strings = [s.decode('utf-8', errors='ignore') for s in strings]
            
            iocs = {
                "ips": [],
                "urls": []
            }
            # 정규표현식으로 IP와 URL 찾기
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            url_pattern = r'https?://[^\s/$.?#].[^\s]*'

            for s in decoded_strings:
                iocs["ips"].extend(re.findall(ip_pattern, s))
                iocs["urls"].extend(re.findall(url_pattern, s))
            
            # 중복 제거
            iocs["ips"] = list(set(iocs["ips"]))
            iocs["urls"] = list(set(iocs["urls"]))
            
            report['internal_iocs'] = iocs
    except Exception as e:
        report['internal_iocs'] = f"Error: {e}"

    return report

def _get_elf_imported_functions(elf):
    """ELF 파일에서 임포트된 함수 목록을 추출하는 헬퍼 함수"""
    functions = []
    dynsym_sec = elf.get_section_by_name('.dynsym')
    if not dynsym_sec:
        return functions
        
    for symbol in dynsym_sec.iter_symbols():
        if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] == 'SHN_UNDEF':
            functions.append(symbol.name.decode('utf-8'))
    return functions