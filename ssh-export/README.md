# SSH 서버 접속 정보

## 사용법
1. 이 폴더의 파일들을 ~/.ssh/ 에 복사
2. pem 파일 권한 설정: chmod 600 ~/.ssh/*.pem
3. config 파일을 ~/.ssh/config 에 추가 (기존 config가 있으면 내용 병합)
4. ssh oci / ssh ubuntu / ssh oci-arm 으로 접속

## 서버 목록

| Host | IP | User | OS | 스펙 | 설명 |
|------|------|------|------|------|------|
| oci | 64.110.68.20 | opc | Oracle Linux 9.4 (x86_64) | 2 CPU / 1GB RAM / 30GB | OCI 기본 서버 |
| ubuntu | 140.238.17.31 | ubuntu | Ubuntu 22.04 (x86_64) | 2 CPU / 1GB RAM / 45GB | 개발서버 (code-server, Docker, AI Remediator) |
| oci-arm | 217.142.140.15 | ubuntu | Ubuntu 24.04 (ARM64) | 1 CPU / 6GB RAM / 48GB | 웹서비스 (Caddy, Node.js 3000/3001) |

## 파일 목록
- config : SSH 설정 파일
- oci.pem : oci 서버 접속 키
- ubuntu.pem : ubuntu 서버 접속 키
- oci-arm.pem : oci-arm 서버 접속 키
