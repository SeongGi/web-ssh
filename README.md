# Web-SSH Portal

웹 브라우저에서 여러 SSH 서버를 관리하고, 웹 터미널로 원격 서버에 접속할 수 있는 Docker 기반 SSH Connection Manager입니다.

---

## 기능

1. 실시간 웹 터미널 (xterm.js + WebSocket)
   - 브라우저에서 동작하는 `xterm.js`를 사용해 네이티브 터미널과 동일한 사용감을 제공합니다.
   - Node.js WebSocket-to-SSH Proxy 방식으로 가볍고 끊김 없는 명령 전송을 지원합니다.

2. 반응형 UI + PWA 지원
   - 모바일 크롬/사파리 접속 시 모바일 전용 레이아웃으로 동작합니다.
   - Visual Viewport API를 통해 가상 키보드가 올라와도 터미널이 가려지지 않습니다.
   - 홈 화면에 바로가기 앱으로 설치 가능합니다.

3. 서버 사양 자동 감지
   - IP만 입력하면 SSH 배너를 분석해 운영체제를 유추합니다.
   - 인증 후 SSH로 접속해 CPU 코어 수, 메모리, 디스크, OS 정보를 자동으로 불러옵니다.

4. 서버 그룹 관리
   - 서버를 프로젝트/클라우드별로 그룹화하고, 접기/펴기 상태를 브라우저에 저장합니다.

5. 세션 및 보안
   - 비밀번호는 PBKDF2 SHA-512 (10,000 iterations) + salt로 저장합니다.
   - HttpOnly, SameSite=Strict 세션 쿠키로 API와 WebSocket 채널을 보호합니다.
   - 대시보드에서 포털 이름, 관리자 ID, 비밀번호를 언제든지 변경할 수 있습니다.

---

## 폴더 구조

```text
ssh-connect/
├── data/                 # 볼륨 데이터 저장소 (Docker 마운트 대상)
│   ├── connections.json  # 등록된 SSH 커넥션 데이터베이스
│   ├── auth.json         # 관리자 계정 정보 및 PBKDF2 해시
│   ├── config.json       # 포털 이름 설정 파일
│   └── keys/             # 서버별 Private Key (.pem) 보관소
├── public/               # 웹 프론트엔드 정적 파일
│   ├── index.html        # 대시보드
│   ├── login.html        # 로그인 화면
│   ├── style.css         # 스타일시트 (반응형 포함)
│   ├── app.js            # 앱 로직, WebSocket 브릿지
│   ├── manifest.json     # PWA 설치 정의
│   ├── sw.js             # 서비스 워커 (오프라인 캐싱)
│   └── icon.jpg          # PWA 아이콘
├── server.js             # Express 서버 및 WebSocket SSH 게이트웨이
├── import-existing.js    # 기존 접속 정보 마이그레이션 스크립트
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 설치 및 실행

Docker만 있으면 됩니다.

### 방법 A: Docker 명령어로 바로 실행

```bash
docker run -d \
  --name web-ssh \
  -p 3000:3000 \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  ghcr.io/seonggi/web-ssh:latest
```

### 방법 B: Docker Compose로 실행 (권장)

```bash
curl -sSL https://raw.githubusercontent.com/SeongGi/web-ssh/main/docker-compose.prod.yml -o docker-compose.yml && docker compose up -d
```

### 방법 C: 소스 코드에서 직접 빌드

```bash
git clone https://github.com/SeongGi/web-ssh.git
cd web-ssh
docker compose up -d --build
```

### 초기 접속 정보

- 접속 URL: `http://localhost:3000`
- 초기 ID: `admin`
- 초기 비밀번호: `adminpassword`

> 처음 로그인 후 대시보드 우측 상단의 계정 설정에서 ID와 비밀번호를 반드시 변경해 주세요.

---

## 백업 및 마이그레이션

서버 목록, 키 파일 등 모든 데이터는 `./data/` 폴더에 저장됩니다.
새 서버로 이전할 때 `./data` 디렉토리를 통째로 복사하면 그대로 옮겨집니다.

---

## Contributors

- SeongGi: 기획, 요구사항 정의, 배포 환경 조율
- Antigravity (AI): 백엔드 SSH-to-WebSocket 프록시, 프론트엔드 UI, PWA 모바일 최적화, 시스템 진단 모듈
