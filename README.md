# Web-SSH Portal 🌐🛡️

**Web-SSH Portal**은 웹 브라우저에서 다수의 SSH 서버를 관리하고 웹 터미널을 통해 실시간으로 원격 서버에 안전하게 접속할 수 있는 **Docker 기반의 웹 SSH Connection Manager**입니다. 

자체적인 관리자 인증 장치, 계정/포털 브랜딩 변경 기능, 서버 그룹 관리 및 접기/펴기 기능, 그리고 머신 스펙 진단기까지 탑재된 프리미엄 모던 웹 솔루션입니다.

---

## ✨ 핵심 기능 (Key Features)

1. **실시간 모던 웹 터미널 (xterm.js & WebSocket)**:
   - 브라우저 환경에서 동작하는 `xterm.js`를 사용해 네이티브 터미널과 동일한 사용감을 선상합니다.
   - 백엔드는 Node.js WebSocket-to-SSH Proxy를 통해 가벼우면서도 끊김 없는 명령 전송을 보장합니다.

2. **반응형 최적화 & PWA 모바일 기기 설치 지원**:
   - 모바일 크롬이나 사파리를 통해 접속 시 모바일 전용 UI로 최적화됩니다.
   - **가상 키보드 가림 완화**: 모바일 키보드가 나타나면 `Visual Viewport API`를 통해 화면 높이와 가로줄 수를 자동으로 계산하여 명령어 창이 키보드 뒤에 가려지지 않도록 조절합니다.
   - PWA(Progressive Web App)를 지원하므로 홈 화면에 바로가기 앱으로 설치하여 단독 앱처럼 쓸 수 있습니다.

3. **서버 사양 진단 및 정보 자동 감지 (OS/Spec Scanner)**:
   - **IP 스캔**: 호스트 IP만 입력하고 스캔을 누르면 SSH 배너를 리딩하여 운영체제를 유추합니다.
   - **시스템 진단 스캔**: 원격 서버의 인증 자격 증명을 기반으로 임시 SSH 접근을 통해 CPU 코어 개수, 메모리 크기, 디스크 여유량 및 정확한 리눅스 배포판 정보(`/etc/os-release`)를 백엔드에서 파싱해 입력란에 자동 적용합니다.

4. **접기/펴기를 지원하는 유연한 서버 그룹화 (Collapsible Grouping)**:
   - 수십 대의 서버들을 프로젝트별/클라우드별(예: OCI Cloud)로 그룹화하여 관리할 수 있으며, 접기/펴기 상태는 브라우저 `localStorage`에 자동 저장됩니다.

5. **강력한 세션 및 보안 로직**:
   - 비밀번호는 평문으로 저장되지 않고 **PBKDF2 SHA-512 (10,000 iterations)** 해시 암호화로 솔트와 함께 데이터베이스에 안전하게 보존됩니다.
   - **HttpOnly & SameSite=Strict** 세션 쿠키 제어를 통해 웹소켓 터미널 채널과 REST API 경로를 빈틈없이 봉쇄합니다.
   - 웹 대시보드 상단 메뉴에서 포털의 이름(ID)과 관리자 비밀번호를 언제든지 실시간으로 커스텀 변경할 수 있습니다.

---

## 🏗️ 폴더 구조 (Folder Structure)

```text
ssh-connect/
├── data/                 # 볼륨 데이터 저장소 (Docker 마운트 대상)
│   ├── connections.json  # 등록된 SSH 커넥션 데이터베이스 (자동 마이그레이션)
│   ├── auth.json         # 관리자 세션 정보 및 PBKDF2 해시 패스워드
│   ├── config.json       # 커스텀 포털 이름(Portal Name) 설정 파일
│   └── keys/             # 등록된 개별 서버들의 Private Key (.pem) 보관소
├── public/               # PWA 웹 프론트엔드 정적 소스 파일
│   ├── index.html        # 대시보드 메인 템플릿
│   ├── login.html        # 로그인 화면
│   ├── style.css         # 모던 글래스모피즘 스타일시트 (반응형 코드 포함)
│   ├── app.js            # 메인 앱 로직, 웹소켓 브릿지 및 API 제어
│   ├── manifest.json     # PWA 설치 정의서
│   ├── sw.js             # 서비스 워커 (오프라인 캐싱 지원)
│   └── icon.jpg          # PWA 홈 아이콘
├── server.js             # Express 서버 및 WebSocket SSH 게이트웨이 백엔드
├── import-existing.js    # 초기 대량 접속기 자동 마이그레이션 스크립트
├── Dockerfile            # 노드 컨테이너 빌드 정의서
├── docker-compose.yml    # 오케스트레이션 구성 파일
└── README.md             # 프로젝트 소개 및 매뉴얼
```

---

## 🚀 빠른 시작 (Quick Start)

### 1. 프로젝트 요구사항
- Docker 및 Docker Compose가 설치되어 있어야 합니다.

### 2. 설치 및 컨테이너 구동 방법

개발팀에서 미리 빌드하여 등록한 **GitHub Container Registry (GHCR)** 공식 이미지를 사용하면, 소스 코드를 클론(Clone)하거나 직접 빌드할 필요 없이 아래의 단순한 명령줄 하나로 즉시 서비스를 구동할 수 있습니다.

#### 방법 A: Docker 단일 명령어로 실행 (가장 빠름 ⚡)
터미널에 아래 명령어를 복사하여 실행합니다:
```bash
docker run -d \
  --name web-ssh \
  -p 3000:3000 \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  ghcr.io/seonggi/web-ssh:latest
```

#### 방법 B: Docker Compose 다운로드 후 실행 (추천 📂)
설정 관리가 편리한 Docker Compose 방식으로 구동하려면 아래 1줄 명령어를 복사해 터미널에 붙여넣습니다:
```bash
curl -sSL https://raw.githubusercontent.com/SeongGi/web-ssh/main/docker-compose.prod.yml -o docker-compose.yml && docker compose up -d
```

#### 방법 C: 소스 코드에서 직접 빌드하여 실행 (개발용 🛠️)
저장소를 클론한 뒤 직접 빌드하여 구동할 수도 있습니다:
```bash
git clone https://github.com/SeongGi/web-ssh.git
cd web-ssh
docker compose up -d --build
```

### 3. 접속 주소 및 초기 관리자 계정
구동 완료 후 브라우저에서 아래 주소로 접속합니다.
- **접속 URL**: `http://localhost:3000` (외부 도메인 바인딩 가능)
- **초기 관리자 계정 ID**: `admin`
- **초기 관리자 비밀번호**: `adminpassword`

> **[중요 보안 경고]**  
> 최초 로그인 후, 대시보드 상단 우측의 **[계정 정보 변경]** 버튼을 클릭하여 기본 아이디(`admin`)와 패스워드(`adminpassword`)를 반드시 새로운 값으로 변경한 후 사용해 주세요! 포털 명칭(기본값: *Web-SSH Portal*)도 대화상자에서 손쉽게 변경하실 수 있습니다.

---

## 🔒 백업 및 마이그레이션

등록하신 연결 서버 목록 및 키 파일들은 호스트 디렉토리의 `./data/` 폴더 내에 저장됩니다. 
- 새로운 서버 환경으로 서비스를 마이그레이션하시려면, 컨테이너를 중지하고 `./data` 디렉토리 전체를 백업하여 신규 서버의 동일 경로에 복사한 뒤 실행해 주시면 그대로 이전됩니다.

---

## 👥 공동 개발자 (Contributors)

이 프로젝트는 **SeongGi**와 Google DeepMind의 AI 페어 프로그래밍 어시스턴트 **Antigravity (AI)**가 공동으로 설계하고 개발하였습니다.
- **SeongGi**: 기획, 프로젝트 방향성 제시, 상세 스펙 요구사항 검증 및 배포 환경 조율
- **Antigravity (AI)**: 백엔드 노드 SSH-to-WebSocket 프록시 개발, 글래스모피즘 UI 코딩, PWA 모바일 최적화 및 시스템 진단 모듈 설계

