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
   - HttpOnly, SameSite=Strict 세션 쿠키로 API와 WebSocket 채널을 보호합니다.
   - 저장되는 자격증명이 없습니다. 인증은 전적으로 Google에 위임합니다.
   - 대시보드에서 포털 이름을 변경할 수 있습니다.

6. 보안 점검 (Security Audit)
   - 서버 카드의 **점검** 버튼, 또는 상단의 **전체 보안 점검** 버튼으로 실행합니다.
   - SSH로 접속해 읽기 전용 검사만 수행합니다. 설치·변경·재시작을 하지 않습니다.
   - SSH 설정, 외부 노출 포트, 호스트 방화벽, fail2ban, 미적용 보안 업데이트,
     NOPASSWD sudo, 키·권한 위생, 무차별 대입 시도, 컨테이너 포트 게시,
     시크릿이 담긴 world-readable 유닛 파일을 확인합니다.
   - 결과는 치명적/높음/중간/낮음/확인불가로 등급을 나눠 보여주고, 텍스트로 복사할 수 있습니다.

7. Google 로그인 (**유일한 로그인 방식**)
   - 아이디/비밀번호 로그인은 제거됐습니다. Google 계정으로만 들어올 수 있습니다.
   - OAuth 2.0 Authorization Code + PKCE 흐름을 사용하며, 외부 라이브러리 없이 표준 라이브러리로 구현되어 있습니다.
   - ID 토큰은 Google JWKS로 서명을 검증하고 `iss`, `aud`, `exp`, `iat`, `nonce`까지 확인합니다.
   - 허용 목록(이메일 또는 도메인)에 있는, Google이 인증한 이메일 계정만 로그인할 수 있습니다.
   - 허용 목록은 **환경변수로만** 바꿀 수 있습니다. 세션이 탈취돼도 UI에서 접근 권한을 넓힐 수 없습니다.
   - 설정이 불완전하면 서버가 **기동을 거부**합니다. 로그인 불가 상태로 떠 있는 것보다 즉시 실패하는 편이 안전합니다.

---

## 폴더 구조

```text
ssh-connect/
├── public/               # 웹 프론트엔드 정적 파일
│   ├── index.html        # 대시보드
│   ├── login.html        # 로그인 화면
│   ├── style.css         # 스타일시트 (반응형 포함)
│   ├── app.js            # 앱 로직, WebSocket 브릿지
│   ├── manifest.json     # PWA 설치 정의
│   ├── sw.js             # 서비스 워커 (오프라인 캐싱)
│   └── icon.jpg          # PWA 아이콘
├── server.js             # Express 서버, WebSocket SSH 게이트웨이, Google OAuth 처리
├── import-existing.js    # 기존 접속 정보 마이그레이션 스크립트
├── .env.example          # 환경변수 예시 (Google 로그인 설정)
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 설치 및 실행

Docker와 Google OAuth 클라이언트가 필요합니다.
**먼저 아래 "Google 로그인 설정"을 완료하세요** — 유일한 로그인 방식이라, 설정 없이는 서버가 기동하지 않습니다.

### 방법 A: Docker 명령어로 바로 실행

```bash
docker run -d \
  --name web-ssh \
  -p 3000:3000 \
  -e DATA_DIR=/app/data \
  -e GOOGLE_CLIENT_ID='xxxxxxxx.apps.googleusercontent.com' \
  -e GOOGLE_CLIENT_SECRET='...' \
  -e GOOGLE_ALLOWED_EMAILS='you@example.com' \
  -e GOOGLE_REDIRECT_URI='https://ssh.example.com/api/auth/google/callback' \
  -e COOKIE_SECURE=true \
  -v web-ssh-data:/app/data \
  --restart unless-stopped \
  ghcr.io/seonggi/web-ssh:latest
```

### 방법 B: Docker Compose로 실행 (권장)

```bash
curl -sSL https://raw.githubusercontent.com/SeongGi/web-ssh/main/docker-compose.prod.yml -o docker-compose.yml
curl -sSL https://raw.githubusercontent.com/SeongGi/web-ssh/main/.env.example -o .env
$EDITOR .env    # GOOGLE_* 값을 채웁니다
docker compose up -d
```

### 방법 C: 소스 코드에서 직접 빌드

```bash
git clone https://github.com/SeongGi/web-ssh.git
cd web-ssh
cp .env.example .env && $EDITOR .env
docker compose up -d --build
```

### 접속

- 접속 URL: `http://localhost:3000` (또는 설정한 도메인)
- 로그인 화면의 **Google 계정으로 로그인** 버튼만 있습니다. 저장된 비밀번호는 없습니다.
- 허용 목록에 없는 계정은 거부됩니다.

HTTPS 리버스 프록시를 사용하는 운영 환경에서는 `COOKIE_SECURE=true`도 설정하세요.

---

## Google 로그인 설정 (필수)

Google 계정이 유일한 로그인 방식입니다. OAuth 클라이언트를 만들고 환경변수를 설정하세요.

### 1. Google Cloud Console에서 OAuth 클라이언트 만들기

1. [Google Cloud Console](https://console.cloud.google.com/)에서 프로젝트를 선택하거나 새로 만듭니다.
2. **API 및 서비스 → OAuth 동의 화면**에서 동의 화면을 구성합니다.
   Google Workspace 조직 내부에서만 쓴다면 User Type을 `내부(Internal)`로 두는 것이 가장 안전합니다.
3. **API 및 서비스 → 사용자 인증 정보 → 사용자 인증 정보 만들기 → OAuth 클라이언트 ID**를 선택하고
   애플리케이션 유형을 **웹 애플리케이션**으로 지정합니다.
4. **승인된 리디렉션 URI**에 포털 주소 + `/api/auth/google/callback`을 등록합니다.

   ```text
   https://ssh.example.com/api/auth/google/callback
   http://localhost:3000/api/auth/google/callback   # 로컬 테스트용
   ```

5. 발급된 클라이언트 ID와 클라이언트 보안 비밀번호를 복사합니다.

### 2. 환경변수 설정

```bash
export GOOGLE_CLIENT_ID='xxxxxxxx.apps.googleusercontent.com'
export GOOGLE_CLIENT_SECRET='...'
export GOOGLE_REDIRECT_URI='https://ssh.example.com/api/auth/google/callback'

# 허용할 계정: 개별 이메일과 도메인 중 하나 이상은 반드시 지정해야 합니다.
export GOOGLE_ALLOWED_EMAILS='admin@example.com,ops@example.com'
export GOOGLE_ALLOWED_DOMAINS='example.com'

docker compose up -d
```

| 환경변수 | 필수 | 설명 |
| --- | --- | --- |
| `GOOGLE_CLIENT_ID` | ✅ | OAuth 클라이언트 ID |
| `GOOGLE_CLIENT_SECRET` | ✅ | OAuth 클라이언트 보안 비밀번호 |
| `GOOGLE_ALLOWED_EMAILS` / `GOOGLE_ALLOWED_DOMAINS` | ✅ (둘 중 하나 이상) | 로그인을 허용할 이메일 또는 이메일 도메인 (쉼표 구분) |
| `GOOGLE_REDIRECT_URI` | ⬜ | 생략하면 요청 호스트에서 유추합니다. 리버스 프록시 뒤에서는 명시하세요. |

`.env.example`을 `.env`로 복사해서 채워도 됩니다.

### 3. 동작 방식과 안전장치

- **설정이 불완전하면 서버가 기동을 거부합니다.** 유일한 로그인 방식이므로, 로그인할 수 없는 상태로
  서비스가 떠 있는 것(정상으로 오인 가능)보다 즉시 실패하는 편이 안전합니다. 부족한 항목이 로그에 출력됩니다.
- **허용 목록이 없으면 기동하지 않습니다.** 허용 목록 없이 켜면 전 세계 아무 Google 계정이나
  모든 관리 서버의 셸을 열 수 있게 됩니다.
- 허용 목록은 **환경변수로만** 변경할 수 있습니다. UI에는 수정 경로가 없으므로, 세션이 탈취돼도
  공격자가 자기 계정을 허용 목록에 추가할 수 없습니다.
- 이메일이 Google에서 인증된(`email_verified`) 계정만 통과합니다.
- CSRF 방지를 위한 `state`, 재생 공격 방지를 위한 `nonce`, 그리고 PKCE(S256)를 함께 사용합니다.
- 저장되는 비밀번호가 없습니다. 계정 잠금·무차별 대입 차단·MFA는 Google이 담당합니다.
- 운영 환경에서는 반드시 HTTPS와 `COOKIE_SECURE=true`를 함께 사용하세요.

### 로그인이 안 될 때 (복구)

저장된 비밀번호가 없으므로 UI로 복구할 수 없습니다. 복구는 환경변수를 고치고 재시작하는 것뿐입니다.

```bash
docker logs ssh-connect | tail -20        # 부족한 설정이 무엇인지 확인
$EDITOR .env                              # GOOGLE_* 수정
docker compose up -d                      # 재시작
```

흔한 원인은 GCP 콘솔의 승인된 리디렉션 URI가 `GOOGLE_REDIRECT_URI`와 한 글자라도 다른 경우
(`redirect_uri_mismatch`)와, 로그인하려는 계정이 허용 목록에 없는 경우(`?error=google_forbidden`)입니다.
포털이 잠겨도 SSH 접속 자체는 영향받지 않으니, 서버에는 평소 쓰는 SSH 클라이언트로 접속하면 됩니다.

---

## 백업 및 마이그레이션

서버 목록과 SSH 개인키는 Git 저장소가 아닌 Docker named volume에 저장됩니다.
관리자 자격증명은 더 이상 저장되지 않습니다(Google 로그인 전용).
Node.js로 직접 실행할 때는 기본적으로 `~/.local/share/web-ssh`에 저장되며,
필요하면 `DATA_DIR` 환경변수로 저장소 밖의 다른 보안 경로를 지정할 수 있습니다.

### 볼륨 이름 확인

`docker compose`는 volume 이름에 **프로젝트 이름을 접두사로 붙입니다.** compose 파일에
`ssh-connect-data`라고 적혀 있어도 실제 볼륨은 `<프로젝트>_ssh-connect-data`
(예: `ssh-connect_ssh-connect-data`)가 됩니다. 데이터를 옮길 때 접두사 없는 이름에
복사하면 컨테이너는 빈 볼륨을 마운트하므로, 항상 실제 이름을 먼저 확인하세요.

```bash
docker inspect <컨테이너> --format '{{range .Mounts}}{{.Name}}{{end}}'
```

### 기존 데이터를 볼륨으로 옮기기

컨테이너를 정지한 후, 위에서 확인한 실제 볼륨 이름으로 복사합니다.

```bash
VOL=$(docker inspect ssh-connect --format '{{range .Mounts}}{{.Name}}{{end}}')
docker run --rm \
  -v "$HOME/.local/share/web-ssh:/source:ro" \
  -v "$VOL:/target" \
  alpine sh -c 'cp -a /source/. /target/ && chmod 700 /target /target/keys && chmod 600 /target/*.json /target/keys/*.pem'
```

구버전에서 올라온 볼륨에 `auth.json`이 남아 있으면 기동 시 자동으로 삭제됩니다.
더 이상 사용되지 않는 비밀번호 해시를 데이터 볼륨에 남겨두지 않기 위한 조치입니다.

백업도 저장소 폴더가 아닌 별도 보안 경로에 만들고 Git에는 추가하지 마세요.
과거 노출된 키나 아카이브는 실행 중인 컨테이너의 데이터 볼륨에 남겨두지 마세요.

---

## Contributors

- SeongGi: 기획, 요구사항 정의, 배포 환경 조율
- Antigravity (AI): 백엔드 SSH-to-WebSocket 프록시, 프론트엔드 UI, PWA 모바일 최적화, 시스템 진단 모듈
