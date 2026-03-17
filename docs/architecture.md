# CloakCat C2 Architecture

## 개요

CloakCat C2는 Rust 기반 Command and Control 프레임워크로, server, agent, cli가 **독립 실행 구조**를 유지합니다. 공통 로직은 `cloakcat-protocol` shared crate로 분리되어 있으며, 의존성 방향은 `shared → 각 구성요소`로 흐릅니다.

## 디렉토리 구조

```
cloak-cat/
├── Cargo.toml                 # workspace
├── cloakcat-protocol/         # 공통 프로토콜 라이브러리
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── constants.rs       # HEALTH_* 상수
│       ├── crypto.rs          # HMAC 서명/검증
│       ├── paths.rs          # Endpoint URL 생성
│       └── types.rs          # RegisterReq, Command, ResultReq 등
├── cat-server/               # C2 HTTP API 서버
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs            # 진입점
│       ├── db.rs             # SQLx/PostgreSQL
│       ├── handlers.rs       # HTTP 핸들러
│       ├── routes.rs         # 라우터 구성
│       ├── state.rs          # AppState, 뷰 타입
│       └── validation.rs     # 프로필 검증
├── cat-agent/                # 에이전트(비콘)
│   ├── Cargo.toml
│   ├── build.rs              # 임베디드 설정
│   └── src/
│       ├── main.rs           # 진입점
│       ├── beacon.rs         # 폴링 루프, 결과 업로드
│       ├── config.rs         # 설정 로드
│       ├── exec.rs           # 명령 실행
│       └── host.rs           # 호스트 정보 수집
├── cat-cli/                  # 운영자 CLI (catctl)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs           # 진입점
│       ├── commands.rs       # REPL 명령 디스패치
│       ├── http.rs           # API 클라이언트
│       ├── output.rs         # 출력 포맷팅
│       ├── build.rs          # build-agent 로직
│       └── types.rs          # API 응답 타입
└── docs/
    └── ARCHITECTURE.md
```

## 구성요소 책임

### cloakcat-protocol (shared)

- **타입**: `RegisterReq`, `RegisterResp`, `Command`, `ResultReq`, `AgentConfig`, `AgentBuildConfig`
- **상수**: `HEALTH_PROFILE_NAME`, `HEALTH_BASE_PATH`, `HEALTH_USER_AGENT`
- **암호화**: `sign_result()`, `verify_result()` (HMAC-SHA256, agent_id+cmd_id+stdout)
- **경로**: `Endpoints::new()` (register, poll, result URL 생성)

### cat-server

- Axum 기반 HTTP API
- PostgreSQL(sqlx) 영속화
- 핸들러: register, poll, result, command, admin
- 프로필 검증 (health_api 경로/User-Agent)
- 상태: `AppState { db: PgPool }` (구조체 기반)

### cat-agent

- 비콘 루프: poll → 실행 → result 업로드
- 설정: embedded + `agent_config.json` / `CLOAKCAT_CONFIG`
- 실행: Windows(cmd) / Unix(shell)
- 호스트 정보: hostname, username, os_version, ip_addrs

### cat-cli (catctl)

- REPL: agents, attack, results, tail, download/upload, recon, tags, build-agent 등
- HTTP 클라이언트 (reqwest blocking)
- 에이전트 식별자 해석 (UUID / alias)

## 디자인 패턴

| 패턴 | 적용 |
|------|------|
| **Layered Architecture** | protocol → server/agent/cli, 의존성 단방향 |
| **Repository** | `db.rs`가 DB 접근 캡슐화 |
| **Handler/Controller** | `handlers.rs`가 HTTP 요청 처리 |
| **Thin Entry Point** | 각 `main.rs`는 초기화 후 모듈 위임 |
| **Struct-based State** | 전역 상태 제거, `AppState` 주입 |

## 의존성

```
cloakcat-protocol  (base)
       │
       ├── cat-server   (axum, sqlx, base64)
       ├── cat-agent   (reqwest, tokio, rand)
       └── cat-cli     (reqwest, rustyline, ctrlc)
```

## 빌드 및 실행

```bash
# 전체 빌드
cargo build --workspace

# 서버 (DATABASE_URL 필요)
cargo run -p cat-server

# 에이전트
cargo run -p cat-agent

# CLI
cargo run -p catctl
```

## 기능 변경 없음

이 아키텍처 개선은 **기능 변경 없이** 구조만 정리했습니다. 프로토콜, 암호화, API, DB 스키마는 동일합니다.
