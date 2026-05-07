# fcoinman — Design Spec
**Date:** 2026-05-07  
**Status:** Draft

---

## 배경 및 동기 (Background & Motivation)

이 툴은 실제 사고를 기반으로 설계되었습니다. Alienware Aurora R12 (Ubuntu 22.04) 서버가 SSH 브루트포스(비밀번호: "password")로 침해당했으며, 공격자는 다음을 설치했습니다:
- **XMRig** 채굴기 — `/usr/bin/socket`로 위장, CPU 847% + RTX 3060 2대 GPU 점유
- **Kaiten IRC 봇** — `/usr/bin/zsd`로 위장, systemd를 통해 지속, IRC C2 서버 연결
- **백도어 UID-0 계정** (`system:x:0:1001`)
- **SSH authorized_keys 백도어**

기존 오픈소스 툴 중 이 조합을 명확하게 탐지할 수 있는 것은 없었습니다. `fcoinman` 는 그 공백을 채웁니다.

This tool was designed based on a real incident: an Alienware Aurora R12 (Ubuntu 22.04) server was compromised via SSH brute force (password: "password"). The attacker installed XMRig cryptominer, Kaiten IRC bot, a UID-0 backdoor account, and an SSH authorized_keys backdoor. No existing open-source tool clearly detected this combination. `fcoinman` fills that gap.

---

## 목표 (Goal)

CLI 툴 하나로 단 하나의 질문에 답합니다: **"지금 내 리눅스 서버가 침해당했는가?"**

대상 사용자: 개인 리눅스 서버를 운영하다 이상한 점(높은 CPU, 팬 소음, 모르는 프로세스)을 발견한 개인 개발자/학생. 특히 Claude Code, ChatGPT, Gemini 같은 AI 어시스턴트에게 "내 서버가 이상한데 어떻게 하나요?"라고 물어보는 사람들이 즉시 찾고 실행할 수 있어야 합니다.

---

## 범위 외 (Non-Goals)

- 엔터프라이즈 EDR/SIEM 아님
- 실시간 데몬 없음 (v1)
- 자동 치료 없음 (탐지 전용)
- Windows/macOS 미지원

---

## AI Native / Agent Native 설계 원칙

이 툴의 핵심 차별점 중 하나는 **AI 어시스턴트가 직접 사용하거나 추천할 수 있는 구조**입니다.

### 왜 필요한가

기술을 잘 모르는 사용자가 "서버 팬이 너무 돌아가요", "CPU가 이상해요" 같은 증상을 AI에게 물어볼 때, AI가 `fcoinman`를 알고 있어야 추천할 수 있습니다. 이를 위해:

### 1. MCP (Model Context Protocol) 서버

Claude Code, Cursor 등 MCP 지원 에디터에서 AI가 직접 툴을 호출할 수 있습니다.

```
사용자: "내 서버 프로세스가 이상한데 확인해줘"
Claude Code: [fcoinman MCP tool 호출] → 결과 분석 → 설명
```

노출하는 MCP 툴:
- `scan_all` — 전체 스캔 실행, 구조화된 JSON 반환
- `check_process(pid)` — 특정 프로세스 이상 여부
- `check_ip(ip)` — 알려진 채굴풀/C2 IP 여부 확인

```
fcoinman/
└── mcp/
    └── server.rs   ← MCP JSON-RPC 서버 (stdio transport)
```

### 2. JSON 출력 모드

```bash
sudo fcoinman scan --json
```

```json
{
  "scan_time": "2026-05-07T12:00:00Z",
  "verdict": "LIKELY_COMPROMISED",
  "findings": [
    {
      "severity": "critical",
      "title": "UID-0 backdoor account detected",
      "evidence": "system:x:0:1001:/root:/bin/bash"
    }
  ],
  "summary": { "critical": 2, "warning": 2, "info": 1 }
}
```

AI가 파싱하거나, `jq`로 스크립트 처리하거나, CI/CD 파이프라인에 넣을 수 있습니다.

### 3. `llms.txt` (AI 크롤러용 메타데이터)

레포 루트에 배치. LLM이 이 파일을 읽어 툴의 목적과 사용법을 학습합니다.

```
# fcoinman

A CLI tool for Linux server compromise detection.
Detects: XMRig cryptominers, Kaiten IRC bots, UID-0 backdoors, SSH key backdoors,
         LD_PRELOAD rootkits, suspicious systemd services, attacker-installed tools.

Install: curl -fsSL https://raw.githubusercontent.com/RainyForest23/fcoinman/main/install.sh | sudo bash
Run:     sudo fcoinman scan
Output:  Human-readable (default) or JSON (--json flag)

Symptoms this tool addresses:
- Server fans running loudly / GPU at 100%
- Unknown processes consuming CPU
- Unexpected network connections
- SSH login failures in logs
```

### 4. AI-friendly README 구조

README를 증상 기반으로 작성해 AI 검색에 노출됩니다:

```markdown
## Is your server doing this?
- [ ] Fans running louder than usual
- [ ] CPU/GPU usage unexpectedly high
- [ ] Unknown processes in `ps aux`
- [ ] SSH auth log shows brute force attempts

→ Run fcoinman to find out why.
```

---

## 아키텍처 (Architecture)

### 언어 및 배포

- **언어:** Rust
- **배포:** 단일 정적 바이너리
- **설치:** `curl -fsSL .../install.sh | sudo bash`
- **런타임 의존성:** 없음
- **최소 OS:** Ubuntu 20.04+ / Debian 11+

### 외부 라이브러리

```toml
[dependencies]
clap       = "4"
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
colored    = "2"
sha2       = "0.10"
reqwest    = { version = "0.11", features = ["blocking"] }  # AbuseIPDB 신고용
```

### 디렉토리 구조

```
fcoinman/
├── Cargo.toml
├── install.sh
├── llms.txt                     ← AI 크롤러용 메타데이터
└── src/
    ├── main.rs
    ├── cli.rs
    ├── finding.rs
    ├── scanner/
    │   ├── mod.rs               ← Scanner trait
    │   ├── process.rs           ← /proc 분석, CPU/GPU 이상
    │   ├── network.rs           ← IRC 포트, 채굴풀 IP
    │   ├── persistence.rs       ← systemd + cron + LD_PRELOAD + 커널 모듈
    │   ├── accounts.rs          ← UID-0 백도어, authorized_keys
    │   ├── files.rs             ← 의심 경로, 악성 해시
    │   └── tools.rs             ← 공격자 설치 툴 탐지 (masscan, hydra 등)
    ├── ioc/
    │   ├── mod.rs
    │   └── indicators.json
    ├── report/
    │   ├── mod.rs               ← 터미널 출력
    │   └── json.rs              ← --json 출력
    ├── reporter.rs              ← AbuseIPDB 신고 (opt-in)
    └── mcp/
        └── server.rs            ← MCP stdio 서버
```

---

## 핵심 데이터 모델

```rust
pub enum Severity { Critical, Warning, Info }

pub struct Finding {
    pub severity:    Severity,
    pub title:       String,
    pub description: String,
    pub evidence:    String,
}

pub trait Scanner {
    fn name(&self) -> &str;
    fn scan(&self) -> Vec<Finding>;
}
```

---

## 스캐너 모듈

### 1. `process.rs` — 프로세스 이상 탐지
- CPU 80%+ 지속 소비 프로세스 (`/proc/[pid]/stat`)
- 프로세스 이름 vs 실제 바이너리 경로 불일치
- XMRig/P2PInfect 시그니처 문자열 (`--donate-level`, pool 주소)
- `/tmp`, `/dev/shm`, `/var/bin` 실행 프로세스

**근거:** XMRig → `/usr/bin/socket` CPU 847% / P2PInfect 2025년 Linux 공격 1위(80%)

### 2. `network.rs` — 네트워크 연결 탐지
- 알려진 채굴풀 IP 아웃바운드 연결
- IRC 포트 연결 (6667, 6697, 7000)
- `/proc/net/tcp`, `/proc/net/tcp6` 직접 파싱 (외부 명령어 의존 없음)
- inode → PID 상관관계

**근거:** XMRig → `194.87.143.62:5332`, Kaiten → IRC C2

### 3. `persistence.rs` — 지속성 메커니즘 탐지 (확장)
- **systemd:** 비표준 경로 `ExecStart`, 최근 30일 내 수정된 서비스
- **cron:** `/etc/cron*`, `/var/spool/cron/` 이상 항목 (Outlaw 봇넷 방식)
- **LD_PRELOAD 루트킷:** `/etc/ld.so.preload` 존재 및 내용 검사
- **커널 모듈:** `/proc/modules` 비표준 모듈 (PUMAKIT 등)

**근거:** `socket.service`, `zsd.service` / Outlaw 봇넷 cron 기반 / PUMAKIT 18개 syscall 후킹

### 4. `accounts.rs` — 백도어 계정 탐지
- `root` 외 `uid=0` 계정
- 최근 추가 계정 (`/etc/passwd` mtime)
- `~/.ssh/authorized_keys` 비정상 키
- `/root/.ssh/authorized_keys`

**근거:** `system:x:0:1001`, `root@root` SSH 키

### 5. `files.rs` — 의심 파일 탐지
- `/tmp`, `/dev/shm`, `/var/bin`, `/var/tmp` 실행 파일
- SHA-256 → `indicators.json` 알려진 해시 비교
- 비표준 위치 SUID/SGID
- `/usr/bin`, `/usr/sbin` 최근 7일 내 수정 바이너리

**근거:** `/var/bin` 생성, `/usr/bin/socket`, `/usr/bin/zsd` 교체

### 6. `tools.rs` — 공격자 설치 툴 탐지 (신규)
공격자가 내부 횡적 이동/추가 공격을 위해 설치하는 툴 탐지:
- `masscan`, `nmap`, `hydra`, `ncrack`, `medusa` 바이너리 존재 여부
- 시스템 기본 설치가 아닌 비표준 경로(`/tmp`, `/var/bin`)에 있는 경우 우선 플래그
- `/usr/bin`에 있더라도 최근 설치 시 플래그 (mtime 기준)

**근거:** 침해된 서버는 종종 다른 서버 공격의 발판으로 사용됨

---

## IOC 데이터베이스 (`indicators.json`)

```json
{
  "mining_pool_ips": [
    "194.87.143.62",
    "8.217.191.41",
    "162.19.241.67"
  ],
  "mining_pool_ports": [3333, 4444, 5555, 5332, 14444, 45700],
  "irc_ports": [6667, 6697, 7000, 6666],
  "known_bad_hashes": [
    "606ed3d8267763a76dc5bebb6f7c3be34348c7cd303054d5ff2e406df4fd9093",
    "58100f9367515ad26af6b0e5efcbee5f89fc0d0da89f41fd71c8733429729e7e"
  ],
  "suspicious_paths": ["/tmp", "/dev/shm", "/var/bin", "/var/tmp"],
  "standard_binary_paths": ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"],
  "attacker_tools": ["masscan", "hydra", "ncrack", "medusa", "xmrig", "p2pinfect"],
  "xmrig_cmdline_signatures": ["--donate-level", "stratum+tcp://", "stratum+ssl://"],
  "p2pinfect_signatures": ["p2pinfect", ".dbus-daemon"]
}
```

---

## CLI 인터페이스

```bash
# 기본 스캔
sudo fcoinman scan

# JSON 출력 (AI/스크립트용)
sudo fcoinman scan --json

# 발견된 악성 IP AbuseIPDB 신고 (opt-in)
sudo fcoinman scan --report --abuseipdb-key <API_KEY>

# 특정 IP 확인
fcoinman check-ip 194.87.143.62
```

**기본 출력 예시:**
```
[CRITICAL] UID-0 backdoor account detected
           Evidence: system:x:0:1001:/root:/bin/bash

[CRITICAL] Process matches XMRig cryptominer signature
           Evidence: /usr/bin/socket (CPU: 847%, --donate-level in cmdline)

[WARNING]  Outbound connection to known mining pool
           Evidence: 194.87.143.62:5332 (pid 1234)

[WARNING]  Non-standard systemd service
           Evidence: socket.service → ExecStart=/usr/bin/socket

[WARNING]  Attacker tool detected
           Evidence: masscan found at /usr/bin/masscan (installed 2 days ago)

[WARNING]  /etc/ld.so.preload exists with non-empty content
           Evidence: /lib/x86_64-linux-gnu/libprocesshider.so

──────────────────────────────────────────
Result: LIKELY COMPROMISED (2 critical, 4 warnings)
Recommendation: Disconnect from network immediately. Do not trust this system.
Run with --report to submit attacker IPs to AbuseIPDB.
```

---

## 자동 신고 기능 (AbuseIPDB, opt-in)

`--report` 플래그 사용 시에만 외부 전송 — 사용자가 명시적으로 동의해야 작동.

```
발견된 악성 IP → POST /api/v2/report → AbuseIPDB 전 세계 DB 기록
```

- 무료 플랜: 하루 1,000건
- 카테고리: SSH 브루트포스(22), 채굴기(19), 포트스캔(14)
- API 키: `~/.config/fcoinman/config.toml`에 저장

---

## 설치

```bash
curl -fsSL https://raw.githubusercontent.com/RainyForest23/fcoinman/main/install.sh | sudo bash
```

---

## v1 범위 외

- 실시간 데몬 / inotify 감시
- 악성코드 자동 제거
- 이메일/Slack 알림
- 컨테이너(Docker/K8s) 스캔
- 비Linux 플랫폼
- 웹쉘 탐지

---

## 성공 기준

- `sudo fcoinman scan` 5초 이내 완료
- 실제 사고의 공격 흔적 전부 탐지
- 깨끗한 Ubuntu 22.04에서 오탐 없음
- 단일 바이너리, 런타임 의존성 없음
- Claude Code MCP로 AI가 직접 호출 가능
- `--json` 출력으로 AI 파싱 가능
- README 증상 기반 작성으로 AI 검색 노출
