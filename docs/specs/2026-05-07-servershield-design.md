# servershield — Design Spec
**Date:** 2026-05-07  
**Status:** Draft

---

## 배경 및 동기 (Background & Motivation)

이 툴은 실제 사고를 기반으로 설계되었습니다. Alienware Aurora R12 (Ubuntu 22.04) 서버가 SSH 브루트포스(비밀번호: "password")로 침해당했으며, 공격자는 다음을 설치했습니다:
- **XMRig** 채굴기 — `/usr/bin/socket`로 위장, CPU 847% + RTX 3060 2대 GPU 점유
- **Kaiten IRC 봇** — `/usr/bin/zsd`로 위장, systemd를 통해 지속, IRC C2 서버 연결
- **백도어 UID-0 계정** (`system:x:0:1001`)
- **SSH authorized_keys 백도어**

기존 오픈소스 툴 중 이 조합을 명확하게 탐지할 수 있는 것은 없었습니다. `servershield`는 그 공백을 채웁니다.

This tool was designed based on a real incident: an Alienware Aurora R12 (Ubuntu 22.04) server was compromised via SSH brute force (password: "password"). The attacker installed:
- **XMRig** cryptominer disguised as `/usr/bin/socket` — consumed 847% CPU + 2x RTX 3060 GPU
- **Kaiten IRC bot** disguised as `/usr/bin/zsd` — persisted via systemd, connected to IRC C2
- **Backdoor UID-0 account** (`system:x:0:1001`)
- **SSH authorized_keys backdoor**

No existing open-source tool would have clearly detected this combination. `servershield` fills that gap.

---

## 목표 (Goal)

CLI 툴 하나로 단 하나의 질문에 답합니다: **"지금 내 리눅스 서버가 침해당했는가?"**

대상 사용자: 개인 리눅스 서버를 운영하다가 이상한 점(높은 CPU, 팬 소음, 모르는 프로세스)을 발견한 개인 개발자/학생.

A CLI tool that answers one question: **"Is my Linux server currently compromised?"**

Target user: individual developers/students who run personal Linux servers and notice something suspicious (high CPU, loud fans, unknown processes).

---

## 범위 외 (Non-Goals)

- 엔터프라이즈 EDR/SIEM 아님
- 실시간 데몬 없음 (v1)
- 자동 치료 없음 (탐지 전용)
- Windows/macOS 미지원

---

## 아키텍처 (Architecture)

### 언어 및 배포 (Language & Distribution)

- **언어:** Rust
- **배포:** 단일 정적 바이너리
- **설치:** `curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash`
- **런타임 의존성:** 없음 (정적 링크)
- **최소 OS:** Ubuntu 20.04+ / Debian 11+ (`/proc` 있는 모든 Linux)

### 외부 라이브러리 (Crate Dependencies)

```toml
[dependencies]
clap    = "4"     # CLI 파싱
serde   = { version = "1", features = ["derive"] }
serde_json = "1"  # IOC DB 파싱
colored = "2"     # 터미널 컬러 출력
sha2    = "0.10"  # 파일 해시 비교
```

### 디렉토리 구조 (Directory Structure)

```
servershield/
├── Cargo.toml
├── install.sh               ← curl 설치 스크립트
└── src/
    ├── main.rs              ← 진입점, 스캐너 오케스트레이션
    ├── cli.rs               ← clap CLI 정의
    ├── finding.rs           ← Finding 구조체, Severity 열거형
    ├── scanner/
    │   ├── mod.rs           ← Scanner trait
    │   ├── process.rs       ← /proc 분석, CPU/GPU 이상 탐지
    │   ├── network.rs       ← IRC 포트, 채굴풀 IP 탐지
    │   ├── persistence.rs   ← systemd 서비스 이상 탐지
    │   ├── accounts.rs      ← UID-0 백도어, authorized_keys
    │   └── files.rs         ← 의심 경로, 알려진 악성 해시
    ├── ioc/
    │   ├── mod.rs           ← IOC 로딩 및 매칭 로직
    │   └── indicators.json  ← 알려진 채굴풀 IP, 악성 해시, IRC 포트
    └── report.rs            ← 컬러 터미널 출력, 심각도 요약
```

---

## 핵심 데이터 모델 (Core Data Model)

```rust
pub enum Severity { Critical, Warning, Info }

pub struct Finding {
    pub severity:    Severity,
    pub title:       String,
    pub description: String,
    pub evidence:    String,  // 실제 발견한 값 (예: "uid=0, name=system")
}
```

```rust
pub trait Scanner {
    fn name(&self) -> &str;
    fn scan(&self) -> Vec<Finding>;
}
```

---

## 스캐너 모듈 (Scanner Modules)

### 1. `process.rs` — 프로세스 이상 탐지
**탐지 항목:**
- CPU 80% 이상 지속 소비 프로세스 (`/proc/[pid]/stat`)
- 프로세스 이름과 실제 바이너리 경로 불일치 (예: `socket`이라는 이름인데 `/bin/socket`이 아님)
- `/proc/[pid]/cmdline`에서 XMRig 시그니처 문자열 (`--donate-level`, 채굴풀 주소)
- 의심 경로에서 실행 중인 프로세스: `/tmp`, `/dev/shm`, `/var/bin`

**실제 사고 근거:** XMRig가 `/usr/bin/socket`으로 위장해 CPU 847% 점유

### 2. `network.rs` — 네트워크 연결 탐지
**탐지 항목:**
- 알려진 채굴풀 IP로의 아웃바운드 연결 (`indicators.json` 기준)
- IRC 포트 연결: 6667, 6697, 7000
- `/proc/net/tcp`, `/proc/net/tcp6` 직접 파싱 (외부 명령어 의존 없음)
- inode → `/proc/[pid]/fd` 매핑으로 연결-프로세스 상관관계 파악

**실제 사고 근거:** XMRig가 `194.87.143.62:5332`, `8.217.191.41:5332`에 연결

### 3. `persistence.rs` — 지속성 메커니즘 탐지
**탐지 항목:**
- `/etc/systemd/system/`, `/lib/systemd/system/`의 모든 `.service` 파일
- `ExecStart` 경로가 비표준인 서비스 (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` 외)
- 최근 30일 내 수정된 서비스 파일
- `/etc/cron*`, `/var/spool/cron/` 크론 항목

**실제 사고 근거:** 공격자가 설치한 `socket.service`, `zsd.service`

### 4. `accounts.rs` — 백도어 계정 탐지
**탐지 항목:**
- `root` 외 `uid=0`인 `/etc/passwd` 항목
- 최근 추가된 계정 (`/etc/passwd` mtime 비교)
- 모든 사용자 `~/.ssh/authorized_keys` — 비정상 코멘트나 출처 불명 키 플래그
- `/root/.ssh/authorized_keys` 집중 검사

**실제 사고 근거:** `system:x:0:1001` UID-0 백도어 계정, `root@root` SSH 키

### 5. `files.rs` — 의심 파일 탐지
**탐지 항목:**
- `/tmp`, `/dev/shm`, `/var/bin`, `/var/tmp`의 실행 가능 파일
- `indicators.json`의 알려진 악성 해시와 SHA-256 비교
- 비표준 위치의 SUID/SGID 바이너리
- `/usr/bin`, `/usr/sbin`에서 최근 7일 내 수정된 바이너리

**실제 사고 근거:** 공격자가 `/var/bin` 생성, `/usr/bin/socket`과 `/usr/bin/zsd` 교체

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
  "standard_binary_paths": ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
}
```

---

## CLI 인터페이스 (CLI Interface)

```
$ sudo servershield scan

Running 5 scanners...

[CRITICAL] UID-0 backdoor account detected
           Evidence: system:x:0:1001:/root:/bin/bash

[CRITICAL] Process matches XMRig cryptominer signature
           Evidence: /usr/bin/socket (CPU: 847%, cmdline contains --donate-level)

[WARNING]  Outbound connection to known mining pool
           Evidence: 194.87.143.62:5332 (pid 1234 → /usr/bin/socket)

[WARNING]  Non-standard systemd service detected
           Evidence: socket.service → ExecStart=/usr/bin/socket

[INFO]     No suspicious authorized_keys entries found

──────────────────────────────────────────
Result: LIKELY COMPROMISED (2 critical, 2 warnings)
Recommendation: Disconnect from network immediately. Do not trust this system.
```

---

## 설치 스크립트 (`install.sh`)

```bash
#!/bin/bash
# 아키텍처 자동 감지 후 GitHub Releases에서 바이너리 다운로드 → /usr/local/bin 배치
```

원라이너:
```bash
curl -fsSL https://raw.githubusercontent.com/RainyForest23/fcoinman/main/install.sh | sudo bash
```

---

## v1 범위 외 (Out of Scope for v1)

- 실시간 데몬 / inotify 감시
- 악성코드 자동 제거
- 이메일/Slack 알림
- 컨테이너(Docker/K8s) 스캔
- 비Linux 플랫폼

---

## 성공 기준 (Success Criteria)

- `sudo servershield scan` 일반 서버에서 5초 이내 완료
- 실제 사고의 5가지 공격 흔적 모두 탐지
- 깨끗한 Ubuntu 22.04에서 오탐(false positive) 없음
- 단일 바이너리, 런타임 의존성 없음
- README에 실제 사고 기반 개발 스토리 포함
