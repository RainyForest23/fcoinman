# fcoinman

**리눅스 서버 침해 탐지 도구** — 실제 사고에서 태어났습니다.

[English](README.md)

---

새벽 3시, 서버 팬이 갑자기 시끄러워졌습니다. 로그인해보니 낯선 프로세스 두 개가 돌고 있었습니다 — `/usr/bin/socket` (CPU 채굴기)과 `/usr/bin/zsd` (IRC 봇). 공격자는 SSH 비밀번호 `password`로 들어와 CPU와 GPU를 전부 채굴에 쓰고 있었습니다.

fcoinman은 그때 있었으면 좋았을 도구입니다. 직접 수동으로 찾아낸 것들, 그리고 그와 함께 나타나는 패턴들을 자동으로 탐지합니다.

```
$ sudo fcoinman scan

Scanned at: 2026-05-08 02:21:00 UTC  |  Host: joe-Alienware-Aurora-R12
Running 7 scanners...

[CRITICAL] UID-0 백도어 계정 탐지
           루트가 아닌 계정이 UID 0을 가지면 root 권한 획득 가능
           Evidence: system:x:0:1001::/var/lib/system:/bin/sh

[CRITICAL] Systemd 서비스에서 채굴기 시그니처 탐지
           ExecStart에 채굴 키워드 포함 (stratum, --algo, --donate-level)
           Evidence: /etc/systemd/system/xorg.service: ExecStart=/usr/lib/xorg/Xorg --algo kawpow --server 54.38.240.253:10443 ...

[CRITICAL] 알려진 악성코드 해시 일치
           /usr/bin/socket — SHA-256: 606ed3d826...

[CRITICAL] 로그 파일이 비어있음 — 증거 인멸 가능성
           Evidence: /var/log/auth.log (0 bytes)

Result: LIKELY COMPROMISED  (8 critical, 3 warnings)
```

## 탐지 항목

| 분류 | 탐지 내용 |
|---|---|
| **프로세스** | XMRig/P2PInfect 커맨드라인 시그니처, `/tmp`·`/dev/shm`에서 실행 중인 프로세스, 비표준 경로의 고 CPU 프로세스 |
| **네트워크** | 알려진 채굴 풀 IP 연결, 스트라텀 포트(3333/4444/5332), IRC C2 포트(6667/6697/6666) |
| **지속성** | 채굴 키워드·의심 경로를 포함한 systemd 서비스, 최근 수정된 크론, `/etc/ld.so.preload` 루트킷, 알려진 LKM 루트킷 모듈 탐지 |
| **파일** | 알려진 악성코드 SHA-256 해시 매칭, ELF strip 탐지, IOC 문자열 추출, 최근 수정된 `/usr/bin` 바이너리 |
| **계정** | `/etc/passwd`의 UID-0 백도어 계정, SSH `authorized_keys`의 `root@root` 키 |
| **로그** | 비어있는 `auth.log`(증거 인멸), SSH 브루트포스 요약(동일 IP 20회 이상 실패), 공격 타임라인 재구성 |
| **도구** | 의심 경로의 공격자 도구: `masscan`, `hydra`, `ncrack`, `medusa`, `xmrig` |

## 설치

```bash
curl -fsSL https://raw.githubusercontent.com/RainyForest23/fcoinman/main/install.sh | sudo bash
```

단일 정적 바이너리 (~860KB), 의존성 없음, 런타임 없음.

**수동 설치:**
```bash
# x86_64 Linux
curl -L https://github.com/RainyForest23/fcoinman/releases/latest/download/fcoinman-x86_64-linux -o /usr/local/bin/fcoinman
chmod +x /usr/local/bin/fcoinman
```

**업데이트:**
```bash
sudo fcoinman update
```

## 사용법

```bash
sudo fcoinman scan               # 전체 스캔 — 7개 탐지기 실행
sudo fcoinman scan --json        # AI 도구·스크립트용 JSON 출력
sudo fcoinman logs               # auth.log 기반 공격 타임라인 재구성
sudo fcoinman summary            # 국가·기관 조회 포함 공격자 순위표
sudo fcoinman analyze /usr/bin/socket   # 바이너리 정적 분석
fcoinman check-ip 194.87.143.62  # 알려진 채굴 풀 IP 확인
```

`/proc`, `/etc/passwd`, 로그 접근을 위해 root 권한이 필요합니다. 대부분의 탐지 결과는 root로만 확인 가능합니다.

### `fcoinman summary` 출력 예시

```
[ATTACK SUMMARY] SSH brute force analysis

  Log files : /var/log/auth.log.1 + /var/log/auth.log
  Lines     : 87,148
  Period    : May 10 00:01:03 ~ May 19 16:58:20
  Attackers : 252 unique IPs  |  Total attempts: 26,573 (all blocked)

  [!] Coordinated subnet attacks detected:
      213.209.159.0/24 — 12 IPs, 14,386 attempts (likely botnet)

  Rank   Attempts  IP               Period                              CC     Org
  ────  ─────────  ───────────────  ──────────────────────────────────  ─────  ────────────────────────
     1      1,878  112.216.129.27   May 10 00:08 ~ May 19 09:01         KR     BORANET
     2      1,417  221.156.137.102  May 10 00:21 ~ May 19 09:09         KR     KORNET
     3      1,230  213.209.159.225  May 10 00:01 ~ May 19 09:02         RO     FeoPrestSRL
  ...
```

실제 데이터: 위 결과는 운영 중인 ML 학습 서버(Ubuntu 22.04)에서 실행한 결과입니다. 서버는 침해되지 않았으며, 모든 시도는 차단됐습니다.

## 실제 감염 서버 스캔 결과

아래 스크린샷은 실제 감염된 서버(Alienware Aurora R12, Ubuntu 22.04)에서 직접 실행한 결과입니다. RTX 3060 두 장이 100% GPU 점유 상태였습니다.

**전체 스캔 — CRITICAL 탐지 결과:**

![scan critical findings](docs/screenshots/01-scan-critical-findings.png)

**네트워크 연결 및 로그 증거:**

![network and logs](docs/screenshots/03-scan-network-logs.png)

**바이너리 분석 — `/usr/bin/socket` (XMRig CPU 채굴기)과 `/usr/bin/zsd` (Kaiten IRC 봇):**

![binary analysis](docs/screenshots/06-analyze-binary.png)

**JSON 출력:**

![json output](docs/screenshots/05-scan-json-output.png)

## JSON 출력 형식

AI 어시스턴트, 스크립트, 파이프라인용으로 설계됐습니다:

```json
{
  "verdict": "LIKELY_COMPROMISED",
  "scanned_at": "2026-05-08T02:21:00Z",
  "hostname": "joe-Alienware-Aurora-R12",
  "summary": { "critical": 8, "warning": 3, "info": 12 },
  "findings": [
    {
      "severity": "Critical",
      "title": "UID-0 백도어 계정 탐지",
      "description": "루트가 아닌 계정이 UID 0을 가지면 root 권한 획득 가능",
      "evidence": "system:x:0:1001::/var/lib/system:/bin/sh"
    }
  ]
}
```

Verdict 값: `LIKELY_COMPROMISED` / `SUSPICIOUS` / `CLEAN`

## 이 도구가 기반한 공격 사례

**침입 경로:** SSH 포트 22 브루트포스. 비밀번호가 `password`였습니다.

**공격자가 설치한 것:**

| 바이너리 | 위장 이름 | 역할 |
|---|---|---|
| XMRig (CPU 채굴기) | `/usr/bin/socket` | 스트라텀 풀로 Monero 채굴 |
| GPU 채굴기 (kawpow) | `xorg.service` | RTX 3060 두 장으로 GPU 채굴 |
| Kaiten IRC 봇 | `/usr/bin/zsd` | C2 채널, IRC로 셸 명령 수신 |

**지속성:** systemd의 `socket.service`와 `zsd.service`. 재부팅 후에도 살아남습니다.

**백도어:** `/etc/passwd`에 `system:x:0:1001` 추가 — UID 0이지만 이름이 `root`가 아님. SSH `authorized_keys`에 공격자 키 삽입.

**증거 인멸:** `auth.log` 0바이트로 초기화. fcoinman이 이 패턴을 명시적으로 탐지합니다.

**C2 인프라:** IRC 서버 `d0wn.in` (Njalla 프라이버시 등록). OPER 자격증명 `botlak/botbot122312`가 바이너리 문자열에 그대로 남아있었습니다.

## 왜 또 다른 보안 도구인가

대부분의 리눅스 보안 도구는 엔터프라이즈용으로 설계됐습니다(Wazuh, Falco, OSSEC) — 배포가 복잡하고, 에이전트가 필요하고, 해석하기 어려운 노이즈를 생산합니다. fcoinman은 뭔가 이상하다는 걸 눈치챈 개인 개발자나 학생이 5초 안에 답을 얻기 위한 도구입니다.

- 에이전트 없음, 데몬 없음, 설정 파일 없음
- 바이너리 하나, 명령어 하나
- 평문 출력 — "룰 #4719와 일치"가 아니라 무엇을 찾았는지 설명
- JSON 모드로 AI 어시스턴트에 바로 전달 가능

## 소스 빌드

```bash
# 네이티브 (Linux)
cargo build --release

# Linux x86_64 정적 바이너리 크로스컴파일 (macOS에서)
brew install filosottile/musl-cross/musl-cross
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## IOC 데이터베이스

침해지표(IOC)는 [`src/ioc/indicators.json`](src/ioc/indicators.json)에 있습니다. 새로운 채굴 풀 IP, 악성코드 해시, 공격자 도구 시그니처 추가를 위한 PR을 환영합니다.

## 릴리즈 기록

### v0.1.7 — 2026-05-19
- **신기능:** `fcoinman summary` — 양쪽 auth.log 합산, 시도 횟수 기준 순위표, 서브넷 봇넷 클러스터 탐지, 상위 15개 IP whois 국가·기관 조회

### v0.1.6 — 2026-05-19
- **수정:** `fcoinman logs` 브루트포스 항목에 첫 번째·마지막 발생 시각 표시

### v0.1.5 — 2026-05-19
- **수정:** 스캔 출력 상단에 스캔 시각과 호스트명 표시

### v0.1.4 — 2026-05-19
- **수정:** 커널 모듈 스캐너를 화이트리스트 방식(~80개 INFO 라인 노이즈)에서 알려진 LKM 루트킷 이름 방식(`diamorphine`, `reptile`, `tyton` 등)으로 전환
- **수정:** 고 CPU 경고를 비표준 경로(`/tmp`, `/dev/shm` 등) 프로세스에만 적용 — Xorg, JetBrains, 컴파일러 오탐 제거
- **수정:** Systemd "최근 수정" 검사를 `/etc/systemd/system/`만 검사하도록 변경 (apt가 관리하는 `/lib/systemd/system/` 제외)

### v0.1.3 — 2026-05-19
- **수정:** v0.1.2 변경으로 발생한 미사용 import CI 빌드 실패 수정

### v0.1.2 — 2026-05-19
- **수정:** IOC 문자열 `OPER` 검사를 첫 번째 단어 기준으로 변경 — 그레고리안 성가 소프트웨어 `/usr/bin/gregorio` 내 `imPROPER STYLE` 문자열이 CRITICAL 오탐을 일으키던 버그 수정
- **수정:** SSH 브루트포스 경고를 IP별 개별 출력에서 단일 요약 라인으로 통합

### v0.1.1 — 2026-05-19
- **수정:** Persistence 스캐너 오탐 대폭 감소 — 좁은 표준 바이너리 경로 목록을 의심 경로 검사로 대체, Rust 상수와 JSON의 중복 IOC 로직 통합
- **수정:** Process 스캐너 자기 자신 제외 — fcoinman이 자신의 프로세스를 채굴기로 오탐하는 버그 수정
- **수정:** IRC 포트 목록에서 7000 제거 (frp 기본 포트로 인한 오탐)
- **수정:** SSH 브루트포스 심각도 CRITICAL → WARNING으로 하향 (차단된 시도 = 침해 아님)
- **수정:** `install.sh` 바이너리 자산 이름 수정

### v0.1.0 — 2026-05-08
- 최초 릴리즈
- 7개 스캐너: accounts, persistence, files, process, network, tools, logs
- 정적 바이너리, 의존성 없음
- `verdict`, `scanned_at`, `hostname` 포함 JSON 출력
- `fcoinman logs` 공격 타임라인
- `fcoinman analyze` 바이너리 정적 분석
- GitHub Actions CI + musl 릴리즈 빌드

## 라이선스

MIT
