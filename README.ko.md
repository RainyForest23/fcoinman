# fcoinman

**리눅스 서버 침해 탐지 도구** — 실제 사고에서 태어났습니다.

[English](README.md)

---

새벽 3시, 서버 팬이 갑자기 시끄러워졌습니다. 로그인해보니 낯선 프로세스 두 개가 돌고 있었습니다 — `/usr/bin/socket` (CPU 채굴기)과 `/usr/bin/zsd` (IRC 봇). 공격자는 SSH 비밀번호 `password`로 들어와 CPU와 GPU를 전부 채굴에 쓰고 있었습니다.

fcoinman은 그때 있었으면 좋았을 도구입니다. 직접 수동으로 찾아낸 것들, 그리고 그와 함께 나타나는 패턴들을 자동으로 탐지합니다.

```
$ sudo fcoinman scan

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

Results: LIKELY_COMPROMISED — 8 critical, 3 warnings
```

## 탐지 항목

| 분류 | 탐지 내용 |
|---|---|
| **프로세스** | XMRig/P2PInfect 커맨드라인 시그니처, 누적 CPU 과점유, `/tmp`·`/dev/shm`에서 실행 중인 프로세스 |
| **네트워크** | 알려진 채굴 풀 IP 연결, 스트라텀 포트(3333/4444/5332), IRC 포트(6667/6697) |
| **지속성** | 채굴 키워드가 포함된 systemd 서비스, 의심 경로를 실행하는 서비스, 최근 수정된 크론, `/etc/ld.so.preload` 루트킷 |
| **파일** | 알려진 악성코드 SHA-256 해시 매칭, ELF strip 탐지, IOC 문자열 추출, 최근 수정된 `/usr/bin` 바이너리 |
| **계정** | `/etc/passwd`의 UID-0 백도어 계정, SSH `authorized_keys`의 `root@root` 키 |
| **로그** | 비어있는 `auth.log`(증거 인멸), SSH 브루트포스(동일 IP 20회 이상 실패), 공격 타임라인 재구성 |
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

## 사용법

```bash
sudo fcoinman scan               # 전체 스캔 — 7개 탐지기 실행
sudo fcoinman scan --json        # AI 도구·스크립트용 JSON 출력
sudo fcoinman logs               # auth.log 기반 공격 타임라인
sudo fcoinman analyze /usr/bin/socket   # 바이너리 정적 분석
fcoinman check-ip 194.87.143.62  # 알려진 채굴 풀 IP 확인
```

`/proc`, `/etc/passwd`, 로그 접근을 위해 root 권한이 필요합니다. 대부분의 탐지 결과는 root로만 확인 가능합니다.

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
- 평문 출력 — "룰 #4719와 일치" 가 아니라 무엇을 찾았는지 설명
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

## 라이선스

MIT
