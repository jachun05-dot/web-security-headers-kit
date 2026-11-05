# web-security-headers-kit (한국어)

어떤 웹사이트에나 붙여 넣어 쓸 수 있는 **HTTP 보안 헤더** 도구 모음이에요.

- **Cloudflare(Pages, Workers), Netlify, Vercel, Nginx, Apache, Express**용 설정 파일을 바로 만들어 줘요.
- 자주 쓰는 외부 서비스(구글 애널리틱스, 애드센스, 구글 폰트, 유튜브, 스트라이프 등)에 맞춰 **콘텐츠 보안 정책(CSP)**을 만들어 줘요.
- 페이지 안의 인라인 `<script>`, `<style>`을 찾아서 **그 내용만 허용(해시)**해 줘요. 그래서 위험한 `'unsafe-inline'`을 쓰지 않아도 돼요.
- 내 사이트 주소를 넣으면 **보안 등급을 매겨 주는 점검 도구**도 들어 있어요.

설치할 다른 패키지는 없어요. Node 18 이상에서 동작하고, MIT 라이선스예요.

## 막아 주는 것과 못 막는 것

보안 헤더는 브라우저에게 "이 페이지에서 위험한 동작은 하지 마"라고 알려 주는 설정이에요. 비용은 거의 들지 않는데 효과가 큰 보호 장치예요.

| 헤더 | 막아 주는 것 |
| --- | --- |
| `Content-Security-Policy` | 몰래 심어진 스크립트(XSS), 모르는 서버로 데이터 전송, 남의 사이트에 내 페이지가 끼워지는 것 |
| `Strict-Transport-Security` | HTTPS를 HTTP로 바꿔치기하는 공격, 공용 와이파이에서 쿠키 탈취 |
| `X-Frame-Options` + `frame-ancestors` | 클릭재킹(내 페이지를 투명하게 덮어 클릭을 훔치는 것) |
| `X-Content-Type-Options` | 업로드된 파일을 브라우저가 스크립트로 착각하는 것 |
| `Referrer-Policy` | 토큰이나 검색어가 담긴 전체 주소가 다른 사이트로 새는 것 |
| `Permissions-Policy` | 카메라, 마이크, 위치 같은 기능을 쓸데없이 쓰는 것 |
| `Cross-Origin-Opener-Policy` / `-Resource-Policy` | 다른 창을 이용한 공격, 다른 사이트가 내 파일을 읽는 것 |

**못 막는 것**도 있어요. 서버 코드의 버그(SQL 인젝션, 로그인·권한 오류), 오래된 라이브러리, 유출된 비밀번호나 키는 헤더로 해결되지 않아요. 맨 아래 [체크리스트](#헤더-밖의-보안-체크리스트)를 함께 봐 주세요.

## 빠른 시작

1. **지금 상태 점검하기**

   ```bash
   node bin/cli.js check https://내-사이트.com
   ```

2. **내 사이트가 쓰는 외부 서비스 확인하기**

   ```bash
   node bin/cli.js services
   ```

3. **내 플랫폼용 설정 만들기 (처음엔 "보고만 하기" 모드로)**

   ```bash
   node bin/cli.js build --format netlify \
     --services google-analytics,google-fonts \
     --hash-from ./public \
     --report-only
   ```

   `--hash-from`은 빌드된 HTML을 훑어서 인라인 스크립트와 스타일을 해시로 허용해요. 인라인 스크립트를 고치면 다시 실행해야 해요.

4. **배포한 뒤 브라우저 개발자 콘솔을 열고 사이트를 둘러보세요.** 보고만 하기 모드는 아무것도 막지 않고, 막혔을 항목을 콘솔에 경고로만 보여줘요. 빠진 것은 `--services`나 `--extra`로 추가하고 다시 만들어요.

5. **경고가 없어지면 `--report-only`를 빼고 다시 배포한 뒤 `check`를 돌려 보세요.** A나 A+가 목표예요.

## 출력 형식

| `--format` | 넣는 곳 |
| --- | --- |
| `netlify` / `cloudflare-pages` | 배포 폴더의 `_headers` 파일 |
| `vercel` | `vercel.json`에 합치기 |
| `nginx` | HTTPS `server { }` 블록 안 |
| `apache` | `.htaccess` 또는 `VirtualHost` (`mod_headers` 필요) |
| `express` | 미들웨어: `app.use(securityHeaders)` |
| `cloudflare-worker` | 사이트 앞에 두는 Worker |
| `json` | 그 밖의 경우에 쓸 헤더 목록 |

바로 쓸 수 있는 예시는 [`examples/`](examples) 폴더에 있어요.

## 주요 옵션

| 옵션 | 뜻 |
| --- | --- |
| `--preset strict` | 기본값. 가장 엄격한 설정이에요. |
| `--preset balanced` | 로그인·결제 팝업을 허용하고, 다른 사이트가 내 이미지를 쓸 수 있게 해요. |
| `--services a,b` | 서비스별로 필요한 주소를 추가해요. |
| `--hash-from <경로>` | 그 HTML의 인라인 스크립트·스타일만 허용해요. |
| `--inline-styles` | `style=""` 같은 인라인 스타일을 허용해요. 위험이 낮고 자주 필요해요. |
| `--extra "img-src=https://cdn.example.com"` | 그 밖에 허용할 주소예요. |
| `--report-only` | 막지 않고 보고만 해요. 처음 일주일 정도 추천해요. |
| `--hsts-preload` | 브라우저의 "HTTPS 전용 목록" 등록용이에요. 아래 주의사항을 꼭 읽어 주세요. |

## 자주 생기는 문제

- **CSP를 켰더니 뭔가 안 돼요.** 브라우저 콘솔에 막힌 주소와 항목이 나와요. 그 주소를 `--extra`로 추가하세요.
- **인라인 스크립트가 막혀요.** 내용이 바뀌어 해시가 달라진 거예요. `--hash-from`으로 다시 만드세요. `onclick="…"` 같은 속성 안의 코드는 해시로 허용할 수 없으니 스크립트 파일로 옮겨야 해요.
- **광고가 안 나와요.** 광고는 여러 주소에서 불러와요. `--services google-adsense`를 쓰고, 한동안은 보고만 하기 모드로 새 주소를 확인하세요.
- **결제나 로그인 팝업이 안 돼요.** `--preset balanced`를 쓰세요.

### HSTS preload 주의

`--hsts-preload`를 켜고 hstspreload.org에 등록하면 브라우저에 "이 도메인은 무조건 HTTPS"로 내장돼요. 그러면 **모든 하위 도메인이 몇 년 동안 HTTPS로 동작해야 하고**, 빼는 데도 몇 달이 걸려요. 확실할 때만 켜세요.

## 헤더 밖의 보안 체크리스트

- [ ] 프레임워크와 라이브러리를 최신으로 유지하기 (`npm audit`, Dependabot)
- [ ] SQL은 항상 매개변수화된 쿼리로 쓰기
- [ ] 사용자가 입력한 내용은 HTML에 넣을 때 이스케이프하고, 서버에서 검증하기
- [ ] 쿠키에 `Secure; HttpOnly; SameSite=Lax`(또는 `Strict`) 붙이기
- [ ] 상태를 바꾸는 요청에는 CSRF 보호 넣기
- [ ] 로그인과 폼에 요청 횟수 제한 걸기, 비밀번호는 Argon2id나 bcrypt로 저장하기
- [ ] 비밀 키는 환경 변수에 두고 저장소에는 절대 올리지 않기
- [ ] 데이터베이스·클라우드 계정은 필요한 권한만 주고, 관리자 계정에는 2단계 인증 켜기
- [ ] 백업을 만들고, 실제로 복원해 보기
- [ ] 문제를 제보받을 수 있게 `/.well-known/security.txt` 두기

## 라이선스

MIT
