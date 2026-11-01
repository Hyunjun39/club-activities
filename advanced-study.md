# 동아리 심화 활동 — OpenModel Lab 취약점 분석

- 대상 URL: `https://lockeytest2026page.xo.je/`
- 점검일: 2026-09-30 (Asia/Seoul)
- 점검 유형: 동아리 공격/방어 실습 환경의 외부 동적 점검
- 점검 범위: 공개 페이지, 모델 검색, 게시판, 로그인, 프로필 수정 및 점검용 계정 간 접근제어
- 실습 근거: 사이트의 `CTF MODE 활성화` 배너와 `/post.php?id=2`의 실습 공지를 확인했다.
- 정리 상태: IDOR로 변경한 점검 계정 B의 프로필을 복원했고, XSS 검증용 게시글과 댓글을 삭제했다.

> 판정 기준: 재현 가능한 응답 차이나 서버 상태 변경이 확인되면 `취약`, 충분한 범위를 확인하지 못하면 `미확인`으로 판정했다. `미확인`은 안전을 뜻하지 않는다.

## 1. 점검 요약 (5대 관점 판정표)

| 관점 | 판정(취약/안전/미확인) | 심각도 |
|------|----------------------|--------|
| SQLi | 취약 | High |
| XSS | 취약 | High |
| IDOR/접근제어 | 취약 | High |
| 인증우회 | 미확인 | 평가 불가 |
| 업로드/설정 | 미확인 | 평가 불가 |

## 2. 취약 항목 상세

### [High] 모델 검색 Boolean-based SQL Injection


**위치:** `GET /models.php` — `q` 파라미터

**요약:** 검색어가 SQL 질의에 안전하게 바인딩되지 않아 조건식을 삽입해 결과를 조작할 수 있다.

#### 재현 절차


1. 존재하지 않는 검색어 뒤에 참 조건을 삽입한다.


2. HTTP 200 응답에서 `3개의 모델`을 확인한다.


3. 조건만 거짓으로 변경한다.


4. HTTP 200 응답에서 `0개의 모델`을 확인한다.


**사용 페이로드:**

```text
zz_audit' OR 1=1 OR 'x'='
zz_audit' OR 1=2 OR 'x'='
```


**증거:**

- 참 조건: HTTP 200, `3개의 모델` — `lockey_audit_evidence/sql_true_confirm.json`
- 거짓 조건: HTTP 200, `0개의 모델` — `lockey_audit_evidence/sql_false_confirm.json`
- 정상 검색 `Tiny`: HTTP 200, `1개의 모델` — `lockey_audit_evidence/search_normal.json`
- 작은따옴표와 주석을 포함한 일부 입력은 HTTP 500을 발생시켰다. 핵심 근거는 오류가 아니라 참·거짓 조건의 일관된 결과 차이다.

**영향 & 권고:** 공격자는 검색 질의를 조작할 수 있으며 DBMS와 DB 계정 권한에 따라 데이터 열람 범위가 확대될 수 있다. 문자열 연결을 제거하고 PDO 준비문과 바인딩 파라미터를 사용한다. DB 계정 권한을 최소화하고 상세 SQL 오류를 노출하지 않는다.

### [High] 게시판 댓글 저장형 XSS


**위치:** `POST /comment_add.php`의 `content` → `GET /post.php?id={게시글 ID}` 댓글 본문

**요약:** 댓글 내용이 HTML 이스케이프 없이 저장·출력되어 게시글 열람자의 브라우저에서 JavaScript가 실행될 수 있다.

#### 재현 절차


1. 점검 계정으로 자체 테스트 게시글을 작성한다.


2. 아래 페이로드를 댓글로 등록한다.


3. 로그아웃 상태에서 게시글을 다시 조회한다.


4. 응답에 페이로드가 HTML 요소로 그대로 포함된 것을 확인한다.


5. 점검 후 테스트 게시글과 댓글을 삭제한다.


**사용 페이로드:**

```html
<img src=x onerror="document.title='AUDIT_XSS_0930_CONTROLLED'">
```


**증거:**

- 댓글 등록 응답에 원문 HTML 포함 — `lockey_audit_evidence/xss_comment_created.json`
- 비로그인 공개 조회에도 원문 HTML 포함 — `lockey_audit_evidence/xss_comment_public.json`
- 기존 게시글 `id=13`의 댓글에서도 `<img src=x onerror="document.title='AUDIT_XSS_COMMENT'">`가 이스케이프되지 않음 — `lockey_audit_evidence/post_existing.json`
- 실행 환경에 브라우저 엔진이 없어 DOM 실행 스크린샷은 촬영하지 못했다. 그러나 `img` 요소와 인라인 `onerror` 속성이 응답에 그대로 삽입되는 실행 가능한 sink를 확인했다.

**영향 & 권고:** 공격자는 게시글 열람자의 권한으로 화면 변조나 요청 실행을 유도할 수 있다. 댓글 출력에 문맥별 HTML 인코딩을 적용한다. HTML을 허용해야 한다면 검증된 허용 목록 기반 정화기를 사용하고 인라인 이벤트를 차단하는 CSP를 적용한다.

### [High] 프로필 수정 IDOR / 수평 권한 상승


**위치:** `POST /profile_edit.php` — 숨김 필드 `user_id`

**요약:** 로그인 사용자가 요청의 `user_id`를 바꾸면 다른 사용자의 프로필을 수정할 수 있다.

#### 재현 절차


1. 점검 계정 A와 B를 생성한다. 사용자 ID는 각각 15와 16이었다.


2. 계정 A로 `/profile_edit.php`를 열어 정상 CSRF 토큰을 받는다.


3. A의 세션과 토큰을 유지한 채 `user_id`를 `15`에서 `16`으로 바꾸어 전송한다.


4. 서버의 `프로필을 수정했습니다.` 응답을 확인한다.


5. 계정 B로 로그인해 `AUDIT_IDOR_0930` 값이 반영된 것을 확인한다.


6. 계정 B로 프로필을 원래 값으로 복원한다.


**사용 페이로드:**

```http
POST /profile_edit.php
Content-Type: application/x-www-form-urlencoded

csrf={A의 유효한 토큰}&user_id=16&display_name=Audit+controlled+B+IDOR+verified&email={B의 테스트 이메일}&bio=AUDIT_IDOR_0930
```


**증거:**

- A의 수정 폼에 `user_id=15` 숨김 필드 존재 — `lockey_audit_evidence/profile_edit_form.json`
- `user_id=16` 변경 요청 성공 — `lockey_audit_evidence/idor_profile_request.json`
- B의 마이페이지에서 변경 값 확인 — `lockey_audit_evidence/idor_profile_verified.json`
- 원래 값 복원 — `lockey_audit_evidence/idor_restored.json`
- 비교 결과: 타 계정 게시글 수정은 HTTP 403과 `권한이 없습니다.`로 차단됨 — `lockey_audit_evidence/other_post_edit_form.json`

**영향 & 권고:** 일반 회원이 다른 회원의 표시 이름, 이메일과 소개를 임의 변경할 수 있다. 서버는 요청의 `user_id`를 신뢰하지 말고 세션의 로그인 사용자 ID만 수정 대상으로 사용해야 한다. 관리자 기능은 역할과 대상별 권한을 서버에서 별도로 검사한다.

## 3. 미확인 및 방어 확인 항목

### [미확인] 인증우회


**위치:** `POST /login.php` — `login`, `password`

**수행 내용:** 점검 계정 A의 사용자명과 틀린 비밀번호, 사용자명 뒤에 `' -- `를 붙인 입력을 각각 전송했다.

**결과:** 두 요청 모두 인증되지 않았고 `아이디/이메일 또는 비밀번호가 올바르지 않습니다.`가 반환됐다.

**사용 페이로드:** `{점검 계정 A 사용자명}' -- ` / 의도적으로 틀린 비밀번호

**증거:** `lockey_audit_evidence/wrong_password.json`, `lockey_audit_evidence/login_injection.json`

**판정 사유:** 이 로그인 SQLi 형태는 실패했으나 세션 고정, 비밀번호 재설정 등 전체 인증 흐름을 점검하지 않았다.

**권고:** 비밀번호는 `password_hash`/`password_verify`로 처리하고 로그인 조회에도 준비문을 사용한다. 로그인 성공 시 세션 ID를 재발급하고 속도 제한을 적용한다.

### [미확인] 업로드/설정


**위치:** 공개 내비게이션, 모델·게시판·마이페이지 및 확인한 폼

**수행 내용:** 노출된 기능에서 파일 업로드 폼을 찾지 못했고 추정 경로 `/upload.php`는 HTTP 404였다.

**증거:** `lockey_audit_evidence/protected_upload.json`

**설정 참고:** 세션 쿠키에서 `Secure`, `HttpOnly`, `SameSite=Lax`를 확인했다. 주요 HTML 응답에는 CSP 등 추가 보안 헤더가 없었으나 이것만으로 업로드 취약점을 판정하지 않았다.

**판정 사유:** 실제 업로드 기능이나 관리자 설정 화면을 확인하지 못했다.

**권고:** 업로드 기능이 있다면 확장자와 MIME을 허용 목록으로 검증하고 웹 루트 밖에 임의 파일명으로 저장하며 실행 권한을 제거한다. CSP, `X-Content-Type-Options`, `Referrer-Policy`도 적용한다.

### [확인된 방어] 비로그인 마이페이지 접근 차단


**위치:** `GET /mypage.php`

**결과:** 비로그인 요청은 `/login.php`로 이동하고 `로그인이 필요합니다.`를 표시했다.

**증거:** `lockey_audit_evidence/unauth_mypage.json`

### [확인된 방어] 타인 게시글 수정 차단


**위치:** `GET /post_edit.php?id=14`

**결과:** 게시글 소유자가 아닌 점검 계정 B의 요청에 HTTP 403과 `권한이 없습니다.`가 반환됐다.

**증거:** `lockey_audit_evidence/other_post_edit_form.json`

## 4. 조치 우선순위

1. `/profile_edit.php`가 수정 대상을 세션 사용자로만 결정하도록 고친다.
2. `/models.php`의 검색 SQL을 준비문으로 변경하고 같은 방식의 모든 검색·필터 쿼리를 검토한다.
3. 댓글 본문을 HTML 이스케이프하거나 정화하고 기존 댓글도 출력 시 동일하게 처리한다.
4. 수정 후 동일 페이로드로 회귀 점검한다. SQLi 참·거짓 입력은 같은 정상 결과를 내고, XSS 문자열은 텍스트로 표시되며, 타 계정 `user_id` 요청은 무시되거나 403으로 거절되어야 한다.

## 5. 증거 보관 및 정리

[실습 증거 파일 내려받기](study-evidence.zip)

- 증거 디렉터리: `lockey_audit_evidence/`
- 보고서에는 비밀번호, 세션 쿠키와 CSRF 토큰을 기재하지 않았다. 저장된 주요 응답 기록에서도 해당 값은 `[REDACTED]` 처리했다.
- 정리 완료: 계정 B 프로필 복원, 테스트 게시글 #14와 연결 댓글 삭제
- 남은 테스트 객체: 재검증용 점검 계정 2개
- 제한: 실제 브라우저 스크린샷은 없으며 판정은 HTTP 요청·응답과 서버 상태 변화에 근거한다.