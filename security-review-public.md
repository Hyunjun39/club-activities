# SECURE MART 보안 스터디 모의해킹 과제

**작성일:** 2026-09-23  
**분류:** Hacking / Security / Web  
**작성자:** Codex (AI 보조 분석)

> 본 문서는 보안 스터디 및 모의해킹 실습을 목적으로 작성되었습니다.  
> 모든 테스트는 사용자가 제공한 소스코드와 사전에 허가받았다고 명시한 환경에서만 진행했습니다.

---

## 1. 점검 개요

### 1.1 점검 대상

- 대상: SECURE MART
- 대상 URL: `https://hxunjxn119.xo.je/?i=2`
- 제공 파일: `shopping_ctf_infinityfree.zip`
- 환경: InfinityFree에 배포된 허가받은 PHP/MySQL 실습 서버
- 점검 기간: 2026-09-23
- 점검 범위: 로그인, 회원가입, 프로필, 게시판 검색, 게시글·댓글, 관리자 기능, 세션 및 HTTP 보안 설정

### 1.2 점검 방식

웹 애플리케이션을 대상으로 다음 방식의 보안 점검을 진행했다.

- **Black-Box:** 공개 페이지 및 인증 경계의 HTTP 요청·응답 차이 분석
- **White-Box:** 제공된 PHP 및 SQL 소스코드 분석
- **검증 원칙:** 데이터 변경과 서비스 장애를 피하고 취약점 확인에 필요한 최소 요청만 수행

호스팅사의 JavaScript 쿠키 검증을 정상 처리한 뒤 애플리케이션에 접근했다. SQL Injection은 데이터 변경이 없는 Boolean 조건 및 합성 행으로 확인했다. 프로필 IDOR 검증을 위해 일반 테스트 계정 1개를 생성했으며, 검증 직후 정상적으로 탈퇴 처리했다. 실제 댓글·게시글·회원 또는 관리자 데이터는 삭제하거나 변경하지 않았다.

### 1.3 주요 점검 결과

| 번호 | 취약점 | 위치 | 위험도 | 확인 방식 |
|---|---|---|---|---|
| 1 | 로그인 SQL Injection 및 인증 우회 | `login.php`, `username` | High | Black-Box + White-Box |
| 2 | 게시판 검색 SQL Injection | `board.php`, `q` | High | Black-Box + White-Box |
| 3 | 프로필 조회 IDOR | `profile.php`, `id` | Medium | Black-Box + White-Box |
| 4 | 댓글 삭제 IDOR | `post.php`, `delete_comment` | Medium | White-Box |
| 5 | 전역적 CSRF 방어 부재 및 GET 상태 변경 | 관리자·계정·게시글·댓글 기능 | High | White-Box |
| 6 | 세션 쿠키 및 HTTP 보안 헤더 미흡 | 전역 HTTP 응답 | Medium | Black-Box + White-Box |

확인된 취약점은 총 **6개**이며, High 3개와 Medium 3개이다.

---

## 2. 취약점 상세

## 2.1 로그인 SQL Injection 및 인증 우회

### 개요

로그인 아이디가 SQL 문자열에 직접 결합된다. 공격자는 `UNION SELECT`로 임의의 사용자 행과 비밀번호 해시를 구성하여 데이터베이스에 계정을 만들지 않고도 인증된 세션을 발급받을 수 있다. 합성 행의 `is_admin` 값도 조작할 수 있어 관리자 권한 획득으로 확대될 가능성이 있다.

### 발견 위치

- 기능: 로그인
- 경로: `/login.php`
- 파라미터: `username`
- 소스 위치: `login.php:9-15`
- 확인 방식: Black-Box + White-Box
- 관련 분류: CWE-89 (SQL Injection), CWE-287 (Improper Authentication)

### 원인

```php
if (VULN_MODE) {
    $sql = "SELECT * FROM users WHERE username = '$username' LIMIT 1";
    try {
        $user = $pdo->query($sql)->fetch();
    } catch (PDOException $e) {
        $user = false;
    }
}

if ($user && password_verify($password, $user['password'])) {
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['is_admin'] = $user['is_admin'];
}
```

`username`에 포함된 따옴표와 SQL 구문이 그대로 해석된다. 또한 조회 결과의 `id`, `password`, `nickname`, `is_admin`을 검증 없이 세션에 복사하므로, 공격자가 합성한 행도 정상 계정처럼 처리된다.

### 검증

실제 서버에서 DB 쓰기가 발생하지 않는 다음 형태의 합성 행을 사용했다. 보고서에는 검증용 bcrypt 값만 생략했다.

```text
username=' UNION SELECT 2147483647,'audit_union','<검증용 bcrypt>',
         'Audit Union',NULL,0,NOW() #
password=<bcrypt와 일치하는 검증용 비밀번호>
```

- 로그인 응답: `HTTP 302`, `Location: index.php`
- 후속 `/index.php` 응답: `HTTP 200`
- 확인 결과: 비로그인 화면에는 없던 `마이페이지`, `프로필`, `로그아웃` 메뉴가 노출됨
- 데이터베이스 변경: 없음
- 정리: 발급된 세션으로 `/logout.php` 요청 후 `HTTP 302` 확인

관리자 데이터 조회나 상태 변경은 수행하지 않았다. 이번 검증은 `is_admin=0`인 합성 사용자로 제한했다. 다만 동일 입력에서 값을 `1`로 바꿀 수 있고 서버가 이 값을 세션에 그대로 저장하므로 관리자 권한 상승 가능성이 코드상 확인된다.

### 영향

- 비밀번호 없이 임의 사용자로 인증 우회
- 세션에 저장되는 사용자 ID 및 닉네임 위조
- `is_admin` 조작을 통한 관리자 기능 접근 가능성
- 다른 취약점과 연계한 회원·게시글 데이터 침해

**위험도:** High

### 대응 방안

취약 모드 분기를 제거하고 모든 환경에서 Prepared Statement를 사용한다. 로그인 직전 사용자 상태를 서버가 신뢰할 수 있는 DB 레코드로부터 다시 검증하는 것이 좋다.

```php
$stmt = $pdo->prepare(
    'SELECT id, username, password, nickname, is_admin
       FROM users
      WHERE username = :username
      LIMIT 1'
);
$stmt->execute(['username' => $username]);
$user = $stmt->fetch();

if ($user && password_verify($password, $user['password'])) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['nickname'] = $user['nickname'];
    $_SESSION['is_admin'] = (int)$user['is_admin'];
    header('Location: index.php');
    exit;
}
```

추가적으로 다음 조치를 적용한다.

- `VULN_MODE` 및 취약 분기를 배포본에서 완전히 제거
- 로그인 시도 횟수 제한과 지연 적용
- 관리자 계정에 다중 인증 적용
- 인증 성공·실패와 관리자 접근에 대한 감사 로그 기록

---

## 2.2 게시판 검색 SQL Injection

### 개요

검색어가 두 개의 `LIKE` 조건에 직접 삽입된다. 공격자는 조건식을 변경해 검색 결과를 조작할 수 있으며, 더 복잡한 구문으로 데이터베이스 정보를 조회할 가능성이 있다.

### 발견 위치

- 기능: 게시판 검색
- 경로: `/board.php`
- 파라미터: `q`
- 소스 위치: `board.php:5-12`
- 확인 방식: Black-Box + White-Box
- 관련 분류: CWE-89 (SQL Injection)

### 원인

```php
if (VULN_MODE) {
    $sql = "SELECT * FROM posts
            WHERE title LIKE '%$q%' OR content LIKE '%$q%'
            ORDER BY id DESC";
    try {
        $posts = $pdo->query($sql)->fetchAll();
    } catch (Exception $e) {
        $posts = [];
    }
}
```

검색어를 SQL 문자열에 직접 연결하며, 예외를 빈 결과로 바꾸기 때문에 문법 오류 역시 응답 차이를 만드는 Oracle로 사용될 수 있다.

### 검증

실제 서버에서 읽기 전용 Boolean 조건으로 확인했다.

| 요청 입력 | HTTP 상태 | 응답 크기 | 게시글 데이터 행 |
|---|---:|---:|---:|
| `q='` | 200 | 933 bytes | 0 |
| `q=' AND 1=1 #` | 200 | 1,080 bytes | 1 |
| `q=' AND 1=2 #` | 200 | 943 bytes | 0 |

참·거짓 조건에 따라 동일 검색 기능의 결과가 달라졌으며, 소스의 문자열 결합 구문과 일치했다. 데이터 추출, 시간 지연, 파일 접근 또는 데이터 변경 페이로드는 사용하지 않았다.

### 영향

- 게시글 외 데이터의 비인가 조회 가능성
- 사용자 계정 및 비밀번호 해시 노출 가능성
- DB 권한에 따라 데이터 변조·삭제로 확대될 가능성
- Blind SQL Injection을 통한 스키마 및 데이터 추론

**위험도:** High

### 대응 방안

```php
$q = trim($_GET['q'] ?? '');
$like = '%' . $q . '%';

$stmt = $pdo->prepare(
    'SELECT id, author_id, author_name, title, content, views, created_at
       FROM posts
      WHERE title LIKE :title OR content LIKE :content
      ORDER BY id DESC'
);
$stmt->execute([
    'title' => $like,
    'content' => $like,
]);
$posts = $stmt->fetchAll();
```

추가적으로 DB 계정에는 애플리케이션에 필요한 최소 권한만 부여하고, SQL 예외 상세는 사용자에게 반환하지 않도록 한다.

---

## 2.3 프로필 조회 IDOR

### 개요

로그인 사용자가 URL의 `id` 값을 바꾸면 다른 사용자의 프로필을 조회할 수 있다. 객체 소유권 또는 공개 범위에 대한 서버 측 인가가 없다.

### 발견 위치

- 기능: 프로필 조회
- 경로: `/profile.php`
- 파라미터: `id`
- 소스 위치: `profile.php:5`, `profile.php:16-23`
- 확인 방식: Black-Box + White-Box
- 관련 분류: CWE-639 (Authorization Bypass Through User-Controlled Key)

### 원인

```php
$id = (int)($_GET['id'] ?? $_SESSION['user_id']);

if (VULN_MODE) {
    $stmt = $pdo->prepare(
        'SELECT id,username,nickname,bio,created_at FROM users WHERE id=?'
    );
    $stmt->execute([$id]);
}
```

로그인 여부만 확인하며 요청한 `id`가 현재 사용자 ID인지, 또는 요청자가 해당 프로필을 볼 권한이 있는지 확인하지 않는다.

### 검증

- 테스트 계정: `codex_audit_20260923_0538`
- 본인 프로필: `/profile.php` → 테스트 계정의 닉네임·아이디·가입일 표시
- 타인 프로필: `/profile.php?id=1` → 초기 관리자 프로필의 닉네임·아이디·가입일 표시
- 두 요청 모두 `HTTP 200`
- 검증 직후 `/delete_account.php`에 정상 POST를 보내 테스트 계정 삭제 완료(`HTTP 302`)
- 정리 검증: 삭제한 자격증명으로 다시 로그인했을 때 `HTTP 200`과 `로그인 정보가 올바르지 않습니다.`가 반환되어 계정 삭제를 재확인

초기 설치 데이터인 관리자 프로필 외의 사용자 ID는 열거하지 않았다.

### 영향

- 사용자 아이디, 닉네임, 자기소개, 가입일의 비인가 조회
- 연속 ID 열거를 통한 회원 목록 수집
- 피싱·계정 공격을 위한 사용자 정보 확보

**위험도:** Medium

### 대응 방안

프로필이 비공개 기능이라면 클라이언트가 전달한 사용자 ID를 사용하지 말고 세션의 ID만 사용한다.

```php
require_login();

$stmt = $pdo->prepare(
    'SELECT id, username, nickname, bio, created_at
       FROM users
      WHERE id = ?'
);
$stmt->execute([(int)$_SESSION['user_id']]);
$user = $stmt->fetch();
```

공개 프로필이 필요한 경우에는 공개 여부 컬럼과 차단 관계 등을 별도로 두고, 반환 필드를 최소화하며 서버 측 정책으로 접근을 허용해야 한다.

---

## 2.4 댓글 삭제 IDOR

### 개요

로그인 사용자는 자신의 댓글뿐 아니라 임의의 댓글 ID를 지정해 다른 사용자의 댓글도 삭제할 수 있다. 삭제 링크도 모든 로그인 사용자에게 표시된다.

### 발견 위치

- 기능: 댓글 삭제
- 경로: `/post.php`
- 파라미터: `delete_comment`
- 소스 위치: `post.php:15-23`, `post.php:51`
- 확인 방식: White-Box
- 관련 분류: CWE-639, CWE-862 (Missing Authorization)

### 원인

```php
if (isset($_GET['delete_comment']) && is_logged_in()) {
    $cid = (int)$_GET['delete_comment'];
    if (VULN_MODE) {
        $pdo->prepare('DELETE FROM comments WHERE id=?')->execute([$cid]);
    }
    header('Location: post.php?id='.$id);
    exit;
}
```

로그인 여부만 확인하고 댓글의 `user_id`와 세션의 `user_id`를 비교하지 않는다. 또한 상태 변경을 GET 요청으로 처리한다.

### 검증

제공 소스에서 삭제 쿼리와 누락된 소유권 조건을 확인했다. 실제 서버의 타인 댓글을 삭제하는 행위는 데이터 무결성에 영향을 주므로 수행하지 않았다.

### 영향

- 다른 사용자의 댓글 무단 삭제
- 게시판 기록 훼손 및 사용자 간 분쟁 유발
- CSRF와 결합한 자동 삭제 공격

**위험도:** Medium

### 대응 방안

삭제는 POST로만 처리하고, 댓글 작성자 또는 관리자임을 서버에서 검증한다.

```php
require_login();
verify_csrf_token($_POST['csrf_token'] ?? '');

$cid = filter_input(INPUT_POST, 'comment_id', FILTER_VALIDATE_INT);
$stmt = $pdo->prepare('SELECT user_id FROM comments WHERE id = ?');
$stmt->execute([$cid]);
$comment = $stmt->fetch();

if (!$comment ||
    ((int)$comment['user_id'] !== (int)$_SESSION['user_id'] && !is_admin())) {
    http_response_code(403);
    exit('삭제 권한이 없습니다.');
}

$pdo->prepare('DELETE FROM comments WHERE id = ?')->execute([$cid]);
```

---

## 2.5 전역적 CSRF 방어 부재 및 GET 상태 변경

### 개요

상태를 변경하는 폼과 링크에 CSRF 토큰 검증이 없다. 특히 관리자 회원·게시글 삭제, 댓글 삭제, 게시글 삭제 및 로그아웃이 GET 요청으로 실행되어 외부 링크나 이미지 요청만으로도 동작할 수 있다.

### 발견 위치

- 관리자 회원·게시글 삭제: `/admin.php?delete_user=...`, `/admin.php?delete_post=...`
- 댓글 삭제: `/post.php?id=...&delete_comment=...`
- 게시글 삭제: `/post_delete.php?id=...`
- 로그아웃: `/logout.php`
- 토큰 없는 POST: 프로필 수정, 게시글 작성·수정, 댓글 작성, 회원 탈퇴
- 확인 방식: White-Box
- 관련 분류: CWE-352 (Cross-Site Request Forgery)

### 원인

```php
// admin.php
if (isset($_GET['delete_user'])) {
    $uid = (int)$_GET['delete_user'];
    $pdo->prepare('DELETE FROM users WHERE id=?')->execute([$uid]);
}

// delete_account.php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pdo->prepare('DELETE FROM users WHERE id = ?')
        ->execute([$_SESSION['user_id']]);
}
```

요청 출처를 검증할 무작위 토큰이 없고, 일부 중요 동작은 안전한 조회 메서드인 GET에 연결되어 있다. 브라우저의 기본 `SameSite=Lax` 동작에만 기대더라도 최상위 GET 이동은 차단되지 않으므로 충분한 방어가 아니다.

### 검증

모든 상태 변경 코드와 폼을 정적으로 점검했으며 `csrf`, `token` 또는 동등한 난수 검증 로직이 없음을 확인했다. 실제 회원·게시글·댓글에 대한 교차 사이트 삭제 요청은 수행하지 않았다.

### 영향

- 로그인 사용자의 프로필·게시글·댓글 무단 변경
- 관리자 권한으로 회원 또는 게시글 삭제
- 사용자 계정 탈퇴 유도
- 강제 로그아웃

**위험도:** High

### 대응 방안

세션별 CSRF 토큰을 생성해 모든 상태 변경 POST 요청에서 상수 시간 비교로 검증한다. GET은 조회에만 사용한다.

```php
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(string $token): void {
    if (empty($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        exit('잘못된 요청입니다.');
    }
}
```

```php
<form method="post" action="admin.php">
  <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
  <input type="hidden" name="action" value="delete_user">
  <input type="hidden" name="user_id" value="<?= e($u['id']) ?>">
  <button type="submit">삭제</button>
</form>
```

추가적으로 `Origin` 또는 `Referer` 검증을 보조 방어로 적용하고, 세션 쿠키에는 명시적인 `SameSite` 속성을 설정한다.

---

## 2.6 세션 쿠키 및 HTTP 보안 헤더 미흡

### 개요

실제 서버가 발급한 `PHPSESSID` 쿠키에 `Secure`, `HttpOnly`, `SameSite` 속성이 없었다. 또한 대표 응답에 HSTS, CSP, `X-Content-Type-Options` 및 클릭재킹 방어 헤더가 없었다.

### 발견 위치

- 기능: 전역 세션 및 HTTP 응답
- 경로: `/`, `/login.php` 등
- 소스 위치: `config.php:11`
- 확인 방식: Black-Box + White-Box
- 관련 분류: CWE-614, CWE-1004, CWE-693

### 원인 및 검증

소스는 쿠키 보안 옵션 설정 없이 바로 세션을 시작한다.

```php
session_start();
```

실제 서버 응답은 다음 형태였다. 세션 값은 보고서에서 제거했다.

```http
Set-Cookie: PHPSESSID=<redacted>; expires=...; Max-Age=86400; path=/
```

관찰된 응답에는 `Secure`, `HttpOnly`, `SameSite`가 없었고, `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`도 없었다.

### 영향

- 비암호화 연결이 허용될 경우 세션 쿠키 노출 가능성
- 향후 XSS 발생 시 JavaScript를 통한 세션 쿠키 탈취 가능성 증가
- CSRF 및 클릭재킹 방어 심층성 저하
- MIME 스니핑과 콘텐츠 주입 공격의 영향 확대 가능성

**위험도:** Medium

### 대응 방안

`session_start()` 전에 쿠키 옵션과 strict mode를 설정한다.

```php
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
```

웹 서버 또는 공통 PHP 진입점에서 다음 정책을 서비스 특성에 맞게 적용한다.

```php
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
```

HSTS는 모든 하위 도메인이 HTTPS를 지원하는지 확인한 뒤 적용해야 한다.

---

## 3. 취약점 요약

| 취약점 | 위치 | 위험도 | 주요 영향 | 조치 상태 |
|---|---|---|---|---|
| 로그인 SQL Injection 및 인증 우회 | `login.php` | High | 임의 인증 및 관리자 권한 상승 가능 | 미조치 |
| 게시판 검색 SQL Injection | `board.php` | High | DB 정보 유출·변조 가능 | 미조치 |
| 프로필 조회 IDOR | `profile.php` | Medium | 다른 회원 프로필 열람 | 미조치 |
| 댓글 삭제 IDOR | `post.php` | Medium | 타인 댓글 무단 삭제 | 미조치 |
| CSRF 방어 부재 | 상태 변경 기능 전반 | High | 관리자·사용자 권한으로 데이터 변경·삭제 | 미조치 |
| 세션 쿠키·보안 헤더 미흡 | 전역 | Medium | 세션 및 브라우저 방어 약화 | 미조치 |

### 추가 관찰사항

- `config.php`의 `VULN_MODE`가 `true`이고 실제 로그인 화면도 취약 모드 활성화를 안내한다. 운영 배포 시 단순히 플래그만 바꾸는 방식보다 취약 코드 자체를 제거해야 한다.
- `README.txt`와 `install.sql`에 초기 관리자 아이디 및 비밀번호가 평문으로 기재되어 있다. 다만 실제 서버에서 문서상 비밀번호와 제공 해시에서 추정 가능한 후보를 각각 1회만 확인했으며 둘 다 로그인에 실패했다. 따라서 현재 서버의 기본 관리자 비밀번호 취약점은 확인되지 않았다.
- `install.sql`의 주석에 적힌 비밀번호와 저장된 bcrypt 해시가 일치하지 않아 초기 설치 후 관리자 접근 장애가 발생할 수 있다. 초기 관리자 비밀번호를 코드·문서에 고정하지 말고 설치 시 일회성 난수로 생성한 뒤 최초 로그인에서 변경하도록 해야 한다.
- PHP 파일 전체에 대해 `php -l` 구문 검사를 수행했으며 구문 오류는 발견되지 않았다.
- 사용자 출력에는 대체로 `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`가 적용되어 이번 범위에서는 반사·저장 XSS를 확인하지 못했다.
- 게시글 수정·삭제는 작성자 또는 관리자 검사를 수행하여 해당 기능에서는 직접적인 IDOR을 확인하지 못했다.

---

## 4. 공통 개선 사항

점검 결과를 바탕으로 다음과 같은 보안 개선이 필요하다.

- 사용자 입력값을 SQL에 결합하지 않고 모든 쿼리에 Prepared Statement 사용
- `VULN_MODE`와 의도적으로 취약한 코드 경로를 배포본에서 완전히 제거
- 서버 측 인증 및 객체 단위 권한 검증을 공통 함수 또는 정책 계층으로 통합
- 모든 상태 변경을 POST로 제한하고 CSRF 토큰 검증 적용
- 세션 쿠키에 `Secure`, `HttpOnly`, `SameSite` 설정
- CSP, HSTS, `X-Content-Type-Options` 등 보안 헤더 적용
- 관리자 기본 자격증명 제거 및 다중 인증·로그인 제한 적용
- DB 계정 최소 권한 적용 및 인증·권한·관리자 동작 감사 로그 기록
- 오류 메시지와 예외 상세를 사용자에게 노출하지 않고 서버 로그에만 기록
- 수정 후 동일 테스트 케이스로 회귀 테스트 수행

권장 조치 우선순위는 다음과 같다.

1. 로그인 및 검색 SQL Injection 제거
2. CSRF 방어 적용과 모든 삭제 기능의 POST 전환
3. 프로필·댓글의 객체 단위 인가 적용
4. 세션 쿠키 및 HTTP 보안 헤더 강화
5. 배포·초기 계정·감사 로그 정책 정비

---

## 5. 결론

이번 점검에서는 총 **6개의 취약점**을 확인했다.

| 취약점 | 위험도 |
|---|---|
| 로그인 SQL Injection 및 인증 우회 | High |
| 게시판 검색 SQL Injection | High |
| 프로필 조회 IDOR | Medium |
| 댓글 삭제 IDOR | Medium |
| 전역적 CSRF 방어 부재 | High |
| 세션 쿠키 및 HTTP 보안 헤더 미흡 | Medium |

가장 시급한 문제는 **로그인 SQL Injection**이다. 실제 서버에서 데이터베이스에 계정을 생성하지 않고도 합성 사용자로 인증된 세션을 발급받을 수 있었으며, 소스 구조상 관리자 권한 값까지 제어할 수 있다. 게시판 검색 SQL Injection과 결합하면 기밀성·무결성·권한 통제 전반에 큰 영향을 줄 수 있으므로 우선 수정해야 한다.

SQL Injection을 제거한 뒤에는 CSRF와 객체 단위 접근통제를 함께 보완해야 한다. 개별 취약 코드만 수정하는 데 그치지 않고 인증·인가, 입력 처리, 상태 변경 요청, 세션 보호를 공통 보안 계층으로 구성하는 것이 필요하다.

---

## 6. 참고

### 테스트 원칙 및 정리 결과

- 허가된 환경에서만 테스트 수행
- 데이터 변경 없는 요청을 우선 사용
- 시간 지연, 대량 열거, 자동화 스캔 및 서비스 가용성에 영향을 주는 테스트 미수행
- 실제 게시글·댓글·회원·관리자 데이터 변경 또는 삭제 미수행
- IDOR 검증용 일반 계정 1개 생성 후 즉시 탈퇴 완료
- SQL Injection 인증 우회 세션 검증 후 즉시 로그아웃 완료
- 초기 관리자 비밀번호는 소스에 근거한 후보 2개만 각각 1회 확인하고 중단

### 참고 자료

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
