# file: app/labs/authentication.py

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.labs.base import LabDefinition, LabFormField, LabLevel


RATE_LIMIT_THRESHOLD = 3


DEMO_AUTH_USERS = [
    {
        "username": "alice",
        "password": "alice-password",
        "role": "customer",
        "status": "active",
    },
    {
        "username": "bob",
        "password": "bob-password",
        "role": "customer",
        "status": "active",
    },
    {
        "username": "admin",
        "password": "admin-password",
        "role": "admin",
        "status": "active",
    },
    {
        "username": "suspended_user",
        "password": "suspended-password",
        "role": "customer",
        "status": "suspended",
    },
    {
        "username": "locked_user",
        "password": "locked-password",
        "role": "customer",
        "status": "locked",
    },
]


LOGIN_FIELDS = [
    LabFormField(
        name="username",
        label="Username",
        placeholder="예: alice",
        help_text="실습용 계정: alice, bob, admin, suspended_user, locked_user",
    ),
    LabFormField(
        name="password",
        label="Password",
        field_type="password",
        placeholder="예: alice-password",
        help_text="실습용 비밀번호는 계정명-password 형태입니다. 예: alice-password",
    ),
]


AUTH_LAB = LabDefinition(
    category="authentication",
    lab_id="auth-weak-login",
    title="약한 로그인 검증 흐름",
    summary="로그인 오류 메시지, 비밀번호 검증, 계정 상태, rate limit 설계를 단계별로 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="상세 오류 + plaintext password 비교",
            goal="사용자 존재 여부와 비밀번호 오류를 구분해서 알려주는 문제가 무엇인지 확인합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "존재하지 않는 사용자와 틀린 비밀번호의 응답 차이를 비교하세요.",
                "비밀번호가 hash가 아니라 평문 컬럼과 직접 비교됩니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자 존재 여부와 비밀번호 오류를 구분해서 응답합니다.
# 또한 평문 비밀번호를 직접 비교합니다.

user = find_user(username)

if user is None:
    return "존재하지 않는 사용자입니다."

if password != user.password_plain:
    return "비밀번호가 틀렸습니다."

return "로그인 성공"
""",
            secure_code="""# 안전한 코드
# 비밀번호는 hash로 검증하고, 실패 응답은 일관되게 반환합니다.

user = find_user(username)

if user is None:
    return "아이디 또는 비밀번호가 올바르지 않습니다."

if not check_password_hash(user.password_hash, password):
    return "아이디 또는 비밀번호가 올바르지 않습니다."

return "로그인 성공"
""",
            defense_notes=[
                "사용자 존재 여부를 오류 메시지로 노출하지 않습니다.",
                "비밀번호는 평문으로 저장하거나 비교하지 않습니다.",
                "로그인 실패 응답은 일관되게 반환해야 합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="hash 검증은 하지만 상세 오류 유지",
            goal="password hash를 사용해도 계정 enumeration 문제가 남을 수 있음을 이해합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "비밀번호 검증은 개선되었습니다.",
                "하지만 사용자 존재 여부를 여전히 구분해서 알려줍니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# hash 검증은 하지만 사용자 존재 여부를 상세히 노출합니다.

user = find_user(username)

if user is None:
    return "존재하지 않는 사용자입니다."

if not check_password_hash(user.password_hash, password):
    return "비밀번호가 틀렸습니다."

return "로그인 성공"
""",
            secure_code="""# 안전한 코드
# 실패 이유를 구분하지 않고 같은 메시지를 반환합니다.

if user is None:
    return GENERIC_LOGIN_ERROR

if not check_password_hash(user.password_hash, password):
    return GENERIC_LOGIN_ERROR
""",
            defense_notes=[
                "비밀번호 hash만으로 인증 흐름 전체가 안전해지는 것은 아닙니다.",
                "사용자 존재 여부를 외부 응답에서 구분하지 않습니다.",
                "응답 시간 차이도 줄이는 것이 좋습니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="일관된 오류지만 계정 상태 검증 누락",
            goal="비밀번호가 맞아도 suspended, locked 계정은 로그인되면 안 된다는 점을 확인합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "오류 메시지는 일관됩니다.",
                "하지만 계정 status를 확인하는지 보세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자와 비밀번호는 확인하지만 계정 상태를 확인하지 않습니다.

if user is None:
    return GENERIC_LOGIN_ERROR

if not check_password_hash(user.password_hash, password):
    return GENERIC_LOGIN_ERROR

# user.status가 suspended여도 로그인 성공
return "로그인 성공"
""",
            secure_code="""# 안전한 코드
# 비밀번호 검증 후 계정 상태도 확인합니다.

if user.status != "active":
    return GENERIC_LOGIN_ERROR

return "로그인 성공"
""",
            defense_notes=[
                "인증은 비밀번호 검증만으로 끝나지 않습니다.",
                "suspended, locked, deleted, pending 상태를 명확히 처리해야 합니다.",
                "계정 상태 실패도 외부에는 일반 로그인 실패처럼 응답하는 편이 안전합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="계정 상태는 확인하지만 rate limit 없음",
            goal="비밀번호 검증과 계정 상태 검증이 있어도 무제한 시도 문제가 남는다는 점을 이해합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "suspended_user와 locked_user는 차단됩니다.",
                "하지만 반복 실패 횟수 제한은 있는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 계정 상태까지 확인하지만 실패 횟수 제한이 없습니다.

if not check_password_hash(user.password_hash, password):
    return GENERIC_LOGIN_ERROR

if user.status != "active":
    return GENERIC_LOGIN_ERROR

return "로그인 성공"
""",
            secure_code="""# 안전한 코드
# 실패 횟수를 기록하고 일정 횟수 이상이면 제한합니다.

if user.failed_attempts >= 3:
    return GENERIC_LOGIN_ERROR

if login_failed:
    user.failed_attempts += 1
    return GENERIC_LOGIN_ERROR

user.failed_attempts = 0
return "로그인 성공"
""",
            defense_notes=[
                "로그인 실패 횟수를 기록해야 합니다.",
                "계정 단위와 IP 단위 rate limit을 함께 고려합니다.",
                "운영 환경에서는 지연, CAPTCHA, 알림, 잠금 정책을 조합합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="hash 검증, 계정 상태 검증, 일관된 오류 응답, rate limit을 함께 적용합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "실패 응답은 모두 동일합니다.",
                "3회 이상 실패하면 demo rate limit에 걸립니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# 비밀번호와 상태는 확인하지만 무제한 시도가 가능했습니다.

if not check_password_hash(user.password_hash, password):
    return GENERIC_LOGIN_ERROR
""",
            secure_code="""# 안전한 코드
# 일관된 오류 응답, hash 검증, 상태 검증, 실패 횟수 제한을 함께 적용합니다.

GENERIC_LOGIN_ERROR = "아이디 또는 비밀번호가 올바르지 않습니다."

user = find_user(username)

if user is None:
    return GENERIC_LOGIN_ERROR

if user.failed_attempts >= 3:
    return GENERIC_LOGIN_ERROR

if not check_password_hash(user.password_hash, password):
    user.failed_attempts += 1
    return GENERIC_LOGIN_ERROR

if user.status != "active":
    return GENERIC_LOGIN_ERROR

user.failed_attempts = 0
return "로그인 성공"
""",
            defense_notes=[
                "비밀번호는 안전한 password hashing 함수로 검증합니다.",
                "로그인 실패 응답은 일관되게 반환합니다.",
                "계정 상태를 확인합니다.",
                "실패 횟수 제한을 둡니다.",
                "실제 운영에서는 IP, 계정, 디바이스, ASN 기반 방어도 함께 고려합니다.",
            ],
        ),
    },
)


def ensure_auth_demo_table():
    """
    Authentication 실습용 계정 테이블을 준비합니다.

    실제 서비스 로그인 테이블이 아니라 로컬 교육용 demo table입니다.
    """

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS auth_demo_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_plain TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                last_failed_at TEXT
            )
            """
        )
    )

    count = db.session.execute(
        text("SELECT COUNT(*) FROM auth_demo_users")
    ).scalar_one()

    if count == 0:
        _insert_demo_users()

    db.session.commit()


def reset_auth_demo_table():
    """
    seed 실행 시 인증 demo table을 초기화하기 위한 함수입니다.
    """

    db.session.execute(text("DROP TABLE IF EXISTS auth_demo_users"))
    db.session.flush()
    ensure_auth_demo_table()


def get_lab(lab_id):
    """
    Authentication 카테고리의 Lab을 반환합니다.
    """

    if lab_id == AUTH_LAB.lab_id:
        return AUTH_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 Authentication Lab Level을 실행합니다.
    """

    ensure_auth_demo_table()

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 Authentication Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    username = form.get("username", "").strip()
    password = form.get("password", "")

    if not username or not password:
        return {
            "kind": "authentication",
            "status": "empty",
            "message": "username과 password를 입력하세요.",
            "success": False,
            "client_message": "입력값이 부족합니다.",
            "attempt": None,
            "reasons": [],
            "rows": [],
        }

    return _attempt_login_for_level(level, username, password)


def _insert_demo_users():
    """
    실습용 계정을 삽입합니다.

    password_plain은 취약 단계 설명을 위해 demo table에만 둡니다.
    실제 서비스에서는 저장하면 안 됩니다.
    """

    for user in DEMO_AUTH_USERS:
        db.session.execute(
            text(
                """
                INSERT INTO auth_demo_users
                    (username, password_plain, password_hash, role, status)
                VALUES
                    (:username, :password_plain, :password_hash, :role, :status)
                """
            ),
            {
                "username": user["username"],
                "password_plain": user["password"],
                "password_hash": generate_password_hash(user["password"]),
                "role": user["role"],
                "status": user["status"],
            },
        )


def _attempt_login_for_level(level, username, password):
    """
    Level별 로그인 검증 흐름입니다.
    """

    user = _fetch_user(username)
    reasons = []
    success = False
    client_message = ""

    used_hash_check = False
    used_plaintext_check = False
    used_generic_error = False
    checked_account_status = False
    checked_rate_limit = False

    if level == 1:
        used_plaintext_check = True

        if user is None:
            client_message = "존재하지 않는 사용자입니다."
            reasons.append("Level 1: 사용자 존재 여부를 상세 오류로 노출했습니다.")
        elif password != user["password_plain"]:
            client_message = "비밀번호가 틀렸습니다."
            reasons.append("Level 1: 평문 비밀번호 컬럼과 직접 비교했습니다.")
            _record_failure(username)
        else:
            success = True
            client_message = "로그인 성공"
            reasons.append("Level 1: 로그인에 성공했습니다. 단, plaintext password 비교 구조입니다.")
            _reset_failures(username)

    elif level == 2:
        used_hash_check = True

        if user is None:
            client_message = "존재하지 않는 사용자입니다."
            reasons.append("Level 2: hash 검증은 도입했지만 사용자 존재 여부를 노출합니다.")
        elif not check_password_hash(user["password_hash"], password):
            client_message = "비밀번호가 틀렸습니다."
            reasons.append("Level 2: 비밀번호 오류를 상세 메시지로 노출합니다.")
            _record_failure(username)
        else:
            success = True
            client_message = "로그인 성공"
            reasons.append("Level 2: hash 검증으로 로그인에 성공했습니다.")
            _reset_failures(username)

    elif level == 3:
        used_hash_check = True
        used_generic_error = True

        if user is None:
            client_message = _generic_login_error()
            reasons.append("Level 3: 사용자 없음도 일반 실패 메시지로 응답합니다.")
        elif not check_password_hash(user["password_hash"], password):
            client_message = _generic_login_error()
            reasons.append("Level 3: 비밀번호 오류도 일반 실패 메시지로 응답합니다.")
            _record_failure(username)
        else:
            success = True
            client_message = "로그인 성공"
            reasons.append("Level 3: 비밀번호는 맞지만 계정 상태 검증은 수행하지 않았습니다.")
            _reset_failures(username)

    elif level == 4:
        used_hash_check = True
        used_generic_error = True
        checked_account_status = True

        if user is None:
            client_message = _generic_login_error()
            reasons.append("Level 4: 일반 실패 메시지를 반환했습니다.")
        elif not check_password_hash(user["password_hash"], password):
            client_message = _generic_login_error()
            reasons.append("Level 4: password hash 검증에 실패했습니다.")
            _record_failure(username)
        elif user["status"] != "active":
            client_message = _generic_login_error()
            reasons.append("Level 4: 계정 상태가 active가 아니어서 차단했습니다.")
        else:
            success = True
            client_message = "로그인 성공"
            reasons.append("Level 4: 비밀번호와 계정 상태 검증을 통과했습니다.")
            reasons.append("하지만 실패 횟수 제한은 아직 적용하지 않았습니다.")
            _reset_failures(username)

    else:
        used_hash_check = True
        used_generic_error = True
        checked_account_status = True
        checked_rate_limit = True

        if user is None:
            client_message = _generic_login_error()
            reasons.append("Level 5: 사용자 없음도 일반 실패 메시지로 응답합니다.")

        elif user["failed_attempts"] >= RATE_LIMIT_THRESHOLD:
            client_message = _generic_login_error()
            reasons.append(
                f"Level 5: 실패 횟수가 {RATE_LIMIT_THRESHOLD}회 이상이라 demo rate limit에 걸렸습니다."
            )

        elif not check_password_hash(user["password_hash"], password):
            client_message = _generic_login_error()
            reasons.append("Level 5: password hash 검증에 실패했고 실패 횟수를 증가시켰습니다.")
            _record_failure(username)

        elif user["status"] != "active":
            client_message = _generic_login_error()
            reasons.append("Level 5: 계정 상태가 active가 아니어서 차단했습니다.")

        else:
            success = True
            client_message = "로그인 성공"
            reasons.append("Level 5: hash, status, rate limit 검증을 통과했습니다.")
            _reset_failures(username)

    refreshed_user = _fetch_user(username)

    status = "ok" if success else "blocked"

    return {
        "kind": "authentication",
        "status": status,
        "message": "로그인 검증 흐름을 시뮬레이션했습니다.",
        "success": success,
        "client_message": client_message,
        "attempt": {
            "username": username,
            "user_exists": user is not None,
            "role": user["role"] if user else "(none)",
            "account_status": user["status"] if user else "(none)",
            "failed_attempts": refreshed_user["failed_attempts"] if refreshed_user else 0,
            "used_plaintext_check": used_plaintext_check,
            "used_hash_check": used_hash_check,
            "used_generic_error": used_generic_error,
            "checked_account_status": checked_account_status,
            "checked_rate_limit": checked_rate_limit,
        },
        "reasons": reasons,
        "rows": [],
    }


def _fetch_user(username):
    """
    username으로 demo user를 조회합니다.
    """

    return db.session.execute(
        text(
            """
            SELECT
                id,
                username,
                password_plain,
                password_hash,
                role,
                status,
                failed_attempts,
                last_failed_at
            FROM auth_demo_users
            WHERE username = :username
            """
        ),
        {"username": username},
    ).mappings().first()


def _record_failure(username):
    """
    로그인 실패 횟수를 증가시킵니다.
    """

    try:
        db.session.execute(
            text(
                """
                UPDATE auth_demo_users
                SET
                    failed_attempts = failed_attempts + 1,
                    last_failed_at = :last_failed_at
                WHERE username = :username
                """
            ),
            {
                "username": username,
                "last_failed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        raise


def _reset_failures(username):
    """
    로그인 성공 시 실패 횟수를 초기화합니다.
    """

    try:
        db.session.execute(
            text(
                """
                UPDATE auth_demo_users
                SET
                    failed_attempts = 0,
                    last_failed_at = NULL
                WHERE username = :username
                """
            ),
            {"username": username},
        )
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        raise


def _generic_login_error():
    return "아이디 또는 비밀번호가 올바르지 않습니다."


def _error_result(message):
    return {
        "kind": "authentication",
        "status": "error",
        "message": message,
        "success": False,
        "client_message": "",
        "attempt": None,
        "reasons": [],
        "rows": [],
    }