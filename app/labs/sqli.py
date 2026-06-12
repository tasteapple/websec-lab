# file: app/labs/sqli.py

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.labs.base import LabDefinition, LabFormField, LabLevel


DEMO_USERS = [
    {
        "username": "lab_admin",
        "password": "admin-lab-pass",
        "email": "lab.admin@example.test",
        "role": "admin",
    },
    {
        "username": "alice",
        "password": "alice-lab-pass",
        "email": "alice@example.test",
        "role": "customer",
    },
    {
        "username": "bob",
        "password": "bob-lab-pass",
        "email": "bob@example.test",
        "role": "customer",
    },
    {
        "username": "support_lee",
        "password": "support-lab-pass",
        "email": "support.lee@example.test",
        "role": "support",
    },
]


def ensure_sqli_demo_table():
    """
    SQL Injection 실습 전용 테이블을 준비합니다.

    핵심 users 테이블에는 안전한 password_hash만 저장합니다.
    반면 이 테이블은 SQL Injection 교육을 위해 격리된 raw password 데이터를 사용합니다.

    실제 서비스에서 raw password 컬럼을 두면 안 됩니다.
    """

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS sqli_demo_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
    )

    count = db.session.execute(
        text("SELECT COUNT(*) FROM sqli_demo_users")
    ).scalar_one()

    if count == 0:
        for user in DEMO_USERS:
            db.session.execute(
                text(
                    """
                    INSERT INTO sqli_demo_users
                        (username, password, email, role)
                    VALUES
                        (:username, :password, :email, :role)
                    """
                ),
                user,
            )

    db.session.commit()


def reset_sqli_demo_table():
    """
    /admin/seed에서 호출할 수 있는 초기화 함수입니다.

    ORM 모델이 아닌 raw SQL 실습용 테이블이므로 별도로 정리합니다.
    """

    db.session.execute(text("DROP TABLE IF EXISTS sqli_demo_users"))
    db.session.flush()
    ensure_sqli_demo_table()


LOGIN_FIELDS = [
    LabFormField(
        name="username",
        label="Username",
        placeholder="예: alice",
        help_text="로컬 교육용 sqli_demo_users 테이블에서 조회합니다.",
    ),
    LabFormField(
        name="password",
        label="Password",
        field_type="password",
        placeholder="예: alice-lab-pass",
        help_text="이 필드는 SQL Injection 구조를 보여주기 위한 교육용 raw password입니다.",
    ),
]


LOGIN_AND_LOOKUP_FIELDS = [
    *LOGIN_FIELDS,
    LabFormField(
        name="lookup_id",
        label="Lookup user id",
        field_type="number",
        placeholder="예: 1",
        help_text="Level 4에서는 로그인은 안전하지만 사용자 조회가 취약한 상태를 보여줍니다.",
    ),
]


SQLI_LOGIN_BYPASS = LabDefinition(
    category="sqli",
    lab_id="sqli-login-bypass",
    title="로그인 우회",
    summary="로그인 쿼리를 문자열로 조립했을 때 생기는 문제와 파라미터 바인딩의 필요성을 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="완전히 취약한 로그인 쿼리",
            goal="사용자 입력을 그대로 SQL 문자열에 붙이면 쿼리 구조가 변할 수 있음을 확인합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "입력값이 SQL 문자열 안에 그대로 들어가는지 확인하세요.",
                "개발자가 보기 편한 문자열 포맷팅은 SQL에서는 위험할 수 있습니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자 입력을 SQL 문자열에 그대로 붙이고 있습니다.

sql = (
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    f"WHERE username = '{username}' "
    f"AND password = '{password}'"
)

rows = db.session.execute(text(sql)).mappings().all()
""",
            secure_code="""# 안전한 코드
# SQL 구조와 사용자 입력을 분리하기 위해 파라미터 바인딩을 사용합니다.

stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE username = :username "
    "AND password = :password"
)

rows = db.session.execute(
    stmt,
    {
        "username": username,
        "password": password,
    },
).mappings().all()
""",
            defense_notes=[
                "SQL 문자열 안에 사용자 입력을 직접 넣지 않습니다.",
                "쿼리 구조는 고정하고 값은 파라미터로 전달합니다.",
                "실제 인증 시스템에서는 raw password가 아니라 password hash 검증을 사용해야 합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="블랙리스트 기반 필터링",
            goal="일부 문자만 차단하는 방식이 왜 방어로 부족한지 이해합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "차단 목록이 늘어나도 SQL 문법 전체를 안전하게 다루기는 어렵습니다.",
                "필터링은 보조 수단일 수 있지만 SQL Injection의 핵심 방어는 아닙니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 일부 위험해 보이는 문자열만 차단합니다.
# 하지만 여전히 SQL 문자열 조립 방식은 그대로 남아 있습니다.

blocked = ["'", '"', "--", ";"]

if any(token in username for token in blocked):
    raise ValueError("blocked input")

if any(token in password for token in blocked):
    raise ValueError("blocked input")

sql = (
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    f"WHERE username = '{username}' "
    f"AND password = '{password}'"
)

rows = db.session.execute(text(sql)).mappings().all()
""",
            secure_code="""# 안전한 코드
# 특정 문자를 맞춰 차단하려고 하지 말고,
# DB 드라이버의 파라미터 바인딩을 사용합니다.

stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE username = :username "
    "AND password = :password"
)

rows = db.session.execute(
    stmt,
    {
        "username": username,
        "password": password,
    },
).mappings().all()
""",
            defense_notes=[
                "블랙리스트는 누락과 우회 가능성이 큽니다.",
                "입력값 검증은 형식 제한에 사용하고, SQL Injection 방어는 파라미터 바인딩으로 처리합니다.",
                "차단 문자 목록을 보안의 중심으로 삼지 않습니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="일부 파라미터만 바인딩",
            goal="한쪽 입력만 안전하게 처리해도 나머지 입력이 취약하면 전체 쿼리가 위험함을 확인합니다.",
            form_fields=LOGIN_FIELDS,
            hints=[
                "username은 안전해 보여도 password가 문자열로 붙고 있습니다.",
                "모든 사용자 입력에 같은 기준을 적용해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# username은 파라미터 바인딩을 사용하지만,
# password는 여전히 문자열로 조립하고 있습니다.

stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE username = :username "
    f"AND password = '{password}'"
)

rows = db.session.execute(
    stmt,
    {"username": username},
).mappings().all()
""",
            secure_code="""# 안전한 코드
# 모든 외부 입력을 파라미터로 전달합니다.

stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE username = :username "
    "AND password = :password"
)

rows = db.session.execute(
    stmt,
    {
        "username": username,
        "password": password,
    },
).mappings().all()
""",
            defense_notes=[
                "일부 파라미터만 안전하게 처리하는 것은 충분하지 않습니다.",
                "쿼리 안에 들어가는 모든 외부 입력은 바인딩해야 합니다.",
                "리팩터링 중 일부만 고친 상태가 실무에서 자주 발생합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="로그인은 안전하지만 조회 기능이 취약",
            goal="핵심 로그인은 고쳤지만 주변 기능 하나가 취약하면 여전히 문제가 남는다는 점을 이해합니다.",
            form_fields=LOGIN_AND_LOOKUP_FIELDS,
            hints=[
                "로그인 쿼리는 안전하게 바뀌었습니다.",
                "하지만 사용자 ID 조회 쿼리는 어떤 방식으로 만들어지는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 로그인 쿼리는 안전합니다.

login_stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE username = :username "
    "AND password = :password"
)

login_rows = db.session.execute(
    login_stmt,
    {
        "username": username,
        "password": password,
    },
).mappings().all()

# 하지만 부가 조회 기능에서 다시 문자열 조립을 사용합니다.

lookup_sql = (
    "SELECT id, username, email, role "
    f"FROM sqli_demo_users WHERE id = {lookup_id}"
)

lookup_rows = db.session.execute(text(lookup_sql)).mappings().all()
""",
            secure_code="""# 안전한 코드
# 로그인과 부가 조회 기능 모두 파라미터 바인딩을 사용합니다.
# 숫자 ID는 정수 변환으로 형식도 제한합니다.

safe_lookup_id = int(lookup_id)

lookup_stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE id = :user_id"
)

lookup_rows = db.session.execute(
    lookup_stmt,
    {"user_id": safe_lookup_id},
).mappings().all()
""",
            defense_notes=[
                "핵심 기능만 안전하게 고쳐서는 충분하지 않습니다.",
                "같은 요청 안의 보조 기능, 디버그 조회, 관리자 편의 기능도 검토해야 합니다.",
                "숫자 입력은 정수 변환과 파라미터 바인딩을 함께 적용합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="모든 쿼리에 파라미터 바인딩을 적용하고, 입력 형식을 명확히 제한합니다.",
            form_fields=LOGIN_AND_LOOKUP_FIELDS,
            hints=[
                "SQL 문장과 사용자 입력이 분리되어 있습니다.",
                "숫자 입력은 정수로 변환한 뒤 파라미터로 전달합니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# 일부 기능은 안전하지만, 주변 조회 기능에서 문자열 조립이 남아 있었습니다.

lookup_sql = (
    "SELECT id, username, email, role "
    f"FROM sqli_demo_users WHERE id = {lookup_id}"
)
""",
            secure_code="""# 안전한 코드
# 모든 사용자 입력은 파라미터로 전달합니다.
# 숫자 입력은 먼저 정수로 변환해 허용되는 형식을 제한합니다.

login_stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE username = :username "
    "AND password = :password"
)

login_rows = db.session.execute(
    login_stmt,
    {
        "username": username,
        "password": password,
    },
).mappings().all()

safe_lookup_id = int(lookup_id)

lookup_stmt = text(
    "SELECT id, username, email, role "
    "FROM sqli_demo_users "
    "WHERE id = :user_id"
)

lookup_rows = db.session.execute(
    lookup_stmt,
    {"user_id": safe_lookup_id},
).mappings().all()
""",
            defense_notes=[
                "SQL Injection 방어의 기본은 파라미터 바인딩입니다.",
                "입력값 검증은 데이터 형식과 업무 규칙을 제한하는 용도로 사용합니다.",
                "실제 인증에서는 raw password 컬럼을 두지 않고 password hash를 검증합니다.",
                "ORM을 쓰더라도 raw SQL을 섞는 구간이 있으면 같은 기준으로 검토해야 합니다.",
            ],
        ),
    },
)


def get_lab(lab_id):
    """
    SQL Injection 카테고리의 Lab을 반환합니다.
    """

    if lab_id == SQLI_LOGIN_BYPASS.lab_id:
        return SQLI_LOGIN_BYPASS

    return None


def run_level(lab_id, level, form):
    """
    특정 SQLi Lab Level을 실행합니다.

    반환값은 템플릿에서 결과 영역에 표시됩니다.
    """

    ensure_sqli_demo_table()

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 SQL Injection Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    username = form.get("username", "")
    password = form.get("password", "")
    lookup_id = form.get("lookup_id", "")

    if level == 1:
        return _run_level_1(username, password)

    if level == 2:
        return _run_level_2(username, password)

    if level == 3:
        return _run_level_3(username, password)

    if level == 4:
        return _run_level_4(username, password, lookup_id)

    if level == 5:
        return _run_level_5(username, password, lookup_id)

    return _error_result("지원하지 않는 Level입니다.")


def _run_level_1(username, password):
    """
    Level 1: 완전히 취약한 구현입니다.

    교육용 취약 코드:
    사용자 입력이 SQL 문자열에 그대로 들어갑니다.
    """

    sql = (
        "SELECT id, username, email, role "
        "FROM sqli_demo_users "
        f"WHERE username = '{username}' "
        f"AND password = '{password}'"
    )

    return _execute_demo_query(sql)


def _run_level_2(username, password):
    """
    Level 2: 단순 블랙리스트 필터링입니다.

    교육용 취약 코드:
    일부 문자만 차단하지만 SQL 문자열 조립은 계속 사용합니다.
    """

    blocked = ["'", '"', "--", ";"]

    if any(token in username for token in blocked):
        return {
            "status": "blocked",
            "message": "username에 차단된 문자열이 포함되어 있습니다.",
            "debug_sql": None,
            "rows": [],
        }

    if any(token in password for token in blocked):
        return {
            "status": "blocked",
            "message": "password에 차단된 문자열이 포함되어 있습니다.",
            "debug_sql": None,
            "rows": [],
        }

    sql = (
        "SELECT id, username, email, role "
        "FROM sqli_demo_users "
        f"WHERE username = '{username}' "
        f"AND password = '{password}'"
    )

    return _execute_demo_query(sql)


def _run_level_3(username, password):
    """
    Level 3: 부분적인 방어입니다.

    username은 파라미터 바인딩하지만 password는 취약하게 문자열 조립합니다.
    """

    stmt = text(
        "SELECT id, username, email, role "
        "FROM sqli_demo_users "
        "WHERE username = :username "
        f"AND password = '{password}'"
    )

    debug_sql = (
        "SELECT id, username, email, role "
        "FROM sqli_demo_users "
        "WHERE username = :username "
        f"AND password = '{password}'"
    )

    try:
        rows = db.session.execute(
            stmt,
            {"username": username},
        ).mappings().all()

        return _rows_result(rows, debug_sql)

    except SQLAlchemyError as exc:
        return _sql_error_result(debug_sql, exc)


def _run_level_4(username, password, lookup_id):
    """
    Level 4: 거의 안전하지만 한 가지 결함이 남아 있습니다.

    로그인 쿼리는 안전하지만 lookup_id 조회에서 문자열 조립을 사용합니다.
    """

    login_stmt = text(
        "SELECT id, username, email, role "
        "FROM sqli_demo_users "
        "WHERE username = :username "
        "AND password = :password"
    )

    login_rows = db.session.execute(
        login_stmt,
        {
            "username": username,
            "password": password,
        },
    ).mappings().all()

    if not lookup_id:
        return {
            "status": "ok" if login_rows else "empty",
            "message": "로그인 쿼리는 안전하게 실행되었습니다. lookup_id를 입력하면 부가 조회도 실행됩니다.",
            "debug_sql": "login query uses parameters; lookup query not executed",
            "rows": [dict(row) for row in login_rows],
        }

    lookup_sql = (
        "SELECT id, username, email, role "
        f"FROM sqli_demo_users WHERE id = {lookup_id}"
    )

    return _execute_demo_query(
        lookup_sql,
        prefix_rows=[dict(row) for row in login_rows],
        prefix_message="로그인 결과와 사용자 ID 조회 결과를 함께 표시합니다.",
    )


def _run_level_5(username, password, lookup_id):
    """
    Level 5: 안전한 구현입니다.

    로그인과 사용자 조회 모두 파라미터 바인딩을 사용합니다.
    """

    login_stmt = text(
        "SELECT id, username, email, role "
        "FROM sqli_demo_users "
        "WHERE username = :username "
        "AND password = :password"
    )

    login_rows = db.session.execute(
        login_stmt,
        {
            "username": username,
            "password": password,
        },
    ).mappings().all()

    rows = [dict(row) for row in login_rows]

    if lookup_id:
        try:
            safe_lookup_id = int(lookup_id)
        except ValueError:
            return {
                "status": "blocked",
                "message": "lookup_id는 정수여야 합니다.",
                "debug_sql": "lookup_id rejected before query execution",
                "rows": rows,
            }

        lookup_stmt = text(
            "SELECT id, username, email, role "
            "FROM sqli_demo_users "
            "WHERE id = :user_id"
        )

        lookup_rows = db.session.execute(
            lookup_stmt,
            {"user_id": safe_lookup_id},
        ).mappings().all()

        rows.extend(dict(row) for row in lookup_rows)

    return {
        "status": "ok" if rows else "empty",
        "message": "파라미터 바인딩으로 쿼리를 실행했습니다.",
        "debug_sql": "all queries use bound parameters",
        "rows": rows,
    }


def _execute_demo_query(sql, prefix_rows=None, prefix_message=None):
    """
    교육용 raw SQL 실행 함수입니다.

    이 함수는 SQL Injection Lab 내부에서만 사용합니다.
    다른 플랫폼 코드에서는 사용자 입력을 SQL 문자열에 직접 넣지 않습니다.
    """

    try:
        rows = db.session.execute(text(sql)).mappings().all()
        result_rows = prefix_rows or []
        result_rows.extend(dict(row) for row in rows)

        return _rows_result(
            result_rows,
            sql,
            message=prefix_message,
        )

    except SQLAlchemyError as exc:
        return _sql_error_result(sql, exc)


def _rows_result(rows, debug_sql, message=None):
    """
    쿼리 결과를 화면에 표시하기 위한 공통 결과 구조입니다.
    """

    if rows:
        return {
            "status": "ok",
            "message": message or "쿼리 결과가 반환되었습니다.",
            "debug_sql": debug_sql,
            "rows": [dict(row) for row in rows],
        }

    return {
        "status": "empty",
        "message": message or "일치하는 사용자가 없습니다.",
        "debug_sql": debug_sql,
        "rows": [],
    }


def _sql_error_result(sql, exc):
    """
    SQL 오류를 학습용으로 보여줍니다.

    실제 서비스에서는 상세 SQL 오류를 사용자에게 보여주면 안 됩니다.
    """

    return {
        "status": "error",
        "message": "SQL 실행 중 오류가 발생했습니다. 실제 서비스에서는 이런 상세 오류를 노출하지 않습니다.",
        "debug_sql": sql,
        "rows": [],
        "error": str(exc),
    }


def _error_result(message):
    return {
        "status": "error",
        "message": message,
        "debug_sql": None,
        "rows": [],
    }