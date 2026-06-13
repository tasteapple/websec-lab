# file: app/labs/xss.py

import re
from html import escape as html_escape

import bleach
from markupsafe import Markup, escape as markupsafe_escape
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.labs.base import LabDefinition, LabFormField, LabLevel


COMMENT_FIELDS = [
    LabFormField(
        name="nickname",
        label="Nickname",
        placeholder="예: alice",
        help_text="댓글 작성자 이름입니다. 일부 Level에서는 이 값도 출력 취약점이 됩니다.",
    ),
    LabFormField(
        name="body",
        label="Comment",
        placeholder="댓글 내용을 입력하세요.",
        help_text="HTML처럼 보이는 문자열을 입력했을 때 각 Level이 어떻게 처리하는지 비교합니다.",
    ),
]


XSS_COMMENT_BOARD = LabDefinition(
    category="xss",
    lab_id="xss-comment-board",
    title="댓글 게시판 Stored XSS",
    summary="사용자 입력을 저장한 뒤 HTML에 출력할 때 escaping이 왜 필요한지 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="입력값을 그대로 렌더링",
            goal="저장된 사용자 입력을 HTML로 그대로 출력하면 어떤 문제가 생기는지 확인합니다.",
            form_fields=COMMENT_FIELDS,
            hints=[
                "댓글 본문과 닉네임이 HTML로 해석되는지 확인하세요.",
                "저장 시점보다 출력 시점의 처리 방식이 중요합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자가 입력한 nickname과 body를 HTML로 신뢰해서 렌더링합니다.

comment = {
    "nickname": Markup(row["nickname"]),
    "body": Markup(row["body"]),
}

# 템플릿:
# {{ comment.nickname }}
# {{ comment.body }}
""",
            secure_code="""# 안전한 코드
# 사용자 입력은 기본적으로 텍스트로 취급합니다.
# Jinja2 기본 escaping을 유지합니다.

comment = {
    "nickname": row["nickname"],
    "body": row["body"],
}

# 템플릿:
# {{ comment.nickname }}
# {{ comment.body }}
""",
            defense_notes=[
                "사용자 입력을 HTML로 신뢰하지 않습니다.",
                "Jinja2의 기본 escaping을 임의로 끄지 않습니다.",
                "저장된 값도 출력 시점에 안전하게 인코딩해야 합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="단순 문자열 필터링",
            goal="특정 문자열만 제거하는 방식이 XSS 방어로 부족한 이유를 이해합니다.",
            form_fields=COMMENT_FIELDS,
            hints=[
                "특정 태그 이름만 제거해도 HTML 전체를 안전하게 만들 수는 없습니다.",
                "블랙리스트는 누락과 우회 가능성이 큽니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# <script> 문자열만 제거합니다.
# 하지만 결과는 여전히 HTML로 렌더링됩니다.

body = re.sub(r"(?i)<\\s*/?\\s*script[^>]*>", "", body)

comment = {
    "nickname": Markup(nickname),
    "body": Markup(body),
}
""",
            secure_code="""# 안전한 코드
# 특정 문자열을 쫓아다니는 대신 출력 컨텍스트에 맞게 escaping합니다.

comment = {
    "nickname": nickname,
    "body": body,
}

# Jinja2 기본 escaping:
# {{ comment.nickname }}
# {{ comment.body }}
""",
            defense_notes=[
                "`<script>`만 제거하는 방식은 충분하지 않습니다.",
                "HTML에는 다양한 태그, 속성, 이벤트 컨텍스트가 있습니다.",
                "XSS 방어의 기본은 출력 컨텍스트별 escaping입니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="본문만 escape 처리",
            goal="일부 필드만 안전하게 처리하면 다른 필드에서 취약점이 남는다는 점을 확인합니다.",
            form_fields=COMMENT_FIELDS,
            hints=[
                "댓글 본문은 escape된 것처럼 보입니다.",
                "닉네임은 어떤 방식으로 출력되는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# body만 HTML escape하고 nickname은 그대로 HTML로 렌더링합니다.

safe_body = html.escape(body)

comment = {
    "nickname": Markup(nickname),      # 여전히 취약
    "body": Markup(safe_body),
}
""",
            secure_code="""# 안전한 코드
# 모든 사용자 입력 필드에 같은 기준을 적용합니다.

comment = {
    "nickname": nickname,
    "body": body,
}

# 템플릿에서 Jinja2 escaping을 유지합니다.
""",
            defense_notes=[
                "본문만 보호하고 닉네임, 제목, 프로필 같은 주변 필드를 놓치면 취약점이 남습니다.",
                "모든 사용자 입력 필드는 출력 위치별로 검토해야 합니다.",
                "수동 escape와 Markup 사용은 신중해야 합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="거의 안전하지만 속성 컨텍스트 결함 존재",
            goal="본문은 sanitize했지만 HTML 속성 출력에서 결함이 남는 실무형 실수를 확인합니다.",
            form_fields=COMMENT_FIELDS,
            hints=[
                "본문은 제한된 태그만 허용하도록 정리됩니다.",
                "닉네임이 HTML 속성에 들어가는 부분을 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# body는 bleach로 정리하지만 nickname은 data-author 속성에 안전하지 않게 들어갑니다.

clean_body = bleach.clean(
    body,
    tags=["b", "i", "strong", "em", "code"],
    attributes={},
    strip=True,
)

comment = {
    "nickname": escape(nickname),
    "body": Markup(clean_body),
    "data_author": Markup(nickname),   # 속성 컨텍스트 결함
}
""",
            secure_code="""# 안전한 코드
# 본문과 속성 모두 컨텍스트에 맞게 escaping합니다.

clean_body = bleach.clean(
    body,
    tags=["b", "i", "strong", "em", "code"],
    attributes={},
    strip=True,
)

comment = {
    "nickname": nickname,
    "body": clean_body,
    "data_author": nickname,
}

# 템플릿에서는 Markup으로 신뢰하지 않고 Jinja2 escaping을 적용합니다.
""",
            defense_notes=[
                "HTML 본문 컨텍스트와 속성 컨텍스트는 다릅니다.",
                "본문 sanitize만으로 모든 출력 위치가 안전해지지는 않습니다.",
                "속성에 들어가는 값도 반드시 escaping되어야 합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="사용자 입력을 텍스트로 취급하고 Jinja2 기본 escaping을 유지합니다.",
            form_fields=COMMENT_FIELDS,
            hints=[
                "입력값은 저장되지만 HTML로 신뢰되지 않습니다.",
                "출력 위치에서 기본 escaping이 적용됩니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# 일부 값을 Markup으로 신뢰 처리하면서 속성 컨텍스트 결함이 남았습니다.

comment = {
    "data_author": Markup(nickname),
}
""",
            secure_code="""# 안전한 코드
# 사용자 입력은 일반 문자열로 템플릿에 전달합니다.
# 템플릿은 Jinja2 기본 escaping을 사용합니다.

comment = {
    "nickname": nickname,
    "body": body,
    "data_author": nickname,
}

# 템플릿:
# <article data-author="{{ comment.data_author }}">
#   <strong>{{ comment.nickname }}</strong>
#   <p>{{ comment.body }}</p>
# </article>
""",
            defense_notes=[
                "기본적으로 사용자 입력을 HTML로 신뢰하지 않습니다.",
                "Jinja2 autoescape를 끄지 않습니다.",
                "필요한 경우 검증된 sanitizer를 사용하되, 속성/본문/JavaScript 컨텍스트를 구분합니다.",
                "저장형 XSS는 한 번 저장되면 다른 사용자 화면에서도 반복적으로 실행될 수 있으므로 출력 방어가 중요합니다.",
            ],
        ),
    },
)


def ensure_xss_demo_table():
    """
    Stored XSS 실습 전용 댓글 테이블을 준비합니다.

    이 테이블은 로컬 교육용이며 실제 서비스 게시판이 아닙니다.
    """

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS xss_demo_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level INTEGER NOT NULL,
                nickname TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    )

    count = db.session.execute(
        text("SELECT COUNT(*) FROM xss_demo_comments")
    ).scalar_one()

    if count == 0:
        _insert_seed_comments()

    db.session.commit()


def reset_xss_demo_table():
    """
    seed 실행 시 XSS demo table도 초기화하기 위한 함수입니다.
    """

    db.session.execute(text("DROP TABLE IF EXISTS xss_demo_comments"))
    db.session.flush()
    ensure_xss_demo_table()


def get_lab(lab_id):
    """
    XSS 카테고리의 Lab을 반환합니다.
    """

    if lab_id == XSS_COMMENT_BOARD.lab_id:
        return XSS_COMMENT_BOARD

    return None


def run_level(lab_id, level, form):
    """
    특정 XSS Lab Level을 실행합니다.
    """

    ensure_xss_demo_table()

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 XSS Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    nickname = form.get("nickname", "").strip()
    body = form.get("body", "").strip()

    if nickname or body:
        _store_comment_for_level(level, nickname, body)

    rows = _fetch_comments(level)
    comments = _render_comments_for_level(level, rows)

    return {
        "kind": "xss-comments",
        "status": "ok",
        "message": "댓글이 저장되고 현재 Level의 출력 방식으로 렌더링되었습니다.",
        "debug_sql": "SELECT id, nickname, body, created_at FROM xss_demo_comments WHERE level = :level ORDER BY id DESC",
        "comments": comments,
        "rows": [],
        "warning": "이 영역은 로컬 XSS 학습용 미리보기입니다. 실제 서비스 코드에서는 사용자 입력을 HTML로 신뢰하지 마세요.",
    }


def _insert_seed_comments():
    """
    각 Level에 기본 댓글을 넣습니다.

    자동 실행되는 위험한 스크립트성 데이터는 넣지 않고,
    HTML처럼 보이는 문자열 정도만 포함합니다.
    """

    seed_rows = []

    for level in range(1, 6):
        seed_rows.extend(
            [
                {
                    "level": level,
                    "nickname": "trainer",
                    "body": "출력 인코딩 차이를 비교하기 위한 기본 댓글입니다.",
                },
                {
                    "level": level,
                    "nickname": "html_tester",
                    "body": "HTML처럼 보이는 입력: <b>bold</b> & <i>italic</i>",
                },
            ]
        )

    for row in seed_rows:
        db.session.execute(
            text(
                """
                INSERT INTO xss_demo_comments
                    (level, nickname, body)
                VALUES
                    (:level, :nickname, :body)
                """
            ),
            row,
        )


def _store_comment_for_level(level, nickname, body):
    """
    Level별 입력 저장 방식입니다.

    일부 Level은 일부러 부족한 방어를 적용합니다.
    """

    if not nickname:
        nickname = "anonymous"

    if not body:
        body = "(empty comment)"

    stored_nickname = nickname
    stored_body = body

    if level == 2:
        # 교육용 취약 방어:
        # script 태그처럼 보이는 부분만 제거합니다.
        stored_nickname = _remove_script_tag_only(stored_nickname)
        stored_body = _remove_script_tag_only(stored_body)

    try:
        db.session.execute(
            text(
                """
                INSERT INTO xss_demo_comments
                    (level, nickname, body)
                VALUES
                    (:level, :nickname, :body)
                """
            ),
            {
                "level": level,
                "nickname": stored_nickname,
                "body": stored_body,
            },
        )
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        raise


def _fetch_comments(level):
    """
    현재 Level의 댓글만 조회합니다.
    """

    return db.session.execute(
        text(
            """
            SELECT id, nickname, body, created_at
            FROM xss_demo_comments
            WHERE level = :level
            ORDER BY id DESC
            """
        ),
        {"level": level},
    ).mappings().all()


def _render_comments_for_level(level, rows):
    """
    Level별 출력 처리 방식입니다.

    Markup을 사용하는 Level은 의도적으로 취약한 렌더링을 보여주기 위한 것입니다.
    """

    comments = []

    for row in rows:
        nickname = row["nickname"]
        body = row["body"]

        if level == 1:
            rendered = {
                "id": row["id"],
                "nickname": Markup(nickname),
                "body": Markup(body),
                "data_author": Markup(nickname),
                "created_at": row["created_at"],
            }

        elif level == 2:
            rendered = {
                "id": row["id"],
                "nickname": Markup(nickname),
                "body": Markup(body),
                "data_author": Markup(nickname),
                "created_at": row["created_at"],
            }

        elif level == 3:
            # body만 escape 처리하고 nickname은 여전히 HTML로 신뢰합니다.
            rendered = {
                "id": row["id"],
                "nickname": Markup(nickname),
                "body": Markup(html_escape(body)),
                "data_author": Markup(nickname),
                "created_at": row["created_at"],
            }

        elif level == 4:
            # body는 제한적으로 sanitize하지만 data-author 속성은 취약하게 둡니다.
            clean_body = bleach.clean(
                body,
                tags=["b", "i", "strong", "em", "code"],
                attributes={},
                strip=True,
            )

            rendered = {
                "id": row["id"],
                "nickname": markupsafe_escape(nickname),
                "body": Markup(clean_body),
                "data_author": Markup(nickname),
                "created_at": row["created_at"],
            }

        else:
            # Level 5:
            # 일반 문자열을 넘기고 Jinja2 기본 escaping에 맡깁니다.
            rendered = {
                "id": row["id"],
                "nickname": nickname,
                "body": body,
                "data_author": nickname,
                "created_at": row["created_at"],
            }

        comments.append(rendered)

    return comments


def _remove_script_tag_only(value):
    """
    교육용 취약 필터입니다.

    script 태그처럼 보이는 부분만 제거하므로 XSS 방어로 충분하지 않습니다.
    """

    return re.sub(r"(?i)<\s*/?\s*script[^>]*>", "", value)


def _error_result(message):
    return {
        "kind": "xss-comments",
        "status": "error",
        "message": message,
        "debug_sql": None,
        "comments": [],
        "rows": [],
    }