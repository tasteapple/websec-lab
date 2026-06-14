# file: app/labs/ssti.py

import re
from html import escape as html_escape

from markupsafe import Markup

from app.labs.base import LabDefinition, LabFormField, LabLevel


PROFILE_FIELDS = [
    LabFormField(
        name="display_name",
        label="Display name",
        placeholder="예: alice",
        help_text="프로필 카드에 표시할 이름입니다.",
    ),
    LabFormField(
        name="role",
        label="Role",
        placeholder="예: learner",
        help_text="프로필 카드에 표시할 역할입니다.",
    ),
    LabFormField(
        name="template_text",
        label="Profile template",
        field_type="textarea",
        placeholder="예: 안녕하세요, {{ name }}님. 역할은 {{ role }}입니다.",
        help_text="Level별로 이 문자열을 서버 템플릿처럼 처리하는 방식을 비교합니다.",
    ),
]


SSTI_LAB = LabDefinition(
    category="ssti",
    lab_id="ssti-profile-card",
    title="프로필 카드 템플릿 렌더링",
    summary="사용자 입력을 서버 템플릿으로 해석할 때 생기는 위험과 안전한 렌더링 방식을 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="사용자 입력을 템플릿으로 직접 렌더링",
            goal="사용자가 작성한 문자열이 서버 템플릿 표현식으로 해석될 때 어떤 문제가 생기는지 이해합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "`{{ name }}` 같은 표현이 서버에서 값으로 치환되는지 확인하세요.",
                "사용자 입력이 템플릿 문법으로 해석되는 순간 신뢰 경계가 무너집니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자가 입력한 문자열을 Jinja2 템플릿으로 직접 컴파일합니다.

user_template = request.form["template_text"]

html = current_app.jinja_env.from_string(user_template).render(
    name=display_name,
    role=role,
)
""",
            secure_code="""# 안전한 코드
# 사용자 입력을 템플릿으로 해석하지 않고 일반 텍스트로 출력합니다.

template_text = request.form["template_text"]

profile = {
    "name": display_name,
    "role": role,
    "message": template_text,
}

# Jinja2 템플릿:
# <p>{{ profile.message }}</p>
""",
            defense_notes=[
                "사용자 입력을 `from_string()` 같은 서버 템플릿 컴파일 함수에 넣지 않습니다.",
                "사용자 입력은 템플릿이 아니라 데이터로 취급합니다.",
                "템플릿은 개발자가 작성한 고정 파일만 사용합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="일부 위험 문자열 차단",
            goal="블랙리스트로 템플릿 인젝션을 막으려는 방식이 부족함을 이해합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "`config`, `class`, `import` 같은 문자열만 막는다고 충분하지 않습니다.",
                "템플릿 문법 전체를 문자열 필터로 안전하게 다루기 어렵습니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 몇 가지 위험해 보이는 문자열만 차단합니다.

blocked = ["config", "__", "class", "import", "os"]

if any(token in user_template for token in blocked):
    raise ValueError("blocked")

html = current_app.jinja_env.from_string(user_template).render(context)
""",
            secure_code="""# 안전한 코드
# 사용자 입력을 서버 템플릿으로 해석하지 않습니다.

safe_message = user_template

return render_template(
    "profile.html",
    name=display_name,
    role=role,
    message=safe_message,
)
""",
            defense_notes=[
                "블랙리스트는 누락과 우회 가능성이 큽니다.",
                "문자열 필터보다 중요한 것은 사용자 입력을 템플릿으로 실행하지 않는 설계입니다.",
                "템플릿 표현식이 필요한 기능은 별도 DSL이나 제한된 치환 문법으로 구현합니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="중괄호 일부 제거",
            goal="템플릿 구분자 일부를 제거해도 완전한 방어가 되지 않는다는 점을 확인합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "입력 저장 전에 `{{`와 `}}`만 제거합니다.",
                "필터링된 결과와 원본 입력을 비교해보세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 템플릿 구분자처럼 보이는 일부 문자열만 제거합니다.

user_template = user_template.replace("{{", "")
user_template = user_template.replace("}}", "")

html = current_app.jinja_env.from_string(user_template).render(context)
""",
            secure_code="""# 안전한 코드
# 템플릿 문법 제거를 방어로 삼지 않고, 입력을 텍스트로 출력합니다.

message = user_template

# Jinja2 autoescape:
# {{ message }}
""",
            defense_notes=[
                "일부 구분자 제거는 템플릿 엔진 전체 문법을 포괄하지 못합니다.",
                "필터링으로 템플릿 실행을 안전하게 만드는 접근은 취약합니다.",
                "사용자 입력은 템플릿이 아니라 데이터로 전달해야 합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="거의 안전하지만 미리보기 기능이 취약",
            goal="저장 화면은 안전하지만 preview 기능에서 템플릿 렌더링이 남는 실무형 실수를 확인합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "일반 저장 경로는 안전해 보입니다.",
                "하지만 미리보기 기능이 사용자 템플릿을 다시 해석합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 저장은 일반 텍스트로 하지만 preview에서 다시 템플릿으로 해석합니다.

saved_message = user_template

if preview:
    preview_html = current_app.jinja_env.from_string(saved_message).render(
        name=display_name,
        role=role,
    )
""",
            secure_code="""# 안전한 코드
# preview도 실제 저장 경로와 같은 escaping 정책을 사용합니다.

saved_message = user_template

preview_html = render_template(
    "profile_preview.html",
    name=display_name,
    role=role,
    message=saved_message,
)
""",
            defense_notes=[
                "저장 경로와 미리보기 경로의 보안 정책이 달라지면 취약점이 생깁니다.",
                "preview, export, email template 같은 보조 기능도 같은 기준으로 검토해야 합니다.",
                "사용자 입력을 다시 서버 템플릿으로 해석하지 않습니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="고정 템플릿과 사용자 데이터의 경계를 명확히 분리합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "사용자가 입력한 문자열은 템플릿이 아니라 데이터입니다.",
                "Level 5에서는 `{{ name }}` 같은 문자열도 그대로 텍스트로 표시됩니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# preview 기능에서 사용자 입력을 다시 템플릿으로 컴파일했습니다.

preview_html = current_app.jinja_env.from_string(saved_message).render(context)
""",
            secure_code="""# 안전한 코드
# 템플릿은 개발자가 작성한 고정 파일만 사용합니다.
# 사용자 입력은 템플릿에 데이터로 전달합니다.

return render_template(
    "profile_card.html",
    name=display_name,
    role=role,
    message=user_template,
)

# profile_card.html:
# <h2>{{ name }}</h2>
# <p>{{ role }}</p>
# <div>{{ message }}</div>
""",
            defense_notes=[
                "서버 템플릿 파일은 개발자가 관리하는 고정 자산으로 둡니다.",
                "사용자 입력을 `from_string()`에 넣지 않습니다.",
                "사용자에게 커스텀 템플릿 기능이 꼭 필요하면 별도의 제한 DSL을 설계합니다.",
                "템플릿 컨텍스트에는 민감 객체나 애플리케이션 내부 객체를 넣지 않습니다.",
            ],
        ),
    },
)


def get_lab(lab_id):
    """
    SSTI 카테고리의 Lab을 반환합니다.
    """

    if lab_id == SSTI_LAB.lab_id:
        return SSTI_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 SSTI Lab Level을 실행합니다.

    실제 위험한 Jinja2 객체 접근을 실행하지 않고,
    제한된 템플릿 표현식만 안전하게 시뮬레이션합니다.
    """

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 SSTI Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    display_name = form.get("display_name", "").strip() or "anonymous"
    role = form.get("role", "").strip() or "learner"
    template_text = form.get("template_text", "").strip()

    if not template_text:
        template_text = "안녕하세요, {{ name }}님. 역할은 {{ role }}입니다."

    return _render_for_level(level, display_name, role, template_text)


def _render_for_level(level, display_name, role, template_text):
    """
    Level별 SSTI 처리 방식을 시뮬레이션합니다.

    Level 1~4는 취약한 설계를 보여주지만,
    실제 Jinja2 위험 객체 접근은 실행하지 않습니다.
    """

    context = {
        "name": display_name,
        "role": role,
    }

    reasons = []
    processed_template = template_text
    rendered_output = ""
    evaluated_expressions = []

    if level == 1:
        reasons.append("Level 1: 사용자 입력을 템플릿처럼 해석했습니다.")
        rendered_output, evaluated_expressions = _unsafe_like_render(
            processed_template,
            context,
            allow_math=True,
        )

    elif level == 2:
        blocked = ["config", "__", "class", "import", "os", "subclasses"]

        if any(token in processed_template.lower() for token in blocked):
            return {
                "kind": "ssti",
                "status": "blocked",
                "message": "블랙리스트 문자열이 포함되어 차단되었습니다.",
                "template": template_text,
                "processed_template": processed_template,
                "rendered_output": "",
                "expressions": [],
                "context": context,
                "reasons": ["Level 2: 블랙리스트 기반 차단이 동작했습니다."],
                "rows": [],
            }

        reasons.append("Level 2: 블랙리스트에 걸리지 않아 템플릿처럼 해석했습니다.")
        rendered_output, evaluated_expressions = _unsafe_like_render(
            processed_template,
            context,
            allow_math=True,
        )

    elif level == 3:
        processed_template = processed_template.replace("{{", "")
        processed_template = processed_template.replace("}}", "")

        reasons.append("Level 3: 일부 템플릿 구분자를 제거했습니다.")
        reasons.append("하지만 사용자 입력을 템플릿으로 다루는 설계 자체는 유지되어 있습니다.")

        rendered_output, evaluated_expressions = _unsafe_like_render(
            processed_template,
            context,
            allow_math=False,
        )

    elif level == 4:
        reasons.append("Level 4: 저장 경로는 안전하지만 preview 기능이 템플릿처럼 해석합니다.")
        rendered_output, evaluated_expressions = _unsafe_like_render(
            processed_template,
            context,
            allow_math=True,
        )

    else:
        reasons.append("Level 5: 사용자 입력을 템플릿으로 해석하지 않고 텍스트로 출력했습니다.")

        # 안전 구현:
        # 입력을 템플릿으로 해석하지 않고 그대로 텍스트로 표시합니다.
        rendered_output = template_text
        evaluated_expressions = []

    return {
        "kind": "ssti",
        "status": "ok",
        "message": "SSTI 렌더링 흐름을 시뮬레이션했습니다.",
        "template": template_text,
        "processed_template": processed_template,
        "rendered_output": rendered_output,
        "expressions": evaluated_expressions,
        "context": context,
        "reasons": reasons,
        "rows": [],
    }


def _unsafe_like_render(template_text, context, allow_math):
    """
    교육용 SSTI 시뮬레이터입니다.

    실제 Jinja2 엔진을 실행하지 않습니다.
    지원하는 표현식:
    - {{ name }}
    - {{ role }}
    - {{ 7 * 7 }} 같은 단순 정수 사칙연산

    지원하지 않는 표현식은 실행하지 않고 표시만 합니다.
    """

    expressions = []

    def replace_expression(match):
        expression = match.group(1).strip()
        expression_result = _evaluate_limited_expression(
            expression,
            context,
            allow_math=allow_math,
        )

        expressions.append(
            {
                "expression": expression,
                "result": expression_result["result"],
                "allowed": expression_result["allowed"],
                "reason": expression_result["reason"],
            }
        )

        if expression_result["allowed"]:
            return str(expression_result["result"])

        return f"[blocked expression: {html_escape(expression)}]"

    rendered = re.sub(r"\{\{\s*(.*?)\s*\}\}", replace_expression, template_text)

    return rendered, expressions


def _evaluate_limited_expression(expression, context, allow_math):
    """
    매우 제한된 표현식만 평가합니다.

    이 함수는 SSTI 개념 설명용이며,
    실제 템플릿 엔진이나 Python eval을 사용하지 않습니다.
    """

    if expression in context:
        return {
            "allowed": True,
            "result": context[expression],
            "reason": "허용된 context 변수입니다.",
        }

    if allow_math and re.fullmatch(r"[0-9+\-*/% ().]+", expression):
        try:
            result = _safe_integer_math(expression)
            return {
                "allowed": True,
                "result": result,
                "reason": "단순 정수 연산만 제한적으로 평가했습니다.",
            }
        except ZeroDivisionError:
            return {
                "allowed": False,
                "result": "",
                "reason": "0으로 나누는 연산은 허용하지 않습니다.",
            }
        except ValueError:
            return {
                "allowed": False,
                "result": "",
                "reason": "허용되지 않은 수식입니다.",
            }

    return {
        "allowed": False,
        "result": "",
        "reason": "허용된 변수 또는 단순 정수 연산이 아닙니다.",
    }


def _safe_integer_math(expression):
    """
    단순 정수 사칙연산만 허용하는 작은 evaluator입니다.

    Python eval을 사용하지 않기 위해 AST 대신 아주 좁은 문자 집합과 길이 제한을 둡니다.
    이 함수는 교육용 시뮬레이션 용도입니다.
    """

    if len(expression) > 60:
        raise ValueError("expression too long")

    if not re.fullmatch(r"[0-9+\-*/% ().]+", expression):
        raise ValueError("unsupported characters")

    # 문자 집합을 강하게 제한한 뒤에도 eval 사용은 일반적으로 권장하지 않습니다.
    # 여기서는 숫자 연산 시뮬레이션만을 위해 builtins를 제거한 제한 환경에서 사용합니다.
    result = eval(expression, {"__builtins__": {}}, {})

    if not isinstance(result, int):
        raise ValueError("only integer result is allowed")

    return result


def _error_result(message):
    return {
        "kind": "ssti",
        "status": "error",
        "message": message,
        "template": "",
        "processed_template": "",
        "rendered_output": "",
        "expressions": [],
        "context": {},
        "reasons": [],
        "rows": [],
    }