# file: app/blueprints/labs.py

from flask import Blueprint, abort, render_template, request

from app.labs.file_upload import get_lab as get_file_upload_lab
from app.labs.file_upload import run_level as run_file_upload_level
from app.labs.registry import get_category
from app.labs.sqli import get_lab as get_sqli_lab
from app.labs.sqli import run_level as run_sqli_level
from app.labs.xss import get_lab as get_xss_lab
from app.labs.xss import run_level as run_xss_level
from app.labs.ssrf import get_lab as get_ssrf_lab
from app.labs.ssrf import run_level as run_ssrf_level
from app.labs.ssti import get_lab as get_ssti_lab
from app.labs.ssti import run_level as run_ssti_level
from app.labs.command_injection import get_lab as get_command_injection_lab
from app.labs.command_injection import run_level as run_command_injection_level
from app.labs.path_traversal import get_lab as get_path_traversal_lab
from app.labs.path_traversal import run_level as run_path_traversal_level
from app.labs.authentication import get_lab as get_authentication_lab
from app.labs.authentication import run_level as run_authentication_level
from app.labs.access_control import get_lab as get_access_control_lab
from app.labs.access_control import run_level as run_access_control_level
from app.labs.business_logic import get_lab as get_business_logic_lab
from app.labs.business_logic import run_level as run_business_logic_level
from app.labs.information_disclosure import get_lab as get_information_disclosure_lab
from app.labs.information_disclosure import run_level as run_information_disclosure_level

labs_bp = Blueprint("labs", __name__, url_prefix="/labs")


LAB_RUNTIME = {
    "sqli": {
        "get_lab": get_sqli_lab,
        "run_level": run_sqli_level,
    },
    "xss": {
        "get_lab": get_xss_lab,
        "run_level": run_xss_level,
    },
    "file-upload": {
        "get_lab": get_file_upload_lab,
        "run_level": run_file_upload_level,
    },
    "ssrf": {
        "get_lab": get_ssrf_lab,
        "run_level": run_ssrf_level,
    },
    "ssti": {
        "get_lab": get_ssti_lab,
        "run_level": run_ssti_level,
    },
    "command-injection": {
        "get_lab": get_command_injection_lab,
        "run_level": run_command_injection_level,
    },
    "path-traversal": {
        "get_lab": get_path_traversal_lab,
        "run_level": run_path_traversal_level,
    },
    "authentication": {
    "get_lab": get_authentication_lab,
    "run_level": run_authentication_level,
    },
    "access-control": {
    "get_lab": get_access_control_lab,
    "run_level": run_access_control_level,
    },
    "business-logic": {
        "get_lab": get_business_logic_lab,
        "run_level": run_business_logic_level,
    },
    "information-disclosure": {
        "get_lab": get_information_disclosure_lab,
        "run_level": run_information_disclosure_level,
    }
}

FORM_UI = {
    "sqli": {
        "title": "로그인 입력",
        "note": "이 입력은 로컬 SQLite의 SQL Injection 실습 테이블에만 적용됩니다.",
    },
    "xss": {
        "title": "댓글 작성",
        "note": "입력값은 로컬 XSS 실습용 댓글 미리보기 영역에만 저장됩니다.",
    },
    "file-upload": {
        "title": "파일 업로드",
        "note": "업로드 파일은 instance/uploads/file-upload/ 아래에만 저장됩니다.",
    },
    "ssrf": {
        "title": "URL 조회 시뮬레이션",
        "note": "실제 외부 네트워크 요청은 하지 않고 로컬 mock endpoint만 시뮬레이션합니다.",
    },
    "ssti": {
        "title": "템플릿 입력",
        "note": "실제 위험한 Jinja2 객체 접근은 실행하지 않고 제한된 표현식만 시뮬레이션합니다.",
    },
    "command-injection": {
        "title": "명령 입력",
        "note": "실제 시스템 명령은 실행하지 않고 mock command runner가 처리 흐름만 분석합니다.",
    },
    "path-traversal": {
        "title": "리포트 경로 입력",
        "note": "실제 시스템 파일은 읽지 않고 instance/reports/path-traversal/ 아래의 demo 파일만 사용합니다.",
    },
    "authentication": {
        "title": "로그인 입력",
        "note": "실제 로그인 세션은 만들지 않고 로컬 demo auth table에서 인증 흐름만 시뮬레이션합니다.",
    },
    "access-control": {
        "title": "접근 제어 실습",
        "note": "실제 접근 제어 테스트는 하지 않고 로컬 demo 환경에서만 시뮬레이션합니다.",
    },
    "business-logic": {
        "title": "비즈니스 로직 실습",
        "note": "실제 비즈니스 로직 테스트는 하지 않고 로컬 demo 환경에서만 시뮬레이션합니다.",
    },
    "information-disclosure": {
        "title": "정보 누출 실습",
        "note": "실제 정보 누출 테스트는 하지 않고 로컬 demo 환경에서만 시뮬레이션합니다.",
    }
}

@labs_bp.get("/<category_slug>")
def category(category_slug):
    """
    카테고리별 Lab 목록 페이지입니다.
    """

    category_data = get_category(category_slug)
    if category_data is None:
        abort(404)

    return render_template(
        "labs/category.html",
        active_page="labs",
        active_category=category_slug,
        category=category_data,
    )


@labs_bp.route("/<category_slug>/<lab_id>/level/<int:level>", methods=["GET", "POST"])
def lab_level(category_slug, lab_id, level):
    """
    특정 Lab의 특정 Level 페이지입니다.
    """

    category_data = get_category(category_slug)
    if category_data is None:
        abort(404)

    runtime = LAB_RUNTIME.get(category_slug)
    if runtime is None:
        abort(404)

    lab = runtime["get_lab"](lab_id)
    if lab is None:
        abort(404)

    level_data = lab.get_level(level)
    if level_data is None:
        abort(404)

    result = None
    has_file_upload = any(
        field.field_type == "file"
        for field in level_data.form_fields
    )

    if request.method == "POST":
        result = runtime["run_level"](
            lab_id,
            level,
            request.form,
            request.files,
        )

    levels = [
        {
            "level": item_level,
        }
        for item_level in sorted(lab.levels.keys())
    ]

    return render_template(
        "labs/lab_level.html",
        active_page="labs",
        active_category=category_slug,
        category=category_data,
        category_slug=category_slug,
        lab=lab,
        lab_id=lab_id,
        level_data=level_data,
        current_level=level,
        levels=levels,
        result=result,
        has_file_upload=has_file_upload,
        form_ui=FORM_UI.get(
        category_slug,{
            "title": "입력 폼",
            "note": "이 입력은 로컬 실습 환경에서만 처리됩니다.",
            },
        ),
    )