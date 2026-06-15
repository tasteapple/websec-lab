# file: app/labs/path_traversal.py

from pathlib import Path

from flask import current_app
from werkzeug.utils import secure_filename

from app.labs.base import LabDefinition, LabFormField, LabLevel


REPORT_FIELDS = [
    LabFormField(
        name="report_path",
        label="Report path",
        placeholder="예: welcome.txt",
        help_text=(
            "Level 1~4에서는 파일 경로 처리 방식의 차이를 확인합니다. "
            "Level 5에서는 report id 또는 허용된 파일명만 처리합니다."
        ),
    )
]


PATH_TRAVERSAL_LAB = LabDefinition(
    category="path-traversal",
    lab_id="download-report",
    title="리포트 다운로드 경로 조작",
    summary="파일 다운로드 기능에서 경로 정규화와 base directory 검증이 왜 필요한지 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="사용자 입력 경로를 그대로 조합",
            goal="사용자 입력을 파일 경로에 그대로 붙이면 의도하지 않은 파일에 접근할 수 있음을 이해합니다.",
            form_fields=REPORT_FIELDS,
            hints=[
                "기준 디렉터리는 public report 디렉터리입니다.",
                "사용자 입력이 경로 조각으로 그대로 붙는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자 입력을 파일 경로에 그대로 붙입니다.

base_dir = REPORT_ROOT / "public"
target_path = base_dir / report_path

content = target_path.read_text()
""",
            secure_code="""# 안전한 코드
# 경로를 정규화한 뒤 허용된 base directory 내부인지 확인합니다.

base_dir = (REPORT_ROOT / "public").resolve()
target_path = (base_dir / report_path).resolve()

if not target_path.is_relative_to(base_dir):
    raise ValueError("path traversal blocked")

content = target_path.read_text()
""",
            defense_notes=[
                "사용자 입력을 파일 경로에 직접 붙이지 않습니다.",
                "정규화된 최종 경로가 허용된 base directory 내부인지 확인합니다.",
                "파일 다운로드는 가능하면 파일명 대신 서버 측 report id로 처리합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="문자열 블랙리스트 필터",
            goal="`..` 같은 문자열만 막는 방식이 왜 부족한지 이해합니다.",
            form_fields=REPORT_FIELDS,
            hints=[
                "문자열 필터는 경로 정규화와 다릅니다.",
                "차단 문자열을 늘리는 방식은 유지보수가 어렵습니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 일부 경로 조작 문자열만 차단합니다.

blocked = ["..", "%2e", "%2f", "\\\\"]

if any(token in report_path.lower() for token in blocked):
    raise ValueError("blocked")

target_path = REPORT_ROOT / "public" / report_path
content = target_path.read_text()
""",
            secure_code="""# 안전한 코드
# 문자열 필터 대신 resolve() 결과를 기준으로 base directory 내부 여부를 확인합니다.

base_dir = (REPORT_ROOT / "public").resolve()
target_path = (base_dir / report_path).resolve()

if not target_path.is_relative_to(base_dir):
    raise ValueError("blocked")
""",
            defense_notes=[
                "블랙리스트는 누락과 우회 가능성이 큽니다.",
                "경로 검증은 문자열 포함 여부가 아니라 정규화된 경로 기준으로 해야 합니다.",
                "운영체제별 경로 구분자 차이도 고려해야 합니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="확장자만 검사",
            goal="확장자만 맞으면 안전하다고 판단하는 방식이 부족함을 이해합니다.",
            form_fields=REPORT_FIELDS,
            hints=[
                "파일이 `.txt`로 끝나는지만 확인합니다.",
                "파일이 public 디렉터리 안에 있는지도 확인해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# .txt 확장자만 확인하고 실제 위치는 확인하지 않습니다.

if not report_path.endswith(".txt"):
    raise ValueError("only txt allowed")

target_path = REPORT_ROOT / report_path
content = target_path.read_text()
""",
            secure_code="""# 안전한 코드
# 확장자 확인과 base directory 검증을 함께 적용합니다.

base_dir = (REPORT_ROOT / "public").resolve()
target_path = (base_dir / report_path).resolve()

if target_path.suffix != ".txt":
    raise ValueError("only txt allowed")

if not target_path.is_relative_to(base_dir):
    raise ValueError("blocked")
""",
            defense_notes=[
                "확장자 검사는 보조 조건일 뿐입니다.",
                "파일 위치 검증이 빠지면 private 영역의 `.txt` 파일에도 접근할 수 있습니다.",
                "정규화된 경로 검증을 반드시 함께 적용합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="루트 내부 검증은 있지만 권한 경계가 넓음",
            goal="전체 reports 루트 내부 여부만 확인하면 private 리포트 접근이 남는다는 점을 확인합니다.",
            form_fields=REPORT_FIELDS,
            hints=[
                "프로젝트 밖 파일은 차단됩니다.",
                "하지만 public과 private의 권한 경계가 분리되어 있는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# reports 루트 내부인지만 확인합니다.
# private 디렉터리 접근까지 허용될 수 있습니다.

report_root = REPORT_ROOT.resolve()
target_path = (REPORT_ROOT / report_path).resolve()

if not target_path.is_relative_to(report_root):
    raise ValueError("blocked")

content = target_path.read_text()
""",
            secure_code="""# 안전한 코드
# 사용자가 접근 가능한 public 디렉터리 내부만 허용합니다.

public_root = (REPORT_ROOT / "public").resolve()
target_path = (public_root / report_path).resolve()

if not target_path.is_relative_to(public_root):
    raise ValueError("blocked")
""",
            defense_notes=[
                "루트 디렉터리 내부 검증만으로는 권한 검증이 충분하지 않습니다.",
                "사용자에게 허용된 하위 영역을 기준으로 검증해야 합니다.",
                "private, admin, archive 같은 영역은 별도 권한 검사를 둬야 합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="파일 경로 입력 대신 서버 측 allowlist report id를 사용합니다.",
            form_fields=REPORT_FIELDS,
            hints=[
                "예: welcome 또는 monthly-summary",
                "사용자 입력을 직접 파일 경로로 사용하지 않습니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# reports 루트 내부 파일이면 private 파일도 읽을 수 있었습니다.

target_path = (REPORT_ROOT / report_path).resolve()

if target_path.is_relative_to(REPORT_ROOT.resolve()):
    content = target_path.read_text()
""",
            secure_code="""# 안전한 코드
# 사용자는 파일 경로가 아니라 report id만 선택합니다.

allowed_reports = {
    "welcome": REPORT_ROOT / "public" / "welcome.txt",
    "monthly-summary": REPORT_ROOT / "public" / "monthly-summary.txt",
}

target_path = allowed_reports[report_id].resolve()
public_root = (REPORT_ROOT / "public").resolve()

if not target_path.is_relative_to(public_root):
    raise ValueError("blocked")

content = target_path.read_text()
""",
            defense_notes=[
                "파일 경로를 사용자에게 직접 입력받지 않습니다.",
                "서버 측 allowlist를 사용합니다.",
                "정규화된 경로가 public root 내부인지 다시 확인합니다.",
                "파일 접근 권한은 객체 단위 권한 검증과 함께 적용해야 합니다.",
            ],
        ),
    },
)


def get_lab(lab_id):
    """
    Path Traversal 카테고리의 Lab을 반환합니다.
    """

    if lab_id == PATH_TRAVERSAL_LAB.lab_id:
        return PATH_TRAVERSAL_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 Path Traversal Lab Level을 실행합니다.

    실제 프로젝트 파일이나 OS 민감 파일은 읽지 않습니다.
    모든 파일 접근은 instance/reports/path-traversal/ 아래로 제한됩니다.
    """

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 Path Traversal Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    report_path = form.get("report_path", "").strip() or "welcome.txt"

    report_root = _ensure_demo_reports()

    return _read_for_level(level, report_root, report_path)


def _ensure_demo_reports():
    """
    Path Traversal 실습용 report 파일을 준비합니다.

    모든 파일은 instance/reports/path-traversal/ 아래에만 생성합니다.
    """

    report_root = Path(current_app.instance_path) / "reports" / "path-traversal"

    public_dir = report_root / "public"
    private_dir = report_root / "private"
    archive_dir = report_root / "archive"

    public_dir.mkdir(parents=True, exist_ok=True)
    private_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)

    files = {
        public_dir / "welcome.txt": (
            "Public report: welcome\n"
            "이 파일은 모든 학습자가 다운로드할 수 있는 공개 리포트입니다.\n"
        ),
        public_dir / "monthly-summary.txt": (
            "Public report: monthly summary\n"
            "이번 달 학습 진행률과 공개 통계를 담은 예시 파일입니다.\n"
        ),
        private_dir / "invoice-alice.txt": (
            "Private report: alice invoice\n"
            "이 파일은 private 영역 예시입니다. 일반 public 다운로드에서 보이면 안 됩니다.\n"
        ),
        private_dir / "admin-note.txt": (
            "Private report: admin note\n"
            "관리자 내부 메모처럼 보이는 로컬 학습용 파일입니다. 실제 비밀값은 없습니다.\n"
        ),
        archive_dir / "2024-q4.txt": (
            "Archive report: 2024 Q4\n"
            "아카이브 영역 예시입니다. 별도 권한 정책이 필요한 파일로 가정합니다.\n"
        ),
    }

    for path, content in files.items():
        if not path.exists():
            path.write_text(content, encoding="utf-8")

    return report_root


def _read_for_level(level, report_root, report_path):
    """
    Level별 파일 경로 처리 로직입니다.

    취약 설계를 보여주되, 실제 읽기는 demo report root 내부로 제한합니다.
    """

    reasons = []
    allowed = False
    content = ""
    target_path = None
    base_dir = None

    if level == 1:
        base_dir = report_root / "public"
        target_path = base_dir / report_path

        reasons.append("Level 1: 사용자 입력을 public base directory 뒤에 그대로 붙였습니다.")
        allowed = True

    elif level == 2:
        base_dir = report_root / "public"
        target_path = base_dir / report_path

        blocked = ["..", "%2e", "%2f", "\\"]

        if any(token in report_path.lower() for token in blocked):
            reasons.append("Level 2: 블랙리스트 경로 조각이 발견되어 차단되었습니다.")
            allowed = False
        else:
            reasons.append("Level 2: 블랙리스트에 걸리지 않아 경로를 허용했습니다.")
            allowed = True

    elif level == 3:
        base_dir = report_root
        target_path = report_root / report_path

        if not report_path.endswith(".txt"):
            reasons.append("Level 3: .txt 확장자가 아니어서 차단되었습니다.")
            allowed = False
        else:
            reasons.append("Level 3: .txt 확장자라서 허용했습니다. 위치 검증은 부족합니다.")
            allowed = True

    elif level == 4:
        base_dir = report_root
        target_path = report_root / report_path

        resolved_root = report_root.resolve()
        resolved_target = target_path.resolve()

        if not _is_relative_to(resolved_target, resolved_root):
            reasons.append("Level 4: reports 루트 밖으로 벗어난 경로라서 차단되었습니다.")
            allowed = False
        else:
            reasons.append("Level 4: reports 루트 내부라서 허용했습니다. public/private 권한 경계는 부족합니다.")
            allowed = True

    else:
        public_root = (report_root / "public").resolve()

        allowed_reports = {
            "welcome": report_root / "public" / "welcome.txt",
            "welcome.txt": report_root / "public" / "welcome.txt",
            "monthly-summary": report_root / "public" / "monthly-summary.txt",
            "monthly-summary.txt": report_root / "public" / "monthly-summary.txt",
        }

        base_dir = public_root

        if report_path not in allowed_reports:
            target_path = None
            reasons.append("Level 5: 서버 측 allowlist에 없는 report id입니다.")
            allowed = False
        else:
            target_path = allowed_reports[report_path]
            resolved_target = target_path.resolve()

            if not _is_relative_to(resolved_target, public_root):
                reasons.append("Level 5: public root 밖의 파일이라서 차단되었습니다.")
                allowed = False
            else:
                reasons.append("Level 5: allowlist와 public root 검증을 통과했습니다.")
                allowed = True

    resolved_root = report_root.resolve()
    resolved_target = target_path.resolve() if target_path else None

    hard_guard_allowed = (
        resolved_target is not None
        and _is_relative_to(resolved_target, resolved_root)
    )

    if allowed and not hard_guard_allowed:
        reasons.append("Hard guard: demo report root 밖으로 벗어나는 실제 파일 읽기를 차단했습니다.")
        allowed = False

    if allowed and resolved_target:
        if not resolved_target.exists() or not resolved_target.is_file():
            reasons.append("대상 파일이 존재하지 않습니다.")
            allowed = False
        else:
            content = resolved_target.read_text(encoding="utf-8")

    status = "ok" if allowed else "blocked"

    return {
        "kind": "path-traversal",
        "status": status,
        "message": "파일 다운로드 경로 처리 결과를 시뮬레이션했습니다.",
        "request": {
            "input": report_path,
            "base_dir": str(base_dir) if base_dir else "(none)",
            "target_path": str(target_path) if target_path else "(none)",
            "resolved_target": str(resolved_target) if resolved_target else "(none)",
            "demo_root": str(resolved_root),
            "allowed": allowed,
            "reasons": reasons,
        },
        "file": {
            "name": resolved_target.name if allowed and resolved_target else "",
            "content": content,
        },
        "rows": [],
    }


def _is_relative_to(path, base):
    """
    Python 3.8 호환성을 고려한 is_relative_to helper입니다.
    """

    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _error_result(message):
    return {
        "kind": "path-traversal",
        "status": "error",
        "message": message,
        "request": None,
        "file": None,
        "rows": [],
    }