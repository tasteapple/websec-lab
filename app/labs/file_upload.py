# file: app/labs/file_upload.py

from pathlib import Path
from uuid import uuid4

from flask import current_app
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from app.labs.base import LabDefinition, LabFormField, LabLevel


MAX_DEMO_UPLOAD_SIZE = 512 * 1024

SAFE_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
LOOSE_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "svg"}

SAFE_IMAGE_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
}

LOOSE_IMAGE_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/svg+xml",
}

BLOCKED_EXTENSIONS = {
    "php",
    "phtml",
    "py",
    "sh",
    "bat",
    "cmd",
    "exe",
}


UPLOAD_FIELDS = [
    LabFormField(
        name="display_name",
        label="Display name",
        placeholder="예: my profile image",
        help_text="화면에 표시할 이름입니다. 파일명과 별개로 취급합니다.",
    ),
    LabFormField(
        name="upload_file",
        label="Upload file",
        field_type="file",
        help_text="로컬 instance/uploads/file-upload/ 아래에만 저장됩니다.",
    ),
]


FILE_UPLOAD_LAB = LabDefinition(
    category="file-upload",
    lab_id="upload-profile-image",
    title="프로필 이미지 업로드",
    summary="파일 업로드에서 확장자, MIME, 저장 경로, 파일명 처리의 차이를 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="모든 파일 업로드 허용",
            goal="검증 없이 파일을 받으면 어떤 문제가 생기는지 이해합니다.",
            form_fields=UPLOAD_FIELDS,
            hints=[
                "파일명, 확장자, MIME 타입을 전혀 확인하지 않습니다.",
                "실제 서비스라면 업로드 디렉터리에서 파일이 실행되지 않도록 분리해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 확장자, MIME 타입, 파일명 검증 없이 업로드를 허용합니다.

uploaded = request.files["upload_file"]
stored_name = uploaded.filename
uploaded.save(upload_dir / stored_name)
""",
            secure_code="""# 안전한 코드
# 허용 확장자와 MIME 타입을 확인하고, 랜덤 파일명으로 저장합니다.

uploaded = request.files["upload_file"]

ext = get_extension(uploaded.filename)

if ext not in {"png", "jpg", "jpeg", "gif"}:
    raise ValueError("unsupported extension")

if uploaded.content_type not in {"image/png", "image/jpeg", "image/gif"}:
    raise ValueError("unsupported content type")

stored_name = f"{uuid4().hex}.{ext}"
uploaded.save(upload_dir / stored_name)
""",
            defense_notes=[
                "사용자 제공 파일명을 그대로 신뢰하지 않습니다.",
                "파일은 실행 불가능한 디렉터리에 저장해야 합니다.",
                "업로드 검증은 확장자, MIME, 크기, 저장 경로를 함께 확인해야 합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="위험 확장자만 블랙리스트",
            goal="일부 확장자만 차단하는 방식이 왜 부족한지 이해합니다.",
            form_fields=UPLOAD_FIELDS,
            hints=[
                "블랙리스트는 빠뜨린 확장자나 이중 확장자에 취약할 수 있습니다.",
                "허용할 파일 형식을 정하는 allowlist가 더 안전합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 몇 가지 위험해 보이는 확장자만 차단합니다.

blocked = {"php", "py", "sh", "exe"}
ext = filename.rsplit(".", 1)[-1].lower()

if ext in blocked:
    raise ValueError("blocked file extension")

uploaded.save(upload_dir / filename)
""",
            secure_code="""# 안전한 코드
# 차단 목록이 아니라 허용 목록을 기준으로 판단합니다.

allowed = {"png", "jpg", "jpeg", "gif"}
ext = get_extension(filename)

if ext not in allowed:
    raise ValueError("unsupported file type")
""",
            defense_notes=[
                "블랙리스트 방식은 누락과 우회 가능성이 큽니다.",
                "업로드 정책은 금지할 것을 나열하기보다 허용할 것을 명확히 정하는 편이 안전합니다.",
                "파일명 전체가 아니라 실제 최종 확장자를 기준으로 판단해야 합니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="MIME 타입만 검사",
            goal="클라이언트가 보낸 MIME 타입만 믿는 방식이 부족한 이유를 이해합니다.",
            form_fields=UPLOAD_FIELDS,
            hints=[
                "MIME 타입은 요청 헤더에 포함된 값이라 신뢰 경계 밖의 데이터입니다.",
                "확장자와 MIME을 함께 확인해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# content_type만 보고 이미지라고 판단합니다.

if uploaded.content_type.startswith("image/"):
    uploaded.save(upload_dir / uploaded.filename)
""",
            secure_code="""# 안전한 코드
# 확장자 allowlist와 MIME allowlist를 함께 확인합니다.

ext = get_extension(uploaded.filename)

if ext not in {"png", "jpg", "jpeg", "gif"}:
    raise ValueError("unsupported extension")

if uploaded.content_type not in {"image/png", "image/jpeg", "image/gif"}:
    raise ValueError("unsupported content type")
""",
            defense_notes=[
                "MIME 타입은 단독 검증 기준으로 부족합니다.",
                "파일 확장자와 MIME 타입을 함께 확인해야 합니다.",
                "필요하면 실제 파일 시그니처 검증도 추가할 수 있습니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="거의 안전하지만 파일명 처리 결함",
            goal="확장자와 MIME은 검사하지만 원본 파일명을 유지하는 실수를 확인합니다.",
            form_fields=UPLOAD_FIELDS,
            hints=[
                "확장자와 MIME 검사는 어느 정도 되어 있습니다.",
                "하지만 저장 파일명은 어떤 방식으로 만들어지는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 확장자와 MIME은 확인하지만 원본 파일명을 저장명으로 사용합니다.
# 같은 이름의 파일이 있으면 덮어쓸 수 있습니다.

if ext in allowed_extensions and uploaded.content_type in allowed_mime_types:
    safe_name = secure_filename(uploaded.filename)
    uploaded.save(upload_dir / safe_name)
""",
            secure_code="""# 안전한 코드
# 원본 파일명은 메타데이터로만 보관하고, 저장 파일명은 랜덤하게 만듭니다.

stored_name = f"{uuid4().hex}.{ext}"
uploaded.save(upload_dir / stored_name)
""",
            defense_notes=[
                "원본 파일명은 충돌, 혼동, 덮어쓰기 문제를 만들 수 있습니다.",
                "저장 파일명은 서버에서 랜덤하게 생성하는 편이 안전합니다.",
                "원본 이름은 화면 표시나 DB 메타데이터 용도로만 사용합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="확장자 allowlist, MIME allowlist, 크기 제한, 랜덤 파일명, 제한된 저장 경로를 적용합니다.",
            form_fields=UPLOAD_FIELDS,
            hints=[
                "저장 경로는 instance/uploads/file-upload/ 내부로 고정됩니다.",
                "저장 파일명은 사용자가 정하지 않습니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# 원본 파일명을 저장명으로 사용해서 충돌과 덮어쓰기 문제가 남았습니다.

safe_name = secure_filename(uploaded.filename)
uploaded.save(upload_dir / safe_name)
""",
            secure_code="""# 안전한 코드
# 허용된 이미지 파일만 랜덤 파일명으로 제한된 디렉터리에 저장합니다.

uploaded = request.files["upload_file"]

ext = get_extension(uploaded.filename)
if ext not in {"png", "jpg", "jpeg", "gif"}:
    raise ValueError("unsupported extension")

if uploaded.content_type not in {"image/png", "image/jpeg", "image/gif"}:
    raise ValueError("unsupported content type")

content = uploaded.read()
if len(content) > 512 * 1024:
    raise ValueError("file too large")

stored_name = f"{uuid4().hex}.{ext}"
safe_path = upload_dir / stored_name
safe_path.write_bytes(content)
""",
            defense_notes=[
                "확장자 allowlist를 사용합니다.",
                "MIME 타입 allowlist를 함께 확인합니다.",
                "파일 크기를 제한합니다.",
                "저장 파일명은 랜덤하게 생성합니다.",
                "업로드 파일은 제한된 디렉터리에만 저장합니다.",
                "실제 운영에서는 업로드 디렉터리에서 스크립트 실행을 비활성화해야 합니다.",
            ],
        ),
    },
)


def get_lab(lab_id):
    """
    File Upload 카테고리의 Lab을 반환합니다.
    """

    if lab_id == FILE_UPLOAD_LAB.lab_id:
        return FILE_UPLOAD_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 File Upload Lab Level을 실행합니다.
    """

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 File Upload Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    files = files or {}
    uploaded = files.get("upload_file")
    display_name = form.get("display_name", "").strip()

    if not uploaded or not isinstance(uploaded, FileStorage) or not uploaded.filename:
        return {
            "kind": "file-upload",
            "status": "empty",
            "message": "업로드할 파일을 선택하세요.",
            "files": [],
            "rows": [],
        }

    return _handle_upload(level, uploaded, display_name)


def _handle_upload(level, uploaded, display_name):
    """
    Level별 업로드 판단 로직입니다.

    Level 1~4는 취약한 판단 로직을 보여주지만,
    실제 저장은 항상 instance/uploads/file-upload/ 아래에서만 수행합니다.
    """

    original_name = uploaded.filename
    content_type = uploaded.content_type or "application/octet-stream"
    ext = _get_extension(original_name)

    content = uploaded.read()
    size = len(content)

    accepted = False
    reasons = []

    if level == 1:
        accepted = True
        reasons.append("Level 1: 검증 없이 업로드를 허용했습니다.")

    elif level == 2:
        if ext in BLOCKED_EXTENSIONS:
            reasons.append(f"Level 2: 블랙리스트 확장자 '{ext}'가 차단되었습니다.")
        else:
            accepted = True
            reasons.append("Level 2: 블랙리스트에 없는 확장자라서 허용되었습니다.")

    elif level == 3:
        if content_type.startswith("image/"):
            accepted = True
            reasons.append("Level 3: MIME 타입이 image/로 시작해서 허용되었습니다.")
        else:
            reasons.append("Level 3: MIME 타입이 image/가 아니어서 차단되었습니다.")

    elif level == 4:
        if ext not in LOOSE_IMAGE_EXTENSIONS:
            reasons.append(f"Level 4: 허용되지 않은 확장자입니다: {ext or '(none)'}")
        elif content_type not in LOOSE_IMAGE_MIME_TYPES:
            reasons.append(f"Level 4: 허용되지 않은 MIME 타입입니다: {content_type}")
        else:
            accepted = True
            reasons.append("Level 4: 확장자와 MIME은 통과했지만 원본 파일명을 기반으로 저장합니다.")

    else:
        if size > MAX_DEMO_UPLOAD_SIZE:
            reasons.append("Level 5: 파일 크기 제한을 초과했습니다.")
        elif ext not in SAFE_IMAGE_EXTENSIONS:
            reasons.append(f"Level 5: 안전한 이미지 확장자가 아닙니다: {ext or '(none)'}")
        elif content_type not in SAFE_IMAGE_MIME_TYPES:
            reasons.append(f"Level 5: 허용된 이미지 MIME 타입이 아닙니다: {content_type}")
        else:
            accepted = True
            reasons.append("Level 5: 확장자, MIME, 크기 검증을 통과했습니다.")

    if not accepted:
        return {
            "kind": "file-upload",
            "status": "blocked",
            "message": "업로드가 차단되었습니다.",
            "files": [
                {
                    "original_name": original_name,
                    "stored_name": None,
                    "display_name": display_name or "(not provided)",
                    "content_type": content_type,
                    "size": size,
                    "accepted": False,
                    "reasons": reasons,
                }
            ],
            "rows": [],
        }

    stored_name = _store_file(level, original_name, ext, content)

    return {
        "kind": "file-upload",
        "status": "ok",
        "message": "파일이 로컬 실습 디렉터리에 저장되었습니다.",
        "files": [
            {
                "original_name": original_name,
                "stored_name": stored_name,
                "display_name": display_name or "(not provided)",
                "content_type": content_type,
                "size": size,
                "accepted": True,
                "reasons": reasons,
            }
        ],
        "rows": [],
    }


def _store_file(level, original_name, ext, content):
    """
    실제 저장 함수입니다.

    안전 제한:
    - 항상 current_app.config["UPLOAD_DIR"] 아래에 저장합니다.
    - Level 1~4에서도 프로젝트 밖으로 나가지 못하게 합니다.
    """

    upload_root = Path(current_app.config["UPLOAD_DIR"])
    lab_dir = upload_root / "file-upload" / f"level-{level}"
    lab_dir.mkdir(parents=True, exist_ok=True)

    if level == 5:
        stored_name = f"{uuid4().hex}.{ext}"
    elif level == 4:
        # 거의 안전하지만 원본 파일명 기반이라 충돌 가능성이 남는 예시입니다.
        stored_name = secure_filename(original_name) or f"upload-{uuid4().hex}"
    else:
        # Level 1~3은 취약한 설계를 설명하되,
        # 실제 저장은 최소한 secure_filename으로 프로젝트 내부에 고정합니다.
        visible_name = secure_filename(original_name) or "unnamed-upload"
        stored_name = f"level{level}-{visible_name}"

    target_path = lab_dir / stored_name
    target_path.write_bytes(content)

    return f"file-upload/level-{level}/{stored_name}"


def _get_extension(filename):
    """
    파일명에서 마지막 확장자를 추출합니다.
    """

    if not filename or "." not in filename:
        return ""

    return filename.rsplit(".", 1)[-1].lower().strip()


def _error_result(message):
    return {
        "kind": "file-upload",
        "status": "error",
        "message": message,
        "files": [],
        "rows": [],
    }