# file: app/labs/ssrf.py

from urllib.parse import urlparse

from app.labs.base import LabDefinition, LabFormField, LabLevel


MOCK_RESPONSES = {
    "/mock/public/status": {
        "scope": "public",
        "service": "status",
        "message": "public mock service is reachable",
    },
    "/mock/internal/profile": {
        "scope": "internal",
        "service": "profile",
        "username": "training-user",
        "role": "customer",
    },
    "/mock/internal/metadata": {
        "scope": "internal",
        "service": "metadata",
        "instance_id": "local-training-instance",
        "environment": "local-only",
        "note": "mock metadata for SSRF training",
    },
    "/mock/internal/admin-note": {
        "scope": "internal",
        "service": "admin-note",
        "message": "this mock endpoint represents internal-only data",
    },
}


SSRF_FIELDS = [
    LabFormField(
        name="target_url",
        label="Target URL",
        placeholder="예: http://127.0.0.1:5000/mock/public/status",
        help_text="실제 외부 요청은 하지 않고, 로컬 mock endpoint만 시뮬레이션합니다.",
    )
]


SSRF_LAB = LabDefinition(
    category="ssrf",
    lab_id="ssrf-local-metadata",
    title="로컬 메타데이터 조회 시뮬레이션",
    summary="서버가 사용자 입력 URL을 가져올 때 발생할 수 있는 SSRF 위험을 로컬 mock으로 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="사용자 입력 URL을 그대로 신뢰",
            goal="서버가 사용자가 지정한 URL을 그대로 요청하면 내부 endpoint 접근 문제가 생길 수 있음을 이해합니다.",
            form_fields=SSRF_FIELDS,
            hints=[
                "입력 URL의 host와 path가 어떻게 처리되는지 확인하세요.",
                "이 실습은 실제 네트워크 요청이 아니라 mock 응답만 사용합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자 입력 URL을 검증 없이 서버가 가져옵니다.

target_url = request.form["target_url"]
response = fetch_url(target_url)
""",
            secure_code="""# 안전한 코드
# 사용자 입력 URL을 직접 요청하지 않고, 서버가 허용한 대상만 선택하게 합니다.

allowed_targets = {
    "public-status": "/mock/public/status",
}

target = allowed_targets[user_choice]
response = fetch_local_mock(target)
""",
            defense_notes=[
                "서버가 사용자 입력 URL을 직접 요청하지 않게 설계합니다.",
                "내부 IP, localhost, metadata endpoint 접근을 차단해야 합니다.",
                "가능하면 URL 직접 입력 대신 서버 측 allowlist key를 사용합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="문자열 블랙리스트 필터",
            goal="localhost 같은 문자열만 차단하는 방식이 부족하다는 점을 이해합니다.",
            form_fields=SSRF_FIELDS,
            hints=[
                "URL에는 host, scheme, path 등 여러 구성 요소가 있습니다.",
                "문자열 포함 여부만으로 URL 보안을 판단하기 어렵습니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# localhost라는 문자열만 차단합니다.

if "localhost" in target_url:
    raise ValueError("blocked")

response = fetch_url(target_url)
""",
            secure_code="""# 안전한 코드
# URL을 파싱한 뒤 허용 scheme, host, path를 명확히 확인합니다.

parsed = urlparse(target_url)

if parsed.scheme != "http":
    raise ValueError("unsupported scheme")

if parsed.hostname != "127.0.0.1":
    raise ValueError("unsupported host")

if parsed.path not in allowed_paths:
    raise ValueError("unsupported path")
""",
            defense_notes=[
                "블랙리스트는 누락과 우회 가능성이 큽니다.",
                "URL은 문자열 검색이 아니라 파싱 후 검증해야 합니다.",
                "host만 보지 말고 scheme, port, path도 함께 확인합니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="host만 확인하는 부분 방어",
            goal="host만 허용해도 path 검증이 없으면 내부 리소스 접근이 남는다는 점을 확인합니다.",
            form_fields=SSRF_FIELDS,
            hints=[
                "host는 허용된 것처럼 보입니다.",
                "하지만 path는 어떤 endpoint든 접근 가능한지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# host만 확인하고 path는 제한하지 않습니다.

parsed = urlparse(target_url)

if parsed.hostname != "127.0.0.1":
    raise ValueError("blocked host")

response = fetch_url(target_url)
""",
            secure_code="""# 안전한 코드
# host뿐 아니라 path도 allowlist로 제한합니다.

allowed_paths = {
    "/mock/public/status",
}

if parsed.path not in allowed_paths:
    raise ValueError("blocked path")
""",
            defense_notes=[
                "host 검증만으로는 충분하지 않습니다.",
                "같은 host 안에도 공개 endpoint와 내부 endpoint가 섞일 수 있습니다.",
                "path allowlist를 함께 적용해야 합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="거의 안전하지만 prefix 검증 결함",
            goal="URL prefix만 확인하는 방식의 경계 검증 문제를 이해합니다.",
            form_fields=SSRF_FIELDS,
            hints=[
                "문자열이 특정 prefix로 시작하는지만 봅니다.",
                "URL은 정규화와 파싱을 거쳐 구조적으로 검증해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# URL이 허용 prefix로 시작하는지만 확인합니다.

allowed_prefix = "http://127.0.0.1:5000/mock/"

if not target_url.startswith(allowed_prefix):
    raise ValueError("blocked")

response = fetch_url(target_url)
""",
            secure_code="""# 안전한 코드
# 파싱 후 scheme, host, port, path를 각각 확인합니다.

parsed = urlparse(target_url)

if parsed.scheme != "http":
    raise ValueError("blocked scheme")

if parsed.hostname != "127.0.0.1":
    raise ValueError("blocked host")

if parsed.port != 5000:
    raise ValueError("blocked port")

if parsed.path not in allowed_paths:
    raise ValueError("blocked path")
""",
            defense_notes=[
                "prefix 검증은 URL 구조를 충분히 이해하지 못합니다.",
                "URL은 반드시 파싱해서 구성 요소별로 검증합니다.",
                "허용 path는 구체적으로 좁게 잡습니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="외부 URL 입력 대신 서버 측 allowlist 대상만 조회하는 안전한 설계를 적용합니다.",
            form_fields=SSRF_FIELDS,
            hints=[
                "Level 5에서는 공개 mock endpoint만 허용됩니다.",
                "내부 endpoint는 같은 localhost에 있어도 차단됩니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# URL prefix 검증에 의존했습니다.

if target_url.startswith("http://127.0.0.1:5000/mock/"):
    response = fetch_url(target_url)
""",
            secure_code="""# 안전한 코드
# 허용 가능한 mock path를 서버에서 직접 관리합니다.

allowed_paths = {
    "/mock/public/status",
}

parsed = urlparse(target_url)

if parsed.scheme != "http":
    raise ValueError("blocked scheme")

if parsed.hostname != "127.0.0.1":
    raise ValueError("blocked host")

if parsed.port != 5000:
    raise ValueError("blocked port")

if parsed.path not in allowed_paths:
    raise ValueError("blocked path")

response = fetch_local_mock(parsed.path)
""",
            defense_notes=[
                "사용자 입력 URL을 그대로 서버가 요청하지 않습니다.",
                "scheme, host, port, path를 모두 검증합니다.",
                "내부 endpoint는 명시적으로 차단합니다.",
                "가능하면 URL 입력 대신 서버 측 key 선택 방식으로 바꿉니다.",
                "이 실습은 실제 네트워크 요청 없이 mock 응답만 사용합니다.",
            ],
        ),
    },
)


def get_lab(lab_id):
    """
    SSRF 카테고리의 Lab을 반환합니다.
    """

    if lab_id == SSRF_LAB.lab_id:
        return SSRF_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 SSRF Lab Level을 실행합니다.

    실제 HTTP 요청은 하지 않고, 입력 URL을 분석한 뒤 MOCK_RESPONSES에서만 응답합니다.
    """

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 SSRF Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    target_url = form.get("target_url", "").strip()

    if not target_url:
        return {
            "kind": "ssrf",
            "status": "empty",
            "message": "조회할 URL을 입력하세요.",
            "request": None,
            "response": None,
            "rows": [],
        }

    return _simulate_fetch(level, target_url)


def _simulate_fetch(level, target_url):
    """
    Level별 SSRF 방어 로직을 시뮬레이션합니다.

    외부 네트워크 요청은 수행하지 않습니다.
    """

    parsed = urlparse(target_url)
    reasons = []
    allowed = False

    if level == 1:
        allowed = True
        reasons.append("Level 1: URL을 검증 없이 허용했습니다.")

    elif level == 2:
        if "localhost" in target_url.lower():
            reasons.append("Level 2: localhost 문자열이 포함되어 차단되었습니다.")
        else:
            allowed = True
            reasons.append("Level 2: localhost 문자열이 없어 허용되었습니다.")

    elif level == 3:
        if parsed.hostname != "127.0.0.1":
            reasons.append(f"Level 3: 허용되지 않은 host입니다: {parsed.hostname}")
        else:
            allowed = True
            reasons.append("Level 3: host가 127.0.0.1이라 허용되었습니다. path 검증은 없습니다.")

    elif level == 4:
        allowed_prefix = "http://127.0.0.1:5000/mock/"

        if not target_url.startswith(allowed_prefix):
            reasons.append("Level 4: 허용 prefix로 시작하지 않아 차단되었습니다.")
        else:
            allowed = True
            reasons.append("Level 4: 허용 prefix로 시작해서 허용되었습니다.")

    else:
        allowed_paths = {
            "/mock/public/status",
        }

        if parsed.scheme != "http":
            reasons.append(f"Level 5: 허용되지 않은 scheme입니다: {parsed.scheme}")
        elif parsed.hostname != "127.0.0.1":
            reasons.append(f"Level 5: 허용되지 않은 host입니다: {parsed.hostname}")
        elif parsed.port != 5000:
            reasons.append(f"Level 5: 허용되지 않은 port입니다: {parsed.port}")
        elif parsed.path not in allowed_paths:
            reasons.append(f"Level 5: 허용되지 않은 path입니다: {parsed.path}")
        else:
            allowed = True
            reasons.append("Level 5: scheme, host, port, path 검증을 모두 통과했습니다.")

    request_info = {
        "target_url": target_url,
        "scheme": parsed.scheme or "(none)",
        "hostname": parsed.hostname or "(none)",
        "port": parsed.port or "(none)",
        "path": parsed.path or "(none)",
        "query": parsed.query or "(none)",
        "allowed": allowed,
        "reasons": reasons,
    }

    if not allowed:
        return {
            "kind": "ssrf",
            "status": "blocked",
            "message": "요청이 차단되었습니다.",
            "request": request_info,
            "response": None,
            "rows": [],
        }

    response = _fetch_local_mock(parsed.path)

    if response is None:
        return {
            "kind": "ssrf",
            "status": "error",
            "message": "이 실습은 등록된 mock endpoint만 응답합니다.",
            "request": request_info,
            "response": {
                "error": "mock endpoint not found",
            },
            "rows": [],
        }

    return {
        "kind": "ssrf",
        "status": "ok",
        "message": "로컬 mock endpoint 응답을 반환했습니다.",
        "request": request_info,
        "response": response,
        "rows": [],
    }


def _fetch_local_mock(path):
    """
    실제 HTTP 요청 대신 로컬 dict에서 mock 응답을 조회합니다.
    """

    return MOCK_RESPONSES.get(path)


def _error_result(message):
    return {
        "kind": "ssrf",
        "status": "error",
        "message": message,
        "request": None,
        "response": None,
        "rows": [],
    }