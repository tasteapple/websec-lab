# file: app/labs/information_disclosure.py

from app.labs.base import LabDefinition, LabFormField, LabLevel


DEMO_PROFILES = [
    {
        "id": 1,
        "username": "alice",
        "display_name": "Alice Kim",
        "email": "alice@example.test",
        "role": "customer",
        "status": "active",
        "phone": "+82-10-0000-0001",
        "department": "training",
        "password_hash_demo": "pbkdf2:sha256:demo-hash-for-alice",
        "api_token_demo": "demo-token-alice-not-real",
        "internal_note": "Alice is a normal training user.",
        "last_login_ip": "127.0.0.1",
    },
    {
        "id": 2,
        "username": "bob",
        "display_name": "Bob Park",
        "email": "bob@example.test",
        "role": "customer",
        "status": "active",
        "phone": "+82-10-0000-0002",
        "department": "training",
        "password_hash_demo": "pbkdf2:sha256:demo-hash-for-bob",
        "api_token_demo": "demo-token-bob-not-real",
        "internal_note": "Bob owns several demo orders.",
        "last_login_ip": "127.0.0.1",
    },
    {
        "id": 3,
        "username": "admin",
        "display_name": "Admin User",
        "email": "admin@example.test",
        "role": "admin",
        "status": "active",
        "phone": "+82-10-0000-0003",
        "department": "security",
        "password_hash_demo": "pbkdf2:sha256:demo-hash-for-admin",
        "api_token_demo": "demo-token-admin-not-real",
        "internal_note": "Admin demo profile. Do not expose internal fields.",
        "last_login_ip": "127.0.0.1",
    },
    {
        "id": 4,
        "username": "suspended_user",
        "display_name": "Suspended User",
        "email": "suspended@example.test",
        "role": "customer",
        "status": "suspended",
        "phone": "+82-10-0000-0004",
        "department": "training",
        "password_hash_demo": "pbkdf2:sha256:demo-hash-for-suspended",
        "api_token_demo": "demo-token-suspended-not-real",
        "internal_note": "Suspended account. Status should not be over-disclosed.",
        "last_login_ip": "127.0.0.1",
    },
]


DEBUG_CONFIG = {
    "APP_ENV": "local-training",
    "DEBUG": True,
    "DATABASE_URI": "sqlite:///instance/app.sqlite3",
    "UPLOAD_DIR": "instance/uploads",
    "EXTERNAL_NETWORK_ENABLED": False,
    "SECRET_KEY_STATUS": "configured-demo-value-hidden",
}


PROFILE_FIELDS = [
    LabFormField(
        name="viewer_username",
        label="Viewer username",
        placeholder="예: alice",
        help_text="현재 요청을 보낸 사용자라고 가정합니다. 예: alice, bob, admin",
    ),
    LabFormField(
        name="profile_username",
        label="Profile username",
        placeholder="예: alice",
        help_text="조회할 프로필 username입니다. 존재하지 않는 값도 입력해보세요.",
    ),
    LabFormField(
        name="debug_flag",
        label="Debug flag",
        placeholder="예: true 또는 false",
        help_text="Level 2에서 debug 정보를 클라이언트 입력으로 노출하는 문제를 보여줍니다.",
    ),
]


INFO_DISCLOSURE_LAB = LabDefinition(
    category="information-disclosure",
    lab_id="debug-profile",
    title="Debug Profile 정보 노출",
    summary="오류 메시지, debug 정보, 과도한 응답 필드가 어떻게 정보 노출로 이어지는지 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="상세 오류와 stack trace 유사 정보 노출",
            goal="존재하지 않는 프로필 조회 시 내부 파일 경로와 함수명이 응답에 노출되는 문제를 확인합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "profile_username에 존재하지 않는 값을 넣어보세요.",
                "사용자에게 보여줄 필요 없는 내부 함수명과 경로가 응답에 포함되는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 예외 내용을 그대로 응답에 포함합니다.

try:
    profile = find_profile(profile_username)
    return jsonify(profile)
except Exception as exc:
    return jsonify({
        "error": str(exc),
        "trace": traceback.format_exc(),
    }), 500
""",
            secure_code="""# 안전한 코드
# 클라이언트에는 일반 메시지를 반환하고, 상세 정보는 서버 로그에만 남깁니다.

try:
    profile = find_profile(profile_username)
except ProfileNotFound:
    current_app.logger.info("profile not found", extra={...})
    return jsonify({
        "message": "요청을 처리할 수 없습니다."
    }), 404
""",
            defense_notes=[
                "예외 메시지와 stack trace를 클라이언트에 그대로 반환하지 않습니다.",
                "내부 파일 경로, 함수명, SQL, config 이름은 공격자에게 힌트가 됩니다.",
                "상세 오류는 서버 로그에만 기록하고 응답은 일반화합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="debug flag로 config 노출",
            goal="클라이언트가 보낸 debug 파라미터를 믿고 내부 설정을 응답에 포함하는 문제를 확인합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "debug_flag에 true를 넣어보세요.",
                "응답에 애플리케이션 설정 비슷한 정보가 추가되는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 클라이언트가 debug=true를 보내면 내부 설정을 응답에 포함합니다.

payload = serialize_profile(profile)

if request.args.get("debug") == "true":
    payload["debug_config"] = current_app.config

return jsonify(payload)
""",
            secure_code="""# 안전한 코드
# debug 응답은 외부 사용자 요청으로 켤 수 없습니다.

payload = serialize_public_profile(profile)

return jsonify(payload)
""",
            defense_notes=[
                "debug 모드는 클라이언트 파라미터로 제어하지 않습니다.",
                "설정값, 경로, feature flag, 내부 endpoint 정보는 응답에 포함하지 않습니다.",
                "운영 환경에서는 debug endpoint 자체를 비활성화해야 합니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="과도한 API 응답 필드",
            goal="필요한 화면은 display_name과 email뿐인데 내부 필드까지 모두 반환하는 문제를 확인합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "정상 프로필을 조회해보세요.",
                "화면에 필요한 필드보다 훨씬 많은 필드가 응답되는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# ORM 객체 전체를 그대로 JSON으로 직렬화합니다.

profile = UserProfile.query.filter_by(username=username).first()

return jsonify(profile.__dict__)
""",
            secure_code="""# 안전한 코드
# 응답 필드를 명시적으로 allowlist합니다.

return jsonify({
    "username": profile.username,
    "display_name": profile.display_name,
    "email": profile.email,
})
""",
            defense_notes=[
                "API 응답은 필요한 필드만 명시적으로 반환합니다.",
                "`__dict__`, ORM 전체 직렬화, `SELECT *` 기반 응답은 피합니다.",
                "password hash, token, internal note, role 같은 내부 필드는 기본 응답에서 제외합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="거의 안전하지만 role/status/internal note 노출",
            goal="민감도가 높은 credential류는 제거했지만, role/status/internal note 같은 내부 운영 정보가 남는 문제를 확인합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "password hash와 token은 빠져 있습니다.",
                "하지만 일반 사용자에게 role, status, internal_note가 필요한지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# credential류는 제거했지만 내부 운영 필드는 여전히 반환합니다.

return jsonify({
    "username": profile.username,
    "display_name": profile.display_name,
    "email": profile.email,
    "role": profile.role,
    "status": profile.status,
    "internal_note": profile.internal_note,
})
""",
            secure_code="""# 안전한 코드
# 사용자 화면에 필요한 최소 필드만 반환합니다.

return jsonify({
    "username": profile.username,
    "display_name": profile.display_name,
    "email": profile.email,
})
""",
            defense_notes=[
                "credential만 제거했다고 충분하지 않습니다.",
                "role, status, 내부 메모, 운영 태그도 정보 노출이 될 수 있습니다.",
                "필드별 공개 필요성을 기준으로 응답 스키마를 설계합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="일반화된 오류 응답과 응답 필드 allowlist를 적용합니다.",
            form_fields=PROFILE_FIELDS,
            hints=[
                "존재하지 않는 사용자를 조회해도 내부 오류 정보가 노출되지 않습니다.",
                "정상 조회 시에도 공개 필드만 반환됩니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# 내부 운영 필드가 응답에 포함되었습니다.

payload = {
    "role": profile.role,
    "status": profile.status,
    "internal_note": profile.internal_note,
}
""",
            secure_code="""# 안전한 코드
# 응답 스키마를 명시적으로 제한하고 오류는 일반화합니다.

profile = find_profile(profile_username)

if profile is None:
    return jsonify({
        "message": "요청을 처리할 수 없습니다."
    }), 404

return jsonify({
    "username": profile.username,
    "display_name": profile.display_name,
    "email": profile.email,
})
""",
            defense_notes=[
                "오류 응답은 일반화합니다.",
                "응답 필드는 allowlist 방식으로 명시합니다.",
                "debug config와 내부 운영 필드는 클라이언트 응답에 포함하지 않습니다.",
                "로그에는 상세 정보를 남기되 사용자 응답과 분리합니다.",
            ],
        ),
    },
)


def get_lab(lab_id):
    """
    Information Disclosure 카테고리의 Lab을 반환합니다.
    """

    if lab_id == INFO_DISCLOSURE_LAB.lab_id:
        return INFO_DISCLOSURE_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 Information Disclosure Lab Level을 실행합니다.
    """

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 Information Disclosure Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    viewer_username = form.get("viewer_username", "").strip() or "alice"
    profile_username = form.get("profile_username", "").strip() or "alice"
    debug_flag = form.get("debug_flag", "").strip().lower()

    return _run_profile_lookup(level, viewer_username, profile_username, debug_flag)


def _run_profile_lookup(level, viewer_username, profile_username, debug_flag):
    viewer = _find_profile(viewer_username)
    profile = _find_profile(profile_username)

    reasons = []
    checks = {
        "generic_error": False,
        "debug_config_exposed": False,
        "field_allowlist": False,
        "overbroad_fields": False,
        "internal_fields_exposed": False,
    }

    if level == 1:
        checks["generic_error"] = False

        if profile is None:
            reasons.append("Level 1: 존재하지 않는 프로필에 대해 상세 오류와 stack trace 유사 정보를 반환했습니다.")

            return {
                "kind": "information-disclosure",
                "status": "error",
                "message": "정보 노출 흐름을 시뮬레이션했습니다.",
                "client_message": "ProfileLookupError: profile not found",
                "viewer": _public_viewer(viewer_username, viewer),
                "payload": None,
                "error_details": _fake_stack_trace(profile_username),
                "checks": checks,
                "reasons": reasons,
                "rows": [],
            }

        checks["overbroad_fields"] = True
        checks["internal_fields_exposed"] = True

        reasons.append("Level 1: 정상 조회에서도 profile 전체 필드를 반환했습니다.")

        return _ok_result(
            client_message="프로필을 반환했습니다.",
            viewer=_public_viewer(viewer_username, viewer),
            payload=_full_profile(profile),
            error_details=None,
            checks=checks,
            reasons=reasons,
        )

    if level == 2:
        checks["overbroad_fields"] = True

        if profile is None:
            reasons.append("Level 2: 프로필 없음 오류는 일반화하지 않았습니다.")

            return {
                "kind": "information-disclosure",
                "status": "error",
                "message": "정보 노출 흐름을 시뮬레이션했습니다.",
                "client_message": f"User profile '{profile_username}' does not exist",
                "viewer": _public_viewer(viewer_username, viewer),
                "payload": None,
                "error_details": {
                    "lookup_key": profile_username,
                    "model": "DemoProfile",
                    "query": "SELECT * FROM demo_profiles WHERE username = ?",
                },
                "checks": checks,
                "reasons": reasons,
                "rows": [],
            }

        payload = _normal_profile_plus_role(profile)

        if debug_flag in {"1", "true", "yes", "on"}:
            payload["debug_config"] = DEBUG_CONFIG
            checks["debug_config_exposed"] = True
            reasons.append("Level 2: 클라이언트 debug_flag 값 때문에 debug_config를 응답에 포함했습니다.")
        else:
            reasons.append("Level 2: debug_flag가 켜져 있지 않아 config는 포함하지 않았지만, 여전히 응답 필드가 넓습니다.")

        return _ok_result(
            client_message="프로필을 반환했습니다.",
            viewer=_public_viewer(viewer_username, viewer),
            payload=payload,
            error_details=None,
            checks=checks,
            reasons=reasons,
        )

    if level == 3:
        checks["overbroad_fields"] = True
        checks["internal_fields_exposed"] = True

        if profile is None:
            reasons.append("Level 3: 존재하지 않는 profile_username 값을 응답에 그대로 반영했습니다.")

            return {
                "kind": "information-disclosure",
                "status": "error",
                "message": "정보 노출 흐름을 시뮬레이션했습니다.",
                "client_message": f"No row found for username={profile_username}",
                "viewer": _public_viewer(viewer_username, viewer),
                "payload": None,
                "error_details": {
                    "profile_username": profile_username,
                    "available_demo_users": [item["username"] for item in DEMO_PROFILES],
                },
                "checks": checks,
                "reasons": reasons,
                "rows": [],
            }

        reasons.append("Level 3: ORM 객체 전체를 직렬화한 것처럼 과도한 필드를 반환했습니다.")

        return _ok_result(
            client_message="프로필 API 응답을 반환했습니다.",
            viewer=_public_viewer(viewer_username, viewer),
            payload=_full_profile(profile),
            error_details=None,
            checks=checks,
            reasons=reasons,
        )

    if level == 4:
        checks["field_allowlist"] = False
        checks["internal_fields_exposed"] = True

        if profile is None:
            checks["generic_error"] = True
            reasons.append("Level 4: 오류 메시지는 일반화했지만 응답 스키마는 아직 완전히 최소화되지 않았습니다.")

            return _blocked_result(
                client_message="요청을 처리할 수 없습니다.",
                viewer=_public_viewer(viewer_username, viewer),
                payload=None,
                error_details=None,
                checks=checks,
                reasons=reasons,
            )

        reasons.append("Level 4: password hash와 token은 제거했습니다.")
        reasons.append("하지만 role, status, internal_note 같은 내부 운영 필드가 여전히 포함됩니다.")

        return _ok_result(
            client_message="프로필을 반환했습니다.",
            viewer=_public_viewer(viewer_username, viewer),
            payload=_semi_safe_profile(profile),
            error_details=None,
            checks=checks,
            reasons=reasons,
        )

    checks["generic_error"] = True
    checks["field_allowlist"] = True

    if profile is None:
        reasons.append("Level 5: 존재하지 않는 프로필에도 일반화된 오류만 반환했습니다.")

        return _blocked_result(
            client_message="요청을 처리할 수 없습니다.",
            viewer=_public_viewer(viewer_username, viewer),
            payload=None,
            error_details=None,
            checks=checks,
            reasons=reasons,
        )

    reasons.append("Level 5: 공개가 필요한 필드만 allowlist로 반환했습니다.")
    reasons.append("Level 5: debug config, 내부 메모, credential류 필드는 제외했습니다.")

    return _ok_result(
        client_message="프로필을 반환했습니다.",
        viewer=_public_viewer(viewer_username, viewer),
        payload=_safe_public_profile(profile),
        error_details=None,
        checks=checks,
        reasons=reasons,
    )


def _find_profile(username):
    for profile in DEMO_PROFILES:
        if profile["username"] == username:
            return profile

    return None


def _public_viewer(viewer_username, viewer):
    if viewer is None:
        return {
            "requested_viewer": viewer_username,
            "exists": False,
            "username": "(none)",
            "role": "(none)",
        }

    return {
        "requested_viewer": viewer_username,
        "exists": True,
        "username": viewer["username"],
        "role": viewer["role"],
    }


def _full_profile(profile):
    """
    과도하게 많은 필드를 반환하는 취약 응답 예시입니다.

    실제 비밀값은 아니며 demo 값만 포함합니다.
    """

    return dict(profile)


def _normal_profile_plus_role(profile):
    return {
        "id": profile["id"],
        "username": profile["username"],
        "display_name": profile["display_name"],
        "email": profile["email"],
        "role": profile["role"],
        "status": profile["status"],
    }


def _semi_safe_profile(profile):
    return {
        "username": profile["username"],
        "display_name": profile["display_name"],
        "email": profile["email"],
        "role": profile["role"],
        "status": profile["status"],
        "internal_note": profile["internal_note"],
    }


def _safe_public_profile(profile):
    return {
        "username": profile["username"],
        "display_name": profile["display_name"],
        "email": profile["email"],
    }


def _fake_stack_trace(profile_username):
    """
    실제 stack trace가 아니라 교육용으로 만든 유사 정보입니다.
    """

    return {
        "exception": "ProfileLookupError",
        "message": f"profile not found: {profile_username}",
        "trace": [
            'File "app/blueprints/labs.py", line 72, in lab_level',
            'File "app/labs/information_disclosure.py", line 214, in run_level',
            'File "app/labs/information_disclosure.py", line 236, in _run_profile_lookup',
            "ProfileLookupError: profile not found",
        ],
        "local_variables": {
            "profile_username": profile_username,
            "table": "demo_profiles",
            "query_hint": "lookup by username",
        },
    }


def _ok_result(client_message, viewer, payload, error_details, checks, reasons):
    return {
        "kind": "information-disclosure",
        "status": "ok",
        "message": "정보 노출 흐름을 시뮬레이션했습니다.",
        "client_message": client_message,
        "viewer": viewer,
        "payload": payload,
        "error_details": error_details,
        "checks": checks,
        "reasons": reasons,
        "rows": [],
    }


def _blocked_result(client_message, viewer, payload, error_details, checks, reasons):
    return {
        "kind": "information-disclosure",
        "status": "blocked",
        "message": "정보 노출 흐름을 시뮬레이션했습니다.",
        "client_message": client_message,
        "viewer": viewer,
        "payload": payload,
        "error_details": error_details,
        "checks": checks,
        "reasons": reasons,
        "rows": [],
    }


def _error_result(message):
    return {
        "kind": "information-disclosure",
        "status": "error",
        "message": message,
        "client_message": "",
        "viewer": None,
        "payload": None,
        "error_details": None,
        "checks": {},
        "reasons": [],
        "rows": [],
    }