# file: app/labs/access_control.py

from sqlalchemy import text

from app.extensions import db
from app.labs.base import LabDefinition, LabFormField, LabLevel


DEMO_USERS = [
    {
        "id": 1,
        "username": "alice",
        "role": "customer",
        "status": "active",
    },
    {
        "id": 2,
        "username": "bob",
        "role": "customer",
        "status": "active",
    },
    {
        "id": 3,
        "username": "admin",
        "role": "admin",
        "status": "active",
    },
    {
        "id": 4,
        "username": "support_lee",
        "role": "support",
        "status": "active",
    },
    {
        "id": 5,
        "username": "suspended_user",
        "role": "customer",
        "status": "suspended",
    },
]


DEMO_ORDERS = [
    {
        "id": 1001,
        "owner_user_id": 1,
        "order_number": "ORD-A-1001",
        "item_name": "Security Notebook",
        "total_cents": 12900,
        "status": "paid",
        "internal_note": "Alice public training order.",
    },
    {
        "id": 1002,
        "owner_user_id": 1,
        "order_number": "ORD-A-1002",
        "item_name": "Premium Workshop Ticket",
        "total_cents": 99000,
        "status": "reserved",
        "internal_note": "Alice workshop access should be owner-only.",
    },
    {
        "id": 2001,
        "owner_user_id": 2,
        "order_number": "ORD-B-2001",
        "item_name": "Local Lab Hoodie",
        "total_cents": 45900,
        "status": "paid",
        "internal_note": "Bob order. Alice should not access this.",
    },
    {
        "id": 2002,
        "owner_user_id": 2,
        "order_number": "ORD-B-2002",
        "item_name": "USB Practice Kit",
        "total_cents": 34900,
        "status": "processing",
        "internal_note": "Bob hardware kit tracking note.",
    },
    {
        "id": 9001,
        "owner_user_id": 3,
        "order_number": "ORD-ADM-9001",
        "item_name": "Internal Debug Mug",
        "total_cents": 1,
        "status": "internal",
        "internal_note": "Admin-only internal demo order. No real secret value.",
    },
]


USER_ID_FIELDS = [
    LabFormField(
        name="viewer_username",
        label="Viewer username",
        placeholder="예: alice",
        help_text="현재 요청을 보낸 사용자라고 가정합니다. 예: alice, bob, admin, support_lee",
    ),
    LabFormField(
        name="user_id",
        label="Requested user_id",
        field_type="number",
        placeholder="예: 1",
        help_text="조회할 주문 소유자 user_id입니다. Level 1에서 이 값을 그대로 신뢰합니다.",
    ),
]


ORDER_ID_FIELDS = [
    LabFormField(
        name="viewer_username",
        label="Viewer username",
        placeholder="예: alice",
        help_text="현재 요청을 보낸 사용자라고 가정합니다. 예: alice, bob, admin, support_lee",
    ),
    LabFormField(
        name="order_id",
        label="Order ID",
        field_type="number",
        placeholder="예: 1001",
        help_text="조회할 주문 ID입니다. 다른 사용자의 주문 ID를 입력했을 때 Level별 차이를 확인합니다.",
    ),
]


ROLE_TAMPER_FIELDS = [
    LabFormField(
        name="viewer_username",
        label="Viewer username",
        placeholder="예: alice",
        help_text="현재 요청을 보낸 사용자라고 가정합니다.",
    ),
    LabFormField(
        name="order_id",
        label="Order ID",
        field_type="number",
        placeholder="예: 2001",
        help_text="조회할 주문 ID입니다.",
    ),
    LabFormField(
        name="claimed_role",
        label="Claimed role",
        placeholder="예: customer 또는 admin",
        help_text="Level 3에서 클라이언트가 보낸 role 값을 신뢰하는 문제를 보여줍니다.",
    ),
]


ACCESS_CONTROL_LAB = LabDefinition(
    category="access-control",
    lab_id="idor-order-view",
    title="주문 상세 IDOR",
    summary="주문 상세 조회에서 객체 소유자 검증과 role 검증이 왜 필요한지 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="user_id 파라미터를 그대로 신뢰",
            goal="요청자가 보낸 user_id로 주문 목록을 조회하면 다른 사용자의 주문을 볼 수 있음을 확인합니다.",
            form_fields=USER_ID_FIELDS,
            hints=[
                "viewer_username과 requested user_id가 서로 일치하는지 확인하지 않습니다.",
                "alice가 user_id=2를 요청하면 어떤 주문이 보이는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 현재 로그인 사용자와 관계없이 user_id 파라미터를 그대로 신뢰합니다.

user_id = request.args["user_id"]

orders = Order.query.filter_by(
    owner_user_id=user_id,
).all()
""",
            secure_code="""# 안전한 코드
# user_id는 클라이언트에서 받지 않고 서버 세션의 현재 사용자 ID를 사용합니다.

current_user_id = session["user_id"]

orders = Order.query.filter_by(
    owner_user_id=current_user_id,
).all()
""",
            defense_notes=[
                "객체 소유자 식별자는 클라이언트 입력보다 서버 측 인증 상태에서 가져와야 합니다.",
                "사용자가 임의로 user_id를 바꿔도 다른 객체를 볼 수 없어야 합니다.",
                "목록 조회와 상세 조회 모두 authorization 검사를 적용해야 합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="order_id 직접 접근",
            goal="주문 ID만 알면 소유자 검증 없이 상세 정보를 볼 수 있는 IDOR 문제를 확인합니다.",
            form_fields=ORDER_ID_FIELDS,
            hints=[
                "주문 ID가 존재하는지만 확인합니다.",
                "viewer가 해당 주문의 owner인지 확인하는지 보세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# order_id로 주문을 찾은 뒤 owner 검증 없이 반환합니다.

order_id = request.args["order_id"]

order = Order.query.get(order_id)

return render_template("order.html", order=order)
""",
            secure_code="""# 안전한 코드
# 주문이 현재 사용자의 소유인지 확인합니다.

order = Order.query.get(order_id)

if order.owner_user_id != current_user.id:
    abort(403)

return render_template("order.html", order=order)
""",
            defense_notes=[
                "객체 ID는 비밀값이 아닙니다.",
                "ID를 알 수 없게 만드는 것보다 접근 권한 검증이 중요합니다.",
                "상세 조회에서는 object-level authorization을 반드시 수행합니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="클라이언트 role 파라미터 신뢰",
            goal="role 값을 클라이언트가 보낸 값으로 판단하면 권한 상승이 가능함을 이해합니다.",
            form_fields=ROLE_TAMPER_FIELDS,
            hints=[
                "claimed_role 값을 admin으로 바꿨을 때 결과를 확인하세요.",
                "권한은 클라이언트 입력이 아니라 서버의 신뢰 가능한 저장소에서 가져와야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# role 값을 클라이언트 파라미터에서 가져옵니다.

claimed_role = request.form["role"]

if claimed_role == "admin":
    return show_any_order(order_id)

return show_order_if_owner(order_id, current_user)
""",
            secure_code="""# 안전한 코드
# role은 서버 DB나 세션의 신뢰 가능한 인증 정보에서 가져옵니다.

server_role = current_user.role

if server_role == "admin":
    return show_any_order(order_id)

return show_order_if_owner(order_id, current_user)
""",
            defense_notes=[
                "role, is_admin, user_id 같은 권한 관련 값은 클라이언트 입력을 신뢰하지 않습니다.",
                "권한 판단은 서버가 관리하는 인증/인가 데이터로 수행합니다.",
                "프론트엔드에서 버튼을 숨기는 것은 접근 제어가 아닙니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="서버 role은 확인하지만 support 권한이 과도함",
            goal="서버 측 role을 확인해도 role 권한 범위가 너무 넓으면 객체 수준 권한 문제가 남는다는 점을 확인합니다.",
            form_fields=ORDER_ID_FIELDS,
            hints=[
                "support_lee로 다른 사용자의 주문을 조회해보세요.",
                "support 역할이 모든 주문의 내부 메모까지 볼 필요가 있는지 생각해보세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# role은 서버에서 가져오지만 support에게 모든 주문 상세를 허용합니다.

if current_user.role in {"admin", "support"}:
    return show_any_order(order_id)

if order.owner_user_id == current_user.id:
    return show_order(order_id)

abort(403)
""",
            secure_code="""# 안전한 코드
# role별로 접근 가능한 객체와 필드를 좁게 제한합니다.

if current_user.role == "admin":
    return show_full_order(order_id)

if order.owner_user_id == current_user.id:
    return show_owner_order(order_id)

# support는 별도 배정된 ticket/order만 제한적으로 접근
if is_assigned_support(current_user, order):
    return show_redacted_order(order_id)

abort(403)
""",
            defense_notes=[
                "서버 role 검증이 있어도 권한 범위가 과도하면 문제가 됩니다.",
                "role-based access control과 object-level authorization을 함께 적용해야 합니다.",
                "필드 단위 접근 제어도 고려해야 합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="서버 측 viewer 정보와 객체 소유자 검증을 함께 적용합니다.",
            form_fields=ORDER_ID_FIELDS,
            hints=[
                "alice는 bob의 주문을 볼 수 없습니다.",
                "admin은 모든 주문을 볼 수 있습니다.",
                "support는 이 demo의 full order view에서는 허용하지 않습니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# support role에게 모든 주문 상세를 허용했습니다.

if current_user.role in {"admin", "support"}:
    return show_any_order(order_id)
""",
            secure_code="""# 안전한 코드
# full order view는 admin 또는 owner만 허용합니다.

viewer = get_current_user_from_server_session()
order = Order.query.get(order_id)

if viewer.status != "active":
    abort(403)

if viewer.role == "admin":
    return show_full_order(order)

if order.owner_user_id == viewer.id:
    return show_owner_order(order)

abort(403)
""",
            defense_notes=[
                "객체 접근은 현재 사용자와 대상 객체의 관계를 기준으로 검증합니다.",
                "권한 관련 값은 서버 측 신뢰 저장소에서 가져옵니다.",
                "admin, support, owner의 권한 범위를 명확히 분리합니다.",
                "목록, 상세, 수정, 삭제 API에 모두 object-level authorization을 적용합니다.",
            ],
        ),
    },
)


def ensure_access_demo_tables():
    """
    Access Control 실습용 user/order 테이블을 준비합니다.
    """

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS access_demo_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
    )

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS access_demo_orders (
                id INTEGER PRIMARY KEY,
                owner_user_id INTEGER NOT NULL,
                order_number TEXT NOT NULL UNIQUE,
                item_name TEXT NOT NULL,
                total_cents INTEGER NOT NULL,
                status TEXT NOT NULL,
                internal_note TEXT NOT NULL
            )
            """
        )
    )

    user_count = db.session.execute(
        text("SELECT COUNT(*) FROM access_demo_users")
    ).scalar_one()

    order_count = db.session.execute(
        text("SELECT COUNT(*) FROM access_demo_orders")
    ).scalar_one()

    if user_count == 0:
        _insert_demo_users()

    if order_count == 0:
        _insert_demo_orders()

    db.session.commit()


def reset_access_demo_tables():
    """
    seed 실행 시 Access Control demo table을 초기화하기 위한 함수입니다.
    """

    db.session.execute(text("DROP TABLE IF EXISTS access_demo_orders"))
    db.session.execute(text("DROP TABLE IF EXISTS access_demo_users"))
    db.session.flush()
    ensure_access_demo_tables()


def get_lab(lab_id):
    """
    Access Control 카테고리의 Lab을 반환합니다.
    """

    if lab_id == ACCESS_CONTROL_LAB.lab_id:
        return ACCESS_CONTROL_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 Access Control Lab Level을 실행합니다.
    """

    ensure_access_demo_tables()

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 Access Control Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    viewer_username = form.get("viewer_username", "").strip() or "alice"

    if level == 1:
        requested_user_id = _int_or_none(form.get("user_id", ""))
        return _run_level_1(viewer_username, requested_user_id)

    if level == 2:
        order_id = _int_or_none(form.get("order_id", ""))
        return _run_level_2(viewer_username, order_id)

    if level == 3:
        order_id = _int_or_none(form.get("order_id", ""))
        claimed_role = form.get("claimed_role", "").strip() or "customer"
        return _run_level_3(viewer_username, order_id, claimed_role)

    if level == 4:
        order_id = _int_or_none(form.get("order_id", ""))
        return _run_level_4(viewer_username, order_id)

    order_id = _int_or_none(form.get("order_id", ""))
    return _run_level_5(viewer_username, order_id)


def _insert_demo_users():
    for user in DEMO_USERS:
        db.session.execute(
            text(
                """
                INSERT INTO access_demo_users
                    (id, username, role, status)
                VALUES
                    (:id, :username, :role, :status)
                """
            ),
            user,
        )


def _insert_demo_orders():
    for order in DEMO_ORDERS:
        db.session.execute(
            text(
                """
                INSERT INTO access_demo_orders
                    (id, owner_user_id, order_number, item_name, total_cents, status, internal_note)
                VALUES
                    (:id, :owner_user_id, :order_number, :item_name, :total_cents, :status, :internal_note)
                """
            ),
            order,
        )


def _run_level_1(viewer_username, requested_user_id):
    """
    user_id 파라미터를 그대로 신뢰하는 취약 흐름입니다.
    """

    viewer = _fetch_user_by_username(viewer_username)
    reasons = []

    if requested_user_id is None:
        return _blocked_result(
            level=1,
            viewer=viewer,
            client_message="user_id가 올바르지 않습니다.",
            reasons=["Level 1: user_id가 숫자가 아니어서 조회하지 않았습니다."],
        )

    target_user = _fetch_user_by_id(requested_user_id)
    orders = _fetch_orders_by_owner_id(requested_user_id)

    reasons.append("Level 1: 요청자가 보낸 user_id를 그대로 신뢰했습니다.")
    reasons.append("현재 viewer와 requested user_id의 관계를 확인하지 않았습니다.")

    if not orders:
        return _blocked_result(
            level=1,
            viewer=viewer,
            target_user=target_user,
            client_message="해당 user_id의 주문이 없습니다.",
            reasons=reasons,
        )

    return _ok_result(
        level=1,
        viewer=viewer,
        target_user=target_user,
        orders=orders,
        client_message="주문 목록을 반환했습니다.",
        reasons=reasons,
        checks={
            "used_client_user_id": True,
            "checked_owner": False,
            "checked_server_role": False,
            "trusted_client_role": False,
            "checked_status": False,
        },
    )


def _run_level_2(viewer_username, order_id):
    """
    order_id 직접 접근 취약 흐름입니다.
    """

    viewer = _fetch_user_by_username(viewer_username)
    order = _fetch_order_by_id(order_id)
    reasons = []

    if order_id is None:
        return _blocked_result(
            level=2,
            viewer=viewer,
            client_message="order_id가 올바르지 않습니다.",
            reasons=["Level 2: order_id가 숫자가 아니어서 조회하지 않았습니다."],
        )

    reasons.append("Level 2: order_id가 존재하는지만 확인했습니다.")
    reasons.append("viewer가 주문 owner인지 확인하지 않았습니다.")

    if order is None:
        return _blocked_result(
            level=2,
            viewer=viewer,
            client_message="주문을 찾을 수 없습니다.",
            reasons=reasons,
        )

    return _ok_result(
        level=2,
        viewer=viewer,
        target_user=_fetch_user_by_id(order["owner_user_id"]),
        orders=[order],
        client_message="주문 상세를 반환했습니다.",
        reasons=reasons,
        checks={
            "used_client_user_id": False,
            "checked_owner": False,
            "checked_server_role": False,
            "trusted_client_role": False,
            "checked_status": False,
        },
    )


def _run_level_3(viewer_username, order_id, claimed_role):
    """
    클라이언트 role 파라미터를 신뢰하는 취약 흐름입니다.
    """

    viewer = _fetch_user_by_username(viewer_username)
    order = _fetch_order_by_id(order_id)
    reasons = []

    if order_id is None:
        return _blocked_result(
            level=3,
            viewer=viewer,
            client_message="order_id가 올바르지 않습니다.",
            reasons=["Level 3: order_id가 숫자가 아니어서 조회하지 않았습니다."],
        )

    if order is None:
        return _blocked_result(
            level=3,
            viewer=viewer,
            client_message="주문을 찾을 수 없습니다.",
            reasons=["Level 3: 주문 ID가 존재하지 않습니다."],
        )

    is_owner = viewer is not None and order["owner_user_id"] == viewer["id"]

    if claimed_role == "admin":
        reasons.append("Level 3: 클라이언트가 보낸 claimed_role=admin 값을 신뢰했습니다.")
        reasons.append("서버에 저장된 실제 role을 확인하지 않았습니다.")

        return _ok_result(
            level=3,
            viewer=viewer,
            target_user=_fetch_user_by_id(order["owner_user_id"]),
            orders=[order],
            client_message="admin 권한으로 주문 상세를 반환했습니다.",
            reasons=reasons,
            checks={
                "used_client_user_id": False,
                "checked_owner": is_owner,
                "checked_server_role": False,
                "trusted_client_role": True,
                "checked_status": False,
            },
        )

    if is_owner:
        reasons.append("Level 3: claimed_role은 admin이 아니지만 viewer가 owner라서 허용했습니다.")

        return _ok_result(
            level=3,
            viewer=viewer,
            target_user=_fetch_user_by_id(order["owner_user_id"]),
            orders=[order],
            client_message="소유자 주문 상세를 반환했습니다.",
            reasons=reasons,
            checks={
                "used_client_user_id": False,
                "checked_owner": True,
                "checked_server_role": False,
                "trusted_client_role": True,
                "checked_status": False,
            },
        )

    return _blocked_result(
        level=3,
        viewer=viewer,
        target_user=_fetch_user_by_id(order["owner_user_id"]),
        client_message="접근이 거부되었습니다.",
        reasons=[
            "Level 3: claimed_role이 admin이 아니고 viewer도 owner가 아닙니다.",
            "하지만 role을 클라이언트 입력으로 판단하는 설계 자체가 취약합니다.",
        ],
        checks={
            "used_client_user_id": False,
            "checked_owner": True,
            "checked_server_role": False,
            "trusted_client_role": True,
            "checked_status": False,
        },
    )


def _run_level_4(viewer_username, order_id):
    """
    서버 role은 확인하지만 support 권한이 과도하게 넓은 흐름입니다.
    """

    viewer = _fetch_user_by_username(viewer_username)
    order = _fetch_order_by_id(order_id)

    if order_id is None:
        return _blocked_result(
            level=4,
            viewer=viewer,
            client_message="order_id가 올바르지 않습니다.",
            reasons=["Level 4: order_id가 숫자가 아니어서 조회하지 않았습니다."],
        )

    if viewer is None:
        return _blocked_result(
            level=4,
            viewer=None,
            client_message="접근이 거부되었습니다.",
            reasons=["Level 4: 서버 DB에서 viewer를 찾을 수 없습니다."],
        )

    if order is None:
        return _blocked_result(
            level=4,
            viewer=viewer,
            client_message="주문을 찾을 수 없습니다.",
            reasons=["Level 4: 주문 ID가 존재하지 않습니다."],
        )

    if viewer["status"] != "active":
        return _blocked_result(
            level=4,
            viewer=viewer,
            target_user=_fetch_user_by_id(order["owner_user_id"]),
            client_message="접근이 거부되었습니다.",
            reasons=["Level 4: viewer 계정 상태가 active가 아니어서 차단했습니다."],
            checks={
                "used_client_user_id": False,
                "checked_owner": False,
                "checked_server_role": True,
                "trusted_client_role": False,
                "checked_status": True,
            },
        )

    is_owner = order["owner_user_id"] == viewer["id"]

    if viewer["role"] in {"admin", "support"}:
        return _ok_result(
            level=4,
            viewer=viewer,
            target_user=_fetch_user_by_id(order["owner_user_id"]),
            orders=[order],
            client_message="role 권한으로 주문 상세를 반환했습니다.",
            reasons=[
                "Level 4: role은 서버 DB에서 가져왔습니다.",
                "하지만 support role에게 모든 주문 상세와 내부 메모를 허용했습니다.",
            ],
            checks={
                "used_client_user_id": False,
                "checked_owner": is_owner,
                "checked_server_role": True,
                "trusted_client_role": False,
                "checked_status": True,
            },
        )

    if is_owner:
        return _ok_result(
            level=4,
            viewer=viewer,
            target_user=_fetch_user_by_id(order["owner_user_id"]),
            orders=[order],
            client_message="소유자 주문 상세를 반환했습니다.",
            reasons=[
                "Level 4: 일반 사용자는 owner인 경우에만 허용했습니다.",
            ],
            checks={
                "used_client_user_id": False,
                "checked_owner": True,
                "checked_server_role": True,
                "trusted_client_role": False,
                "checked_status": True,
            },
        )

    return _blocked_result(
        level=4,
        viewer=viewer,
        target_user=_fetch_user_by_id(order["owner_user_id"]),
        client_message="접근이 거부되었습니다.",
        reasons=[
            "Level 4: viewer가 owner도 아니고 admin/support도 아니어서 차단했습니다.",
        ],
        checks={
            "used_client_user_id": False,
            "checked_owner": True,
            "checked_server_role": True,
            "trusted_client_role": False,
            "checked_status": True,
        },
    )


def _run_level_5(viewer_username, order_id):
    """
    안전한 object-level authorization 흐름입니다.
    """

    viewer = _fetch_user_by_username(viewer_username)
    order = _fetch_order_by_id(order_id)

    generic_denied = "접근이 거부되었습니다."

    if order_id is None:
        return _blocked_result(
            level=5,
            viewer=viewer,
            client_message=generic_denied,
            reasons=["Level 5: order_id가 올바르지 않아 차단했습니다."],
        )

    if viewer is None:
        return _blocked_result(
            level=5,
            viewer=None,
            client_message=generic_denied,
            reasons=["Level 5: 서버 DB에서 viewer를 찾을 수 없어 차단했습니다."],
        )

    if order is None:
        return _blocked_result(
            level=5,
            viewer=viewer,
            client_message=generic_denied,
            reasons=["Level 5: 주문이 존재하지 않아 차단했습니다."],
        )

    target_user = _fetch_user_by_id(order["owner_user_id"])

    checks = {
        "used_client_user_id": False,
        "checked_owner": True,
        "checked_server_role": True,
        "trusted_client_role": False,
        "checked_status": True,
    }

    if viewer["status"] != "active":
        return _blocked_result(
            level=5,
            viewer=viewer,
            target_user=target_user,
            client_message=generic_denied,
            reasons=["Level 5: viewer 계정 상태가 active가 아니어서 차단했습니다."],
            checks=checks,
        )

    is_owner = order["owner_user_id"] == viewer["id"]
    is_admin = viewer["role"] == "admin"

    if not is_owner and not is_admin:
        return _blocked_result(
            level=5,
            viewer=viewer,
            target_user=target_user,
            client_message=generic_denied,
            reasons=[
                "Level 5: viewer가 owner도 아니고 admin도 아니어서 차단했습니다.",
                "support role은 이 full order view에서는 허용하지 않습니다.",
            ],
            checks=checks,
        )

    return _ok_result(
        level=5,
        viewer=viewer,
        target_user=target_user,
        orders=[order],
        client_message="주문 상세를 반환했습니다.",
        reasons=[
            "Level 5: 서버 측 viewer 정보를 사용했습니다.",
            "Level 5: 계정 상태, 서버 role, 객체 owner 관계를 검증했습니다.",
        ],
        checks=checks,
    )


def _fetch_user_by_username(username):
    return db.session.execute(
        text(
            """
            SELECT id, username, role, status
            FROM access_demo_users
            WHERE username = :username
            """
        ),
        {"username": username},
    ).mappings().first()


def _fetch_user_by_id(user_id):
    return db.session.execute(
        text(
            """
            SELECT id, username, role, status
            FROM access_demo_users
            WHERE id = :id
            """
        ),
        {"id": user_id},
    ).mappings().first()


def _fetch_order_by_id(order_id):
    if order_id is None:
        return None

    return db.session.execute(
        text(
            """
            SELECT
                o.id,
                o.owner_user_id,
                u.username AS owner_username,
                o.order_number,
                o.item_name,
                o.total_cents,
                o.status,
                o.internal_note
            FROM access_demo_orders o
            JOIN access_demo_users u ON u.id = o.owner_user_id
            WHERE o.id = :id
            """
        ),
        {"id": order_id},
    ).mappings().first()


def _fetch_orders_by_owner_id(owner_user_id):
    return db.session.execute(
        text(
            """
            SELECT
                o.id,
                o.owner_user_id,
                u.username AS owner_username,
                o.order_number,
                o.item_name,
                o.total_cents,
                o.status,
                o.internal_note
            FROM access_demo_orders o
            JOIN access_demo_users u ON u.id = o.owner_user_id
            WHERE o.owner_user_id = :owner_user_id
            ORDER BY o.id
            """
        ),
        {"owner_user_id": owner_user_id},
    ).mappings().all()


def _format_order(order):
    return {
        "id": order["id"],
        "owner_user_id": order["owner_user_id"],
        "owner_username": order["owner_username"],
        "order_number": order["order_number"],
        "item_name": order["item_name"],
        "total": f"{order['total_cents'] / 100:.2f}",
        "status": order["status"],
        "internal_note": order["internal_note"],
    }


def _format_user(user):
    if user is None:
        return {
            "id": "(none)",
            "username": "(none)",
            "role": "(none)",
            "status": "(none)",
        }

    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "status": user["status"],
    }


def _default_checks():
    return {
        "used_client_user_id": False,
        "checked_owner": False,
        "checked_server_role": False,
        "trusted_client_role": False,
        "checked_status": False,
    }


def _ok_result(level, viewer, target_user, orders, client_message, reasons, checks):
    return {
        "kind": "access-control",
        "status": "ok",
        "message": "접근 제어 흐름을 시뮬레이션했습니다.",
        "level": level,
        "allowed": True,
        "client_message": client_message,
        "viewer": _format_user(viewer),
        "target_user": _format_user(target_user),
        "orders": [_format_order(order) for order in orders],
        "checks": checks or _default_checks(),
        "reasons": reasons,
        "rows": [],
    }


def _blocked_result(
    level,
    viewer,
    client_message,
    reasons,
    target_user=None,
    checks=None,
):
    return {
        "kind": "access-control",
        "status": "blocked",
        "message": "접근 제어 흐름을 시뮬레이션했습니다.",
        "level": level,
        "allowed": False,
        "client_message": client_message,
        "viewer": _format_user(viewer),
        "target_user": _format_user(target_user),
        "orders": [],
        "checks": checks or _default_checks(),
        "reasons": reasons,
        "rows": [],
    }


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _error_result(message):
    return {
        "kind": "access-control",
        "status": "error",
        "message": message,
        "level": None,
        "allowed": False,
        "client_message": "",
        "viewer": _format_user(None),
        "target_user": _format_user(None),
        "orders": [],
        "checks": _default_checks(),
        "reasons": [],
        "rows": [],
    }