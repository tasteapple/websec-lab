# file: app/labs/business_logic.py

from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.labs.base import LabDefinition, LabFormField, LabLevel


DEMO_PRODUCTS = [
    {
        "sku": "NOTEBOOK",
        "name": "Security Notebook",
        "unit_price_cents": 12900,
        "stock": 5,
    },
    {
        "sku": "HOODIE",
        "name": "Local Lab Hoodie",
        "unit_price_cents": 45900,
        "stock": 2,
    },
    {
        "sku": "TICKET",
        "name": "Premium Workshop Ticket",
        "unit_price_cents": 99000,
        "stock": 1,
    },
]


DEMO_COUPONS = [
    {
        "code": "WELCOME10",
        "discount_type": "percent",
        "discount_value": 10,
        "active": 1,
        "max_uses_per_user": 1,
    },
    {
        "code": "SAVE5000",
        "discount_type": "fixed",
        "discount_value": 5000,
        "active": 1,
        "max_uses_per_user": 1,
    },
    {
        "code": "STACKME",
        "discount_type": "fixed",
        "discount_value": 3000,
        "active": 1,
        "max_uses_per_user": 1,
    },
    {
        "code": "EXPIRED50",
        "discount_type": "percent",
        "discount_value": 50,
        "active": 0,
        "max_uses_per_user": 1,
    },
]


CHECKOUT_FIELDS = [
    LabFormField(
        name="username",
        label="Username",
        placeholder="예: alice",
        help_text="실습용 구매자 이름입니다. 예: alice, bob, coupon_tester",
    ),
    LabFormField(
        name="product_sku",
        label="Product SKU",
        placeholder="예: NOTEBOOK",
        help_text="상품 SKU입니다. 사용 가능: NOTEBOOK, HOODIE, TICKET",
    ),
    LabFormField(
        name="quantity",
        label="Quantity",
        field_type="number",
        placeholder="예: 1",
        help_text="구매 수량입니다. Level 1에서는 음수 수량 문제가 드러납니다.",
    ),
    LabFormField(
        name="coupon_code",
        label="Coupon code",
        placeholder="예: WELCOME10",
        help_text="쿠폰 코드입니다. Level 3에서는 WELCOME10,WELCOME10처럼 쉼표로 여러 개 입력해보세요.",
    ),
    LabFormField(
        name="client_price_cents",
        label="Client price cents",
        field_type="number",
        placeholder="예: 12900",
        help_text="Level 2에서 클라이언트가 보낸 가격을 신뢰하는 문제를 보여줍니다.",
    ),
]


BUSINESS_LOGIC_LAB = LabDefinition(
    category="business-logic",
    lab_id="coupon-checkout",
    title="쿠폰 checkout 로직 검증",
    summary="가격, 수량, 쿠폰, 재고 검증 순서에서 발생하는 비즈니스 로직 취약점을 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="수량 검증 누락",
            goal="음수 또는 0 수량을 허용하면 주문 금액 계산이 깨질 수 있음을 확인합니다.",
            form_fields=CHECKOUT_FIELDS,
            hints=[
                "quantity에 음수를 넣었을 때 total이 어떻게 계산되는지 확인하세요.",
                "가격 계산 전에 수량 범위를 먼저 검증해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# quantity를 검증하지 않고 가격 계산에 사용합니다.

quantity = int(request.form["quantity"])

subtotal = product.unit_price_cents * quantity
discount = calculate_discount(coupon, subtotal)
total = subtotal - discount
""",
            secure_code="""# 안전한 코드
# 수량은 가격 계산 전에 명확한 범위로 검증합니다.

quantity = int(request.form["quantity"])

if quantity < 1 or quantity > 5:
    raise ValueError("invalid quantity")

subtotal = product.unit_price_cents * quantity
""",
            defense_notes=[
                "수량은 반드시 양수 범위로 제한합니다.",
                "금액 계산 전에 입력 도메인을 검증합니다.",
                "0, 음수, 과도하게 큰 수량을 모두 검토해야 합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="클라이언트 가격 신뢰",
            goal="브라우저가 보낸 가격을 서버가 신뢰하면 금액 조작이 가능함을 이해합니다.",
            form_fields=CHECKOUT_FIELDS,
            hints=[
                "client_price_cents 값을 실제 상품 가격보다 낮게 넣어보세요.",
                "서버는 상품 가격을 DB에서 다시 조회해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 클라이언트가 보낸 가격을 서버 계산에 사용합니다.

unit_price = int(request.form["client_price_cents"])
quantity = int(request.form["quantity"])

subtotal = unit_price * quantity
""",
            secure_code="""# 안전한 코드
# 가격은 서버 DB의 상품 정보에서 가져옵니다.

product = Product.query.filter_by(sku=sku).first()
unit_price = product.unit_price_cents

subtotal = unit_price * quantity
""",
            defense_notes=[
                "가격, 할인율, 배송비 같은 금액 필드는 클라이언트를 신뢰하지 않습니다.",
                "서버가 상품 ID 또는 SKU로 가격을 다시 조회해야 합니다.",
                "프론트엔드 가격은 표시용일 뿐 결제 기준이 아닙니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="쿠폰 중복 적용",
            goal="같은 쿠폰을 여러 번 적용하거나 여러 쿠폰을 무제한 적용하는 문제를 확인합니다.",
            form_fields=CHECKOUT_FIELDS,
            hints=[
                "coupon_code에 WELCOME10,WELCOME10 또는 SAVE5000,STACKME를 넣어보세요.",
                "쿠폰은 사용 가능 여부와 사용자별 사용 횟수를 검증해야 합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 쉼표로 전달된 쿠폰을 모두 적용합니다.
# 같은 쿠폰을 여러 번 써도 막지 않습니다.

coupon_codes = request.form["coupon_code"].split(",")

for code in coupon_codes:
    coupon = find_coupon(code)
    discount += calculate_discount(coupon, subtotal)
""",
            secure_code="""# 안전한 코드
# 한 주문에는 허용된 쿠폰 하나만 적용하고 사용자별 사용 횟수를 확인합니다.

coupon = find_coupon(coupon_code)

if not coupon.active:
    raise ValueError("invalid coupon")

if already_used(username, coupon.code):
    raise ValueError("coupon already used")
""",
            defense_notes=[
                "쿠폰 중복 적용 여부를 서버에서 검증합니다.",
                "사용자별, 주문별, 캠페인별 사용 제한을 명확히 둡니다.",
                "쿠폰 할인액이 subtotal을 초과하지 않게 제한합니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="재고 검증 순서 오류",
            goal="재고가 부족해도 주문이 생성되는 흐름을 확인합니다.",
            form_fields=CHECKOUT_FIELDS,
            hints=[
                "TICKET은 재고가 1개입니다.",
                "quantity를 2 이상으로 넣었을 때 주문이 허용되는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 재고가 0보다 큰지만 확인하고 요청 수량 전체를 비교하지 않습니다.

if product.stock <= 0:
    raise ValueError("out of stock")

create_order(product, quantity)

# 나중에 stock을 차감하면서 음수 재고가 될 수 있음
product.stock -= quantity
""",
            secure_code="""# 안전한 코드
# 주문 생성 전에 요청 수량과 현재 재고를 비교합니다.

if quantity < 1:
    raise ValueError("invalid quantity")

if product.stock < quantity:
    raise ValueError("not enough stock")

create_order(product, quantity)
product.stock -= quantity
""",
            defense_notes=[
                "재고는 요청 수량 전체와 비교해야 합니다.",
                "주문 생성과 재고 차감은 하나의 일관된 흐름으로 처리해야 합니다.",
                "운영 환경에서는 트랜잭션과 row-level lock도 고려합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="서버 측 가격 계산, 수량 검증, 쿠폰 사용 횟수 검증, 재고 검증을 함께 적용합니다.",
            form_fields=CHECKOUT_FIELDS,
            hints=[
                "가격은 client_price_cents가 아니라 서버 demo product table에서 가져옵니다.",
                "Level 5에서 성공한 주문은 demo stock과 coupon usage에 반영됩니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# 재고가 0보다 큰지만 보고 주문을 생성했습니다.

if product.stock > 0:
    create_order(product, quantity)
""",
            secure_code="""# 안전한 코드
# 서버 측 상품 가격, 수량, 쿠폰, 재고를 모두 검증합니다.

product = find_product(sku)
quantity = validate_quantity(request.form["quantity"])

if product.stock < quantity:
    raise ValueError("not enough stock")

coupon = find_active_coupon(coupon_code)

if coupon and already_used(username, coupon.code):
    raise ValueError("coupon already used")

subtotal = product.unit_price_cents * quantity
discount = calculate_discount(coupon, subtotal)
total = max(subtotal - discount, 0)

create_order(...)
product.stock -= quantity
record_coupon_usage(...)
""",
            defense_notes=[
                "금액 계산은 서버에서만 수행합니다.",
                "수량은 명확한 범위로 제한합니다.",
                "쿠폰은 활성 상태와 사용자별 사용 횟수를 확인합니다.",
                "재고는 주문 수량 이상인지 확인합니다.",
                "주문 생성, 재고 차감, 쿠폰 사용 기록은 일관된 흐름으로 처리합니다.",
            ],
        ),
    },
)


def ensure_business_demo_tables():
    """
    Business Logic 실습용 product/coupon/order 테이블을 준비합니다.
    """

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS business_demo_products (
                sku TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                unit_price_cents INTEGER NOT NULL,
                stock INTEGER NOT NULL
            )
            """
        )
    )

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS business_demo_coupons (
                code TEXT PRIMARY KEY,
                discount_type TEXT NOT NULL,
                discount_value INTEGER NOT NULL,
                active INTEGER NOT NULL,
                max_uses_per_user INTEGER NOT NULL
            )
            """
        )
    )

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS business_demo_coupon_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                coupon_code TEXT NOT NULL,
                used_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            """
        )
    )

    db.session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS business_demo_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                product_sku TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                subtotal_cents INTEGER NOT NULL,
                discount_cents INTEGER NOT NULL,
                total_cents INTEGER NOT NULL,
                coupon_code TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
    )

    product_count = db.session.execute(
        text("SELECT COUNT(*) FROM business_demo_products")
    ).scalar_one()

    coupon_count = db.session.execute(
        text("SELECT COUNT(*) FROM business_demo_coupons")
    ).scalar_one()

    if product_count == 0:
        _insert_demo_products()

    if coupon_count == 0:
        _insert_demo_coupons()

    db.session.commit()


def reset_business_demo_tables():
    """
    seed 실행 시 Business Logic demo table을 초기화하기 위한 함수입니다.
    """

    db.session.execute(text("DROP TABLE IF EXISTS business_demo_orders"))
    db.session.execute(text("DROP TABLE IF EXISTS business_demo_coupon_usage"))
    db.session.execute(text("DROP TABLE IF EXISTS business_demo_coupons"))
    db.session.execute(text("DROP TABLE IF EXISTS business_demo_products"))
    db.session.flush()
    ensure_business_demo_tables()


def get_lab(lab_id):
    """
    Business Logic 카테고리의 Lab을 반환합니다.
    """

    if lab_id == BUSINESS_LOGIC_LAB.lab_id:
        return BUSINESS_LOGIC_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 Business Logic Lab Level을 실행합니다.
    """

    ensure_business_demo_tables()

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 Business Logic Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    username = form.get("username", "").strip() or "alice"
    product_sku = form.get("product_sku", "").strip().upper() or "NOTEBOOK"
    quantity = _int_or_none(form.get("quantity", ""))
    coupon_code = form.get("coupon_code", "").strip().upper()
    client_price_cents = _int_or_none(form.get("client_price_cents", ""))

    product = _fetch_product(product_sku)

    if product is None:
        return _blocked_result(
            client_message="상품을 찾을 수 없습니다.",
            reasons=[f"상품 SKU가 존재하지 않습니다: {product_sku}"],
            checkout=_empty_checkout(
                username=username,
                product_sku=product_sku,
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
            ),
        )

    if quantity is None:
        return _blocked_result(
            client_message="수량이 올바르지 않습니다.",
            reasons=["quantity가 숫자가 아니어서 처리하지 않았습니다."],
            checkout=_empty_checkout(
                username=username,
                product_sku=product_sku,
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
            ),
        )

    if level == 1:
        return _run_level_1(username, product, quantity, coupon_code, client_price_cents)

    if level == 2:
        return _run_level_2(username, product, quantity, coupon_code, client_price_cents)

    if level == 3:
        return _run_level_3(username, product, quantity, coupon_code, client_price_cents)

    if level == 4:
        return _run_level_4(username, product, quantity, coupon_code, client_price_cents)

    return _run_level_5(username, product, quantity, coupon_code, client_price_cents)


def _insert_demo_products():
    for product in DEMO_PRODUCTS:
        db.session.execute(
            text(
                """
                INSERT INTO business_demo_products
                    (sku, name, unit_price_cents, stock)
                VALUES
                    (:sku, :name, :unit_price_cents, :stock)
                """
            ),
            product,
        )


def _insert_demo_coupons():
    for coupon in DEMO_COUPONS:
        db.session.execute(
            text(
                """
                INSERT INTO business_demo_coupons
                    (code, discount_type, discount_value, active, max_uses_per_user)
                VALUES
                    (:code, :discount_type, :discount_value, :active, :max_uses_per_user)
                """
            ),
            coupon,
        )


def _run_level_1(username, product, quantity, coupon_code, client_price_cents):
    """
    수량 검증 누락 흐름입니다.
    """

    reasons = [
        "Level 1: quantity를 검증하지 않고 가격 계산에 사용했습니다.",
        "음수 또는 0 수량도 계산에 들어갈 수 있습니다.",
    ]

    subtotal = product["unit_price_cents"] * quantity
    coupons = _parse_coupon_list(coupon_code)[:1]
    discount = _calculate_total_discount(coupons, subtotal, allow_inactive=True)
    total = subtotal - discount

    return _ok_result(
        client_message="checkout 계산 결과를 반환했습니다.",
        reasons=reasons,
        checkout=_build_checkout(
            level=1,
            username=username,
            product=product,
            quantity=quantity,
            coupon_code=coupon_code,
            client_price_cents=client_price_cents,
            unit_price_used=product["unit_price_cents"],
            subtotal=subtotal,
            discount=discount,
            total=total,
            accepted=True,
            checks={
                "validated_quantity": False,
                "trusted_client_price": False,
                "checked_coupon_usage": False,
                "checked_stock": False,
                "updated_stock": False,
                "server_price_used": True,
            },
        ),
    )


def _run_level_2(username, product, quantity, coupon_code, client_price_cents):
    """
    클라이언트 가격 신뢰 흐름입니다.
    """

    if quantity < 1:
        return _blocked_result(
            client_message="수량이 올바르지 않습니다.",
            reasons=["Level 2: quantity는 양수로 제한했습니다."],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
            ),
        )

    if client_price_cents is None:
        client_price_cents = product["unit_price_cents"]

    reasons = [
        "Level 2: quantity는 검증했지만 client_price_cents를 서버 계산에 사용했습니다.",
        "클라이언트가 보낸 가격은 조작 가능한 값입니다.",
    ]

    subtotal = client_price_cents * quantity
    coupons = _parse_coupon_list(coupon_code)[:1]
    discount = _calculate_total_discount(coupons, subtotal, allow_inactive=True)
    total = max(subtotal - discount, 0)

    return _ok_result(
        client_message="클라이언트 가격 기준 checkout 계산 결과를 반환했습니다.",
        reasons=reasons,
        checkout=_build_checkout(
            level=2,
            username=username,
            product=product,
            quantity=quantity,
            coupon_code=coupon_code,
            client_price_cents=client_price_cents,
            unit_price_used=client_price_cents,
            subtotal=subtotal,
            discount=discount,
            total=total,
            accepted=True,
            checks={
                "validated_quantity": True,
                "trusted_client_price": True,
                "checked_coupon_usage": False,
                "checked_stock": False,
                "updated_stock": False,
                "server_price_used": False,
            },
        ),
    )


def _run_level_3(username, product, quantity, coupon_code, client_price_cents):
    """
    쿠폰 중복 적용 취약 흐름입니다.
    """

    if quantity < 1:
        return _blocked_result(
            client_message="수량이 올바르지 않습니다.",
            reasons=["Level 3: quantity는 양수로 제한했습니다."],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
            ),
        )

    coupons = _parse_coupon_list(coupon_code)

    reasons = [
        "Level 3: 서버 가격과 양수 수량은 사용했습니다.",
        "하지만 쉼표로 전달된 쿠폰을 모두 적용하고 중복 사용을 막지 않았습니다.",
    ]

    subtotal = product["unit_price_cents"] * quantity
    discount = _calculate_total_discount(coupons, subtotal, allow_inactive=False)
    total = max(subtotal - discount, 0)

    return _ok_result(
        client_message="쿠폰 적용 checkout 계산 결과를 반환했습니다.",
        reasons=reasons,
        checkout=_build_checkout(
            level=3,
            username=username,
            product=product,
            quantity=quantity,
            coupon_code=coupon_code,
            client_price_cents=client_price_cents,
            unit_price_used=product["unit_price_cents"],
            subtotal=subtotal,
            discount=discount,
            total=total,
            accepted=True,
            checks={
                "validated_quantity": True,
                "trusted_client_price": False,
                "checked_coupon_usage": False,
                "checked_stock": False,
                "updated_stock": False,
                "server_price_used": True,
            },
        ),
    )


def _run_level_4(username, product, quantity, coupon_code, client_price_cents):
    """
    재고 검증 순서 오류 흐름입니다.
    """

    if quantity < 1:
        return _blocked_result(
            client_message="수량이 올바르지 않습니다.",
            reasons=["Level 4: quantity는 양수로 제한했습니다."],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
            ),
        )

    if product["stock"] <= 0:
        return _blocked_result(
            client_message="재고가 없습니다.",
            reasons=["Level 4: stock이 0 이하라서 차단했습니다."],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
            ),
        )

    coupons = _parse_coupon_list(coupon_code)[:1]
    subtotal = product["unit_price_cents"] * quantity
    discount = _calculate_total_discount(coupons, subtotal, allow_inactive=False)
    total = max(subtotal - discount, 0)
    projected_stock = product["stock"] - quantity

    reasons = [
        "Level 4: stock이 0보다 큰지만 확인했습니다.",
        "요청 quantity가 현재 stock 이하인지 확인하지 않았습니다.",
        f"현재 stock={product['stock']}, 요청 quantity={quantity}, 예상 stock={projected_stock}입니다.",
    ]

    return _ok_result(
        client_message="재고 검증이 불완전하지만 checkout을 허용했습니다.",
        reasons=reasons,
        checkout=_build_checkout(
            level=4,
            username=username,
            product=product,
            quantity=quantity,
            coupon_code=coupon_code,
            client_price_cents=client_price_cents,
            unit_price_used=product["unit_price_cents"],
            subtotal=subtotal,
            discount=discount,
            total=total,
            accepted=True,
            projected_stock=projected_stock,
            checks={
                "validated_quantity": True,
                "trusted_client_price": False,
                "checked_coupon_usage": False,
                "checked_stock": False,
                "updated_stock": False,
                "server_price_used": True,
            },
        ),
    )


def _run_level_5(username, product, quantity, coupon_code, client_price_cents):
    """
    안전한 checkout 흐름입니다.
    """

    checks = {
        "validated_quantity": True,
        "trusted_client_price": False,
        "checked_coupon_usage": True,
        "checked_stock": True,
        "updated_stock": False,
        "server_price_used": True,
    }

    if quantity < 1 or quantity > 5:
        return _blocked_result(
            client_message="수량이 올바르지 않습니다.",
            reasons=["Level 5: quantity는 1 이상 5 이하만 허용합니다."],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
                checks=checks,
            ),
        )

    if product["stock"] < quantity:
        return _blocked_result(
            client_message="재고가 부족합니다.",
            reasons=[
                "Level 5: 요청 quantity가 현재 stock보다 커서 차단했습니다.",
                f"현재 stock={product['stock']}, 요청 quantity={quantity}",
            ],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
                checks=checks,
            ),
        )

    coupons = _parse_coupon_list(coupon_code)

    if len(coupons) > 1:
        return _blocked_result(
            client_message="쿠폰은 한 주문에 하나만 사용할 수 있습니다.",
            reasons=["Level 5: 여러 쿠폰이 입력되어 차단했습니다."],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
                checks=checks,
            ),
        )

    coupon = _fetch_coupon(coupons[0]) if coupons else None

    if coupons and coupon is None:
        return _blocked_result(
            client_message="유효하지 않은 쿠폰입니다.",
            reasons=[f"Level 5: 존재하지 않는 쿠폰입니다: {coupons[0]}"],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
                checks=checks,
            ),
        )

    if coupon and not coupon["active"]:
        return _blocked_result(
            client_message="유효하지 않은 쿠폰입니다.",
            reasons=[f"Level 5: 비활성 쿠폰입니다: {coupon['code']}"],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
                checks=checks,
            ),
        )

    if coupon and _coupon_used_count(username, coupon["code"]) >= coupon["max_uses_per_user"]:
        return _blocked_result(
            client_message="이미 사용한 쿠폰입니다.",
            reasons=[
                f"Level 5: 사용자 {username}은 쿠폰 {coupon['code']}의 사용 가능 횟수를 초과했습니다."
            ],
            checkout=_empty_checkout(
                username=username,
                product_sku=product["sku"],
                quantity=quantity,
                coupon_code=coupon_code,
                client_price_cents=client_price_cents,
                product=product,
                checks=checks,
            ),
        )

    subtotal = product["unit_price_cents"] * quantity
    discount = _calculate_coupon_discount(coupon, subtotal) if coupon else 0
    discount = min(discount, subtotal)
    total = max(subtotal - discount, 0)
    projected_stock = product["stock"] - quantity

    try:
        db.session.execute(
            text(
                """
                INSERT INTO business_demo_orders
                    (username, product_sku, quantity, subtotal_cents, discount_cents, total_cents, coupon_code, created_at)
                VALUES
                    (:username, :product_sku, :quantity, :subtotal_cents, :discount_cents, :total_cents, :coupon_code, :created_at)
                """
            ),
            {
                "username": username,
                "product_sku": product["sku"],
                "quantity": quantity,
                "subtotal_cents": subtotal,
                "discount_cents": discount,
                "total_cents": total,
                "coupon_code": coupon["code"] if coupon else None,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        db.session.execute(
            text(
                """
                UPDATE business_demo_products
                SET stock = stock - :quantity
                WHERE sku = :sku
                """
            ),
            {
                "quantity": quantity,
                "sku": product["sku"],
            },
        )

        if coupon:
            _record_coupon_usage(username, coupon["code"])

        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        raise

    checks["updated_stock"] = True

    return _ok_result(
        client_message="안전한 checkout이 완료되었습니다.",
        reasons=[
            "Level 5: 서버 측 상품 가격을 사용했습니다.",
            "Level 5: quantity, coupon usage, stock을 모두 검증했습니다.",
            "Level 5: demo order 생성, stock 차감, coupon usage 기록을 수행했습니다.",
        ],
        checkout=_build_checkout(
            level=5,
            username=username,
            product=product,
            quantity=quantity,
            coupon_code=coupon["code"] if coupon else "",
            client_price_cents=client_price_cents,
            unit_price_used=product["unit_price_cents"],
            subtotal=subtotal,
            discount=discount,
            total=total,
            accepted=True,
            projected_stock=projected_stock,
            checks=checks,
        ),
    )


def _fetch_product(sku):
    return db.session.execute(
        text(
            """
            SELECT sku, name, unit_price_cents, stock
            FROM business_demo_products
            WHERE sku = :sku
            """
        ),
        {"sku": sku},
    ).mappings().first()


def _fetch_coupon(code):
    if not code:
        return None

    return db.session.execute(
        text(
            """
            SELECT code, discount_type, discount_value, active, max_uses_per_user
            FROM business_demo_coupons
            WHERE code = :code
            """
        ),
        {"code": code},
    ).mappings().first()


def _parse_coupon_list(coupon_code):
    if not coupon_code:
        return []

    return [
        item.strip().upper()
        for item in coupon_code.split(",")
        if item.strip()
    ]


def _calculate_total_discount(coupon_codes, subtotal, allow_inactive):
    total_discount = 0

    for code in coupon_codes:
        coupon = _fetch_coupon(code)

        if coupon is None:
            continue

        if not allow_inactive and not coupon["active"]:
            continue

        total_discount += _calculate_coupon_discount(coupon, subtotal)

    return total_discount


def _calculate_coupon_discount(coupon, subtotal):
    if coupon is None:
        return 0

    if coupon["discount_type"] == "percent":
        return int(subtotal * coupon["discount_value"] / 100)

    if coupon["discount_type"] == "fixed":
        return coupon["discount_value"]

    return 0


def _coupon_used_count(username, coupon_code):
    row = db.session.execute(
        text(
            """
            SELECT used_count
            FROM business_demo_coupon_usage
            WHERE username = :username
              AND coupon_code = :coupon_code
            """
        ),
        {
            "username": username,
            "coupon_code": coupon_code,
        },
    ).mappings().first()

    if row is None:
        return 0

    return row["used_count"]


def _record_coupon_usage(username, coupon_code):
    existing = db.session.execute(
        text(
            """
            SELECT id, used_count
            FROM business_demo_coupon_usage
            WHERE username = :username
              AND coupon_code = :coupon_code
            """
        ),
        {
            "username": username,
            "coupon_code": coupon_code,
        },
    ).mappings().first()

    now = datetime.now(timezone.utc).isoformat()

    if existing is None:
        db.session.execute(
            text(
                """
                INSERT INTO business_demo_coupon_usage
                    (username, coupon_code, used_count, updated_at)
                VALUES
                    (:username, :coupon_code, 1, :updated_at)
                """
            ),
            {
                "username": username,
                "coupon_code": coupon_code,
                "updated_at": now,
            },
        )
    else:
        db.session.execute(
            text(
                """
                UPDATE business_demo_coupon_usage
                SET
                    used_count = used_count + 1,
                    updated_at = :updated_at
                WHERE id = :id
                """
            ),
            {
                "id": existing["id"],
                "updated_at": now,
            },
        )


def _build_checkout(
    level,
    username,
    product,
    quantity,
    coupon_code,
    client_price_cents,
    unit_price_used,
    subtotal,
    discount,
    total,
    accepted,
    checks,
    projected_stock=None,
):
    return {
        "level": level,
        "username": username,
        "product_sku": product["sku"],
        "product_name": product["name"],
        "server_unit_price": product["unit_price_cents"],
        "client_price_cents": client_price_cents if client_price_cents is not None else "(none)",
        "unit_price_used": unit_price_used,
        "quantity": quantity,
        "coupon_code": coupon_code or "(none)",
        "subtotal_cents": subtotal,
        "discount_cents": discount,
        "total_cents": total,
        "current_stock": product["stock"],
        "projected_stock": projected_stock if projected_stock is not None else product["stock"],
        "accepted": accepted,
        "checks": checks,
    }


def _empty_checkout(
    username,
    product_sku,
    quantity,
    coupon_code,
    client_price_cents,
    product=None,
    checks=None,
):
    checks = checks or {
        "validated_quantity": False,
        "trusted_client_price": False,
        "checked_coupon_usage": False,
        "checked_stock": False,
        "updated_stock": False,
        "server_price_used": False,
    }

    return {
        "level": None,
        "username": username,
        "product_sku": product_sku,
        "product_name": product["name"] if product else "(none)",
        "server_unit_price": product["unit_price_cents"] if product else 0,
        "client_price_cents": client_price_cents if client_price_cents is not None else "(none)",
        "unit_price_used": 0,
        "quantity": quantity if quantity is not None else "(invalid)",
        "coupon_code": coupon_code or "(none)",
        "subtotal_cents": 0,
        "discount_cents": 0,
        "total_cents": 0,
        "current_stock": product["stock"] if product else 0,
        "projected_stock": product["stock"] if product else 0,
        "accepted": False,
        "checks": checks,
    }


def _ok_result(client_message, reasons, checkout):
    return {
        "kind": "business-logic",
        "status": "ok",
        "message": "checkout 비즈니스 로직을 시뮬레이션했습니다.",
        "allowed": True,
        "client_message": client_message,
        "checkout": checkout,
        "reasons": reasons,
        "products": _fetch_all_products(),
        "rows": [],
    }


def _blocked_result(client_message, reasons, checkout):
    return {
        "kind": "business-logic",
        "status": "blocked",
        "message": "checkout 비즈니스 로직을 시뮬레이션했습니다.",
        "allowed": False,
        "client_message": client_message,
        "checkout": checkout,
        "reasons": reasons,
        "products": _fetch_all_products(),
        "rows": [],
    }


def _fetch_all_products():
    rows = db.session.execute(
        text(
            """
            SELECT sku, name, unit_price_cents, stock
            FROM business_demo_products
            ORDER BY sku
            """
        )
    ).mappings().all()

    return [
        {
            "sku": row["sku"],
            "name": row["name"],
            "unit_price_cents": row["unit_price_cents"],
            "stock": row["stock"],
        }
        for row in rows
    ]


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _error_result(message):
    return {
        "kind": "business-logic",
        "status": "error",
        "message": message,
        "allowed": False,
        "client_message": "",
        "checkout": None,
        "reasons": [],
        "products": [],
        "rows": [],
    }