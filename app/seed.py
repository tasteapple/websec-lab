# file: app/seed.py

from decimal import Decimal
from pathlib import Path

from flask import current_app
from sqlalchemy import text

from app.extensions import db
from app.labs.sqli import reset_sqli_demo_table
from app.labs.xss import reset_xss_demo_table
from app.models import (
    Comment,
    LabProgress,
    Order,
    Post,
    Product,
    UploadedFile,
    User,
    utc_now,
)
from app.labs.authentication import reset_auth_demo_table
from app.labs.access_control import reset_access_demo_tables
from app.labs.business_logic import reset_business_demo_tables

def seed_database():
    """
    로컬 개발용 샘플 데이터를 초기화합니다.

    주의:
    - 기존 ORM 테이블 데이터를 모두 삭제하고 다시 생성합니다.
    - SQLi / XSS 실습 전용 raw SQL 테이블도 별도로 초기화합니다.
    - 실제 서비스용 기능이 아니라 로컬 교육용 기능입니다.
    - 업로드 파일은 instance/uploads/ 내부에만 생성합니다.
    """

    # ORM 모델 기반 테이블 초기화
    db.drop_all()
    db.create_all()

    # ORM 모델이 아닌 SQL Injection 실습 전용 raw SQL 테이블 초기화
    reset_sqli_demo_table()

    # ORM 모델이 아닌 XSS 실습 전용 raw SQL 테이블 초기화
    reset_xss_demo_table()

    # ORM 모델이 아닌 Authentication 실습 전용 raw SQL 테이블 초기화
    reset_auth_demo_table()

    # ORM 모델이 아닌 Access Control 실습 전용 raw SQL 테이블 초기화
    reset_access_demo_tables()

    # ORM 모델이 아닌 Business Logic 실습 전용 raw SQL 테이블 초기화
    reset_business_demo_tables()

    users = _create_users()
    products = _create_products()
    posts = _create_posts(users)

    _create_comments(users, posts)
    _create_orders(users, products)
    _create_uploaded_files(users)
    _create_lab_progress(users)

    db.session.commit()

    # demo table count도 실제 DB에서 조회합니다.
    sqli_demo_user_count = db.session.execute(
        text("SELECT COUNT(*) FROM sqli_demo_users")
    ).scalar_one()

    xss_demo_comment_count = db.session.execute(
        text("SELECT COUNT(*) FROM xss_demo_comments")
    ).scalar_one()

    auth_demo_user_count = db.session.execute(
        text("SELECT COUNT(*) FROM auth_demo_users")
    ).scalar_one()
    
    access_demo_user_count = db.session.execute(
    text("SELECT COUNT(*) FROM access_demo_users")
    ).scalar_one()
    
    access_demo_order_count = db.session.execute(
    text("SELECT COUNT(*) FROM access_demo_orders")
    ).scalar_one()

    business_demo_product_count = db.session.execute(
        text("SELECT COUNT(*) FROM business_demo_products")
    ).scalar_one()

    business_demo_coupon_count = db.session.execute(
        text("SELECT COUNT(*) FROM business_demo_coupons")
    ).scalar_one()

    business_demo_order_count = db.session.execute(
        text("SELECT COUNT(*) FROM business_demo_orders")
    ).scalar_one()
    
    return {
        "users": User.query.count(),
        "posts": Post.query.count(),
        "comments": Comment.query.count(),
        "products": Product.query.count(),
        "orders": Order.query.count(),
        "uploaded_files": UploadedFile.query.count(),
        "lab_progress": LabProgress.query.count(),
        "sqli_demo_users": sqli_demo_user_count,
        "xss_demo_comments": xss_demo_comment_count,
        "auth_demo_users": auth_demo_user_count,
        "access_demo_users": access_demo_user_count,
        "access_demo_orders": access_demo_order_count,
        "business_demo_products": business_demo_product_count,
        "business_demo_coupons": business_demo_coupon_count,
        "business_demo_orders": business_demo_order_count,
    }


def _create_users():
    """
    다양한 권한과 상태의 사용자를 만듭니다.

    비밀번호는 모두 hash로 저장됩니다.
    실습 편의를 위해 raw password는 README나 seed 설명에서만 알려줄 수 있습니다.
    """

    user_specs = [
        {
            "username": "admin",
            "email": "admin.local@example.test",
            "password": "AdminPass!234",
            "role": "admin",
        },
        {
            "username": "security_trainer",
            "email": "trainer@example.test",
            "password": "TrainerPass!234",
            "role": "editor",
        },
        {
            "username": "support_lee",
            "email": "support.lee@example.test",
            "password": "SupportPass!234",
            "role": "support",
        },
        {
            "username": "alice",
            "email": "alice@example.test",
            "password": "AlicePass!234",
            "role": "customer",
        },
        {
            "username": "bob",
            "email": "bob@example.test",
            "password": "BobPass!234",
            "role": "customer",
        },
        {
            "username": "charlie",
            "email": "charlie@example.test",
            "password": "CharliePass!234",
            "role": "customer",
        },
        {
            "username": "minji",
            "email": "minji@example.test",
            "password": "MinjiPass!234",
            "role": "customer",
        },
        {
            "username": "qa_user",
            "email": "qa@example.test",
            "password": "QaPass!234",
            "role": "tester",
        },
        {
            "username": "readonly_guest",
            "email": "guest@example.test",
            "password": "GuestPass!234",
            "role": "guest",
        },
        {
            "username": "suspended_user",
            "email": "suspended@example.test",
            "password": "SuspendedPass!234",
            "role": "suspended",
        },
        {
            "username": "coupon_tester",
            "email": "coupon@example.test",
            "password": "CouponPass!234",
            "role": "customer",
        },
        {
            "username": "api_client",
            "email": "api.client@example.test",
            "password": "ApiPass!234",
            "role": "api",
        },
    ]

    users = {}

    for spec in user_specs:
        user = User(
            username=spec["username"],
            email=spec["email"],
            role=spec["role"],
        )
        user.set_password(spec["password"])

        db.session.add(user)
        users[user.username] = user

    db.session.flush()
    return users


def _create_products():
    """
    비즈니스 로직과 race condition 실습에 사용할 상품 데이터입니다.
    """

    product_specs = [
        {
            "name": "Local Lab Hoodie",
            "description": "내부 교육용 굿즈입니다. 일반 주문 흐름 실습에 사용합니다.",
            "price": Decimal("49000.00"),
            "stock": 25,
        },
        {
            "name": "Security Notebook",
            "description": "메모용 노트입니다. 낮은 금액 상품 테스트에 사용합니다.",
            "price": Decimal("3500.00"),
            "stock": 200,
        },
        {
            "name": "USB Practice Kit",
            "description": "파일 업로드와 다운로드 설명에 등장하는 가상의 실습 키트입니다.",
            "price": Decimal("12000.00"),
            "stock": 40,
        },
        {
            "name": "Limited Sticker Pack",
            "description": "재고가 적은 상품입니다. race condition 실습에 적합합니다.",
            "price": Decimal("1000.00"),
            "stock": 2,
        },
        {
            "name": "Premium Workshop Ticket",
            "description": "고가 상품입니다. 가격 조작과 권한 검증 실습에 사용합니다.",
            "price": Decimal("250000.00"),
            "stock": 5,
        },
        {
            "name": "Sold Out Badge",
            "description": "품절 상품입니다. 재고 검증 누락 실습에 사용합니다.",
            "price": Decimal("8000.00"),
            "stock": 0,
        },
        {
            "name": "Coupon Test Item",
            "description": "쿠폰 중복 사용과 할인 계산 실습에 사용하는 상품입니다.",
            "price": Decimal("30000.00"),
            "stock": 15,
        },
        {
            "name": "Internal Debug Mug",
            "description": "정보 노출 실습 설명에 등장하는 내부용 상품입니다.",
            "price": Decimal("15000.00"),
            "stock": 12,
        },
    ]

    products = {}

    for spec in product_specs:
        product = Product(**spec)
        db.session.add(product)
        products[product.name] = product

    db.session.flush()
    return products


def _create_posts(users):
    """
    게시글 데이터입니다.

    일부 글은 access control, information disclosure 실습에서
    '보이면 안 되는 데이터처럼 보이는 상황'을 재현하는 데 사용합니다.
    """

    post_specs = [
        {
            "user": "security_trainer",
            "title": "SQL Injection 실습 안내",
            "body": (
                "이 게시글은 SQL 쿼리를 문자열로 조립했을 때 생기는 문제를 설명합니다. "
                "실습은 로컬 SQLite 데이터에만 적용됩니다."
            ),
        },
        {
            "user": "security_trainer",
            "title": "XSS 출력 인코딩 메모",
            "body": (
                "사용자 입력은 저장 시점보다 출력 시점의 컨텍스트가 중요합니다. "
                "HTML, 속성, JavaScript 문자열 컨텍스트를 구분해서 다룹니다."
            ),
        },
        {
            "user": "alice",
            "title": "프로필 이미지가 안 올라가요",
            "body": "PNG 파일을 올렸는데 미리보기가 나오지 않습니다. 파일 크기 제한을 확인해야 할 것 같습니다.",
        },
        {
            "user": "bob",
            "title": "주문 수량이 이상합니다",
            "body": "동시에 두 번 주문 버튼을 눌렀을 때 재고가 어떻게 처리되는지 확인하고 싶습니다.",
        },
        {
            "user": "charlie",
            "title": "비공개 리포트 다운로드 테스트",
            "body": "이 글은 path traversal 실습에서 권한 검증 예제로 사용됩니다.",
        },
        {
            "user": "support_lee",
            "title": "지원팀 처리 메모",
            "body": "문의 처리 상태를 일반 사용자에게 얼마나 보여줄지 검토해야 합니다.",
        },
        {
            "user": "qa_user",
            "title": "QA 테스트 케이스 목록",
            "body": "빈 값, 긴 값, 특수문자, 다국어 입력, 중복 요청을 각각 확인합니다.",
        },
        {
            "user": "admin",
            "title": "관리자 공지 초안",
            "body": "관리자 전용으로 작성된 초안처럼 보이는 데이터입니다. 객체 권한 검증 실습에 사용합니다.",
        },
    ]

    posts = []

    for spec in post_specs:
        post = Post(
            user=users[spec["user"]],
            title=spec["title"],
            body=spec["body"],
        )
        db.session.add(post)
        posts.append(post)

    db.session.flush()
    return posts


def _create_comments(users, posts):
    """
    댓글 데이터입니다.

    XSS 실습을 위해 HTML처럼 보이는 문자열도 포함하지만,
    실제 공격 자동화용 페이로드 묶음은 넣지 않습니다.
    """

    comment_specs = [
        {
            "post_index": 0,
            "user": "alice",
            "body": "문자열 포맷팅과 파라미터 바인딩 차이를 비교해보고 싶습니다.",
        },
        {
            "post_index": 0,
            "user": "bob",
            "body": "로그인 실패 메시지가 너무 자세하면 사용자 존재 여부가 노출될 수도 있겠네요.",
        },
        {
            "post_index": 1,
            "user": "charlie",
            "body": "HTML처럼 보이는 입력 예시: <b>강조 텍스트</b>",
        },
        {
            "post_index": 1,
            "user": "minji",
            "body": "특수문자 테스트: < > & \" ' /",
        },
        {
            "post_index": 2,
            "user": "support_lee",
            "body": "확장자, MIME 타입, 저장 경로를 모두 확인해야 합니다.",
        },
        {
            "post_index": 3,
            "user": "coupon_tester",
            "body": "동시 요청 상황에서는 서버 측 트랜잭션이 중요합니다.",
        },
        {
            "post_index": 4,
            "user": "qa_user",
            "body": "파일명에 ../ 같은 경로 조각이 들어오면 반드시 정규화 후 검증해야 합니다.",
        },
        {
            "post_index": 5,
            "user": "readonly_guest",
            "body": "읽기 전용 계정이 수정 기능에 접근하지 못하는지 확인해야 합니다.",
        },
        {
            "post_index": 6,
            "user": "admin",
            "body": "테스트 데이터는 실제 개인정보가 아니라 example.test 도메인만 사용합니다.",
        },
        {
            "post_index": 7,
            "user": "security_trainer",
            "body": "관리자 글도 객체 단위 권한 검증 없이는 노출될 수 있습니다.",
        },
    ]

    for spec in comment_specs:
        comment = Comment(
            post=posts[spec["post_index"]],
            user=users[spec["user"]],
            body=spec["body"],
        )
        db.session.add(comment)

    db.session.flush()


def _create_orders(users, products):
    """
    주문 데이터입니다.

    주문 상태를 다양하게 구성해서 business logic 실습에서 사용할 수 있게 합니다.
    """

    order_specs = [
        {
            "user": "alice",
            "product": "Local Lab Hoodie",
            "quantity": 1,
            "total_price": Decimal("49000.00"),
            "status": "paid",
        },
        {
            "user": "alice",
            "product": "Security Notebook",
            "quantity": 3,
            "total_price": Decimal("10500.00"),
            "status": "shipped",
        },
        {
            "user": "bob",
            "product": "Limited Sticker Pack",
            "quantity": 1,
            "total_price": Decimal("1000.00"),
            "status": "pending",
        },
        {
            "user": "bob",
            "product": "Premium Workshop Ticket",
            "quantity": 1,
            "total_price": Decimal("250000.00"),
            "status": "cancelled",
        },
        {
            "user": "charlie",
            "product": "USB Practice Kit",
            "quantity": 2,
            "total_price": Decimal("24000.00"),
            "status": "paid",
        },
        {
            "user": "minji",
            "product": "Coupon Test Item",
            "quantity": 1,
            "total_price": Decimal("27000.00"),
            "status": "paid",
        },
        {
            "user": "coupon_tester",
            "product": "Coupon Test Item",
            "quantity": 2,
            "total_price": Decimal("60000.00"),
            "status": "refunded",
        },
        {
            "user": "suspended_user",
            "product": "Internal Debug Mug",
            "quantity": 1,
            "total_price": Decimal("15000.00"),
            "status": "pending",
        },
    ]

    for spec in order_specs:
        order = Order(
            user=users[spec["user"]],
            product=products[spec["product"]],
            quantity=spec["quantity"],
            total_price=spec["total_price"],
            status=spec["status"],
        )
        db.session.add(order)

    db.session.flush()


def _create_uploaded_files(users):
    """
    업로드 파일 메타데이터와 작은 placeholder 파일을 만듭니다.

    실제 파일은 반드시 current_app.config["UPLOAD_DIR"] 아래에만 저장합니다.
    """

    upload_dir = Path(current_app.config["UPLOAD_DIR"])
    upload_dir.mkdir(parents=True, exist_ok=True)

    file_specs = [
        {
            "user": "alice",
            "original_name": "profile.png",
            "stored_name": "seed_alice_profile.png",
            "content_type": "image/png",
            "content": b"seed png placeholder\n",
        },
        {
            "user": "bob",
            "original_name": "avatar.jpg",
            "stored_name": "seed_bob_avatar.jpg",
            "content_type": "image/jpeg",
            "content": b"seed jpg placeholder\n",
        },
        {
            "user": "charlie",
            "original_name": "quarterly-report.pdf",
            "stored_name": "seed_charlie_report.pdf",
            "content_type": "application/pdf",
            "content": b"%PDF-1.4 seed placeholder\n",
        },
        {
            "user": "qa_user",
            "original_name": "long-filename-test-image-with-many-characters.png",
            "stored_name": "seed_qa_long_filename.png",
            "content_type": "image/png",
            "content": b"long filename placeholder\n",
        },
        {
            "user": "support_lee",
            "original_name": "support-note.txt",
            "stored_name": "seed_support_note.txt",
            "content_type": "text/plain",
            "content": b"support note placeholder\n",
        },
        {
            "user": "security_trainer",
            "original_name": "training-material.html",
            "stored_name": "seed_training_material.html",
            "content_type": "text/html",
            "content": b"<p>HTML-like training material placeholder</p>\n",
        },
    ]

    for spec in file_specs:
        stored_path = upload_dir / spec["stored_name"]

        # seed 파일도 upload_dir 내부에만 기록합니다.
        stored_path.write_bytes(spec["content"])

        uploaded_file = UploadedFile(
            user=users[spec["user"]],
            original_name=spec["original_name"],
            stored_name=spec["stored_name"],
            content_type=spec["content_type"],
            size=stored_path.stat().st_size,
        )
        db.session.add(uploaded_file)

    db.session.flush()


def _create_lab_progress(users):
    """
    진행률 샘플 데이터입니다.

    일부 사용자만 Level을 완료한 상태로 두어
    /progress 페이지에서 다양한 상태를 보여줄 수 있게 합니다.
    """

    progress_specs = [
        # Alice: SQLi를 꽤 진행한 사용자
        {
            "user": "alice",
            "category": "sqli",
            "lab_id": "sqli-login-bypass",
            "levels": [1, 2, 3],
        },
        # Bob: XSS 초반만 완료
        {
            "user": "bob",
            "category": "xss",
            "lab_id": "xss-comment-board",
            "levels": [1],
        },
        # Charlie: 파일 다운로드 실습 진행
        {
            "user": "charlie",
            "category": "path-traversal",
            "lab_id": "download-report",
            "levels": [1, 2],
        },
        # Trainer: 여러 카테고리 검수 완료
        {
            "user": "security_trainer",
            "category": "sqli",
            "lab_id": "sqli-login-bypass",
            "levels": [1, 2, 3, 4, 5],
        },
        {
            "user": "security_trainer",
            "category": "xss",
            "lab_id": "xss-comment-board",
            "levels": [1, 2, 3, 4, 5],
        },
        {
            "user": "security_trainer",
            "category": "csrf",
            "lab_id": "csrf-change-email",
            "levels": [1, 2, 3],
        },
        # QA: 여러 경계 케이스 확인 중
        {
            "user": "qa_user",
            "category": "file-upload",
            "lab_id": "upload-profile-image",
            "levels": [1, 2, 3, 4],
        },
        {
            "user": "qa_user",
            "category": "ssrf",
            "lab_id": "ssrf-local-metadata",
            "levels": [1, 2],
        },
        {
            "user": "qa_user",
            "category": "request-smuggling",
            "lab_id": "smuggling-parser-diff",
            "levels": [1],
        },
    ]

    for spec in progress_specs:
        for level in spec["levels"]:
            progress = LabProgress(
                user=users[spec["user"]],
                category=spec["category"],
                lab_id=spec["lab_id"],
                level=level,
                solved=True,
                solved_at=utc_now(),
            )
            db.session.add(progress)

    db.session.flush()