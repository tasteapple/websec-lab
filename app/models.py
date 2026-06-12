# file: app/models.py

from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


def utc_now():
    """
    DB timestamp 기본값으로 사용할 UTC 시간입니다.

    SQLite는 timezone 정보를 강하게 관리하지 않으므로,
    애플리케이션 레벨에서 UTC 기준으로 통일합니다.
    """
    return datetime.now(timezone.utc)


class User(db.Model):
    """
    실습용 사용자 모델입니다.

    role 값은 access control, authentication, business logic 실습에서 사용합니다.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)

    # 평문 비밀번호는 저장하지 않습니다.
    # 취약한 로그인 실습에서는 별도 Lab 코드에서 잘못된 비교 예제를 보여줍니다.
    password_hash = db.Column(db.String(255), nullable=False)

    # 예: admin, editor, customer, support, suspended
    role = db.Column(db.String(40), nullable=False, default="customer")

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    posts = db.relationship("Post", back_populates="user", cascade="all, delete-orphan")
    comments = db.relationship("Comment", back_populates="user", cascade="all, delete-orphan")
    orders = db.relationship("Order", back_populates="user", cascade="all, delete-orphan")
    uploaded_files = db.relationship("UploadedFile", back_populates="user", cascade="all, delete-orphan")
    progress_items = db.relationship("LabProgress", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, raw_password):
        """
        안전한 비밀번호 저장 예시입니다.

        Werkzeug의 password hashing을 사용합니다.
        """
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        """
        안전한 비밀번호 검증 예시입니다.

        문자열 직접 비교가 아니라 hash 검증을 사용합니다.
        """
        return check_password_hash(self.password_hash, raw_password)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Post(db.Model):
    """
    게시글 모델입니다.

    Stored XSS, access control, information disclosure 실습에서 사용할 수 있습니다.
    """

    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    user = db.relationship("User", back_populates="posts")
    comments = db.relationship("Comment", back_populates="post", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Post {self.id}: {self.title}>"


class Comment(db.Model):
    """
    댓글 모델입니다.

    XSS 실습에서 사용자 입력을 어떻게 출력해야 하는지 비교할 때 사용합니다.
    """

    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)

    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    body = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    post = db.relationship("Post", back_populates="comments")
    user = db.relationship("User", back_populates="comments")

    def __repr__(self):
        return f"<Comment {self.id} post={self.post_id}>"


class Product(db.Model):
    """
    상품 모델입니다.

    Business logic, race condition, API mass assignment 실습에서 사용합니다.
    """

    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(120), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)

    # SQLite에서도 실습상 가격을 명확히 다루기 위해 Numeric을 사용합니다.
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)

    orders = db.relationship("Order", back_populates="product")

    def __repr__(self):
        return f"<Product {self.name} stock={self.stock}>"


class Order(db.Model):
    """
    주문 모델입니다.

    수량, 총액, 상태를 이용해 business logic 실습을 구성합니다.
    """

    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)

    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)

    # 예: pending, paid, shipped, cancelled, refunded
    status = db.Column(db.String(40), nullable=False, default="pending")

    user = db.relationship("User", back_populates="orders")
    product = db.relationship("Product", back_populates="orders")

    def __repr__(self):
        return f"<Order {self.id} user={self.user_id} status={self.status}>"


class UploadedFile(db.Model):
    """
    업로드 파일 메타데이터 모델입니다.

    실제 파일은 instance/uploads/ 아래에 저장하고,
    DB에는 원본 이름과 저장 이름, MIME 타입, 크기만 기록합니다.
    """

    __tablename__ = "uploaded_files"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)

    content_type = db.Column(db.String(120), nullable=False)
    size = db.Column(db.Integer, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    user = db.relationship("User", back_populates="uploaded_files")

    def __repr__(self):
        return f"<UploadedFile {self.original_name} stored={self.stored_name}>"


class LabProgress(db.Model):
    """
    사용자별 Lab 진행률 모델입니다.

    같은 사용자, 같은 카테고리, 같은 Lab, 같은 Level 조합은 한 번만 저장합니다.
    """

    __tablename__ = "lab_progress"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    category = db.Column(db.String(80), nullable=False, index=True)
    lab_id = db.Column(db.String(120), nullable=False, index=True)
    level = db.Column(db.Integer, nullable=False)

    solved = db.Column(db.Boolean, nullable=False, default=False)
    solved_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", back_populates="progress_items")

    __table_args__ = (
        db.UniqueConstraint(
            "user_id",
            "category",
            "lab_id",
            "level",
            name="uq_lab_progress_user_lab_level",
        ),
    )

    def mark_solved(self):
        """
        진행률을 완료 상태로 바꿉니다.
        """
        self.solved = True
        self.solved_at = utc_now()

    def __repr__(self):
        return (
            f"<LabProgress user={self.user_id} "
            f"{self.category}/{self.lab_id}/level/{self.level} solved={self.solved}>"
        )