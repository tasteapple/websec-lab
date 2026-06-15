# file: app/labs/registry.py

"""
Lab registry입니다.

이 파일은 전체 취약점 카테고리와 Lab 목록의 기준점입니다.
사이드바, 대시보드, 진행률, 학습 페이지에서 공통으로 사용합니다.
"""

LAB_CATEGORIES = [
    {
        "slug": "sqli",
        "title": "SQL Injection",
        "nav_title": "SQL Injection",
        "description": "SQL 쿼리를 문자열로 조립했을 때 발생하는 문제와 파라미터 바인딩을 학습합니다.",
        "labs": [
            {
                "id": "sqli-login-bypass",
                "title": "로그인 우회",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "xss",
        "title": "Cross-Site Scripting",
        "nav_title": "XSS",
        "description": "사용자 입력을 HTML, 속성, JavaScript 컨텍스트에 출력할 때 필요한 방어를 학습합니다.",
        "labs": [
            {
                "id": "xss-reflected-search",
                "title": "검색 결과 Reflected XSS",
                "levels": 5,
                "implemented": False,
            },
            {
                "id": "xss-comment-board",
                "title": "댓글 게시판 Stored XSS",
                "levels": 5,
                "implemented": True,
            },
            {
                "id": "xss-dom-preview",
                "title": "클라이언트 미리보기 DOM XSS",
                "levels": 5,
                "implemented": False,
            },
        ],
    },
    {
        "slug": "csrf",
        "title": "Cross-Site Request Forgery",
        "nav_title": "CSRF",
        "description": "상태 변경 요청에 CSRF token과 SameSite 정책이 왜 필요한지 학습합니다.",
        "labs": [
            {
                "id": "csrf-change-email",
                "title": "이메일 변경 CSRF",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "ssrf",
        "title": "Server-Side Request Forgery",
        "nav_title": "SSRF",
        "description": "서버가 사용자 입력 URL을 요청할 때 생기는 위험을 로컬 mock endpoint로 학습합니다.",
        "labs": [
            {
                "id": "ssrf-local-metadata",
                "title": "로컬 메타데이터 조회 시뮬레이션",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "ssti",
        "title": "Server-Side Template Injection",
        "nav_title": "SSTI",
        "description": "사용자 입력을 서버 템플릿으로 해석하면 왜 위험한지 학습합니다.",
        "labs": [
            {
                "id": "ssti-profile-card",
                "title": "프로필 카드 템플릿 렌더링",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "command-injection",
        "title": "OS Command Injection",
        "nav_title": "Command Injection",
        "description": "명령 실행 기능을 설계할 때 shell 사용을 피하고 allowlist를 적용하는 방법을 학습합니다.",
        "labs": [
            {
                "id": "cmd-dns-lookup",
                "title": "진단 명령 실행 실습",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "file-upload",
        "title": "File Upload Vulnerabilities",
        "nav_title": "File Upload",
        "description": "업로드 파일의 확장자, MIME, 저장 경로, 실행 권한 분리를 학습합니다.",
        "labs": [
            {
                "id": "upload-profile-image",
                "title": "프로필 이미지 업로드",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "path-traversal",
        "title": "File Download / Path Traversal",
        "nav_title": "Path Traversal",
        "description": "파일 다운로드 기능에서 경로 정규화와 base directory 검증을 학습합니다.",
        "labs": [
            {
                "id": "download-report",
                "title": "리포트 다운로드 경로 조작",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "authentication",
        "title": "Authentication Vulnerabilities",
        "nav_title": "Authentication",
        "description": "로그인, 비밀번호 검증, 오류 메시지, 계정 상태 처리를 학습합니다.",
        "labs": [
            {
                "id": "auth-weak-login",
                "title": "약한 로그인 로직",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "access-control",
        "title": "Access Control Vulnerabilities",
        "nav_title": "Access Control",
        "description": "객체 단위 권한 검증과 역할 기반 접근 제어를 학습합니다.",
        "labs": [
            {
                "id": "idor-order-view",
                "title": "주문 상세 IDOR",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "business-logic",
        "title": "Business Logic Vulnerabilities",
        "nav_title": "Business Logic",
        "description": "쿠폰, 주문, 가격 계산처럼 기능 흐름에서 발생하는 논리 결함을 학습합니다.",
        "labs": [
            {
                "id": "coupon-checkout",
                "title": "쿠폰 checkout 로직 검증",
                "levels": 5,
                "implemented": True,
            }
        ],
    },
    {
        "slug": "info-disclosure",
        "title": "Information Disclosure",
        "nav_title": "Info Disclosure",
        "description": "디버그 정보, 상세 오류, 내부 데이터가 노출되는 문제를 학습합니다.",
        "labs": [
            {
                "id": "info-debug-leak",
                "title": "디버그 정보 노출",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "insecure-deserialization",
        "title": "Insecure Deserialization",
        "nav_title": "Deserialization",
        "description": "신뢰할 수 없는 직렬화 데이터를 처리할 때의 위험과 안전한 JSON 검증을 학습합니다.",
        "labs": [
            {
                "id": "deserialize-preferences",
                "title": "사용자 설정 역직렬화",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "xxe",
        "title": "XML External Entity",
        "nav_title": "XXE",
        "description": "XML 파서 설정과 외부 엔티티 비활성화의 필요성을 학습합니다.",
        "labs": [
            {
                "id": "xxe-xml-profile",
                "title": "XML 프로필 업로드",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "nosql-injection",
        "title": "NoSQL Injection",
        "nav_title": "NoSQL Injection",
        "description": "JSON 기반 조건 필터에서 발생할 수 있는 검증 누락을 학습합니다.",
        "labs": [
            {
                "id": "nosql-product-filter",
                "title": "JSON 조건 필터 우회",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "host-header",
        "title": "HTTP Host Header Attacks",
        "nav_title": "Host Header",
        "description": "Host 헤더를 신뢰해 URL을 생성할 때 생기는 문제를 학습합니다.",
        "labs": [
            {
                "id": "host-reset-link",
                "title": "비밀번호 재설정 링크 생성",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "jwt",
        "title": "JWT Vulnerabilities",
        "nav_title": "JWT",
        "description": "JWT 서명 검증, 알고리즘 고정, 만료 검증의 중요성을 학습합니다.",
        "labs": [
            {
                "id": "jwt-role-confusion",
                "title": "JWT role 검증 오류",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "oauth",
        "title": "OAuth Misconfiguration",
        "nav_title": "OAuth",
        "description": "로컬 mock OAuth 흐름에서 state와 redirect URI 검증을 학습합니다.",
        "labs": [
            {
                "id": "oauth-callback-confusion",
                "title": "mock OAuth callback 검증",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "cors",
        "title": "CORS Misconfiguration",
        "nav_title": "CORS",
        "description": "Origin 검증과 credential 허용 설정의 위험을 학습합니다.",
        "labs": [
            {
                "id": "cors-trusted-origin",
                "title": "Origin 검증 실수",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "clickjacking",
        "title": "Clickjacking",
        "nav_title": "Clickjacking",
        "description": "iframe 삽입을 제한하는 보안 헤더와 UI 보호 기법을 학습합니다.",
        "labs": [
            {
                "id": "clickjacking-transfer",
                "title": "iframe 보호 설정",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "websocket",
        "title": "WebSocket Vulnerabilities",
        "nav_title": "WebSocket",
        "description": "WebSocket 연결 후 메시지 단위 권한 검증이 필요한 이유를 학습합니다.",
        "labs": [
            {
                "id": "ws-support-chat",
                "title": "채팅 권한 검증",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "cache-poisoning",
        "title": "Web Cache Poisoning",
        "nav_title": "Cache Poisoning",
        "description": "캐시 키 설계와 헤더 기반 응답 변조 문제를 mock cache로 학습합니다.",
        "labs": [
            {
                "id": "cache-header-poison",
                "title": "헤더 기반 캐시 오염 시뮬레이션",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "cache-deception",
        "title": "Web Cache Deception",
        "nav_title": "Cache Deception",
        "description": "사용자별 동적 응답을 정적 파일처럼 캐싱할 때 생기는 문제를 학습합니다.",
        "labs": [
            {
                "id": "cache-profile-static",
                "title": "정적 확장자 캐시 오해",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "prototype-pollution",
        "title": "Prototype Pollution",
        "nav_title": "Prototype Pollution",
        "description": "JavaScript 객체 병합에서 신뢰할 수 없는 key를 처리하는 방법을 학습합니다.",
        "labs": [
            {
                "id": "proto-settings-merge",
                "title": "설정 병합 취약점",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "graphql",
        "title": "GraphQL API Vulnerabilities",
        "nav_title": "GraphQL",
        "description": "GraphQL 필드 권한, 과도한 조회, introspection 설정 문제를 학습합니다.",
        "labs": [
            {
                "id": "graphql-user-query",
                "title": "과도한 필드 조회와 권한",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "api-testing",
        "title": "API Testing Vulnerabilities",
        "nav_title": "API Testing",
        "description": "Mass Assignment, 과도한 응답, 상태 변경 API 검증을 학습합니다.",
        "labs": [
            {
                "id": "api-mass-assignment",
                "title": "Mass Assignment",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "race-conditions",
        "title": "Race Conditions",
        "nav_title": "Race Conditions",
        "description": "동시 요청에서 재고, 쿠폰, 상태 변경이 꼬이는 문제를 안전하게 시뮬레이션합니다.",
        "labs": [
            {
                "id": "race-coupon-redeem",
                "title": "쿠폰 동시 사용",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "request-smuggling",
        "title": "HTTP Request Smuggling",
        "nav_title": "Request Smuggling",
        "description": "실제 프록시 체인 공격이 아니라 요청 파싱 차이를 안전한 시뮬레이터로 학습합니다.",
        "labs": [
            {
                "id": "smuggling-parser-diff",
                "title": "요청 파싱 차이 시뮬레이터",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "dom-vulnerabilities",
        "title": "DOM-based Vulnerabilities",
        "nav_title": "DOM Vulnerabilities",
        "description": "클라이언트 측 URL, hash, query string 처리에서 생기는 DOM 기반 문제를 학습합니다.",
        "labs": [
            {
                "id": "dom-open-redirect",
                "title": "DOM 기반 리다이렉트",
                "levels": 5,
            }
        ],
    },
    {
        "slug": "llm-prompt-injection",
        "title": "LLM / Prompt Injection",
        "nav_title": "LLM Prompt Injection",
        "description": "외부 LLM API 없이 mock 상담 봇으로 prompt injection의 기초를 학습합니다.",
        "labs": [
            {
                "id": "llm-support-bot",
                "title": "mock 상담 봇 prompt injection",
                "levels": 5,
            }
        ],
    },
]


def get_categories():
    """
    전체 카테고리 목록을 반환합니다.

    원본 리스트를 직접 수정하지 않도록 호출부에서는 읽기 용도로만 사용합니다.
    """
    return LAB_CATEGORIES


def get_category(category_slug):
    """
    slug로 카테고리 하나를 찾습니다.
    """
    for category in LAB_CATEGORIES:
        if category["slug"] == category_slug:
            return category

    return None


def get_total_lab_count():
    """
    전체 Lab 개수를 계산합니다.
    """
    return sum(len(category["labs"]) for category in LAB_CATEGORIES)


def get_total_level_count():
    """
    전체 Level 개수를 계산합니다.
    """
    return sum(
        lab["levels"]
        for category in LAB_CATEGORIES
        for lab in category["labs"]
    )


def get_lab_summary(category_slug, lab_id):
    """
    registry metadata에서 특정 Lab 요약 정보를 찾습니다.
    """

    category = get_category(category_slug)

    if category is None:
        return None

    for lab in category["labs"]:
        if lab["id"] == lab_id:
            return lab

    return None