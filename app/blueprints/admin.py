# file: app/blueprints/admin.py

from flask import Blueprint, abort, jsonify, request

from app.seed import seed_database


admin_bp = Blueprint("admin", __name__)


def _require_local_request():
    """
    /admin/seed는 로컬 개발 전용 endpoint입니다.

    교육용 취약 코드와 샘플 데이터를 다루므로,
    기본적으로 localhost 요청만 허용합니다.
    """

    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)


@admin_bp.get("/admin/seed")
def seed_help():
    """
    seed 초기화 안내 페이지입니다.

    실제 초기화는 POST 요청에서만 수행합니다.
    """

    _require_local_request()

    return """
    <!doctype html>
    <html lang="ko">
      <head>
        <meta charset="utf-8">
        <title>Seed Database</title>
        <style>
          body {
            margin: 40px;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f6f7f9;
            color: #222;
          }
          main {
            max-width: 760px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 28px;
          }
          code {
            background: #f0f2f4;
            padding: 2px 6px;
            border-radius: 4px;
          }
          .warning {
            border-left: 4px solid #b45309;
            background: #fff7ed;
            padding: 12px 16px;
            margin: 18px 0;
          }
          button {
            padding: 8px 14px;
            border: 1px solid #333;
            border-radius: 6px;
            background: #222;
            color: white;
            cursor: pointer;
          }
        </style>
      </head>
      <body>
        <main>
          <h1>Seed Database</h1>

          <p>
            이 페이지는 로컬 개발용 샘플 데이터를 초기화합니다.
          </p>

          <div class="warning">
            기존 SQLite 데이터가 모두 삭제되고 다시 생성됩니다.
          </div>

          <p>터미널에서 실행하려면:</p>

          <pre><code>curl -X POST "http://127.0.0.1:5000/admin/seed?confirm=reset-lab-db"</code></pre>

          <form method="post" action="/admin/seed?confirm=reset-lab-db">
            <button type="submit">로컬 샘플 데이터 초기화</button>
          </form>

          <p>
            <a href="/">대시보드로 돌아가기</a>
          </p>
        </main>
      </body>
    </html>
    """


@admin_bp.post("/admin/seed")
def seed():
    """
    로컬 SQLite DB를 초기화하고 샘플 데이터를 넣습니다.

    confirm query parameter를 요구해서 실수로 실행되는 것을 줄입니다.
    """

    _require_local_request()

    if request.args.get("confirm") != "reset-lab-db":
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "confirm=reset-lab-db query parameter가 필요합니다.",
                }
            ),
            400,
        )

    counts = seed_database()

    return jsonify(
        {
            "status": "ok",
            "message": "로컬 샘플 데이터가 초기화되었습니다.",
            "counts": counts,
        }
    )