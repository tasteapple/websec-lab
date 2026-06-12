# file: run.py

from app import create_app


# Flask CLI가 찾을 수 있는 애플리케이션 객체입니다.
# 실행 예:
# python -m flask --app run run --debug --host 127.0.0.1 --port 5000
app = create_app()