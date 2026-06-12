# file: app/extensions.py

from flask_sqlalchemy import SQLAlchemy


# Flask 확장 객체는 여기에서 먼저 만들고,
# create_app() 안에서 실제 Flask 앱과 연결합니다.
#
# 이렇게 하면 앱 팩토리 패턴을 유지할 수 있고,
# 테스트 앱을 따로 만들기도 쉬워집니다.
db = SQLAlchemy()