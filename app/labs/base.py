# file: app/labs/base.py

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LabFormField:
    """
    Lab 입력 폼에 표시할 필드 정의입니다.

    템플릿이 특정 Lab의 폼 구조를 몰라도 렌더링할 수 있도록
    field metadata를 공통 구조로 관리합니다.
    """

    name: str
    label: str
    field_type: str = "text"
    placeholder: str = ""
    help_text: str = ""


@dataclass(frozen=True)
class LabLevel:
    """
    하나의 Lab Level 정의입니다.

    vulnerable_code와 secure_code는 화면에서 비교용으로 표시됩니다.
    실제 처리 로직은 각 Lab 모듈의 handler 함수에 둡니다.
    """

    level: int
    title: str
    goal: str
    form_fields: list[LabFormField]
    hints: list[str]
    vulnerable_code: str
    secure_code: str
    defense_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LabDefinition:
    """
    하나의 실습 문제 정의입니다.
    """

    category: str
    lab_id: str
    title: str
    summary: str
    levels: dict[int, LabLevel]

    @property
    def level_count(self):
        return len(self.levels)

    def get_level(self, level):
        return self.levels.get(level)