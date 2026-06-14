# file: app/labs/command_injection.py

from app.labs.base import LabDefinition, LabFormField, LabLevel
from app.services.mock_command_runner import (
    run_blocklist_shell_simulation,
    run_command_allowlist_but_raw_argument,
    run_safe_allowlist,
    run_shlex_without_argument_policy,
    run_vulnerable_shell_simulation,
)


COMMAND_FIELDS = [
    LabFormField(
        name="command",
        label="Command",
        placeholder="예: nslookup",
        help_text="실습용 명령 이름입니다. 실제 시스템 명령은 실행되지 않습니다.",
    ),
    LabFormField(
        name="target",
        label="Target",
        placeholder="예: example.test",
        help_text="명령 인자입니다. Level별로 검증 방식이 달라집니다.",
    ),
]


RAW_COMMAND_FIELDS = [
    LabFormField(
        name="raw_command",
        label="Raw command line",
        placeholder="예: nslookup example.test",
        help_text="Level 4에서 토큰화와 allowlist의 차이를 보여주기 위한 입력입니다.",
    )
]


COMMAND_INJECTION_LAB = LabDefinition(
    category="command-injection",
    lab_id="cmd-dns-lookup",
    title="진단 명령 실행 실습",
    summary="사용자 입력을 OS 명령 문자열에 붙일 때 생기는 문제와 allowlist 기반 설계를 학습합니다.",
    levels={
        1: LabLevel(
            level=1,
            title="사용자 입력을 명령 문자열에 그대로 연결",
            goal="사용자 입력이 shell 명령 문자열에 포함되면 명령 구조가 바뀔 수 있음을 이해합니다.",
            form_fields=COMMAND_FIELDS,
            hints=[
                "target 값이 명령 문자열에 그대로 붙는지 확인하세요.",
                "이 실습은 실제 shell을 실행하지 않고 mock runner가 분석만 수행합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 사용자 입력을 shell 명령 문자열에 그대로 붙입니다.

command_line = f"nslookup {target}"

subprocess.run(
    command_line,
    shell=True,
)
""",
            secure_code="""# 안전한 코드
# shell 문자열을 만들지 않고, 허용된 기능만 서버 코드로 분기합니다.

if command == "nslookup":
    result = run_dns_lookup_mock(validated_host)

elif command == "ping":
    result = run_ping_mock(validated_host)
""",
            defense_notes=[
                "`shell=True`에 사용자 입력을 넘기지 않습니다.",
                "사용자 입력을 명령 문자열에 직접 붙이지 않습니다.",
                "명령 이름과 인자 형식을 모두 제한해야 합니다.",
            ],
        ),
        2: LabLevel(
            level=2,
            title="일부 구분자 블랙리스트",
            goal="몇 가지 명령 구분자만 차단하는 방식이 부족하다는 점을 이해합니다.",
            form_fields=COMMAND_FIELDS,
            hints=[
                "블랙리스트가 모든 shell 문법을 포괄할 수 있는지 생각해보세요.",
                "차단 목록보다 안전한 실행 모델을 선택하는 것이 중요합니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# 일부 구분자만 차단합니다.

blocked = [";", "&&"]

if any(token in target for token in blocked):
    raise ValueError("blocked")

command_line = f"nslookup {target}"
subprocess.run(command_line, shell=True)
""",
            secure_code="""# 안전한 코드
# shell 파싱이 개입되지 않도록 문자열 명령을 만들지 않습니다.

validated_host = validate_hostname(target)
result = run_dns_lookup_mock(validated_host)
""",
            defense_notes=[
                "블랙리스트는 누락과 우회 가능성이 큽니다.",
                "명령어 보안은 문자열 필터보다 실행 모델이 중요합니다.",
                "shell 자체를 거치지 않는 구조가 안전합니다.",
            ],
        ),
        3: LabLevel(
            level=3,
            title="명령 이름만 allowlist",
            goal="명령 이름만 제한하고 인자를 검증하지 않으면 문제가 남는다는 점을 확인합니다.",
            form_fields=COMMAND_FIELDS,
            hints=[
                "command 값은 제한되어 있습니다.",
                "target 값은 어떤 방식으로 명령 문자열에 들어가는지 확인하세요.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# command 이름은 allowlist로 제한하지만 target은 그대로 붙입니다.

allowed_commands = {"nslookup", "ping"}

if command not in allowed_commands:
    raise ValueError("blocked command")

command_line = f"{command} {target}"
subprocess.run(command_line, shell=True)
""",
            secure_code="""# 안전한 코드
# command와 target을 각각 검증합니다.

if command not in {"nslookup", "ping"}:
    raise ValueError("blocked command")

if not is_safe_hostname(target):
    raise ValueError("invalid host")

result = run_mock_command(command, target)
""",
            defense_notes=[
                "명령 이름 allowlist만으로는 충분하지 않습니다.",
                "각 명령이 허용하는 인자 형식을 별도로 제한해야 합니다.",
                "문자열 조립을 계속 사용하면 shell 해석 문제가 남습니다.",
            ],
        ),
        4: LabLevel(
            level=4,
            title="shell은 줄였지만 인자 정책이 부족",
            goal="토큰화와 명령 allowlist가 있어도 사용자가 옵션과 인자를 과도하게 제어하면 정책 문제가 남는다는 점을 이해합니다.",
            form_fields=RAW_COMMAND_FIELDS,
            hints=[
                "명령어 문자열을 shlex로 나누는 것은 shell=True보다 낫습니다.",
                "하지만 사용자가 전체 명령줄을 통제한다면 기능 정책이 여전히 넓습니다.",
            ],
            vulnerable_code="""# 교육용 취약 코드
# shell=True는 피했지만 사용자가 전체 명령줄을 제어합니다.

tokens = shlex.split(raw_command)

if tokens[0] not in {"nslookup", "ping"}:
    raise ValueError("blocked command")

subprocess.run(tokens, shell=False)
""",
            secure_code="""# 안전한 코드
# 사용자가 전체 명령줄을 입력하지 못하게 하고,
# command와 argument를 분리해 검증합니다.

command = request.form["command"]
target = request.form["target"]

if command not in allowed_commands:
    raise ValueError("blocked command")

if not is_safe_hostname(target):
    raise ValueError("invalid host")

result = run_mock_command(command, target)
""",
            defense_notes=[
                "`shell=False`는 좋은 방향이지만 충분조건은 아닙니다.",
                "사용자가 전체 명령줄과 옵션을 제어하지 못하게 해야 합니다.",
                "기능 단위로 허용 명령과 허용 인자를 좁게 설계합니다.",
            ],
        ),
        5: LabLevel(
            level=5,
            title="안전한 구현",
            goal="shell 없이 allowlist 기반 mock command runner를 사용합니다.",
            form_fields=COMMAND_FIELDS,
            hints=[
                "명령 이름과 인자 형식을 둘 다 검증합니다.",
                "실제 시스템 명령은 실행되지 않고 mock 결과만 반환됩니다.",
            ],
            vulnerable_code="""# 이전 단계의 문제
# shell=False를 사용했지만 사용자가 전체 명령줄을 제어했습니다.

tokens = shlex.split(raw_command)
subprocess.run(tokens, shell=False)
""",
            secure_code="""# 안전한 코드
# 명령 이름과 인자를 각각 검증하고, shell을 사용하지 않습니다.

allowed_commands = {
    "nslookup": run_dns_lookup_mock,
    "ping": run_ping_mock,
    "whoami-demo": run_whoami_mock,
}

if command not in allowed_commands:
    raise ValueError("blocked command")

if command in {"nslookup", "ping"}:
    if not is_safe_hostname(target):
        raise ValueError("invalid host")

result = allowed_commands[command](target)
""",
            defense_notes=[
                "shell 명령 문자열을 만들지 않습니다.",
                "명령 이름은 allowlist로 제한합니다.",
                "명령 인자는 명령별 정책으로 검증합니다.",
                "실제 시스템 명령이 필요한 경우에도 `shell=False`와 리스트 인자를 사용해야 합니다.",
                "이 실습은 실제 시스템 명령 대신 mock runner만 사용합니다.",
            ],
        ),
    },
)


def get_lab(lab_id):
    """
    Command Injection 카테고리의 Lab을 반환합니다.
    """

    if lab_id == COMMAND_INJECTION_LAB.lab_id:
        return COMMAND_INJECTION_LAB

    return None


def run_level(lab_id, level, form, files=None):
    """
    특정 Command Injection Lab Level을 실행합니다.
    """

    lab = get_lab(lab_id)
    if lab is None:
        return _error_result("존재하지 않는 Command Injection Lab입니다.")

    if level not in lab.levels:
        return _error_result("존재하지 않는 Level입니다.")

    if level == 4:
        raw_command = form.get("raw_command", "").strip()

        if not raw_command:
            raw_command = "nslookup example.test"

        result = run_shlex_without_argument_policy(raw_command)

    else:
        command = form.get("command", "").strip() or "nslookup"
        target = form.get("target", "").strip() or "example.test"

        if level == 1:
            command_line = f"nslookup {target}"
            result = run_vulnerable_shell_simulation(command_line)

        elif level == 2:
            command_line = f"nslookup {target}"
            result = run_blocklist_shell_simulation(
                command_line,
                blocked_tokens=[";", "&&"],
            )

        elif level == 3:
            result = run_command_allowlist_but_raw_argument(command, target)

        else:
            result = run_safe_allowlist(command, target)

    return {
        "kind": "command-injection",
        "status": "ok" if result.accepted else "blocked",
        "message": "mock command runner가 명령 처리 흐름을 시뮬레이션했습니다.",
        "command_line": result.command_line,
        "mode": result.mode,
        "accepted": result.accepted,
        "reasons": result.reasons,
        "fragments": result.fragments,
        "rows": [],
    }


def _error_result(message):
    return {
        "kind": "command-injection",
        "status": "error",
        "message": message,
        "command_line": "",
        "mode": "",
        "accepted": False,
        "reasons": [],
        "fragments": [],
        "rows": [],
    }