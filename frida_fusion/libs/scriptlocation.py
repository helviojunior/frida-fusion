from pathlib import Path


class ScriptLocation(object):
    def __init__(self, file_name: str = "<unknown>", function_name: str = "<unknown>", line: str = "<unknown>"):
        self.file_name = file_name if file_name is not None else "<unknown>"
        self.function_name = function_name if function_name is not None else "<unknown>"
        self.line = str(line) if line is not None else "<unknown>"

    def get_int_line(self):
        try:
            return int(self.line)
        except Exception:
            return 0

    def __str__(self):
        return f"{self.file_name}:{self.line} ({self.function_name})"

    def __repr__(self):
        return str(self)

    @staticmethod
    def parse_from_dict(data: dict):

        file_name = Path(data.get("file_name", "unknown")).name
        function_name = data.get("function_name", "unknown")
        line = str(data.get("line", -1))

        if 'fileName' in data.keys():
            file_name = Path(data.get("fileName", file_name)).name

        if 'lineNumber' in data.keys():
            line = str(data.get("lineNumber", line))

        return ScriptLocation(
            file_name=file_name,
            function_name=function_name,
            line=line
        )
