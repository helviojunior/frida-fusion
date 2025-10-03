import json
import os.path
from pathlib import Path
from frida_fusion.libs.logger import Logger
from frida_fusion.libs.database import Database
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.module import ModuleBase


class SharedPreferences(ModuleBase):
    _hide_commons = [
        "RCTI18nUtil",
        "NETWORK_USAGE_TRACKING_",
    ]

    class SharedPreferencesDB(Database):
        dbName = ""

        def __init__(self, db_name: str):
            super().__init__(
                auto_create=True,
                db_name=db_name
            )
            self.create_db()

        def create_db(self):
            super().create_db()
            conn = self.connect_to_db(check=False)

            # definindo um cursor
            cursor = conn.cursor()

            # criando a tabela (schema)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS [shared_preferences] (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package TEXT NOT NULL,
                    module TEXT NULL,
                    class_name TEXT NULL,
                    method TEXT NULL,
                    args TEXT NULL,
                    result TEXT NULL,
                    stack_trace TEXT NULL,
                    created_date datetime not null DEFAULT (datetime('now','localtime'))
                );
            """)

            conn.commit()

            # Must get the constraints
            self.get_constraints(conn)

    def __init__(self):
        super().__init__('Shared Preferences', 'Hook android.content.SharedPreferences functions')
        self._shared_preferences_db = None
        self._package = None
        self._suppress_messages = False
        self.mod_path = str(Path(__file__).resolve().parent)

    def start_module(self, **kwargs) -> bool:
        if 'db_path' not in kwargs:
            raise Exception("parameter db_path not found")

        self._package = kwargs['package']
        self._shared_preferences_db = SharedPreferences.SharedPreferencesDB(db_name=kwargs['db_path'])
        return True

    def js_files(self) -> list:
        return [
            os.path.join(self.mod_path, "shared_preferences.js")
        ]

    def suppress_messages(self):
        self._suppress_messages = True

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:

        if 'SharedPreferences.' in module:
            try:
                received_data['args'] = json.loads(received_data.get('args', "[]"))
            except Exception:
                pass
            try:
                received_data['result'] = json.loads(received_data.get('result', ""))
            except Exception:
                pass

            s_args = received_data.get('args', "[]")
            if not isinstance(s_args, str):
                s_args = json.dumps(s_args, default=Logger.json_serial)

            s_result = received_data.get('result', "")
            if not isinstance(s_result, str):
                s_result = json.dumps(s_result, default=Logger.json_serial)

            class_name = received_data.get('class', '<unknown>')
            s_method = received_data.get('method', '<unknown>')

            self._shared_preferences_db.insert_one(
                table_name='shared_preferences',
                package=self._package,
                module=module,
                class_name=class_name,
                method=s_method,
                args=s_args,
                result=s_result,
                stack_trace=stack_trace
            )

        if module in [
            "SharedPreferences.getString",
            "SharedPreferences.getInt",
            "SharedPreferences.getLong",
            "SharedPreferences.getFloat",
            "SharedPreferences.getStringSet",
            "SharedPreferences.putString",
            "SharedPreferences.putInt",
            "SharedPreferences.putLong",
            "SharedPreferences.putFloat",
            "SharedPreferences.putStringSet",
        ]:
            if self._check_show(received_data):
                class_name = received_data.get('class', '<unknown>')
                s_method = received_data.get('method', '<unknown>')

                l_args = ', '.join([
                    "null" if v is None else (str(v) if isinstance(v, float) else (
                        str(v) if isinstance(v, int) else f"'{str(v)}'" if isinstance(v, str) else f"{str(v)}"))
                    for v in received_data.get('args', [])
                ])
                data = "null"
                try:
                    data = json.dumps(received_data.get('result', None), default=Logger.json_serial, indent=4,
                                      sort_keys=False)
                except Exception:
                    pass
                Logger.print_message(
                    level="I",
                    message=f"{class_name}->{s_method}({l_args})\nResult: {data}",
                    script_location=script_location
                )

        if 'SharedPreferences.' in module:
            if self._check_show(received_data):
                data = json.dumps(received_data, default=Logger.json_serial, indent=4, sort_keys=False)
                Logger.print_message(
                    level="D",
                    message=f"{module}:\n{data}\n{stack_trace}",
                    script_location=script_location
                )

        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        # Nothing by now
        return True

    def _check_show(self, received_data: dict = None) -> bool:
        if self._suppress_messages:
            return False

        c_args = received_data.get('args', "[]")
        if not isinstance(c_args, str):
            c_args = json.dumps(c_args, default=Logger.json_serial)

        return not any([
            True
            for k in SharedPreferences._hide_commons
            if k in c_args
        ])
