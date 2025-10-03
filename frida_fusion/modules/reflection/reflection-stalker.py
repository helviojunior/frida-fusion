import errno
import sys
import json
import os.path
from pathlib import Path
from argparse import _ArgumentGroup, Namespace
from frida_fusion.libs.logger import Logger
from frida_fusion.libs.database import Database
from frida_fusion.module import ModuleBase
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.exceptions import SilentKillError


class Reflection(ModuleBase):

    _EXCLUSION_LIST = [
        "android.view.View.onDraw", 
        "android.graphics.Picture",
        "com.facebook.fbreact.specs.NativeAnimatedModuleSpec",
        "com.facebook.react.uimanager.BaseViewManager.setTransform",
        "com.facebook.react.uimanager.ReanimatedUIManager.updateView",
        "com.facebook.fbreact.specs.NativeStatusBarManagerAndroidSpec"
    ]

    class StalkerDB(Database):
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
                CREATE TABLE IF NOT EXISTS [reflection_stalker] (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    method TEXT NOT NULL,
                    method_b64 TEXT NULL,
                    method_name TEXT NULL,
                    target_class TEXT NULL,
                    target_tostring TEXT NULL,
                    params_count TEXT NULL,
                    params TEXT NULL,
                    error TEXT NULL,
                    return_summary TEXT NULL,
                    return_class TEXT NULL,
                    stack_trace TEXT NULL,
                    created_date datetime not null DEFAULT (datetime('now','localtime'))
                );
            """)

            conn.commit()

            # Must get the constraints
            self.get_constraints(conn)

    def __init__(self):
        super().__init__('Reflection Stalker', 'Monitor reflection calls/invoke')
        self.mod_path = str(Path(__file__).resolve().parent)
        self._stalker_db = None
        self._suppress_messages = False
        self._ignore_list = []
        self.js_file = os.path.join(self.mod_path, "reflection-stalker.js")

    def start_module(self, **kwargs) -> bool:
        if 'db_path' not in kwargs:
            raise Exception("parameter db_path not found")

        self._stalker_db = Reflection.StalkerDB(db_name=kwargs['db_path'])

    def js_files(self) -> list:
        return [
            self.js_file
        ]

    def suppress_messages(self):
        self._suppress_messages = True

    def dynamic_script(self) -> str:
        return f""
    

    def add_params(self, flags: _ArgumentGroup):
        flags.add_argument('--ignore-stalker-text',
                         dest='reflection_stalker_ignore',
                         metavar='text',
                         action='append',
                         help='Text to ignore at screen output. You can specify multiple values repeating the flag.')

    def load_from_arguments(self, args: Namespace) -> bool:
        self._ignore_list = []

        if args.reflection_stalker_ignore is None or len(args.reflection_stalker_ignore) == 0:
            return True

        self._ignore_list = list(set([
            txt.lower()
            for t1 in args.reflection_stalker_ignore
            if (txt := t1.strip()) != ''
            ]))

        return True

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:


        if module in ["java.lang.reflect.Method!invoke!throw",
                      "java.lang.reflect.Method!invoke!call"
                      ]:
            
            # Exclusion list
            method = received_data.get('method', '')
            for em in Reflection._EXCLUSION_LIST:
                if em in method:
                    return

            params_preview = received_data.get('params_preview', '[]')
            try:
                params = json.dumps(json.loads(params_preview), default=Logger.json_serial)
            except Exception:
                params = params_preview

            return_summary = received_data.get('return_summary', None)
            try:
                return_summary = json.dumps(json.loads(return_summary), default=Logger.json_serial)
            except Exception:
                pass

            backtrace = received_data.get('backtrace_raw', None)
            try:
                if backtrace is None:
                    raise Exception()

                if isinstance(backtrace, str):
                    backtrace = json.loads(backtrace)

                bt = "Stack trace:\n    at "
                bt += '\n    at '.join([
                    ln 
                    for ln in backtrace
                    if 'dalvik.system.VMStack.getThreadStackTrace' not in ln
                    and 'java.lang.Thread.getStackTrace' not in ln
                    ])

                backtrace = bt
            except Exception:
                backtrace = received_data.get('backtrace', stack_trace)

            self._stalker_db.insert_one(
                table_name='reflection_stalker',
                stack_trace=backtrace,
                error=received_data.get('error', ''),
                method=received_data.get('method', ''),
                method_b64=received_data.get('method_b64', ''),
                method_name=received_data.get('method_name', ''),
                target_class=received_data.get('target_class', ''),
                target_tostring=received_data.get('target_tostring', ''),
                params_count=received_data.get('params_count', ''),
                params=params,
                return_summary=return_summary,
                return_class=received_data.get('return_class', '')
            )

            if not self._suppress_messages:
                txt = json.dumps(received_data, indent=4)
                for em in self._ignore_list:
                    if em in txt.lower():
                        return

                Logger.print_message(
                        level="I",
                        message=f"Reflection: {received_data.get('method', '')}",
                        script_location=script_location
                    )
                
                
                Logger.print_message(
                        level="D",
                        message=f"Reflection: {module}\n{txt}",
                        script_location=script_location
                    )

        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        return True


