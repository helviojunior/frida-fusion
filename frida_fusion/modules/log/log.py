import json
import os.path
from pathlib import Path
from frida_fusion.libs.logger import Logger
from frida_fusion.libs.database import Database
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.module import ModuleBase


class AndroidLog(ModuleBase):
    def __init__(self):
        super().__init__('Log', 'Hook android.util.Log.* functions')
        self._package = None
        self._suppress_messages = False
        self.mod_path = str(Path(__file__).resolve().parent)

    def start_module(self, **kwargs) -> bool:
        if 'db_path' not in kwargs:
            raise Exception("parameter db_path not found")

        self._package = kwargs['package']
        return True

    def js_files(self) -> list:
        return [
            os.path.join(self.mod_path, "log.js")
        ]

    def suppress_messages(self):
        self._suppress_messages = True

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:

        if 'android.util.Log' in module:
            level = received_data.get('level', "I")
            if level is None:
                level = "I"
            message = received_data.get('message', '')
            tag = received_data.get('tag', '')
            if tag is None or tag.strip() == '':
                tag = None
            try:
                received_data['rawargs'] = json.loads(received_data.get('rawargs', ''))
            except Exception:
                pass

            # raw_args = received_data.get('rawargs', '')
            if Logger.check_print(level="D"):
                message += f"\n{stack_trace}"

            if not self._suppress_messages:
                Logger.print_message(
                    level=level.upper(),
                    message=f"{message}",
                    script_location=ScriptLocation(
                        file_name=tag,
                        line=f"{script_location.file_name}",
                        function_name=script_location.function_name
                    ) if tag is not None else script_location
                )

        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        # Nothing by now
        return True
