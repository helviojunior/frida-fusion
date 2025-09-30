import errno
import os.path
import json
from pathlib import Path
from frida_fusion.libs.logger import Logger
from frida_fusion.module import ModuleBase
from frida_fusion.libs.scriptlocation import ScriptLocation


class OkHttpLogging(ModuleBase):

    def __init__(self):
        super().__init__('OkHttp3 logging', 'Use okhttp-logging by Helvio Junior (M4v3r1ck)')
        self.mod_path = str(Path(__file__).resolve().parent)
        self.js_file = os.path.join(self.mod_path, "okhttp-logging.js")
        self._suppress_messages = False
        self._log_level = 'BODY'

    '''
    const Level = {
          NONE: 'NONE',
          BASIC: 'BASIC',
          HEADERS: 'HEADERS',
          BODY: 'BODY',
          STREAMING: 'STREAMING'
        };
    '''

    def start_module(self, **kwargs) -> bool:
        pass

    def js_files(self) -> list:
        return [
            self.js_file
        ]

    def suppress_messages(self):
        self._suppress_messages = True

    def dynamic_script(self) -> str:
        return f"const FF_OKHTTP_LOGGING_LEVEL = '{self._log_level}';"

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:

        if module == "okhttp!intercept":

            if not self._suppress_messages:
                data=json.dumps(received_data, default=Logger.json_serial, indent=4, sort_keys=False)

                Logger.print_message(
                    level="I",
                    message=f"HTTP package\n{data}",
                    script_location=script_location
                )

        elif module == "okhttp!intercept!interceptors":
            if not self._suppress_messages:
                t_name = received_data.get('type', 'interceptor')
                i_class = received_data.get('interceptorclass', '')
                Logger.print_message(
                    level="I",
                    message=f"okhttp {t_name} found!\nClass: {i_class}",
                    script_location=script_location
                )
            
        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        return True


