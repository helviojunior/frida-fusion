import base64
import errno
import os.path
import json
from pathlib import Path
from frida_fusion.libs.logger import Logger
from frida_fusion.module import ModuleBase
from frida_fusion.libs.scriptlocation import ScriptLocation


class OkHttpLogging(ModuleBase):

    def __init__(self):
        super().__init__('OkHttp3 logging', 'Use okhttp-logging')
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
                Logger.print_message(
                    level="I",
                    message=self.format_output(received_data),
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

    @classmethod
    def format_output(cls, received_data: dict = None) -> str:
        unk = "<unknown>"
        error = received_data.get("error", None)
        response_code = received_data.get("response-code", None)
        elapsed_ime = received_data.get("elapsed-time", "")
        method = received_data.get("method", unk)
        url = received_data.get("url", unk)
        protocol = (received_data.get("protocol", unk) or unk).upper()
        headers = received_data.get("request-header", "").replace("\r", "")
        data = f'--> {method} {url} {protocol}\n'
        data += f'{headers}\n'
        request_body = received_data.get("request-body", None)
        try:
            if request_body is not None and request_body.strip() != "":
                request_body = base64.b64decode(request_body.encode("UTF-8")).decode("UTF-8")
            else:
                request_body = None
        except Exception:
            pass

        if request_body is not None:
            data += f'{request_body}\n\n'

        if error is not None:
            data += f'<-- HTTP ERROR ({elapsed_ime}ms)\n'
            data += f'{error}\n'

        if response_code is not None:
            response_status = received_data.get("response-status", None)
            response_body = received_data.get("response-body", None)
            response_header = received_data.get("response-header", "")
            try:
                if response_body is not None and response_body.strip() != "":
                    response_body = base64.b64decode(response_body.encode("UTF-8")).decode("UTF-8")
                else:
                    response_body = None
            except Exception:
                pass

            # Try to decode as json
            try:
                response_body = json.dumps(
                    json.loads(response_body),
                    default=Logger.json_serial,
                    indent=4, sort_keys=False)
            except Exception:
                pass

            data += f'<-- {response_code} {response_status} ({elapsed_ime}ms)\n'
            data += f'{response_header}\n'
            if response_body is not None:
                data += f'{response_body}\n\n'

        data += f'<-- END HTTP\n'

        return data
