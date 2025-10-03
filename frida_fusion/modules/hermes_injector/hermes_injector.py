import errno
import os.path
import base64
import sys
from pathlib import Path
from argparse import _ArgumentGroup, Namespace
from frida_fusion.libs.logger import Logger
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.module import ModuleBase


class HermesJSInjector(ModuleBase):

    def __init__(self):
        super().__init__('Hermes Injector', 'Inject JavaScript at Hermes engine used by React Native.')
        self.mod_path = str(Path(__file__).resolve().parent)
        self.js_file = os.path.join(self.mod_path, "hermes_injector.js")
        self.hermes_js_file = ""
        self._suppress_messages = False

    def start_module(self, **kwargs) -> bool:
        pass

    def js_files(self) -> list:
        return [
            self.js_file
        ]

    def suppress_messages(self):
        self._suppress_messages = True

    def dynamic_script(self) -> str:
        return f"const FUSION_HERMES_JS = '{self.hermes_js_file}';"
    
    def add_params(self, flags: _ArgumentGroup):
        flags.add_argument('--hermes-js-script',
                           dest='hermes_js_file',
                           metavar='file',
                           default=None,
                           required=True,
                           type=str,
                           help='Hermes JS file path')

    def load_from_arguments(self, args: Namespace) -> bool:
        if args.hermes_js_file is None:
            return False

        try:
            b_data = bytearray()
            with open(os.path.join(self.mod_path, "hermes_hook.js"), 'rb') as f:
                b_data = bytearray(f.read())

            if len(b_data) > 0:
                b_data += bytearray([0x0a, 0x0a])

            with open(args.hermes_js_file, 'rb') as f:
                b_data += bytearray(f.read())
            
            self.hermes_js_file = base64.b64encode(b_data).decode("UTF-8")

        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl('{!} {R}error: could not open hermes js file {O}permission denied{R}{W}\r\n')
                sys.exit(1)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open hermes js file {O}it is an directory{R}{W}\r\n')
                sys.exit(1)
            else:
                Logger.pl('{!} {R}error: could not open hermes js file: %s{W}\r\n' % str(x))
                sys.exit(1)

        return True

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:
        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        return True


