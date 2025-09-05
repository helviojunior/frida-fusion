import errno
import os.path
from pathlib import Path
from frida_fusion.libs.logger import Logger
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.module import ModuleBase


class TlsUnpinning(ModuleBase):

    def __init__(self):
        super().__init__('Multiple unpinning', 'Use frida_multiple_unpinning by Maurizio Siddu (@akabe1)')
        self.mod_path = str(Path(__file__).resolve().parent)
        self.js_file = os.path.join(self.mod_path, "frida_multiple_unpinning.js")

    def start_module(self, **kwargs) -> bool:
        if not os.path.isfile(self.js_file):
            Logger.pl("{+} Downloading CodeShare script from @akabe1/frida-multiple-unpinning")
            data = self._get_codeshare("@akabe1/frida-multiple-unpinning/")
            if data.get('source', None) is None or data.get('source', '').strip(" \r\n") == "":
                raise Exception("source code is empty")

            try:
                with open(self.js_file, "w", encoding='utf-8') as f:
                    f.write(data.get('source', ''))
            except IOError as x:
                if x.errno == errno.EACCES:
                    Logger.pl('{!} {R}error: could not open output file to write {O}permission denied{R}{W}\r\n')
                elif x.errno == errno.EISDIR:
                    Logger.pl('{!} {R}error: could not open output file to write {O}it is an directory{R}{W}\r\n')
                else:
                    Logger.pl('{!} {R}error: could not open output file to write{W}\r\n')

                # Try to save locally
                self.js_file = str(Path("frida_multiple_unpinning.js").resolve().absolute())
                with open(self.js_file, "w", encoding='utf-8') as f:
                    f.write(data.get('source', ''))

        return True

    def js_files(self) -> list:
        return [
            self.js_file
        ]

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


