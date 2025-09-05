import os
import pkgutil
import importlib
from pathlib import Path

from .libs.database import Database
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .fusion import Fusion  # só no type checker


class ModuleBase(object):

    name = ''
    description = ''
    mod_path = ''

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.mod_path = str(Path(__file__).resolve().parent)
        pass

    def start_db(self, db_path: str) -> bool:
        raise Exception('Method "start_db" is not yet implemented.')

    def js_files(self) -> list:
        return []

    def key_value_event(self,
                        script_location: "Fusion.ScriptLocation" = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:
        raise Exception('Method "key_value_event" is not yet implemented.')

    def data_event(self,
                   script_location: "Fusion.ScriptLocation" = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        raise Exception('Method "data_event" is not yet implemented.')


class Module(object):
    modules = {}

    def __init__(self, name, description, module, qualname, class_name):
        self.name = name
        self.description = description
        self.module = module
        self.qualname = qualname
        self._class = class_name
        pass

    def create_instance(self):
        return self._class()

    @classmethod
    def get_instance(cls, name: str):
        if len(Module.modules) == 0:
            Module.modules = Module.list_modules()

        selected_modules = [
            mod for mod in Module.modules
            if mod == name
        ]

        mod = None
        if len(selected_modules) == 1:
            mod = Module.modules[selected_modules[0]].create_instance()

        return mod

    @classmethod
    def get_base_module(cls) -> str:
        file = Path(__file__).stem

        parent_module = f'.{cls.__module__}.'.replace(f'.{file}.', '').strip(' .')

        return '.'.join((parent_module, 'modules'))

    @classmethod
    def list_modules(cls) -> dict:
        try:

            base_module = Module.get_base_module()

            modules = {}

            base_path = os.path.join(
                Path(__file__).resolve().parent, 'modules'
            )

            for loader, modname, ispkg in pkgutil.walk_packages([base_path]):
                if not ispkg:
                    importlib.import_module(f'{base_module}.{modname}')

            for iclass in ModuleBase.__subclasses__():
                t = iclass()
                if t.name in modules:
                    raise Exception(f'Duplicated Module name: {iclass.__module__}.{iclass.__qualname__}')

                modules[t.name.lower()] = Module(
                    name=t.name,
                    description=t.description,
                    module=str(iclass.__module__),
                    qualname=str(iclass.__qualname__),
                    class_name=iclass
                )

            return modules

        except Exception as e:
            raise Exception('Error listing command modules', e)
