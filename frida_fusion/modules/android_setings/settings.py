import json
import os.path
from pathlib import Path
import base64
import string

from frida_fusion.libs.logger import Logger
from frida_fusion.libs.database import Database
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.module import ModuleBase


class Settings(ModuleBase):
    class SettingsDB(Database):
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
                CREATE TABLE IF NOT EXISTS [android_settings] (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NULL,
                    name TEXT NULL,
                    flag INTEGER NULL DEFAULT (0),
                    data TEXT NULL,
                    created_date datetime not null DEFAULT (datetime('now','localtime')),
                    UNIQUE (module, name, flag, data)
                );
            """)

            conn.commit()

            # Must get the constraints
            self.get_constraints(conn)

    def __init__(self):
        super().__init__('Settings', 'Hook Android Settings functions')
        self._settings_db = None
        self.mod_path = str(Path(__file__).resolve().parent)

    def start_module(self, **kwargs) -> bool:
        if 'db_path' not in kwargs:
            raise Exception("parameter db_path not found")

        self._settings_db = Settings.SettingsDB(db_name=kwargs['db_path'])
        return True

    def js_files(self) -> list:
        return [
            os.path.join(self.mod_path, "settings.js")
        ]

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:

        if module in ["Settings$Secure.getString",
                      "Settings$Secure.putString",
                      "Settings$Secure.getUriFor",
                      "Settings$Secure.getInt",
                      "Settings$System.getString",
                      "Settings$System.putString",
                      "Settings$System.getUriFor",
                      "Settings$System.getInt",
                      "Settings$Global.getInt"
                      ]:
            name = received_data.get('name', None)
            flag = received_data.get('flag', 0)
            value = received_data.get('value', None)
            result = received_data.get('result', value)

            self._settings_db.insert_ignore_one(
                table_name='android_settings',
                module=module,
                name=name,
                flag=flag,
                data=result
            )

        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        #Nothing by now
        return True


