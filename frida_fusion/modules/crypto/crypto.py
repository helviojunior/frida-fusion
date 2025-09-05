import os.path
from pathlib import Path
import base64
import string

from frida_fusion.libs.logger import Logger
from frida_fusion.libs.database import Database
from frida_fusion.module import ModuleBase

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from frida_fusion.fusion import Fusion  # só no type checker


class Crypto(ModuleBase):
    class CryptoDB(Database):
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
                CREATE TABLE IF NOT EXISTS [crypto] (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    algorithm TEXT NOT NULL,
                    init_key TEXT NOT NULL,
                    iv TEXT NULL,
                    hashcode TEXT NULL,
                    flow TEXT NULL,
                    key TEXT NULL,
                    clear_text TEXT NULL,
                    clear_text_b64 TEXT NULL,
                    cipher_data TEXT NULL,
                    status TEXT NULL DEFAULT ('open'),
                    stack_trace TEXT NULL,
                    created_date datetime not null DEFAULT (datetime('now','localtime'))
                );
            """)

            conn.commit()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS [digest] (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    algorithm TEXT NOT NULL,
                    hashcode TEXT NULL,
                    clear_text TEXT NULL,
                    clear_text_b64 TEXT NULL,
                    hash_b64 TEXT NULL,
                    hash_hex TEXT NULL,
                    stack_trace TEXT NULL,
                    created_date datetime not null DEFAULT (datetime('now','localtime'))
                );
            """)

            conn.commit()

            # Must get the constraints
            self.get_constraints(conn)

        @classmethod
        def get_printable(cls, b64_data):
            try:
                text = base64.b64decode(b64_data).decode("UTF-8")
                if all(c in string.printable for c in text):
                    return text
                else:
                    return ''
            except Exception as e:
                # Color.pl('{!} {R}Erro getPrintable:{O} %s{W}' % str(e))
                return ''

        def update_crypto(self, iv=None, hashcode=None, flow=None, key=None, before_final=None,
                          after_final=None, stack_trace=None, id=None):

            conn = self.connect_to_db(check=False)
            cursor = conn.cursor()

            select = "select id, flow from [crypto] where status = 'open'"
            data = []
            if hashcode is not None and (before_final is not None or after_final is not None):
                select += " and hashcode = ?"
                data = (hashcode,)

            if id is not None and (before_final is not None or after_final is not None):
                select += " and id = ?"
                data = (id,)

            cursor.execute(select, data)

            f = cursor.fetchall()
            if f:
                last = f[0]
                id = last[0]
                dbflow = last[1]
                integrity = False

                data = []
                update = "update [crypto] set "
                if iv is not None:
                    integrity = True
                    update += " iv = ?,"
                    data.append(iv)

                if hashcode is not None:
                    integrity = True
                    update += " hashcode = ?,"
                    data.append(hashcode)

                if flow is not None:
                    integrity = True
                    update += " flow = ?,"
                    data.append(flow)

                if key is not None:
                    integrity = True
                    update += " key = ?,"
                    data.append(key)

                if key is not None:
                    integrity = True
                    update += " key = ?,"
                    data.append(key)

                if stack_trace is not None:
                    integrity = True
                    update += " stack_trace = ?,"
                    data.append(stack_trace)

                if before_final is not None:
                    integrity = True
                    if dbflow == "enc":
                        update += " clear_text = ?, clear_text_b64 = ?,"
                        data.append(self.get_printable(before_final))
                    else:
                        update += " cipher_data = ?,"

                    data.append(before_final)

                if after_final is not None:
                    integrity = True
                    if dbflow == "enc":
                        update += " cipher_data = ?, status = 'complete'"

                    else:
                        update += " clear_text = ?, clear_text_b64 = ?, status = 'complete'"
                        data.append(self.get_printable(after_final))

                    data.append(after_final)

                if integrity:
                    # update += " status = 'incositente'"

                    # Em cenários onde o campo de entrada (encriptado é nulo, não vai ter nada a processar)
                    update = update.strip(",").strip()
                    update += " where id = ?"

                    data.append(id)
                    # data.append(None)

                    cursor.execute(update, data)

                    conn.commit()

                    # Color.pl('{+} {W}Crypto atualizada. {C}ID: {O}%s{W}' % id)

            conn.close()

        def insert_digest(self, hashcode, algorithm, data_input, data_output, stack_trace):

            conn = self.connect_to_db(check=False)

            clear_text = ""
            clear_text_b64 = ""
            if data_input is not None:

                if isinstance(clear_text, bytes):
                    clear_text = clear_text.decode("UTF-8")
                    clear_text_b64 = base64.b64encode(clear_text).decode("UTF-8")
                else:
                    clear_text_b64 = data_input
                    try:
                        clear_text = base64.b64decode(data_input).decode("UTF-8")
                    except:
                        pass

            hash_b64 = ""
            hash_hex = ""
            if data_output is not None:
                if isinstance(data_output, bytes):
                    hash_hex = ''.join('{:02X}'.format(b) for b in data_output)
                    hash_b64 = base64.b64encode(data_output).decode("UTF-8")
                else:
                    hash_b64 = data_output
                    hash_hex = ''.join('{:02X}'.format(b) for b in base64.b64decode(data_output))

            cursor = conn.cursor()
            cursor.execute("""
            insert into [digest] ([hashcode], [algorithm], [clear_text], [clear_text_b64], [hash_b64], [hash_hex], [stack_trace])
            VALUES (?,?,?,?,?,?,?);
            """, (hashcode, algorithm, clear_text, clear_text_b64, hash_b64, hash_hex, stack_trace,))

            conn.commit()

            conn.close()

            # Color.pl('{+} {W}Inserindo crypto. {C}Algorithm: {O}%s{W}' % algorithm)

        def insert_crypto(self, algorithm, init_key):

            conn = self.connect_to_db(check=False)

            cursor = conn.cursor()
            cursor.execute("""
            update [crypto] set status = 'incomplete' where status = 'open';
            """)

            cursor = conn.cursor()
            cursor.execute("""
            insert into [crypto] ([algorithm], [init_key])
            VALUES (?,?);
            """, (algorithm, init_key,))

            conn.commit()

            conn.close()

            # Color.pl('{+} {W}Inserindo crypto. {C}Algorithm: {O}%s{W}' % algorithm)

        def insert_crypto2(self, algorithm, key, iv, clear_text, cipher_data, flow='enc'):

            conn = self.connect_to_db(check=False)

            if isinstance(clear_text, bytes):
                clear_text = clear_text.decode("UTF-8")

            if isinstance(cipher_data, bytes):
                cipher_data = cipher_data.decode("UTF-8")

            if isinstance(key, bytes):
                key = base64.b64encode(key).decode("UTF-8")

            if isinstance(iv, bytes):
                iv = base64.b64encode(iv).decode("UTF-8")

            clear_text_b64 = base64.b64encode(clear_text.encode("UTF-8")).decode("UTF-8")

            cursor = conn.cursor()
            cursor.execute("""
            insert into [crypto] ([flow], [algorithm], [init_key], [key], [iv], [clear_text], [clear_text_b64], [cipher_data], [status])
            VALUES (?,?,?,?,?,?,?,?,?);
            """, (flow, algorithm, key, key, iv, clear_text, clear_text_b64, cipher_data, 'complete',))

            conn.commit()

            conn.close()

            # Color.pl('{+} {W}Inserindo crypto. {C}Algorithm: {O}%s{W}' % algorithm)

    def __init__(self):
        super().__init__('Crypto', 'Hook cryptography/hashing functions')
        self._crypto_db = None
        self.mod_path = str(Path(__file__).resolve().parent)

    def start_module(self, **kwargs) -> bool:
        if 'db_path' not in kwargs:
            raise Exception("parameter db_path not found")

        self._crypto_db = Crypto.CryptoDB(db_name=kwargs['db_path'])
        return True

    def js_files(self) -> list:
        return [
            os.path.join(self.mod_path, "crypto.js")
        ]

    def key_value_event(self,
                        script_location: "Fusion.ScriptLocation" = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:

        if module == "secretKeySpec.init":
            algorithm = received_data.get('algorithm', None)
            bData = received_data.get('key', None)
            self._crypto_db.insert_crypto(algorithm, bData)

        elif module == "IvParameterSpec.init":
            bData = received_data.get('iv_key', None)
            # print("IV: %s" % bData)
            self._crypto_db.update_crypto(bData)

        elif module == "cipher.init":
            hashcode = received_data.get('hashcode', None)
            opmode = received_data.get('opmode', "")
            if 'encrypt' in opmode:
                self._crypto_db.update_crypto(None, hashcode, 'enc')
            elif 'decrypt' in opmode:
                self._crypto_db.update_crypto(None, hashcode, 'dec')

        elif module == "cipher.doFinal":
            self._crypto_db.update_crypto(None, None, None, None,
                                          received_data.get('input', ''),
                                          stack_trace=stack_trace)
            self._crypto_db.update_crypto(None, None, None, None, None,
                                          received_data.get('output', ''),
                                          stack_trace=stack_trace)

        elif module == "messageDigest.update":
            hashcode = received_data.get('hashcode', None)
            algorithm = received_data.get('algorithm', None)
            bInput = received_data.get('input', None)
            self._crypto_db.insert_digest(hashcode, algorithm, bInput, None, stack_trace=stack_trace)

        elif module == "messageDigest.digest":
            hashcode = received_data.get('hashcode', None)
            algorithm = received_data.get('algorithm', None)
            bInput = received_data.get('input', None)  # Se não existir teve um messageDigest.update antes
            bOutput = received_data.get('output', None)
            self._crypto_db.insert_digest(hashcode, algorithm, bInput, bOutput, stack_trace=stack_trace)

        return True

    def data_event(self,
                   script_location: "Fusion.ScriptLocation" = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        #Nothing by now
        return True


