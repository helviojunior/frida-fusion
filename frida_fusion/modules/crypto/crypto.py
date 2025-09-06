import json
import os.path
from pathlib import Path
import base64
import string

from frida_fusion.libs.logger import Logger
from frida_fusion.libs.database import Database
from frida_fusion.libs.scriptlocation import ScriptLocation
from frida_fusion.module import ModuleBase


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
                    hashcode TEXT NOT NULL,
                    algorithm TEXT NULL,
                    init_key TEXT NULL,
                    iv TEXT NULL,
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
                CREATE TABLE IF NOT EXISTS [crypto_key] (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NULL,
                    printable_key TEXT NULL,
                    salt TEXT NULL,
                    iteration_count INTEGER NULL DEFAULT (0),
                    key_class TEXT NULL DEFAULT ('<unknown>'),
                    additional_data TEXT NULL,
                    created_date datetime not null DEFAULT (datetime('now','localtime')),
                    UNIQUE (key, key_class)
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
                          after_final=None, stack_trace=None, id=None, algorithm=None,
                          status=None):

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
                    update += " algorithm = ?,"
                    data.append(algorithm)

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

                if status is not None:
                    integrity = True
                    update += " status = ?,"
                    data.append(status)

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

                    cursor = conn.cursor()
                    cursor.execute("""
                    delete from [crypto]
                    where algorithm is null and init_key is null and key is null and clear_text is null
                    and hashcode in (
                        select hashcode from [crypto]
                        where id = ?
                    )
                    """, (id,))

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

        def insert_crypto(self, hashcode, algorithm, init_key):

            if hashcode is None:
                return

            rows = self.select(
                table_name='crypto',
                hashcode=hashcode,
                status='open'
            )
            if len(rows) == 0 or not any(iter([
                True
                for r in rows
                if (
                    (algorithm is not None and algorithm == r['algorithm'])
                    or (r['algorithm'] is None or r['algorithm'].strip() == "")
                ) and (
                    (
                        (init_key is not None and init_key != '' and init_key != 'IA==')
                        and (init_key == r['init_key'] or init_key == r['key'])
                    )
                    or (r['init_key'] is None or r['init_key'].strip() == "")
                )
            ])):
                if init_key is not None and init_key != '' and init_key != 'IA==':
                    self.insert_one(
                        table_name='crypto',
                        hashcode=hashcode,
                        algorithm=algorithm,
                        init_key=init_key,
                        status='open')
                else:
                    self.insert_one(
                        table_name='crypto',
                        hashcode=hashcode,
                        algorithm=algorithm,
                        status='open')

        def insert_crypto_key(self, key, key_class, salt=None,
                              iteration_count=0, module="<unknown>", additional_data=dict):
            if key is not None and key != '' and key != 'IA==':
                self.insert_ignore_one(
                    table_name='crypto_key',
                    key=key,
                    printable_key=self.get_printable(key),
                    key_class=key_class,
                    salt=salt,
                    iteration_count=iteration_count,
                    additional_data=json.dumps({
                        **{"module": module},
                        **(additional_data if additional_data is not None and isinstance(additional_data, dict) else {})
                    }, default=Logger.json_serial)
                )

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
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:

        if module in ["X509EncodedKeySpec.init", "GCMParameterSpec.init", "PBEParameterSpec.init"]:

            key_class = received_data.get('classtype', module)
            salt = None
            iteration_count = 0

            key = received_data.get('key', None)
            if module == "GCMParameterSpec.init":
                key = received_data.get('iv_key', None)

            if module == "PBEParameterSpec.init":
                key = "None"
                salt = received_data.get('pbe_salt', None)
                iteration_count = received_data.get('iteration_count', None)

            self._crypto_db.insert_crypto_key(
                key=key,
                key_class=key_class,
                salt=salt,
                iteration_count=iteration_count,
                module=module,
                additional_data=received_data
            )

        if module == "SecretKeySpec.init":
            algorithm = received_data.get('algorithm', None)
            key = received_data.get('key', None)
            hashcode = received_data.get('hashcode', None)
            key_class = received_data.get('classtype', "SecretKeySpec")
            self._crypto_db.insert_crypto(
                hashcode=hashcode,
                algorithm=algorithm,
                init_key=key)

            self._crypto_db.insert_crypto_key(
                key=key,
                key_class=key_class,
                module=module,
                additional_data=received_data
            )

        elif module == "IvParameterSpec.init":
            bData = received_data.get('iv_key', None)
            key_class = received_data.get('classtype', "IvParameterSpec")
            # print("IV: %s" % bData)
            self._crypto_db.update_crypto(iv=bData)

            self._crypto_db.insert_crypto_key(
                key=bData,
                key_class=key_class,
                module=module,
                additional_data=received_data
            )

        elif module == "cipher.init":
            hashcode = received_data.get('hashcode', None)
            opmode = received_data.get('opmode', "")
            key_class = received_data.get('keytype', "")
            key = received_data.get('key', None)
            algorithm = received_data.get('algorithm', None)

            self._crypto_db.insert_crypto(
                hashcode=hashcode,
                algorithm=algorithm,
                init_key=key
            )

            self._crypto_db.update_crypto(
                hashcode=hashcode,
                flow='enc' if 'encrypt' in opmode else ('dec' if 'decrypt' in opmode else str(opmode)),
                key=key,
                algorithm=algorithm
            )

            self._crypto_db.insert_crypto_key(
                key=key,
                key_class=key_class,
                module=module,
                additional_data=received_data
            )

            Logger.print_message(
                level="W",
                message=f"Cipher init received\nHashcode: {hashcode}\nOpmode: {opmode}\nKeytype: {key_class}",
                script_location=script_location
            )

        elif module == "cipher.doFinal":
            hashcode = received_data.get('hashcode', None)

            self._crypto_db.insert_crypto(
                hashcode=hashcode,
                algorithm=None,
                init_key=None
            )

            self._crypto_db.update_crypto(
                hashcode=hashcode,
                before_final=received_data.get('input', ''),
                after_final=received_data.get('output', ''),
                stack_trace=stack_trace,
                status="complete"
            )

            Logger.print_message(
                level="D",
                message=f"Cipher doFinal received\n{stack_trace}",
                script_location=script_location
            )

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

            hash_hex = ""
            if bOutput is not None:
                try:
                    if isinstance(bOutput, bytes):
                        hash_hex = ''.join('{:02x}'.format(b) for b in bOutput)
                    else:
                        hash_hex = ''.join('{:02x}'.format(b) for b in base64.b64decode(bOutput))
                except:
                    pass

            # Do not print TLS certificate verification hash
            if 'com.android.org.conscrypt.ConscryptEngine.verifyCertificateChain' not in stack_trace:
                Logger.print_message(
                    level="D",
                    message=f"Message digest\nAlgorithm: {algorithm}\nHash: {hash_hex}\n{stack_trace}",
                    script_location=script_location
                )

        return True

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        #Nothing by now
        return True


