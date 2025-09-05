import time
import frida
import json, base64
import argparse
import sys, os
import threading
import signal, sys
import re
from pathlib import Path
from datetime import datetime

from libs.color import Color
from libs.database import Database


class FridaConnector(object):
    running = True
    debug = True
    print_timestamp = False
    max_filename = 28

    _script_name = Path(__file__).name

    def __init__(self, frida_scripts: str, app_id: str, print_timestamp: bool = False):
        self.db = Database(auto_create=True)
        self.device = None
        self.session = None
        self.frida_scripts = frida_scripts
        self.app_id = app_id
        self.done = threading.Event()
        self.pid = 0
        self.script_trace = {}
        FridaConnector.print_timestamp = print_timestamp
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        Color.pl('\n{+} {O}Exiting...{O}{W}')
        self.done.set()

    def wait(self):
        self.done.wait()  # bloqueia até receber o set()
        try:
            session.detach()
        except:
            try:
                self.device.kill(self.pid)
            except:
                pass

    def get_device(self, USB=False, IP=False, device_id=False):
        try:
            if USB:
                self.device = frida.get_usb_device()
            else:
                process = frida.get_device_manager()
                if IP:
                    self.device = process.add_remote_device(IP)
                else:
                    self.device = frida.get_device(device_id) if device_id else frida.get_usb_device()
        except Exception as e:
            Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))
            self.device = None

        return self.device

    def translate_location(self, location: dict) -> dict:
        if location is None or not isinstance(location, dict):
            return {"file_name": "<unknown>", "function_name": "<unknown>", "line": "<unknown>"}

        file_name = Path(location.get("file_name", "unknown")).name
        function_name = location.get("function_name", "unknown")
        line_nr = location.get("line", -1)

        if file_name != "bundle.js":
            return location

        return next(iter([
            {
                "file_name": k,
                "function_name": function_name,
                "line": 1 + line_nr - v[0]
            }
            for k, v in self.script_trace.items()
            if v[0] <= line_nr <= v[1]
        ]), {"file_name": "<unknown>", "function_name": "<unknown>", "line": "<unknown>"})

    def load_all_scripts(self):
        self.script_trace = {}
        offset = 1
        line_cnt = 0

        base_path = str(Path(__file__).resolve().parent)
        src = ""
        try:
            src += self.sanitize_js(
                open(os.path.join(base_path, "frida_scripts", '0_helpers.js'), 'r', encoding='utf-8').read())
            src += "\n\n"
        except Exception as e:
            Color.pl('\n{!} {R}Error loading helpers.js:{O} %s{W}' % str(e))
            sys.exit(1)

        line_cnt = len(src.split("\n")) - 1

        self.script_trace['0_helpers.js'] = (offset, line_cnt)
        offset += line_cnt

        files_js = []
        if os.path.isfile(args.frida_scripts):
            files_js = [args.frida_scripts]
        else:
            files_js = [f for f in sorted(os.listdir(self.frida_scripts)) if f != '0_helpers.js' and f.endswith(".js")]

        for f in files_js:

            file_data = self.sanitize_js(open(os.path.join(self.frida_scripts, f), 'r', encoding='utf-8').read())
            if '#NOLOAD' in file_data:
                Color.pl('{!} {O}Alert:{W} {G}#NOLOAD{W} tag found at {G}%s{W}, ignoring file.{W}' % str(f))
            else:
                Color.pl("{*} Loading script file " + f)
                for r in ["*", "-", "+", "!"]:
                    file_data = file_data.replace(f"console.log('[{r}] ", f"sendMessage('{r}', '")
                    file_data = file_data.replace(f'console.log("[{r}] ', f'sendMessage("{r}", "')
                    file_data = file_data.replace(f"console.log('[{r}]", f"sendMessage('{r}', '")
                    file_data = file_data.replace(f'console.log("[{r}]', f'sendMessage("{r}", "')

                file_data = re.sub(r'(?<!\w)send\(', 'iSend(', file_data)

                file_data = file_data.replace(f'console.log(', f'sendMessage("I", ')
                file_data += "\n\n"

                line_cnt = len(file_data.split("\n")) - 1

                self.script_trace[f] = (offset, offset + line_cnt)
                offset += line_cnt

                src += file_data

                if len(f) > FridaConnector.max_filename:
                    FridaConnector.max_filename = len(f)

        try:
            s = self.session.create_script(src, name="bundle")
            s.on("message", self.make_handler("bundle.js"))  # register the message handler
            s.load()
        except Exception as e:
            Color.pl('{!} {R}Error:{O} %s{W}' % str(e))
            print("")
            sys.exit(1)

    # Metodo 1, convencional
    def method1(self):
        self.running = True

        self.pid = self.device.spawn([self.app_id])
        self.session = self.device.attach(self.pid)
        self.session.on("detached", self.on_detached)

        Color.pl("{+} Iniciando scripts frida...")
        self.load_all_scripts()
        self.device.resume(self.pid)

    # Metodo 2, aguarda um tempo antes de injetar a thread
    def method2(self):
        self.running = True

        self.pid = self.device.spawn([self.app_id])

        self.device.resume(self.pid)

        time.sleep(0.2)  # Without it Java.perform silently fails

        self.session = self.device.attach(self.pid)
        self.session.on("detached", self.on_detached)

        Color.pl("{+} Iniciando scripts frida...")
        load_all_scripts()

    def make_handler(self, script_name):
        def handler(message, payload):
            if message["type"] == "send":

                try:

                    script_location = {"file_name": "<unknown>", "function_name": "<unknown>", "line": "<unknown>"}
                    jData = message.get("payload", {})
                    if isinstance(jData, str):
                        jData = json.loads(message["payload"])

                    # Check another payload level
                    p1 = jData.get("payload", None)
                    if p1 is not None:
                        location = jData.get("location", None)
                        jData = jData.get("payload", {})
                        script_location = self.translate_location(location)

                    if script_location.get("file_name", "<unknown>") == "<unknown>":
                        script_location["file_name"] = script_name

                    mType = jData.get('type', '').lower()
                    mLevel = jData.get('level', None)
                    if mType == "message":
                        b64msg = jData.get('message', '')
                        if mLevel == "*" and not FridaConnector.debug:
                            return
                        msg = base64.b64decode(b64msg).decode("UTF-8")
                        self.printMessage(mLevel, msg, **script_location)


                    elif mType == "key_value_data":
                        if FridaConnector.debug:
                            self.printMessage("*", "RAW JSON:\n    %s" % (
                                json.dumps(jData, indent=4).replace("\n", "\n    ")
                            ), **script_location)

                        stackTrace = jData.get('stack_trace', '')
                        try:
                            stackTrace = base64.b64decode(stackTrace).decode("UTF-8")
                        except:
                            pass
                        self.db.insertHistory('frida', json.dumps(jData), stackTrace)

                        received_data = {
                            k.lower(): v
                            for item in jData.get('data', [])
                            if isinstance(item, dict)
                            if (k := item.get("key", None)) is not None
                               and (v := item.get("value", None)) is not None
                        }

                        mDataModule = jData.get('module', None)
                        if mDataModule == "secretKeySpec.init":
                            algorithm = received_data.get('algorithm', None)
                            bData = received_data.get('key', None)
                            self.db.insertCrypto(algorithm, bData)

                        elif mDataModule == "IvParameterSpec.init":
                            bData = received_data.get('iv_key', None)
                            # print("IV: %s" % bData)
                            self.db.updateCrypto(bData)

                        elif mDataModule == "cipher.init":
                            hashcode = received_data.get('hashcode', None)
                            opmode = received_data.get('opmode', "")
                            if 'encrypt' in opmode:
                                self.db.updateCrypto(None, hashcode, 'enc')
                            elif 'decrypt' in opmode:
                                self.db.updateCrypto(None, hashcode, 'dec')


                        elif mDataModule == "cipher.doFinal":
                            self.db.updateCrypto(None, None, None, None, received_data.get('input', ''),
                                                 stack_trace=stackTrace)
                            self.db.updateCrypto(None, None, None, None, None, received_data.get('output', ''),
                                                 stack_trace=stackTrace)

                        elif mDataModule == "messageDigest.update":
                            hashcode = received_data.get('hashcode', None)
                            algorithm = received_data.get('algorithm', None)
                            bInput = received_data.get('input', None)
                            self.db.insertDigest(hashcode, algorithm, bInput, None, stack_trace=stackTrace)


                        elif mDataModule == "messageDigest.digest":
                            hashcode = received_data.get('hashcode', None)
                            algorithm = received_data.get('algorithm', None)
                            bInput = received_data.get('input',
                                                       None)  # Se não existir teve um messageDigest.update antes
                            bOutput = received_data.get('output', None)
                            self.db.insertDigest(hashcode, algorithm, bInput, bOutput, stack_trace=stackTrace)

                    # Legacy
                    elif mType == "data":
                        if FridaConnector.debug:
                            self.printMessage(mLevel, json.dumps(jData), **script_location)

                        stackTrace = jData.get('stack_trace', '')
                        try:
                            stackTrace = base64.b64decode(stackTrace).decode("UTF-8")
                        except:
                            pass
                        self.db.insertHistory('frida', json.dumps(jData), stackTrace)

                        mDataType = jData.get('type_value', None)
                        if mDataType == "shared_key":
                            sharedKey = jData.get('base64_data', None)
                            if sharedKey is None:
                                sharedKey = base64.b64decode(payload).decode("UTF-8")
                            self.db.insertSharedKey(sharedKey)
                        elif mDataType == "key_spec_init":
                            algorithm = jData.get('algorithm', None)
                            bData = jData.get('base64_data', None)
                            self.db.insertCrypto(algorithm, bData)
                            # print(algorithm)
                            # print(jData)
                        elif mDataType == "key_spec_iv":
                            bData = jData.get('base64_data', None)
                            # print("IV: %s" % bData)
                            self.db.updateCrypto(bData)
                            # print(jData)
                        elif mDataType == "key_spec_hashcode_enc":
                            hashcode = jData.get('hashcode', None)
                            self.db.updateCrypto(None, hashcode, 'enc')
                            # print(hashcode)
                            # print(jData)
                        elif mDataType == "key_spec_hashcode_dec":
                            hashcode = jData.get('hashcode', None)
                            self.db.updateCrypto(None, hashcode, 'dec')
                            # print(hashcode)
                            # print(jData)
                        elif mDataType == "key_spec_key":
                            bData = jData.get('base64_data', None)
                            # print("Key: %s" % bData)
                            self.db.updateCrypto(None, None, None, bData)
                            # print(jData)
                        elif mDataType == "key_spec_before_dofinal":
                            bData = jData.get('base64_data', '')
                            stackTrace = jData.get('stack_trace', '')
                            try:
                                stackTrace = base64.b64decode(stackTrace).decode("UTF-8")
                            except:
                                pass
                            self.db.updateCrypto(None, None, None, None, bData, stack_trace=stackTrace)
                            # print(bData)
                            # print(jData)
                        elif mDataType == "key_spec_after_dofinal":
                            bData = jData.get('base64_data', '')
                            stackTrace = jData.get('stack_trace', '')
                            try:
                                stackTrace = base64.b64decode(stackTrace).decode("UTF-8")
                            except:
                                pass
                            self.db.updateCrypto(None, None, None, None, None, bData, stack_trace=stackTrace)
                            # print(bData)
                            # print(jData)
                        else:
                            self.printMessage(message=message, **script_location)

                    elif mType == "native-exception":
                        if self.check_frida_native_exception(jData):
                            # FridaConnector.running = False
                            # time.sleep(0.2)
                            print(self.format_frida_native_exception(jData))
                            # self.done.set()

                    elif mType == "java-uncaught":
                        self.printMessage("E", jData.get('stack', ''), **script_location)

                    else:
                        self.printMessage(mLevel, message, **script_location)

                except Exception as e:
                    self.printMessage("E", message, **script_location)
                    self.printMessage("E", payload, **script_location)
                    self.printException(e)

            else:
                try:
                    if message["type"] == "error":
                        self.printMessage("E", message.get('description', '') + "\n" + message.get('stack', ''),
                                          file_name=message.get('fileName', None), line=message.get('lineNumber', None))
                        FridaConnector.running = False
                        time.sleep(0.2)
                        Color.pl('\n{+} {O}Exiting...{O}{W}')
                        self.done.set()
                    else:
                        self.printMessage("I", message, **script_location)
                        self.printMessage("I", payload, **script_location)
                except:
                    self.printMessage("I", message, **script_location)
                    self.printMessage("I", payload, **script_location)

        return handler

    def on_detached(self, reason, crash):
        Color.pl('\n{!} {R}DETACHED:{O} reason=%s{W}' % str(reason))
        if crash:
            # crash é um dict com info de sinal, endereço, etc. quando disponível
            print("[CRASH] details:", crash)

        self.done.set()

    @classmethod
    def printMessage(cls, level: str = "*", message: str = "",
                     file_name: str = "", function_name: str = "", line: str = ""):

        if not FridaConnector.running and not FridaConnector.debug:
            return

        if level is None:
            level = "*"

        prefix = ""
        if FridaConnector.print_timestamp:
            ts = datetime.now()
            stamp = f"{ts:%H:%M:%S}.{int(ts.microsecond / 1000):03d}"
            prefix += f"\033[2m{stamp.ljust(13)}{FridaConnector._color_reset}"

        dbg_tag = next(iter([
            k
            for k in FridaConnector._level_map.keys()
            if level.upper() == k
        ]), FridaConnector._level_tag.get(level, "I"))

        dbg_idx = FridaConnector._level_map.get(dbg_tag, 0)
        fg_color = FridaConnector._color_level[dbg_idx]
        tag_color = FridaConnector._color_tags[dbg_idx]

        if file_name == "frida/node_modules/frida-java-bridge/lib/class-factory.js":
            file_name = "frida/.../class-factory.js"
        else:
            file_name = str(Path(file_name).name)

        prefix += f"{fg_color}{file_name.rjust(FridaConnector.max_filename)}{FridaConnector._color_reset}\033[2m:{str(line).ljust(10)}{FridaConnector._color_reset} "
        prefix_len = len(Color.escape_ansi(prefix))

        f_message = ""
        for l in message.split("\n"):
            if f_message == "":
                f_message += f"{prefix}{tag_color} {dbg_tag} {FridaConnector._color_reset} {fg_color}{l}{FridaConnector._color_reset}"
            else:
                f_message += f"\n{''.rjust(prefix_len)}{tag_color} {dbg_tag} {FridaConnector._color_reset} {fg_color}{l}{FridaConnector._color_reset}"

        Color.pl(f_message)

    @classmethod
    def printException(cls, e):

        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

    @classmethod
    def check_frida_native_exception(cls, evt: dict) -> bool:
        d = evt.get('details', {})
        mem = d.get('memory', {}) or {}
        bt = d.get('backtrace', []) or []
        # if mem.get('address','') == "0x0" and len(bt) > 0 and ('boot-core' in bt[0] or 'boot-framework' in bt[0]):
        if len(bt) > 0 and ('boot-core' in bt[0] or 'boot-framework' in bt[0]):
            return False

        return True

    @classmethod
    def format_frida_native_exception(cls, evt: dict) -> str:
        # ANSI
        RED = "\033[31m";
        GREEN = "\033[32m";
        YELLOW = "\033[33m"
        BLUE = "\033[34m";
        MAGENTA = "\033[35m";
        CYAN = "\033[36m"
        BOLD = "\033[1m";
        DIM = "\033[2m";
        RESET = "\033[0m"

        d = evt.get('details', {})
        msg = d.get('message', '')
        ety = d.get('type', '')
        adr = d.get('address', '')
        mem = d.get('memory', {}) or {}
        ctx = d.get('context', {}) or {}
        ncx = d.get('nativeContext', '')
        bt = d.get('backtrace', []) or []  # lista já formatada vinda do JS

        def reg_line(keys):
            return "  " + "   ".join(
                f"{CYAN}{k.rjust(3)}{RESET}: {MAGENTA}{ctx.get(k, '').ljust(18)}{RESET}" for k in keys)

        regs_order = [
            'pc', 'lr', 'sp', 'fp',
            'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
            'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28'
        ]

        lines = [""]
        lines.append(f"{BOLD}{RED}===== Native Exception ====={RESET}")
        lines.append(f"{YELLOW}Type:{RESET} {ety}")
        lines.append(f"{YELLOW}Message:{RESET} {msg}")
        lines.append(f"{YELLOW}Address:{RESET} {GREEN}{adr}{RESET}\n")

        if mem:
            lines.append(f"{BOLD}Memory:{RESET}")
            lines.append(f"  {CYAN}operation{RESET}: {mem.get('operation', '')}")
            lines.append(f"  {CYAN}address{RESET}:   {MAGENTA}{mem.get('address', '')}{RESET}\n")

        lines.append(f"{BOLD}Context (ARM64):{RESET}")

        group = []
        for r in regs_order[4:]:
            group.append(r)
            if len(group) == 4:
                lines.append(reg_line(group));
                group = []
        if group:
            lines.append(reg_line(group))

        lines.append(reg_line(['lr', 'sp', 'pc', 'fp']))

        lines.append(f"\n{YELLOW}nativeContext:{RESET} {MAGENTA}{ncx}{RESET}")

        # Backtrace (se disponível)
        if bt:
            lines.append(f"\n{BOLD}{BLUE}Backtrace:{RESET}")
            for frame in bt:
                # Heurística simples de cor: endereço/offset em magenta, módulo em verde
                # frame já vem no formato " 0  func (module+0xOFF)"
                # vamos apenas aplicar cores mantendo o texto
                try:
                    func_part, rest = frame.split(" (", 1)
                    mod_part = rest.rstrip(")")
                    # tenta separar "module+0xOFF"
                    if "+" in mod_part:
                        mod_name, off = mod_part.split("+", 1)
                        colored = f"{DIM}{func_part}{RESET} ({GREEN}{mod_name}{RESET}+{MAGENTA}{off}{RESET})"
                    else:
                        colored = f"{DIM}{func_part}{RESET} ({GREEN}{mod_part}{RESET})"
                except Exception:
                    colored = frame  # fallback sem cores se parsing falhar
                lines.append("  " + colored)

        lines.append(f"{BOLD}{RED}============================{RESET}")
        return "\n".join(lines)

    @classmethod
    def sanitize_js(cls, s: str) -> str:
        s = s.lstrip('\ufeff')  # remove BOM
        s = s.replace('\u2028', '\n')  # Unicode line separator
        s = s.replace('\u2029', '\n')  # Unicode paragraph separator
        s = s.replace('\u00A0', ' ')  # non-breaking space
        s = s.replace('\u200B', '')  # zero-width space
        return s

