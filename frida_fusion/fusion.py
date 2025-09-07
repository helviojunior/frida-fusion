#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from __future__ import annotations

from .libs.color import Color
from .libs.scriptlocation import ScriptLocation

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception('You may need to run Frida Fusion from the root directory (which includes README.md)', e)

import codecs
import time
import frida
import json
import base64
import os
import signal
import sys
import re
import threading
import queue
from pathlib import Path
from datetime import datetime

from .libs.database import Database
from .libs.logger import Logger


class Fusion(object):
    running = True
    debug = True
    print_timestamp = False
    max_filename = 28

    _script_name = Path(__file__).name
    _db_jobs = queue.Queue()

    def __init__(self):
        self.device = None
        self.session = None
        self.done = threading.Event()
        self.pid = 0
        self.script_trace = {}
        self._modules = []
        signal.signal(signal.SIGINT, self.signal_handler)

        t = threading.Thread(target=Fusion._db_worker, daemon=True)
        t.start()

    def signal_handler(self, sig, frame):
        if Logger.debug_level <= 2:
            Logger.debug_level = 2

        Fusion.running = False
        Logger.pl('\n{!} {O}interrupted, shutting down...{W}\n')
        time.sleep(0.5)
        self.done.set()

    def wait(self):
        self.done.wait()  # bloqueia até receber o set()
        try:
            self.session.detach()
        except:
            try:
                self.device.kill(self.pid)
            except:
                pass

    def get_device(self):
        try:
            if Configuration.use_usb:
                self.device = frida.get_usb_device()
            else:
                process = frida.get_device_manager()
                if Configuration.device_id is not None:
                    self.device = frida.get_device(Configuration.device_id)
                elif Configuration.remote_host is not None:
                    self.device = process.add_remote_device(Configuration.remote_host)

        except Exception as e:
            self.device = None
            Logger.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        return self.device

    def translate_location(self, location: dict) -> ScriptLocation:
        if location is None or not isinstance(location, dict):
            return ScriptLocation()

        loc = ScriptLocation.parse_from_dict(location)

        if loc.file_name != "fusion_bundle.js":
            return loc

        return next(iter([
            ScriptLocation(
                file_name=k,
                function_name=loc.function_name,
                line=str(1 + loc.get_int_line() - v[0])
            )
            for k, v in self.script_trace.items()
            if v[0] <= loc.get_int_line() <= v[1]
        ]), loc)

    @classmethod
    def print_message(cls, level: str = "*", message: str = "",
                      script_location: ScriptLocation = None):

        if Fusion.running is False and Logger.debug_level >= 2:
            return

        if script_location is None:
            script_location = ScriptLocation(
                file_name=Fusion._script_name
            )

        Logger.print_message(
            level=level,
            message=message,
            script_location=script_location,
            filename_col_len=Fusion.max_filename
        )

    def load_all_scripts(self):
        self.script_trace = {}
        offset = 1
        line_cnt = 0

        Logger.pl("{*} Loading FridaFusion helpers script")
        src = ""
        try:
            src += self.sanitize_js(
                open(os.path.join(
                    Configuration.base_path, "libs", 'helpers.js'),
                    'r', encoding='utf-8').read())
            src += "\n\n"
        except Exception as e:
            Logger.pl('\n{!} {R}Error loading helpers.js:{O} %s{W}' % str(e))
            sys.exit(1)

        line_cnt = len(src.split("\n")) - 1

        self.script_trace['helpers.js'] = (offset, line_cnt)
        offset += line_cnt

        files_js = []

        for m in self._modules:
            files_js += m.js_files()

        if os.path.isfile(Configuration.frida_scripts):
            files_js += [Configuration.frida_scripts]
        else:
            files_js += [
                os.path.join(Configuration.frida_scripts, f)
                for f in sorted(os.listdir(Configuration.frida_scripts))
                if f.endswith(".js")
            ]

        for file_path in files_js:
            file_name = Path(file_path).name
            file_data = self.sanitize_js(open(file_path, 'r', encoding='utf-8').read())
            if '#NOLOAD' in file_data:
                Logger.pl('{!} {O}Alert:{W} {G}#NOLOAD{W} tag found at {G}%s{W}, ignoring file.{W}' % str(file_name))
            else:
                Logger.pl("{*} Loading script file " + file_name)
                for r in ["*", "-", "+", "!"]:
                    file_data = file_data.replace(f"console.log('[{r}] ", f"fusion_sendMessage('{r}', '")
                    file_data = file_data.replace(f'console.log("[{r}] ', f'fusion_sendMessage("{r}", "')
                    file_data = file_data.replace(f"console.log('[{r}]", f"fusion_sendMessage('{r}', '")
                    file_data = file_data.replace(f'console.log("[{r}]', f'fusion_sendMessage("{r}", "')

                file_data = re.sub(r'(?<!\w)send\(', 'fusion_Send(', file_data)

                file_data = file_data.replace(f'console.log(', f'fusion_sendMessage("I", ')
                file_data += "\n\n"

                line_cnt = len(file_data.split("\n")) - 1

                self.script_trace[file_name] = (offset, offset + line_cnt)
                offset += line_cnt

                src += file_data

                if len(file_name) > Fusion.max_filename:
                    Fusion.max_filename = len(file_name)

            Logger.filename_col_len = Fusion.max_filename

        try:
            s = self.session.create_script(src, name="fusion_bundle")
            s.on("message", self.make_handler("fusion_bundle.js"))  # register the message handler
            s.load()
        except Exception as e:

            try:
                err = str(e)
                pattern = re.compile(r'script\(line (\d+)\):')
                matches = [
                    (
                        m.group(0),
                        self.translate_location(dict(
                            file_name="fusion_bundle.js",
                            line=m.group(1),
                        ))
                    )
                    for m in pattern.finditer(err)
                ]
                for m in matches:
                    err = err.replace(m[0], f"{m[1].file_name}(line {m[1].line})")
                Logger.pl('{!} {R}Error:{O} %s{W}' % err)
                print("")
                sys.exit(1)
            except Exception:
                Logger.pl('{!} {R}Error:{O} %s{W}' % str(e))
                print("")
                sys.exit(1)

    def attach(self, pid: int):
        self.running = True
        self.pid = pid

        self.session = self.device.attach(self.pid)
        self.session.on("detached", self.on_detached)

        Logger.pl("{+} Starting frida scripts")
        self.load_all_scripts()
        self.device.resume(self.pid)

    def std_spawn(self):
        self.running = True

        self.pid = self.device.spawn([Configuration.package])
        self.session = self.device.attach(self.pid)
        self.session.on("detached", self.on_detached)

        Logger.pl("{+} Starting frida scripts")
        self.load_all_scripts()
        self.device.resume(self.pid)

    def wait_spawn(self):
        self.running = True

        self.pid = self.device.spawn([Configuration.package])
        self.device.resume(self.pid)

        time.sleep(0.2)  # Without it Java.perform silently fails

        self.session = self.device.attach(self.pid)
        self.session.on("detached", self.on_detached)

        Logger.pl("{+} Starting frida scripts")
        self.load_all_scripts()

    def make_handler(self, script_name):
        def handler(message, payload):

            if not Fusion.running:
                return

            if message["type"] == "send":
                try:
                    script_location = ScriptLocation()
                    jData = message.get("payload", {})
                    if isinstance(jData, str):
                        jData = json.loads(message["payload"])

                    # Check another payload level
                    p1 = jData.get("payload", None)
                    if p1 is not None:
                        location = jData.get("location", None)
                        jData = jData.get("payload", {})
                        script_location = self.translate_location(location)

                    if isinstance(jData, str):
                        msg = jData
                        try:
                            msg = base64.b64encode(jData.encode("UTF-8"))
                        except Exception:
                            pass

                        jData = {
                            "type": "message",
                            "level": "I",
                            "message": msg
                        }

                    if script_location.file_name == "<unknown>":
                        script_location.file_name = script_name

                    mType = jData.get('type', '').lower()
                    mLevel = jData.get('level', None)
                    if mType == "message":
                        msg = jData.get('message', '')
                        try:
                            msg = base64.b64decode(msg).decode("UTF-8")
                        except:
                            pass
                        self.print_message(mLevel, msg, script_location=script_location)

                    elif mType == "key_value_data":
                        self.print_message("V", "RAW JSON:\n    %s" % (
                            json.dumps(jData, indent=4).replace("\n", "\n    ")
                        ), script_location=script_location)

                        stack_trace = jData.get('stack_trace', '')
                        try:
                            stack_trace = base64.b64decode(stack_trace).decode("UTF-8")
                        except:
                            pass
                        self.insert_history('frida', json.dumps(jData), stack_trace)

                        if len(Configuration.enabled_modules) > 0:

                            received_data = {
                                k.lower(): v
                                for item in jData.get('data', [])
                                if isinstance(item, dict)
                                if (k := item.get("key", None)) is not None
                                   and (v := item.get("value", None)) is not None
                            }

                            self._raise_key_value_event(
                                script_location=script_location,
                                stack_trace=stack_trace,
                                module=jData.get('module', None),
                                received_data=received_data
                            )

                    # Legacy
                    elif mType == "data":
                        self.print_message("V", "RAW JSON:\n    %s" % (
                            json.dumps(jData, indent=4).replace("\n", "\n    ")
                        ), script_location=script_location)

                        stack_trace = jData.get('stack_trace', '')
                        try:
                            stack_trace = base64.b64decode(stack_trace).decode("UTF-8")
                        except:
                            pass
                        self.insert_history('frida', json.dumps(jData), stack_trace)

                        self._raise_data_event(
                            script_location=script_location,
                            stack_trace=stack_trace,
                            received_data=json.dumps(jData)
                        )

                    elif mType == "native-exception":
                        self.insert_history('frida', json.dumps(jData))
                        if self.check_frida_native_exception(jData):
                            Logger.pl(self.format_frida_native_exception(jData))

                    elif mType == "java-uncaught":
                        self.insert_history('frida', json.dumps(jData))
                        self.print_message("E", jData.get('stack', ''), script_location=script_location)

                    else:
                        self.print_message(mLevel, message, script_location=script_location)

                except Exception as err:
                    script_location = ScriptLocation(file_name=Fusion._script_name)
                    self.print_message("E", message, script_location=script_location)
                    self.print_message("E", payload, script_location=script_location)
                    self.print_exception(err)

            else:
                script_location = ScriptLocation.parse_from_dict(message)
                try:
                    if message["type"] == "error":
                        description = message.get('description', '')
                        if description is not None and description.strip() != "":
                            description += "\n"

                        stack = "Stack trace:\n"
                        stack += message.get('stack', '')

                        pattern = re.compile(r'(fusion_bundle\.js):(\d+)')
                        matches = [
                            (
                                m.group(0),
                                self.translate_location(dict(
                                    file_name=m.group(1),
                                    line=m.group(2),
                                ))
                            )
                            for m in pattern.finditer(stack)
                        ]
                        for m in matches:
                            stack = stack.replace(m[0], f"{m[1].file_name}:{m[1].line}")

                        if script_location.file_name == "fusion_bundle.js" and len(matches) >= 1:
                            script_location.file_name = matches[0][1].file_name
                            script_location.line = matches[0][1].line

                        elif script_location.file_name == "class-factory.js" and len(matches) == 1:
                            script_location.file_name = matches[0][1].file_name
                            script_location.line = matches[0][1].line

                        self.insert_history('frida', json.dumps({
                            "type": "error",
                            "description": description,
                            "stack": stack
                        }))

                        self.print_message("F", description + stack,
                                           script_location=script_location)
                        Fusion.running = False
                        time.sleep(0.2)
                        Logger.pl('\n{+} {O}Exiting...{O}{W}')
                        self.done.set()
                    else:
                        self.print_message("I", message, script_location=script_location)
                        self.print_message("I", payload, script_location=script_location)
                except:
                    self.print_message("I", message, script_location=script_location)
                    self.print_message("I", payload, script_location=script_location)

        return handler

    def on_detached(self, reason, crash):
        Logger.pl('\n{!} {R}DETACHED:{O} reason=%s{W}' % str(reason))
        if crash is not None and isinstance(crash, dict):
            # crash é um dict com info de sinal, endereço, etc. quando disponível
            try:
                Logger.pl("[CRASH] details: " + json.dumps(crash))
            except:
                Logger.pl("[CRASH] details: " + str(crash))
        elif crash is not None:
            Logger.pl("[CRASH] details: " + str(crash))

        self.done.set()

    def _raise_key_value_event(self,
                               script_location: ScriptLocation = None,
                               stack_trace: str = None,
                               module: str = None,
                               received_data: dict = None):
        for m in self._modules:
            try:
                m.key_value_event(
                    script_location=script_location,
                    stack_trace=stack_trace,
                    module=module,
                    received_data=received_data
                )
            except Exception as e:
                if Configuration.debug_level >= 2:
                    self.print_message("E", f"Error resizing event to module {m.name}: {str(e)}")
                else:
                    self.print_exception(e)

    def _raise_data_event(self,
                          script_location: ScriptLocation = None,
                          stack_trace: str = None,
                          received_data: str = None):
        for m in self._modules:
            try:
                m.data_event(
                    script_location=script_location,
                    stack_trace=stack_trace,
                    received_data=received_data
                )
            except Exception as e:
                if Configuration.debug_level >= 2:
                    self.print_message("E", f"Error resizing event to module {m.name}: {str(e)}")
                else:
                    self.print_exception(e)

    @classmethod
    def insert_history(cls,  source: str, data: str, stack_trace: str = ''):
        Fusion._db_jobs.put(dict(
            source=source,
            data=data,
            stack_trace=stack_trace
        ))

    @classmethod
    def _db_worker(cls):
        db = Database(auto_create=True, db_name=Configuration.db_path)

        while Fusion.running:
            kwargs = Fusion._db_jobs.get()
            db.insert_history(**kwargs)

    @classmethod
    def print_exception(cls, err):
        from traceback import format_exc
        err_txt = 'Error:{O} %s{W}' % str(err)
        err_txt += '\n{O}Full stack trace below\n'
        err_txt += format_exc().strip()

        err_txt = err_txt.replace('\n', '\n{W}   ')
        err_txt = err_txt.replace('  File', '{W}{D}File')
        err_txt = err_txt.replace('  Exception: ', '{R}Exception: {O}')

        Logger.print_message(
            level="E",
            message=Color.s(err_txt),
            filename_col_len=Fusion.max_filename,
            script_location=Logger.get_caller_info(stack_index=2)
        )

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
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
        MAGENTA = "\033[35m"
        CYAN = "\033[36m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
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
                lines.append(reg_line(group))
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
        s = s.lstrip('\ufeff')          # remove BOM
        s = s.replace('\u2028', '\n')   # Unicode line separator
        s = s.replace('\u2029', '\n')   # Unicode paragraph separator
        s = s.replace('\u00A0', ' ')    # non-breaking space
        s = s.replace('\u200B', '')     # zero-width space
        return s

    def main(self):
        Logger.pl(Configuration.get_banner())
        Configuration.initialize()

        try:
            print(f" 🛠️  Starting Frida Fusion instrumentation")
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            Logger.pl('{+} {C}Start time {O}%s{W}' % timestamp)

            self._modules = [
                m.create_instance()
                for _, m in Configuration.enabled_modules.items()
            ]

            if len(self._modules) > 0:
                Logger.pl("{+} Starting selected modules")
                for m in self._modules:
                    m.start_module(db_path=Configuration.db_path)

            self.get_device()
            if self.device is not None:
                if Configuration.pid > 0:
                    self.attach(Configuration.pid)
                else:
                    if Configuration.use_delay:
                        self.wait_spawn()
                    else:
                        self.std_spawn()

                self.wait()
            else:
                print(' ')
                sys.exit(4)

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            Logger.pl('{+} {C}End time {O}%s{W}' % timestamp)
            print(' ')
            sys.exit(0)

        except Exception as e:
            Logger.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

            if Configuration.debug_level <= 1:
                Logger.pl('\n{!} {O}Full stack trace below')
                from traceback import format_exc
                err = format_exc().strip()
                err = err.replace('\n', '\n{W}{!} {W}   ')
                err = err.replace('  File', '{W}{D}File')
                err = err.replace('  Exception: ', '{R}Exception: {O}')
                Logger.pl('\n{!}    ' + err)

            Logger.pl('\n{!} {R}Exiting{W}\n')
            sys.exit(2)

        except KeyboardInterrupt as e:
            sys.exit(3)


def run():
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    o = Fusion()
    o.main()

