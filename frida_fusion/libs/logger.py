#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import base64
import inspect
import json
import datetime
from pathlib import Path

from .scriptlocation import ScriptLocation
from ..libs.color import Color


class Logger(object):
    ''' Helper object for easily printing colored text to the terminal. '''

    out_file = ''
    debug_level = 0
    print_timestamp = True
    filename_col_len = 0

    level_map = {
        "V": 0,
        "D": 1,
        "I": 2,
        "W": 3,
        "E": 4,
        "F": 5,
    }

    level_tag = {
        "*": "D",
        "+": "I",
        "-": "W",
    }

    @staticmethod
    def pl(text):
        '''Prints text using colored format with trailing new line.'''
        Color.pl(text)

        if Logger.out_file != '':
            try:
                with open(Logger.out_file, "a") as text_file:
                    text_file.write(Color.escape_ansi(Color.sc(text)) + '\n')
            except:
                pass

    @staticmethod
    def pl_file(text):
        '''Prints text using colored format with trailing new line.'''

        if Logger.out_file != '':
            try:
                with open(Logger.out_file, "a") as text_file:
                    text_file.write(Color.escape_ansi(Color.sc(text)) + '\n')
            except:
                Color.pl(text)
        else:
            Color.pl(text)

    @classmethod
    def get_caller_info(cls, stack_index: int = 1) -> ScriptLocation:
        """Retrieves information about the calling script, function, and line number."""
        # inspect.stack() returns a list of frame records.
        # Each frame record is a tuple containing:
        # (frame object, filename, line number, function name, list of lines of context, index of current line in context)

        # The first element (index 0) is the current function (get_caller_info).
        # The second element (index 1) is the caller of get_caller_info.
        caller_frame = inspect.stack()[stack_index]

        # Extract information from the caller's frame
        filename = caller_frame.filename
        line_number = caller_frame.lineno
        function_name = caller_frame.function

        # Optionally, get the base name of the script for cleaner output
        script_name = Path(filename).name

        return ScriptLocation(
            file_name=script_name,
            function_name=function_name,
            line=str(line_number)
        )

    @staticmethod
    def json_serial(obj):
        """JSON serializer for objects not serializable by default json code"""

        if isinstance(obj, (datetime.datetime, datetime.date)):
            # obj = obj.astimezone(datetime.timezone(datetime.timedelta(hours=0), 'Z'))
            return obj.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("UTF-8")

        try:
            return str(obj)
        except:
            return f"[ERROR] Type %s not serializable{type(obj)}"

    @classmethod
    def print_message(cls, level: str = "*", message: str = "",
                      script_location: ScriptLocation = None, filename_col_len: int = 26):

        if level is None:
            level = "*"

        dbg_tag = next(iter([
            k
            for k in Logger.level_map.keys()
            if level.upper() == k
        ]), Logger.level_tag.get(level, "I"))

        dbg_idx = Logger.level_map.get(dbg_tag, 0)

        if Logger.debug_level > dbg_idx:
            return

        if filename_col_len < 26:
            filename_col_len = 26

        if Logger.filename_col_len > filename_col_len:
            filename_col_len = Logger.filename_col_len

        prefix = ""
        if Logger.print_timestamp:
            ts = datetime.datetime.now()
            stamp = f"{ts:%H:%M:%S}.{int(ts.microsecond / 1000):03d}"
            prefix += f"\033[2m{stamp.ljust(13)}{Color.color_reset}"

        fg_color = Color.color_level[dbg_idx]
        tag_color = Color.color_tags[dbg_idx]

        if script_location is None:
            script_location = cls.get_caller_info(stack_index=2)

        if script_location.file_name == "frida/node_modules/frida-java-bridge/lib/class-factory.js":
            file_name = "frida/.../class-factory.js"
        else:
            file_name = str(Path(script_location.file_name).name)

        if len(file_name) > filename_col_len:
            file_name = f"{file_name[0:filename_col_len-3]}..."

        prefix += (f"{fg_color}{file_name.rjust(filename_col_len)}"
                   f"{Color.color_reset}\033[2m:{str(script_location.line).ljust(10)}"
                   f"{Color.color_reset} ")
        prefix_len = len(Color.escape_ansi(prefix))

        f_message = ""
        if message is None:
            message = ""

        if isinstance(message, dict):
            try:
                message = json.dumps(message, ident=4, default=Logger.json_serial)
            except:
                message = str(message)

        for line in message.split("\n"):
            if f_message == "":
                f_message += (f"{prefix}{tag_color} {dbg_tag} {Color.color_reset} "
                              f"{fg_color}{line}{Color.color_reset}")
            else:
                f_message += (f"\n{''.rjust(prefix_len)}{tag_color} {dbg_tag} "
                              f"{Color.color_reset} {fg_color}{line}{Color.color_reset}")

        Logger.pl(f_message)
