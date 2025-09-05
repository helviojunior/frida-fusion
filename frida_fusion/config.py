#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import os
import errno
import sys
import signal
from pathlib import Path

from .module import Module, ModuleManager, InternalModule, ExternalModule
from .libs.color import Color
from .libs.logger import Logger
from .__meta__ import __version__


class Configuration(object):
    ''' Stores configuration variables and functions for Frida Fusion. '''
    version = '0.0.0'

    initialized = False  # Flag indicating config has been initialized
    debug_level = 0
    cmd_line = ''
    base_path = str(Path(__file__).resolve().parent)
    db_path = os.path.join(str(Path(".").resolve()), "fusion.db")
    enabled_modules = {}

    # Device vars
    device_id = None
    use_usb = False
    remote_host = None

    # App vars
    package = ''
    pid = 0

    # Scripts
    frida_scripts = None

    # General
    out_file = None
    print_timestamp = False
    use_delay = False

    @staticmethod
    def initialize():
        '''
            Sets up default initial configuration values.
            Also sets config values based on command-line arguments.
        '''

        # Only initialize this class once
        if Configuration.initialized:
            return

        Configuration.debug_level = 0  # Verbosity level.

        # Overwrite config values with arguments (if defined)
        Configuration.load_from_arguments()

        Configuration.initialized = True

    @staticmethod
    def load_from_arguments():
        ''' Sets configuration values based on Argument.args object '''
        from .args import Arguments

        config_check = 0

        sys.argv[0] = 'frida-fusion'

        list_modules = any(['--list-modules' == word for word in sys.argv])
        #show_help = any(['-h' == word for word in sys.argv])

        if list_modules:
            mods = ModuleManager.list_modules()

            if len(mods) == 0:
                Color.pl('{!} {R}error: no modules found{R}{W}\r\n')
                sys.exit(1)

            max_name = max(iter([
                len(m.name) + 3
                for _, m in mods.items()
            ] + [15]))
            Color.pl(f"Available internal modules")
            for m in [m for _, m in mods.items() if isinstance(m, InternalModule)]:
                Color.pl(f"  {m.safe_name().ljust(max_name)} : {m.description}")

            Color.pl(f"\nAvailable external modules")
            ext_mods = [m for _, m in mods.items() if isinstance(m, ExternalModule)]
            if len(ext_mods) == 0:
                Color.pl(("  No external modules available. You can set {G}FUSION_MODULES{W} environment variable "
                          "to set an external modules Path"))
            for m in ext_mods:
                Color.pl(f"  {m.safe_name().ljust(max_name)} : {m.description}")

            print("")
            sys.exit(0)

        args = Arguments().args

        Color.pl('{+} {W}Startup parameters')

        if args.out_file is not None and args.out_file != '':
            Configuration.out_file = args.out_file
            try:
                with open(Configuration.out_file, 'a') as f:
                    # file opened for writing. write to it here
                    Logger.out_file = Configuration.out_file
                    f.write(Color.sc(Configuration.get_banner()) + '\n')
                    f.write(Color.sc('{+} {W}Startup parameters') + '\n')
                    pass
            except IOError as x:
                if x.errno == errno.EACCES:
                    Color.pl('{!} {R}error: could not open output file to write {O}permission denied{R}{W}\r\n')
                    sys.exit(1)
                elif x.errno == errno.EISDIR:
                    Color.pl('{!} {R}error: could not open output file to write {O}it is an directory{R}{W}\r\n')
                    sys.exit(1)
                else:
                    Color.pl('{!} {R}error: could not open output file to write{W}\r\n')
                    sys.exit(1)

        if args.app_id is None and args.pid == 0:
            Color.pl('{!} {R}error: you must specify either {O}--package{R} or {O}--attach-pid{R}{W}\r\n')
            Configuration.mandatory()

        if args.app_id is not None and args.pid > 0:
            Color.pl('{!} {R}error: you must specify just one parameter {O}--package{R} or {O}--attach-pid{R}{W}\r\n')
            Configuration.mandatory()

        if args.app_id is not None:
            Configuration.package = args.app_id
            Logger.pl('     {C}package:{O} %s{W}' % Configuration.package)
        elif args.pid > 0:
            Configuration.pid = args.pid
            Logger.pl('     {C}process id:{O} %s{W}' % Configuration.pid)

        if args.use_usb is True:
            Configuration.use_usb = True
            Logger.pl('     {C}device:{O} USB{W}')
        elif args.device_id is not None:
            Configuration.device_id = args.device_id
            Logger.pl('     {C}device:{O} %s{W}' % Configuration.device_id)
        elif args.use_remote and args.remote_host is not None:
            Configuration.remote_host = args.remote_host
            Logger.pl('     {C}device:{O} remote %s{W}' % Configuration.remote_host)

        if Configuration.use_usb is False and Configuration.device_id is None and Configuration.remote_host is None:
            Color.pl('{!} {R}error: you must specify just one parameter {O}--usb{R}, {O}--device{R} or {O}--remote{R}{W}\r\n')
            Configuration.mandatory()

        if args.frida_scripts is not None and args.frida_scripts.strip() != "":
            if not os.path.exists(args.frida_scripts):
                Color.pl(
                    '{!} {R}error: scripts path not found{R}{W}\r\n')
                Configuration.mandatory()
            Configuration.frida_scripts = args.frida_scripts

        if Configuration.frida_scripts is None:
            Color.pl(
                '{!} {R}error: you must specify scripts path {O}--script-path{R}{W}\r\n')
            Configuration.mandatory()

        Logger.pl('     {C}scripts path:{O} %s{W}' % Configuration.frida_scripts)

        if args.delay:
            Configuration.use_delay = True

        if args.show_time:
            Configuration.print_timestamp = True
        Logger.print_timestamp = Configuration.print_timestamp

        if str(args.debug_level).upper() not in Logger.level_map.keys():
            Color.pl(
                '{!} {R}error: invalid debug level{R}{W}\r\n')
            Configuration.mandatory()

        Configuration.debug_level = Logger.level_map.get(str(args.debug_level).upper(), 0)
        Logger.debug_level = Configuration.debug_level

        Logger.pl('     {C}min debug level:{O} %s{W}' % str(args.debug_level).upper())

        if args.enabled_modules is not None and isinstance(args.enabled_modules, list):
            mods = ModuleManager.list_modules()
            for mod in args.enabled_modules:
                fm = next(iter([
                    m
                    for _, m in mods.items()
                    if m.safe_name() == mod.lower()
                ]), None)
                if fm is None:
                    Color.pl(
                        '{!} {R}error: module {O}%s{R} not found{W}\r\n' % mod)
                    sys.exit(1)

                name = fm.safe_name()
                if name not in Configuration.enabled_modules.keys():
                    Configuration.enabled_modules[name] = fm

        if len(Configuration.enabled_modules) > 0:
            Logger.pl('     {C}modules:{O} %s{W}' % ', '.join([
                m.name
                for _, m in Configuration.enabled_modules.items()
            ]))

        Logger.pl("")

    @staticmethod
    def get_banner():
        Configuration.version = str(__version__)

        return '''
 {P}[ {R}FRIDA {P}]{G}—o—( {O}FUSION {G})—o—{P}[ {C}MOBILE TESTS {P}] {W}{D}// v%s{W}
     {O}> {W}{D}{O}hook your mobile tests with Frida{W}
    
    ''' % Configuration.version

    @staticmethod
    def mandatory():
        Color.pl(
            '{!} {R}error: missing a mandatory option, use {O}-h{R} help{W}\r\n')
        sys.exit(1)

    @staticmethod
    def exit_gracefully(code=0):
        ''' Deletes temp and exist with the given code '''
        exit(code)

    @staticmethod
    def kill(code=0):
        ''' Deletes temp and exist with the given code '''
        os.kill(os.getpid(), signal.SIGTERM)
