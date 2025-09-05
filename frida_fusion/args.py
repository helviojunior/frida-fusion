#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import argparse
import sys

from .libs.color import Color
from .__meta__ import __description__

class Arguments(object):
    ''' Holds arguments used by the Frida Fusion '''
    restore = False

    def __init__(self, custom_args=''):
        self.verbose = any(['-v' in word for word in sys.argv])
        self.restore = any(['-R' in word for word in sys.argv])
        self.args = self.get_arguments(custom_args)

    def _verbose(self, msg):
        if self.verbose:
            return Color.s(msg)
        else:
            return argparse.SUPPRESS

    def get_arguments(self, custom_args=''):
        ''' Returns parser.args() containing all program arguments '''

        parser = argparse.ArgumentParser(
            usage=argparse.SUPPRESS,
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80,
                                                                width=130)
        )

        device_group = parser.add_argument_group('Device selector')
        self._add_device_args(device_group)

        app_group = parser.add_argument_group('Application selector')
        self._add_app_args(app_group)

        glob = parser.add_argument_group('General Setting')
        self._add_global_args(glob)

        modules_group = parser.add_argument_group('Modules')
        self._add_modules_args(modules_group)

        return parser.parse_args()

    def _add_app_args(self, app):
        app.add_argument('-f',
                         '--package',
                         dest='app_id',
                         metavar='[APP ID]',
                         required=False,
                         default=None,
                         help='Spawn application ID')

        app.add_argument('-p',
                         '--attach-pid',
                         dest='pid',
                         metavar='[PID]',
                         default=0,
                         required=False,
                         type=int,
                         help='Spawn application ID')

    def _add_device_args(self, device):
        device.add_argument('-D',
                            '--device',
                            dest='device_id',
                            metavar='[ID]',
                            type=str,
                            required=False,
                            default=None,
                            help='Connect to device with the given ID')

        device.add_argument('-U',
                            '--usb',
                            action='store_true',
                            dest='use_usb',
                            default=False,
                            required=False,
                            help='Connect to USB device')

        device.add_argument('-R',
                            '--remote',
                            action='store_true',
                            dest='use_remote',
                            default=False,
                            required=False,
                            help='Connect to remote frida-server')

        device.add_argument('-H',
                            '--host',
                            dest='remote_host',
                            metavar='[HOST]',
                            type=str,
                            required=False,
                            default=None,
                            help='Connect to remote frida-server on HOS')

    def _add_global_args(self, glob):
        glob.add_argument('-s',
                          '--script-path',
                          dest='frida_scripts',
                          default=None,
                          metavar='[path]',
                          type=str,
                          help='JS File path or directory with Frida script')

        glob.add_argument('--delay-injection',
                          action='store_true',
                          dest='delay',
                          default=False,
                          help='Delay script injection')

        glob.add_argument('--show-time',
                          action='store_true',
                          dest='show_time',
                          default=False,
                          help='Display time')

        glob.add_argument('-o',
                          action='store',
                          dest='out_file',
                          metavar='[output file]',
                          type=str,
                          help=Color.s('Save output to disk (default: {G}none{W})'))

        glob.add_argument('-l',
                          '--min-level',
                          action='store',
                          dest='debug_level',
                          metavar='[level]',
                          type=str,
                          default='I',
                          help=Color.s('Minimum log level to be displayed (V,D,I,W,E,F) (default: {G}I{W})'))

    def _add_modules_args(self, modules):
        modules.add_argument('--list-modules',
                             action='store_true',
                             default=False,
                             dest='list_modules',
                             help=Color.s('List available modules'))

        modules.add_argument('-m',
                             '--module',
                             action='append',
                             dest='enabled_modules',
                             help='Enabled module by name. You can specify multiple values repeating the flag.')


