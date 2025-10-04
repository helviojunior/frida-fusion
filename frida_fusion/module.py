import os
import sys
import re
from argparse import _ArgumentGroup, Namespace

import inspect
from typing import Optional

import frida
import pkgutil
import importlib
import requests
import importlib.util
from pathlib import Path

from .__meta__ import __version__
from .libs.logger import Logger
from .libs.scriptlocation import ScriptLocation


class ModuleLoaderError(Exception):
    pass


class ModuleBase(object):

    name = ''
    description = ''
    mod_path = ''

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.mod_path = str(Path(__file__).resolve().parent)
        pass

    def safe_name(self):
        return ModuleBase.get_safe_name(self.name)

    def start_module(self, **kwargs) -> bool:
        raise Exception('Method "start_module" is not yet implemented.')

    def load_from_arguments(self, args: Namespace) -> bool:
        return True

    def js_files(self) -> list:
        return []

    def dynamic_script(self) -> str:
        return ""

    def suppress_messages(self):
        pass

    def add_params(self, flags: _ArgumentGroup):
        pass

    def key_value_event(self,
                        script_location: ScriptLocation = None,
                        stack_trace: str = None,
                        module: str = None,
                        received_data: dict = None
                        ) -> bool:
        raise Exception('Method "key_value_event" is not yet implemented.')

    def data_event(self,
                   script_location: ScriptLocation = None,
                   stack_trace: str = None,
                   received_data: str = None
                   ) -> bool:
        raise Exception('Method "data_event" is not yet implemented.')

    @staticmethod
    def get_safe_name(name):
        name = name.replace(" ", "_").lower()
        return re.sub(r'[^a-zA-Z0-9_.-]+', '', name)

    @classmethod
    def _get_codeshare(cls, uri: str) -> dict:

        if uri is None or len(uri) <= 10:
            raise Exception("Invalid codeshare uri. Uri must be only user/project_name.")

        uri = uri.strip(" /@.")

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": f"Frida-fusion v{__version__}, Frida v{frida.__version__}"
        }

        try:
            resp = requests.get(f"https://codeshare.frida.re/api/project/{uri}", headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data is None:
                raise Exception("data is empty")

            if data.get('source', None) is None or data.get('source', '').strip(" \r\n") == "":
                raise Exception("source code is empty")

            return data

        except Exception as e:
            raise ModuleLoaderError("Error getting codeshare data") from e


class Module(object):
    modules = {}

    def __init__(self, name, description, module, qualname, class_name):
        self.name = name
        self.description = description
        self.module = module
        self.qualname = qualname
        self._class = class_name
        self.py_file = Path(__file__)
        pass

    def __str__(self):
        return f"<{self.__class__.__qualname__} {self.name}>"

    def __repr__(self):
        return str(self.name)

    def safe_name(self):
        return ModuleBase.get_safe_name(self.name)

    def create_instance(self):
        return self._class()

    @classmethod
    def get_base_module(cls) -> str:
        file = Path(__file__).stem

        parent_module = f'.{cls.__module__}.'.replace(f'.{file}.', '').strip(' .')

        return '.'.join((parent_module, 'modules'))


class InternalModule(Module):
    pass


class ExternalModule(Module):
    pass


class LocalModule(Module):
    pass


class ModuleManager:
    initialized = False  # Flag indicating modules has been initialized
    modules: dict[str, Module] = {}

    @classmethod
    def _safe_import_from_path(cls, path: Path, loaded_files: set):
        """
        Importa um .py arbitrário usando um nome único e registra o arquivo
        para não ser importado duas vezes.
        """
        real = path.resolve()

        try:
            if real in loaded_files:
                return

            # nome único, estável, baseado no caminho
            pseudo_name = (
                    "fusion_ext_"
                    + "_".join(real.parts).replace(":", "_").replace("\\", "_").replace("/", "_")
                    .replace(".", "_")
            )
            spec = importlib.util.spec_from_file_location(pseudo_name, real)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[pseudo_name] = mod
                spec.loader.exec_module(mod)
                loaded_files.add(real)
        except Exception as ie:
            Logger.print_exception('\n{!} {R}Error loading external module: {G}%s{R}\n    {O} %s{W}\n' % (
                str(ie), str(real)))

            sys.exit(2)
            pass

    @classmethod
    def _import_via_pkgutil(cls, roots: list[Path], loaded_files: set):
        """
        Varre roots com pkgutil.walk_packages. Isso encontra
        - módulos .py no nível do root
        - pacotes (pastas com __init__.py) e seus submódulos
        NÃO entra em subpastas sem __init__.py (por isso depois complementamos).
        """
        str_roots = [str(p) for p in roots]
        for loader, modname, is_pkg in pkgutil.walk_packages(str_roots):
            try:
                mod = importlib.import_module(modname)
                mfile = getattr(mod, "__file__", None)
                if mfile:
                    loaded_files.add(Path(mfile).resolve())
            except Exception as ie:
                Logger.pl(
                    '\n{!} {R}Error loading internal module: {G}%s{R}\n    {O} %s{W}' % (
                        str(ie), str(loader.path)))
                pass

    @classmethod
    def _load_any_py_recursively(cls, root: Path, loaded_files: set):
        """
        Carrega *todo* arquivo .py sob root (rglob), incluindo subpastas sem __init__.py,
        sem duplicar o que já foi importado.
        """
        for py in root.rglob("*.py"):
            # exclui caches e similares
            if any(part in {"__pycache__"} for part in py.parts):
                continue
            cls._safe_import_from_path(py, loaded_files)

    @classmethod
    def _get_class_path(cls, class_def) -> Optional[Path]:
        # Tenta pegar o arquivo-fonte .py quando existir
        path = inspect.getsourcefile(class_def) or inspect.getfile(class_def)
        return Path(path).resolve() if path else None

    @classmethod
    def list_modules(cls, local_path: Path = None) -> dict:
        if ModuleManager.initialized and local_path is None:
            return ModuleManager.modules

        try:
            base_module = Module.get_base_module()
            ModuleManager.modules = {}

            # --- 1) Varredura padrão do seu pacote interno: <este_arquivo>/modules ---
            base_path = Path(__file__).resolve().parent / "modules"
            internal_mod_roots = [p for p in base_path.iterdir() if p.is_dir()]

            internal_mods = []
            local_files: set[Path] = set()

            # Vamos usar pkgutil para o pacote interno (mantém o comportamento)
            loaded_files: set[Path] = set()
            mods = [str(p) for p in internal_mod_roots]
            for loader, modname, is_pkg in pkgutil.walk_packages(mods):
                if not is_pkg:
                    # Reconstrói o caminho relativo para montar o import dentro do pacote base
                    mod_path = Path(getattr(loader, "path", ""))
                    try:
                        rel = mod_path.resolve().relative_to(base_path.resolve())
                        dotted = "." + ".".join(rel.parts) if rel.parts else ""
                    except Exception:
                        dotted = ""
                    importlib.import_module(f"{base_module}{dotted}.{modname}")
                    internal_mods.append(f"{base_module}{dotted}.{modname}")

            # --- 2) Varredura de caminhos externos via FUSION_MODULES ---
            env_value = os.environ.get("FUSION_MODULES", "").strip()
            if env_value:
                extra_roots = [Path(p).expanduser() for p in env_value.split(os.pathsep) if p.strip()]
                existing_roots = [p for p in extra_roots if p.exists() and p.is_dir()]

                # Para que pkgutil encontre módulos top-level nesses roots
                # (sem precisar de nomes de pacote), colocamos cada root no sys.path
                # durante a varredura. Usamos um conjunto para restaurar depois se preferir.
                original_sys_path = list(sys.path)
                try:
                    for root in existing_roots:
                        if str(root) not in sys.path:
                            sys.path.insert(0, str(root))

                    # 2a) Encontrar módulos top-level e pacotes (com __init__.py)
                    cls._import_via_pkgutil(existing_roots, loaded_files)

                    # 2b) Complementar: carregar QUALQUER .py (inclusive subpastas sem __init__.py)
                    for root in existing_roots:
                        cls._load_any_py_recursively(root, loaded_files)
                finally:
                    # opcional: restaurar sys.path (seguro para evitar vazamentos)
                    sys.path[:] = original_sys_path

            # --- 3) Varredura de caminhos externos via local_path parameter ---
            if local_path is not None and isinstance(local_path, Path) and local_path.exists():

                if local_path.is_dir():

                    for py in local_path.glob("*.py"):
                        # exclui caches e similares
                        if any(part in {"__pycache__"} for part in py.parts):
                            continue
                        cls._safe_import_from_path(py, local_files)
                elif local_path.suffix.lower() == ".py":
                    cls._safe_import_from_path(local_path, local_files)

            # --- 4) Instanciar subclasses de ModuleBase e montar o registry ---
            for i_class in ModuleBase.__subclasses__():
                t = i_class()
                key = t.safe_name()
                c_path = ModuleManager._get_class_path(i_class)
                m_file = next(iter(
                    v.py_file
                    for k, v in ModuleManager.modules.items()
                    if k == key
                    and c_path is not None
                    and c_path == v.py_file
                ), None)

                # Already exists and the python file is different
                if key in ModuleManager.modules and m_file is not None:
                    raise ModuleLoaderError(
                        f"Duplicated Module name: {i_class.__module__}.{i_class.__qualname__}"
                    )

                # Already exists and already imported
                if m_file is not None:
                    continue

                if str(i_class.__module__) in internal_mods:
                    ModuleManager.modules[key] = InternalModule(
                        name=t.name,
                        description=t.description,
                        module=str(i_class.__module__),
                        qualname=str(i_class.__qualname__),
                        class_name=i_class,
                    )
                elif c_path is not None and c_path in local_files:
                    ModuleManager.modules[key] = LocalModule(
                        name=t.name,
                        description=t.description,
                        module=str(i_class.__module__),
                        qualname=str(i_class.__qualname__),
                        class_name=i_class,
                    )
                else:
                    ModuleManager.modules[key] = ExternalModule(
                        name=t.name,
                        description=t.description,
                        module=str(i_class.__module__),
                        qualname=str(i_class.__qualname__),
                        class_name=i_class,
                    )

            # Ordenado por grupo e nome
            ModuleManager.modules = dict(sorted(
                ModuleManager.modules.items(),
                key=lambda kv: (
                    {InternalModule: 0, ExternalModule: 1, LocalModule: 2}.get(type(kv[1]), 3),
                    kv[1].name.casefold()
                )
            ))

            ModuleManager.initialized = True
            return ModuleManager.modules

        except Exception as e:
            # Envolve a exceção original para manter contexto
            raise ModuleLoaderError("Error listing modules") from e
