"""
this plugin is based on the research of David Maynor  (see
https://seclists.org/bugtraq/2008/Feb/442).
"""

import logging
import re
from typing import Callable, Iterable, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import pslist

vollog = logging.getLogger(__name__)

TOKEN = re.compile(rb"[\x20-\x7e]{2,}")
FIELDS = {b"longname", b"name", b"password", b"realname",
          b"shortname", b"uid", b"gid", b"home", b"shell"}
TARGETS = ("loginwindow",)  


class LoginwindowCreds(interfaces.plugins.PluginInterface):
   

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    WINDOW = 1024  

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 1, 0)),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.BooleanRequirement(
                name="all", optional=True, default=False,
                description="Emit every parsed info"),
        ]

  

    @classmethod
    def _parse(cls, window: bytes):
        tokens = TOKEN.findall(window)
        if b"longname" not in tokens or b"password" not in tokens:
            return None

        out = {}
        for i, tok in enumerate(tokens):
            if tok in FIELDS and tok not in out:
                nxt = tokens[i + 1] if i + 1 < len(tokens) else None
                out[tok] = None if nxt in FIELDS else nxt

        
        pw = out.get(b"password")
        if not pw or b" " in pw or len(pw) > 128:
            return None
        ln = out.get(b"longname")
        if ln and (b" " in ln or len(ln) > 128):
            return None
        return out

    def _scan_layer(self, layer_name: str, source: str
                    ) -> Iterable[Tuple[str, format_hints.Hex, tuple]]:
        layer = self.context.layers[layer_name]
        show_all = self.config.get("all")
        seen = set()

        for offset in layer.scan(context=self.context,
                                 scanner=scanners.BytesScanner(b"longname")):
            try:
                window = layer.read(offset, self.WINDOW, pad=True)
            except Exception:
                continue
            fields = self._parse(window)
            if fields is None:
                continue
            row = tuple(v.decode("latin-1") if v else "" for v in
                        (fields.get(b"longname"), fields.get(b"name"),
                         fields.get(b"password")))
            if not show_all and row in seen:
                continue
            seen.add(row)
            yield source, format_hints.Hex(offset), row


    @staticmethod
    def _target_filter() -> Callable[[interfaces.objects.ObjectInterface], bool]:
        
        return lambda proc: utility.array_to_string(proc.p_comm) not in TARGETS

    def _generator(self):
        kernel_name = self.config["kernel"]
        for proc in pslist.PsList.list_tasks_allproc(
                self.context, kernel_name, filter_func=self._target_filter()):
            comm = utility.array_to_string(proc.p_comm)
            layer_name = proc.add_process_layer()
            if layer_name is None:
                vollog.debug("No process layer for %s (pid %d)", comm, proc.p_pid)
                continue
            for _, offset, row in self._scan_layer(layer_name, comm):
                yield 0, (comm, int(proc.p_pid), offset, *row)

    def run(self):
        return renderers.TreeGrid(
            [("Process", str), ("PID", int), ("Offset", format_hints.Hex),
             ("Longname", str), ("Name", str), ("Password", str)],
            self._generator())
