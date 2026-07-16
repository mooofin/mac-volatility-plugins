"""Recover the system hostname from a macOS memory image.

XNU keeps the live hostname in a kernel global ``hostname`` (a ``char[]``, the
value ``sysctl kern.hostname`` returns).  
"""

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

MAXHOSTNAMELEN = 256


class Hostname(interfaces.plugins.PluginInterface):
   

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"]),
        ]

    def _from_symbol(self):
        kernel = self.context.modules[self.config["kernel"]]
        addr = kernel.get_absolute_symbol_address("hostname")
        raw = self.context.layers[kernel.layer_name].read(addr, MAXHOSTNAMELEN)
        host = raw.split(b"\x00", 1)[0].decode("latin-1")
        yield 0, (host or renderers.NotAvailableValue(),
                  "kern.hostname", format_hints.Hex(addr))

    def run(self):
        return renderers.TreeGrid(
            [("Hostname", str), ("Source", str), ("Offset", format_hints.Hex)],
            self._from_symbol())
