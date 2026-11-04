import logging

import ida_kernwin

logger = logging.getLogger(__name__)

MIN_KERNEL_VERSION = (9, 2)


cyberchef_ok = True

try:
    from PySide6 import QtCore  # noqa: F401
except ImportError:
    logger.warning("no PySide6, skipping")
    cyberchef_ok = False

kernel_version_str = ida_kernwin.get_kernel_version()
parts = [int(part) for part in kernel_version_str.split(".") if part.isdigit()]
kernel_version = tuple(parts) if parts else (0,)
if kernel_version < MIN_KERNEL_VERSION:
    logger.warning("IDA too old (must be 9.2+): %s", kernel_version_str)
    cyberchef_ok = False


if cyberchef_ok:
    # only attempt to import cyberchef once we know the required dependencies are present.
    # otherwise we'll hit ImportError and other problems
    from ida_cyberchef.plugin import cyberchef_plugin_t

    def PLUGIN_ENTRY():
        return cyberchef_plugin_t()

else:
    try:
        import ida_idaapi
    except ImportError:
        import idaapi as ida_idaapi

    class nop_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "cyberchef disabled"
        comment = "cyberchef is disabled for this IDA version"
        help = ""
        wanted_hotkey = ""

        def init(self):
            return ida_idaapi.PLUGIN_SKIP

    # we have to define this symbol, or IDA logs a message
    def PLUGIN_ENTRY():
        # we have to return something here, or IDA logs a message
        return nop_plugin_t()
