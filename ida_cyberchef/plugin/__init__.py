import logging

import ida_bytes
import ida_idaapi
import ida_kernwin
from PySide6 import QtWidgets

from ida_cyberchef.cyberchef_widget import CyberChefWidget
from ida_cyberchef.qt_models.input_model import InputSource

logger = logging.getLogger(__name__)


def list_widgets(prefix: str = "CyberChef-") -> list[str]:
    """Probe A-Z for existing widgets, return found captions.

    Args:
        prefix: Caption prefix to search for

    Returns: List of found widget captions (e.g., ["CyberChef-A", "CyberChef-C"])
    """
    found = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        caption = f"{prefix}{letter}"
        if ida_kernwin.find_widget(caption) is not None:
            found.append(caption)
    return found


def find_next_available_caption(prefix: str = "CyberChef-") -> str:
    """Find first gap or next letter for widget caption.

    Args:
        prefix: Caption prefix to use

    Returns: First available caption (e.g., "CyberChef-B")

    Raises:
        RuntimeError: If all 26 instances are in use
    """
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        caption = f"{prefix}{letter}"
        if ida_kernwin.find_widget(caption) is None:
            return caption
    raise RuntimeError("All 26 CyberChef instances in use")


def _read_and_validate_selection(v) -> tuple[bool, int, int, int]:
    """Read and validate a range selection from the given viewer.

    Args:
        v: IDA viewer handle from ida_kernwin.get_current_viewer()

    Returns:
        (ok, start, end, length) where ok is False if validation failed.
    """
    if ida_kernwin.get_widget_type(v) not in (
        ida_kernwin.BWN_HEXVIEW,
        ida_kernwin.BWN_DISASM,
    ):
        return False, 0, 0, 0

    has_range, start, end = ida_kernwin.read_range_selection(v)
    if not has_range or ida_idaapi.BADADDR in (start, end):
        logger.warning("No valid selection for Send to CyberChef")
        return False, 0, 0, 0

    length = end - start
    if length <= 0:
        logger.warning("Invalid selection length for Send to CyberChef")
        return False, 0, 0, 0

    return True, start, end, length


def _populate_widget_from_selection(form, start: int, length: int) -> None:
    """Populate a CyberChefForm widget with a selection from IDA.

    Args:
        form: CyberChefForm instance with a valid .w attribute
        start: Start address of the selection
        length: Number of bytes selected
    """
    form.w.set_location_source(start, length)


class UILocationHook(ida_kernwin.UI_Hooks):
    def __init__(self, w, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.w: CyberChefWidget = w
        self.w.get_input_model().source_changed.connect(self._on_source_changed)
        self.populate(ida_kernwin.get_screen_ea())

    def populate_from_cursor(self, ea):
        buf = ida_bytes.get_bytes(ea, 0x100)
        self.w.get_input_model().set_external_data(buf)

    def populate_from_selection(self):
        v = ida_kernwin.get_current_viewer()
        ok, start, _end, length = _read_and_validate_selection(v)
        if not ok:
            self.w.get_input_model().clear_external_data()
            return

        # TODO: maybe use item head/end

        buf = ida_bytes.get_bytes(start, length)
        self.w.get_input_model().set_external_data(buf, start)

    def populate(self, ea: int):
        source = self.w.get_input_model().get_input_source()
        if source == InputSource.MANUAL:
            # nothing to do
            pass
        elif source == InputSource.FROM_CURSOR:
            self.populate_from_cursor(ea)
        elif source == InputSource.FROM_SELECTION:
            self.populate_from_selection()
        elif source == InputSource.FROM_LOCATION:
            # FROM_LOCATION mode maintains pinned address/length and should not
            # respond to cursor or selection changes. Data only updates when user
            # explicitly edits the location fields or uses 'Send to CyberChef' action.
            pass
        else:
            raise RuntimeError("unexpected input source")

    def _on_source_changed(self, source: InputSource):
        """Handle input source change by populating with current IDA state."""
        if source not in (InputSource.MANUAL, InputSource.FROM_LOCATION):
            self.populate(ida_kernwin.get_screen_ea())

    def screen_ea_changed(self, ea: ida_idaapi.ea_t, prev_ea: ida_idaapi.ea_t) -> None:
        if ea == prev_ea:
            return
        self.populate(ea)


class ContextMenuUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugmod: "cyberchef_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def finish_populating_widget_popup(self, widget, popup, ctx):
        if ctx.widget_type in (ida_kernwin.BWN_HEXVIEW, ida_kernwin.BWN_DISASM):
            self.plugmod.register_instance_actions()

            existing = list_widgets()

            if existing:
                for caption in existing:
                    action_name = (
                        f"cyberchef:send_to_{caption.replace('-', '_').lower()}"
                    )
                    ida_kernwin.attach_action_to_popup(
                        widget, popup, action_name, "CyberChef/"
                    )

            ida_kernwin.attach_action_to_popup(
                widget, popup, "cyberchef:send_new", "CyberChef/"
            )


class CyberChefForm(ida_kernwin.PluginForm):
    def __init__(
        self,
        caption: str = "CyberChef-A",
        form_registry: dict[str, "CyberChefForm"] | None = None,
    ) -> None:
        super().__init__()
        self.TITLE = caption
        self.form_registry = form_registry

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.w = CyberChefWidget(parent=self.parent, show_ida_buttons=True)

        output_panel = self.w.get_output_panel()
        output_panel.copy_to_db_requested.connect(self._on_copy_to_db)
        output_panel.set_comment_requested.connect(self._on_set_comment)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.w)
        self.parent.setLayout(layout)

        self.location_hooks = UILocationHook(self.w)
        self.location_hooks.hook()

        if self.form_registry is not None:
            self.form_registry[self.TITLE] = self

    def _on_copy_to_db(self, address: int, data: bytes):
        """Handle copy to IDB request from output panel.

        Args:
            address: Address to patch
            data: Bytes to write
        """
        logger.debug("_on_copy_to_db called: address=%s, data type=%s, len=%s", hex(address) if isinstance(address, int) else address, type(data).__name__, len(data) if isinstance(data, bytes) else "N/A")
        if not isinstance(address, int) or address < 0 or address == ida_idaapi.BADADDR:
            message = f"Cannot patch IDB: invalid address {address!r}"
            logger.warning(message)
            ida_kernwin.warning(message)
            return

        if not isinstance(data, bytes) or len(data) == 0:
            data_len = len(data) if isinstance(data, bytes) else "N/A"
            message = (
                f"Cannot patch IDB: invalid data {type(data).__name__}, len={data_len}"
            )
            logger.warning(message)
            ida_kernwin.warning(message)
            return

        ida_bytes.patch_bytes(address, data)

        actual = ida_bytes.get_bytes(address, len(data))
        if actual != data:
            logger.warning(
                "Patch verification failed at %s: wrote %d bytes but read back different data",
                hex(address),
                len(data),
            )
            return

        logger.info("Patched %d bytes at %s", len(data), hex(address))

    def _on_set_comment(self, text: str):
        """Handle set comment request from output panel.

        Args:
            text: Comment text to set
        """
        try:
            # Try to get the selection start address first, fall back to cursor
            ea = self.w.get_input_model().get_external_address()
            if ea is None:
                ea = ida_kernwin.get_screen_ea()

            ida_bytes.set_cmt(ea, text, False)
            logger.info("Set comment at address %s", hex(ea))
        except Exception as e:
            logger.error("Failed to set comment: %s", e)

    def OnClose(self, form):
        if self.location_hooks:
            self.location_hooks.unhook()

        if self.form_registry is not None:
            self.form_registry.pop(self.TITLE, None)


class create_cyberchef_widget_action_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, plugmod: "cyberchef_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def activate(self, ctx):
        self.plugmod.create_viewer()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class send_to_cyberchef_action_handler_t(ida_kernwin.action_handler_t):
    """Action handler for 'Send to CyberChef' context menu item."""

    def __init__(self, plugmod: "cyberchef_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def activate(self, ctx):
        """Handle 'Send to CyberChef' action - always creates new instance."""
        v = ida_kernwin.get_current_viewer()
        ok, start, _end, length = _read_and_validate_selection(v)
        if not ok:
            return 0

        form = self.plugmod.create_viewer()

        if form and form.w:
            _populate_widget_from_selection(form, start, length)

        return 1

    def update(self, ctx):
        """Enable action when there's a valid selection."""
        v = ida_kernwin.get_current_viewer()

        if ida_kernwin.get_widget_type(v) not in (
            ida_kernwin.BWN_HEXVIEW,
            ida_kernwin.BWN_DISASM,
        ):
            return ida_kernwin.AST_DISABLE

        has_range, start, end = ida_kernwin.read_range_selection(v)
        if has_range and ida_idaapi.BADADDR not in (start, end) and end > start:
            return ida_kernwin.AST_ENABLE

        return ida_kernwin.AST_DISABLE


class send_to_specific_widget_action_handler_t(ida_kernwin.action_handler_t):
    """Action handler for sending to a specific CyberChef instance."""

    def __init__(
        self,
        form_registry: dict[str, CyberChefForm],
        caption: str,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.form_registry = form_registry
        self.caption = caption

    def activate(self, ctx):
        """Send selection to specific CyberChef instance."""
        v = ida_kernwin.get_current_viewer()
        ok, start, _end, length = _read_and_validate_selection(v)
        if not ok:
            return 0

        widget = ida_kernwin.find_widget(self.caption)
        if widget is None:
            logger.warning(f"Widget {self.caption} not found")
            return 0

        ida_kernwin.activate_widget(widget, True)

        form = self.form_registry.get(self.caption)
        if form and hasattr(form, "w"):
            _populate_widget_from_selection(form, start, length)
        else:
            logger.warning(f"Cannot populate {self.caption} - unable to access form")

        return 1

    def update(self, ctx):
        """Enable action when there's a valid selection."""
        v = ida_kernwin.get_current_viewer()

        if ida_kernwin.get_widget_type(v) not in (
            ida_kernwin.BWN_HEXVIEW,
            ida_kernwin.BWN_DISASM,
        ):
            return ida_kernwin.AST_DISABLE

        has_range, start, end = ida_kernwin.read_range_selection(v)
        if has_range and ida_idaapi.BADADDR not in (start, end) and end > start:
            return ida_kernwin.AST_ENABLE

        return ida_kernwin.AST_DISABLE


class create_desktop_widget_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self, plugmod: "cyberchef_plugmod_t", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.plugmod = plugmod

    def create_desktop_widget(self, ttl, cfg):
        if ttl.startswith("CyberChef-"):
            return self.plugmod.create_viewer(caption=ttl).GetWidget()


class cyberchef_plugmod_t(ida_idaapi.plugmod_t):
    ACTION_NAME = "cyberchef:create"
    SEND_ACTION_NAME = "cyberchef:send_selection"
    MENU_PATH = "View/Open subviews/Strings"

    def __init__(self):
        super().__init__()
        self.installation_hooks: create_desktop_widget_hooks_t | None = None
        self.context_menu_hooks: ContextMenuUIHooks | None = None
        self.form_registry: dict[str, CyberChefForm] = {}

        # IDA doesn't invoke this for plugmod_t, only plugin_t
        self.init()

    def create_viewer(self, caption: str | None = None) -> CyberChefForm:
        if caption is None:
            caption = find_next_available_caption()
        form = CyberChefForm(caption, self.form_registry)
        form.Show(form.TITLE)
        return form

    def register_open_action(self):
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.ACTION_NAME,
                "CyberChef",
                create_cyberchef_widget_action_handler_t(self),
            )
        )

        # TODO: add icon
        ida_kernwin.attach_action_to_menu(
            self.MENU_PATH, self.ACTION_NAME, ida_kernwin.SETMENU_APP
        )

    def unregister_open_action(self):
        ida_kernwin.unregister_action(self.ACTION_NAME)
        ida_kernwin.detach_action_from_menu(self.MENU_PATH, self.ACTION_NAME)

    def register_autoinst_hooks(self):
        self.installation_hooks = create_desktop_widget_hooks_t(self)
        self.installation_hooks.hook()

    def unregister_autoinst_hooks(self):
        if self.installation_hooks:
            self.installation_hooks.unhook()

    def register_send_action(self):
        """Register 'Send to CyberChef' context menu actions."""
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                "cyberchef:send_new",
                "New window",
                send_to_cyberchef_action_handler_t(self),
                None,
                "Send selected bytes to new CyberChef window",
                -1,
            )
        )

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.SEND_ACTION_NAME,
                "Send to CyberChef",
                send_to_cyberchef_action_handler_t(self),
                None,
                "Send selected bytes to CyberChef for transformation",
                -1,
            )
        )

    def unregister_send_action(self):
        """Unregister 'Send to CyberChef' actions."""
        ida_kernwin.unregister_action("cyberchef:send_new")
        ida_kernwin.unregister_action(self.SEND_ACTION_NAME)

    def register_instance_actions(self):
        """Register actions for all existing widget instances."""
        existing = list_widgets()

        for caption in existing:
            action_name = f"cyberchef:send_to_{caption.replace('-', '_').lower()}"

            ida_kernwin.unregister_action(action_name)

            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    action_name,
                    f"Send to {caption}",
                    send_to_specific_widget_action_handler_t(
                        self.form_registry, caption
                    ),
                    None,
                    f"Send selected bytes to {caption}",
                    -1,
                )
            )

    def register_context_menu_hooks(self):
        self.context_menu_hooks = ContextMenuUIHooks(self)
        self.context_menu_hooks.hook()

    def unregister_context_menu_hooks(self):
        if self.context_menu_hooks:
            self.context_menu_hooks.unhook()

    def init(self):
        # do things here that will always run,
        #  and don't require the menu entry (edit > plugins > ...) being selected.
        #
        # note: IDA doesn't call init, we do in __init__
        self.register_autoinst_hooks()
        self.register_open_action()
        self.register_send_action()
        self.register_context_menu_hooks()

    def run(self, arg):
        # do things here that users invoke via the menu entry (edit > plugins > ...)
        self.create_viewer()

    def term(self):
        self.unregister_context_menu_hooks()
        self.unregister_send_action()
        self.unregister_open_action()
        self.unregister_autoinst_hooks()


class cyberchef_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    help = "CyberChef data transformations"
    comment = ""
    # TODO: don't show in plugins menu
    wanted_name = "CyberChef"
    wanted_hotkey = "Shift-c"

    def init(self):
        return cyberchef_plugmod_t()
