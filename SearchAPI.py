__AUTHOR__ = 'Alya Gomaa'

PLUGIN_NAME = "Search API"
PLUGIN_HOTKEY = 'Ctrl+Alt+]'
VERSION = 'v1.0'

  
import os
import idc
import idaapi
import idautils
import webbrowser



major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)

if using_pyqt5:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5.Qt import QApplication

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication



def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return api_search()

class api_search(idaapi.plugin_t):
    """
    The IDA Plugin for google search.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Google Search API"
    help = "Click instruction and right-click 'Google Search'"
    wanted_name = "Search API"
    wanted_hotkey = PLUGIN_HOTKEY

    #--------------------------------------------------------------------------
    # Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # initialize the menu actions our plugin will inject
        self._init_action_google_search()

        # initialize plugin hooks
        self._init_hooks()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # unhook our plugin hooks
        self._hooks.unhook()

        # unregister our actions & free their resources
        self._del_action_google_search()


        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    #--------------------------------------------------------------------------
    # Plugin Hooks 
    #--------------------------------------------------------------------------
    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).
        NOTE: This is called when the ui_ready_to_run event fires.
        """
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_GOOGLE_SEARCH  = "prefix:google_search"


    def _init_action_google_search(self):
        """
        Register the google search action with IDA.
        """

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_GOOGLE_SEARCH,               # The action name.
            "Google Search",                         # The action text.
            IDACtxEntry(google_search),              # The action handler.
            None,                                    # Optional: action shortcut
            "Search for the selected API"            # Optional: tooltip
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"


    def _del_action_google_search(self):
        """
        Delete the action from IDA.
        """
        idaapi.unregister_action(self.ACTION_GOOGLE_SEARCH)




#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):
    def ready_to_run(self):
        """
        UI ready to run -- an IDA event fired when everything is spunup.
        NOTE: this is a placeholder func, it gets replaced on a live instance
        but we need it defined here for IDA 7.2+ to properly hook it.
        """
        pass
    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_api_search_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def finish_populating_tform_popup(self, form, popup):
        """
        A right click menu is about to be shown. (IDA 6.x)
        """
        inject_api_search_actions(form, popup, idaapi.get_tform_type(form))
        return 0


    def hxe_callback(self, event, *args):
        """
        HexRays event callback.
        We lump this under the (UI) Hooks class for organizational reasons.
        """

        #
        # if the event callback indicates that this is a popup menu event
        # (in the hexrays window), we may want to install our menu
        # actions depending on what the cursor right clicked.
        #

        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            idaapi.attach_action_to_popup(
                form,
                popup,
                api_search.ACTION_GOOGLE_SEARCH,
                "Google Search",
                idaapi.SETMENU_APP
            )

        # done
        return 0

#------------------------------------------------------------------------------
# Wrappers
#------------------------------------------------------------------------------


def inject_api_search_actions(form, popup, form_type): #inject class actions
    """
    Inject actions to popup menu(s) based on context.
    """
    
    if form_type == idaapi.BWN_DISASMS: # disassembly window
        # insert the action entry into the menu
        
        idaapi.attach_action_to_popup(
            form,
            popup,
            api_search.ACTION_GOOGLE_SEARCH,
            "Google Search",
            idaapi.SETMENU_APP
        )

    # done
    return 0

#------------------------------------------------------------------------------
# Google Search
#------------------------------------------------------------------------------


def google_search():
    """
    Search for the API function at cursor.
    """
    
    if using_ida7api:
        current_instruction = idaapi.get_screen_ea()   #get the address at the cursor
        API= idc.print_operand(current_instruction,0)  #get the function name
        if ' ' in API or len(API)<4 :
            print('SearchApi: Please select a call instruction.')
        else:
            #in case a segment register gets copied with the API 
            
            API = API[ API.index(':')+1:] if ':' in API else API 
            webbrowser.open_new_tab('https://www.google.com/search?q=' + API + '+MSDN')
    else:

        current_instruction = idaapi.ScreenEA() 
        API= idc.GetOpnd(current_instruction,0)
        if ' ' in API or len(API)<4:
            print('SearchApi: Please select a call instruction.')
        else:
            API = API[ API.index(':')+1:] if ':' in API else API
            webbrowser.open_new_tab('https://www.google.com/search?q=' + API + '+MSDN')

        
            


    return 


#------------------------------------------------------------------------------
# IDA ctxt
#------------------------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS

