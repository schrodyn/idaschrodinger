#
# https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/
#
import idc
import ida_loader
import ida_idaapi
import ida_kernwin

from idaapi import *

def py_go_rva():
    '''Add ability to jump to address based on RVA.'''
    rva = ida_kernwin.ask_addr(0x0, "RVA address")
    if not rva:
        return

    ea = idaapi.get_imagebase()+rva
    if ea == ida_idaapi.BADADDR:
        print('error: EA for RVA not found')
        return

    print('EA for RVA: 0x%x' % (ea))
    ida_kernwin.jumpto(ea)


print("+============================+")
print("+ schrodinger idapythonrc.py +")
print("+============================+")

idaapi.add_hotkey("Shift-g", py_go_rva)
