#!/usr/bin/env python
# coding=utf-8

from idc import *
from idautils import *
from idaapi import *
from ida_funcs import *
import ida_hexrays
import json
import os
import ida_pro

class ExportPseudo():
    def __init__(self):
        pass

    def get_pseudo_of(self, func_address, save_path):
        # 获取函数对象
        func = self.get_func_by_address(func_address)
        if func is None:
            print("Function not found at address 0x{:X}".format(func_address))
            return False

        # 反编译函数
        pseudocode = self.decompile_function(func)
        if pseudocode is None:
            print("Failed to decompile function at address 0x{:X}".format(func_address))
            return False

        print(pseudocode)
        # 保存伪代码到文件
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(pseudocode)
        print("Pseudocode saved to {}".format(save_path))
        return True

    def get_func_by_address(self, func_address):
        func = ida_funcs.get_func(func_address)
        return func

    def decompile_function(self, func):
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler is not available.")
            return None
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc is None:
                raise ida_hexrays.DecompilationFailure
            return str(cfunc)
        except ida_hexrays.DecompilationFailure:
            print("Decompilation failed for function at address 0x{:X}".format(func.start_ea))
            return None

if __name__ == "__main__":
    if len(idc.ARGV) < 3:
        usage = 'Usage: idat -A -S"{} function_address path_to_save_pseudo" binary_or_idb\n'.format(os.path.abspath(__file__))
        os.write(1, usage.encode('utf-8'))
        ida_pro.qexit(0)

    function_address = idc.ARGV[1]
    path_to_save_pseudo = idc.ARGV[2]

    # 将函数地址转换为整数
    func_address_int = int(function_address, 0)  # 支持十进制和十六进制（0x前缀）

    print("Function address: 0x{:X}".format(func_address_int))

    ida_auto.auto_wait()  # 等待自动分析完成

    e = ExportPseudo()
    e.get_pseudo_of(func_address_int, path_to_save_pseudo)
    ida_pro.qexit(0)