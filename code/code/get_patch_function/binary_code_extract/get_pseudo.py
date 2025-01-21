
import subprocess, os, sys

sys.path.append(".")

import get_pseudo
from settings import ida_path

def get_function_address(binary_path, function_name):
    try:
        # 使用 nm 获取二进制文件中的符号表
        result = subprocess.run(["nm", binary_path], capture_output=True, text=True, check=True)
        
        # 遍历结果中的每一行
        for line in result.stdout.splitlines():
            # nm 的输出格式：<地址> <符号类型> <符号名称>
            parts = line.split()
            if len(parts) >= 3 and parts[2] == function_name:
                # 提取起始地址
                address = parts[0]
                print(f"Function '{function_name}' start address: {address}")
                return address

        # 如果没有找到该函数
        print(f"Function '{function_name}' not found in {binary_path}")
        return None
    
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while executing nm: {e}")
        return None

class PseudoGenerator():
    def __init__(self, ida):
        self._ida = ida
        if not self._ida.endswith('.exe'):  # osx and linux
            self._ida = "TVHEADLESS=1 " + self._ida
        self._script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ida_script_get_pseudo.py")

    def clear_corrupt_ida_database(self, binary_path):
        # remove files ending with .id0 .id1 .id2 after the ida crashing
        cmd = "rm {}.id0 {}.id1 {}.id2 >/dev/null 2>&1".format(binary_path, binary_path, binary_path)
        os.system(cmd)

    def run(self, binary, function_name, function_address, force_generation=False):

        if not os.path.isabs(binary):
            binary = os.path.join(PROJ_ROOT_DIR, binary)

        def is64bit(bin):
            ret = os.popen('file {}'.format(bin))
            if 'x86-64' in ret.read():
                ret.close()
                return True

            ret.close()
            return False

        ida = self._ida
        if is64bit(binary):
            ida = self._ida + "64"

        self._binary = binary
        self._function_name = function_name  # IDA will replace all '.' with '_' in function names
        self._function_address = function_address  # IDA will replace all '.' with '_' in function names
        save_pseudo_path = self._binary + "_" + self._function_name  + "_" + self._function_address + ".idapseudo"
        if not force_generation and os.path.exists(save_pseudo_path):
            return save_pseudo_path

        self.clear_corrupt_ida_database(self._binary)

        cmd = '{}  -Lidaerror.log -A -S"{} {} {}" {}'.format(ida, self._script,
                                                             self._function_address, save_pseudo_path, self._binary)
        print("[*] pseudo dump: {}".format(cmd))
        res = os.system(cmd)
        if res != 0:
            raise FileNotFoundError("'{}' returns {}".format(cmd, res))
        return save_pseudo_path


def get_func_pseudo(binary_path, binary_strip_path, function_name):
    function_address = get_function_address(binary_path, function_name)

    print("function_address: ", function_address)

    if function_address is not None:
        pseudo_generator = PseudoGenerator(ida_path)
        pseudo_path = pseudo_generator.run(binary_strip_path, function_name, "0x"+function_address)
        print(f"Pseudo code saved to {pseudo_path}")

if __name__ == "__main__":

    binary_path = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/dataset/bin/O3/openssl-1.0.1h"
    binary_strip_path = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/dataset/bin/O3/openssl-1.0.1h.strip"

    function_name = "ssl3_send_client_key_exchange"

    get_func_pseudo(binary_path, binary_strip_path, function_name)

    