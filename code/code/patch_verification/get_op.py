import json
import re

class CodeAnalyzer:
    def __init__(self):
        self.var_map = {}
        self.var_counter = 1

    def normalize_variable(self, expr):
        if not expr:
            return expr
        
        # 存储当前表达式的变量映射
        current_var_map = {}
        
        def replace_var(match):
            var = match.group(0)
            if var not in current_var_map:
                current_var_map[var] = f"x{len(current_var_map) + 1}"
            return current_var_map[var]

        # 替换复杂的指针和结构体访问
        patterns = [
            r'\*\*\(_DWORD \*\*\)\([^)]+\)',  # 匹配 **(_DWORD **)(...)
            r'\*\(_DWORD \*?\)?[^)]*\)+',      # 匹配 *(_DWORD )(...) 
            r'[a-zA-Z_][a-zA-Z0-9_]*(?:->[\w]+)*',  # 匹配变量名和结构体访问
            r'\d+',  # 匹配数字
        ]

        for pattern in patterns:
            expr = re.sub(pattern, replace_var, expr)

        return expr

    def extract_basic_operations(self, code):
        operations = set()
        
        # 移除注释
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE).strip()
        
        # 提取if条件
        if_match = re.search(r'if\s*\((.*)\)', code)
        if if_match:
            conditions = if_match.group(1).split('&&')
            for cond in conditions:
                cond = cond.strip()
                if '==' in cond:
                    normalized = self.normalize_variable(cond)
                    operations.add(normalized)

        # 提取赋值语句
        assignments = re.findall(r'(\w+)\s*=\s*([^;]+);', code)
        for var, value in assignments:
            normalized = f"{self.normalize_variable(var)} = {self.normalize_variable(value)}"
            operations.add(normalized)

        # 提取return语句
        return_match = re.search(r'return\s+([^;]+);', code)
        if return_match:
            return_expr = return_match.group(1)
            normalized = f"return = {self.normalize_variable(return_expr)}"
            operations.add(normalized)

        return operations

    def process_match_result(self, input_json):
        result = {}
        
        for key, value in input_json["match result"].items():
            result[key] = {
                "source code": set(),
                "pseudo code": set()
            }
            
            # 处理源代码
            source_code = key.split("//")[0].strip()
            result[key]["source code"] = self.extract_basic_operations(source_code)
            
            # 处理伪代码
            for pseudo_code in value:
                result[key]["pseudo code"].update(self.extract_basic_operations(pseudo_code))
        
        # 将集合转换为列表用于JSON序列化
        for key in result:
            result[key]["source code"] = list(result[key]["source code"])
            result[key]["pseudo code"] = list(result[key]["pseudo code"])
        
        return result

def main():
    input_json_str = '''{ "match result": { "if (s->method->version == TLS1_2_VERSION && alg2 == (SSL_HANDSHAKE_MAC_DEFAULT|TLS1_PRF)) //patch_code": [ "if ( **(_DWORD **)(a1 + 8) == 771 && *(_DWORD )((_DWORD )((_DWORD *)(a1 + 88) + 836) + 36) == 49200 )" ], "return SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256; //locate_code": [ "v2 = 131200;" ], "return alg2; //locate_code": [ "v2 = *(_DWORD )((_DWORD )((_DWORD *)(a1 + 88) + 836) + 36);", "return v2;" ] }, "corresponding pseudo code": "" }'''
    
    input_json = json.loads(input_json_str)
    analyzer = CodeAnalyzer()
    result = analyzer.process_match_result(input_json)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()