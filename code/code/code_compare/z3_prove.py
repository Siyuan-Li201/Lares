from z3 import *


def check_equivalence(expr_str1, expr_str2):
    # 创建变量字典
    vars_dict = {}
    
    # 处理括号平衡
    def balance_parentheses(expr):
        left_count = expr.count('(')
        right_count = expr.count(')')
        if left_count > right_count:
            expr = expr + ')' * (left_count - right_count)
        elif right_count > left_count:
            expr = '(' * (right_count - left_count) + expr

        if "==" not in expr and "=" in expr and expr[expr.index("=") - 1] not in ["!", ">", "<", "|", "&", "^"]:
            expr = expr.replace("=", "==")
 
        if "!" in expr and expr[expr.index("!") + 1] != "=":
            expr = expr.replace("!", "")

        find_op_item = False
        op_list = ["=", ">", "<"]
        for op_item in op_list:
            if op_item in expr:
                find_op_item = True
                break
        if not find_op_item:
            expr = expr + "==0"
        
        if "NULL" in expr:
            expr = expr.replace("NULL", "0")

        if "null" in expr:
            expr = expr.replace("null", "0")

        if "return" in expr:
            expr = expr.replace("return", "return_")

        return expr
    
    # 处理十六进制数
    def process_hex_numbers(expr):
        import re
        # 匹配16进制数
        pattern = r'0x[0-9a-fA-F]+'
        def hex_replace(match):
            return str(int(match.group(0), 16))
        return re.sub(pattern, hex_replace, expr)
    
    # 解析表达式中的变量
    def get_variables(expr_str):
        import re
        # 匹配x开头的变量
        x_vars = re.findall(r'(?<![\w\d])x\d+', expr_str)
        # 匹配其他合法变量名（字母开头，可包含数字和下划线）
        other_vars = re.findall(r'(?<![\w\d])[a-wyz][a-zA-Z0-9_]*', expr_str)
        return sorted(list(set(x_vars + other_vars)))
    
    # 预处理表达式
    expr_str1 = balance_parentheses(process_hex_numbers(expr_str1))
    expr_str2 = balance_parentheses(process_hex_numbers(expr_str2))
    
    # 获取两个表达式中的所有变量
    all_vars = sorted(list(set(get_variables(expr_str1) + get_variables(expr_str2))))
    
    # 为每个变量创建BitVec
    for var in all_vars:
        vars_dict[var] = BitVec(var, 64)
    
    # 将字符串表达式转换为z3表达式
    def str_to_z3_expr(expr_str):
        # 创建局部的变量空间
        local_dict = vars_dict.copy()
        return eval(expr_str, {"vars_dict": vars_dict}, local_dict)
    
    try:
        # 转换两个表达式
        expr1 = str_to_z3_expr(expr_str1)
        expr2 = str_to_z3_expr(expr_str2)
        
        # 检查等价性
        s = Solver()
        s.add(Not(expr1 == expr2))

        s2 = Solver()
        s2.add(expr1 == expr2)
        
        if s.check() == unsat or s2.check() == unsat:
            return True, "Expressions are equivalent"
        else:
            model = s.model()
            counter_example = {str(d): model[d] for d in model}
            return False, f"Expressions are not equivalent. Counter-example: {counter_example}"
    except Exception as e:
        return False, f"Error processing expressions: {str(e)}"

# def check_equivalence(expr_str1, expr_str2):
#     # 创建变量字典
#     vars_dict = {}
    
#     # 解析表达式中的变量
#     def get_variables(expr_str):
#         import re
#         return sorted(list(set(re.findall(r'x\d+', expr_str))))
    
#     # 获取两个表达式中的所有变量
#     all_vars = sorted(list(set(get_variables(expr_str1) + get_variables(expr_str2))))
    
#     # 为每个变量创建BitVec
#     for var in all_vars:
#         vars_dict[var] = BitVec(var, 64)
    
#     # 将字符串表达式转换为z3表达式
#     def str_to_z3_expr(expr_str):
#         # 创建局部的变量空间
#         local_dict = vars_dict.copy()
        
#         # 处理十六进制数
#         parts = expr_str.split()
#         for i in range(len(parts)):
#             if '0x' in parts[i]:
#                 parts[i] = str(int(parts[i], 16))
#         expr_str = ' '.join(parts)
        
#         # 执行表达式
#         return eval(expr_str, {"vars_dict": vars_dict}, local_dict)
    
#     try:
#         # 转换两个表达式
#         expr1 = str_to_z3_expr(expr_str1)
#         expr2 = str_to_z3_expr(expr_str2)
        
#         # 检查等价性
#         s = Solver()
#         s.add(Not(expr1 == expr2))

#         s2 = Solver()
#         s2.add(expr1 == expr2)
        
#         if s.check() == unsat or s2.check() == unsat:
#             return True, "Expressions are equivalent"
#         else:
#             model = s.model()
#             counter_example = {str(d): model[d] for d in model}
#             return False, f"Expressions are not equivalent. Counter-example: {counter_example}"
#     except Exception as e:
#         return False, f"Error processing expressions: {str(e)}"

# 测试代码
if __name__ == "__main__":
    # 测试用例
    test_cases = [
        ("x1 == 0x0303", "x1 ^ 0x303 != 0"),
        ("x1 + x2 == 0x10", "x2 + x1 == 0x10"),
        ("x1 & x2 == 0", "x1 | x2 == 0xf"),
        ("x1 == x2 | 0x10 )", "x1 == x2 | 0x10"),
        ("return == x1 | x2", "return == x1 | x2"),
        ("x1", "x1"),
        ("x1 == NULL", "x2 == 0"),
        ("!x1", "x1 == 0"),
        ("x1 != 0", "x1 == 0"),
        ("x1 >= 771", "x1<771"),
        ("x1 >= 771", "x1<=770"),
    ]
    
    for expr1, expr2 in test_cases:
        result, message = check_equivalence(expr1, expr2)
        print(f"\nTesting: {expr1} vs {expr2}")
        print(f"Result: {result}")
        print(f"Message: {message}")