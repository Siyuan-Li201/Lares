

key_word=['auto','break','case','char','const','continue','default','do',
              'double','else','enum','extern','float','for','goto','if',
              'int','long','register','return','short','signed','sizeof','static',
              'struct','switch','typedef','union','unsigned','void','volatile','while']


def extract_conditions_pseudo(lexer_output):
# 将输入转换为token列表
    tokens = []
    for line in lexer_output:
        if line.strip():
            token, token_type = line.strip().split('\t')
            tokens.append((token, token_type))
    
    conditions = []
    i = 0
    while i < len(tokens):
        token, token_type = tokens[i]
        
        # 检查是否是条件关键字
        if token in ['if', 'while', 'switch', 'for']:
            # 找到左括号
            while i < len(tokens) and tokens[i][0] != '(':
                i += 1
            if i >= len(tokens):
                break
                
            # 提取括号内的条件
            condition = []
            parentheses_count = 1
            i += 1  # 跳过左括号
            
            while i < len(tokens) and parentheses_count > 0:
                current_token = tokens[i][0]
                if current_token == '(':
                    parentheses_count += 1
                elif current_token == ')':
                    parentheses_count -= 1
                    if parentheses_count == 0:
                        break
                condition.append(current_token)
                i += 1
                
            # 将条件字符串按照逻辑运算符分割
            condition_str = ' '.join(condition)
            sub_conditions = split_logical_conditions_pseudo(condition_str)
            conditions.extend(sub_conditions)
            
        # 检查case语句
        elif token == 'case':
            case_condition = []
            i += 1
            while i < len(tokens) and tokens[i][0] != ':':
                case_condition.append(tokens[i][0])
                i += 1
            if case_condition:
                conditions.append(' '.join(case_condition))
        
        i += 1
    
    return conditions



def extract_conditions(lexer_output):
    # 将输入转换为token列表
    tokens = []
    for line in lexer_output:
        if line.strip():
            token, token_type = line.strip().split('\t')
            tokens.append((token, token_type))
    
    conditions = []
    i = 0
    while i < len(tokens):
        token, token_type = tokens[i]
        
        # 检查是否是条件关键字
        if token in ['if', 'while', 'switch', 'for']:
            # 找到左括号
            while i < len(tokens) and tokens[i][0] != '(':
                i += 1
            if i >= len(tokens):
                break
                
            # 提取括号内的条件
            condition = []
            parentheses_count = 1
            i += 1  # 跳过左括号
            
            while i < len(tokens) and parentheses_count > 0:
                current_token = tokens[i][0]
                if current_token == '(':
                    parentheses_count += 1
                elif current_token == ')':
                    parentheses_count -= 1
                    if parentheses_count == 0:
                        break
                condition.append(current_token)
                i += 1
                
            # 将条件字符串按照逻辑运算符分割
            condition_str = ' '.join(condition)
            sub_conditions = split_logical_conditions(condition_str)
            conditions.extend(sub_conditions)
            
        # 检查case语句
        elif token == 'case':
            case_condition = []
            i += 1
            while i < len(tokens) and tokens[i][0] != ':':
                case_condition.append(tokens[i][0])
                i += 1
            if case_condition:
                conditions.append(' '.join(case_condition))
        
        i += 1
    
    return conditions

def split_logical_conditions_pseudo(condition_str):
    """将条件字符串按照逻辑运算符（&& 和 ||）分割"""
    # 首先按照 || 分割
    or_parts = condition_str.split('|')
    sub_conditions = []
    
    # 然后对每个部分按照 && 分割
    for or_part in or_parts:
        and_parts = or_part.split('&')
        for part in and_parts:
            # 清理空白字符并添加到结果列表
            cleaned_part = ' '.join(part.split())
            if cleaned_part:
                sub_conditions.append(cleaned_part)
    
    return sub_conditions


def split_logical_conditions(condition_str):
    """将条件字符串按照逻辑运算符（&& 和 ||）分割"""
    # 首先按照 || 分割
    or_parts = condition_str.split('||')
    sub_conditions = []
    
    # 然后对每个部分按照 && 分割
    for or_part in or_parts:
        and_parts = or_part.split('&&')
        for part in and_parts:
            # 清理空白字符并添加到结果列表
            cleaned_part = ' '.join(part.split())
            if cleaned_part:
                sub_conditions.append(cleaned_part)
    
    return sub_conditions


def normalize_condition(condition):
    def is_complex_expr(expr):
        complex_indicators = ['*', '->', '.', '[', ']', '(']
        return any(indicator in expr for indicator in complex_indicators)

    def is_function_call(i, words):
        return i + 1 < len(words) and (words[i].isidentifier() or (len(words[i])>1 and words[i][1:].isidentifier())) and words[i+1].startswith('(')

    words = condition.split()
    normalized = []
    var_map = {}
    var_counter = 1

    i = 0
    while i < len(words):
        # 检查是否是return语句
        if words[i] == 'return':
            normalized.append('return =')
            i += 1
            continue
            
        # 检查是否是函数调用
        if is_function_call(i, words):
            current_expr = []
            bracket_count = 0
            while i < len(words):
                current_expr.append(words[i])
                if '(' in words[i]:
                    bracket_count += words[i].count('(')
                if ')' in words[i]:
                    bracket_count -= words[i].count(')')
                if bracket_count == 0 and len(current_expr) > 1:
                    break
                i += 1
            
            expr = ' '.join(current_expr)
            if expr not in var_map:
                var_map[expr] = f'x{var_counter}'
                var_counter += 1
            normalized.append(var_map[expr])
            i += 1
            continue

        current_expr = []
        while i < len(words) and (is_complex_expr(words[i]) or (current_expr and words[i] not in ['==', '!=', '>', '<', '>=', '<=', '^', '|', '&'])):
            current_expr.append(words[i])
            i += 1
            
        if current_expr:
            expr = ' '.join(current_expr)
            if expr not in var_map:
                var_map[expr] = f'x{var_counter}'
                var_counter += 1
            normalized.append(var_map[expr])
        else:
            if (words[i].isidentifier() or (len(words[i])>1 and words[i][0] != "0" and words[i][1:].isidentifier())) and not words[i] in ['if', 'while', 'for', 'switch', 'NULL', "null", "None", "none"]:
                if words[i] not in var_map:
                    var_map[words[i]] = f'x{var_counter}'
                    var_counter += 1
                normalized.append(var_map[words[i]])
            else:
                normalized.append(words[i])
            i += 1

    return ' '.join(normalized)

# def normalize_condition(condition):
#         # Helper function to identify complex expressions
#         def is_complex_expr(expr):
#             complex_indicators = ['*', '->', '.', '[', ']', '(']
#             return any(indicator in expr for indicator in complex_indicators)

#         words = condition.split()
#         normalized = []
#         var_map = {}
#         var_counter = 1

#         i = 0
#         while i < len(words):
#             current_expr = []
            
#             # Collect complex expression
#             while i < len(words) and (is_complex_expr(words[i]) or (current_expr and words[i] not in ['==', '!=', '>', '<', '>=', '<='])):
#                 current_expr.append(words[i])
#                 i += 1
                
#             if current_expr:
#                 expr = ' '.join(current_expr)
#                 if expr not in var_map:
#                     var_map[expr] = f'x{var_counter}'
#                     var_counter += 1
#                 normalized.append(var_map[expr])
#             else:
#                 if words[i].isidentifier() and not words[i] in ['if', 'while', 'for', 'switch']:
#                     if words[i] not in var_map:
#                         var_map[words[i]] = f'x{var_counter}'
#                         var_counter += 1
#                     normalized.append(var_map[words[i]])
#                 else:
#                     normalized.append(words[i])
#                 i += 1

#         return ' '.join(normalized)

def extract_assignments(lexer_output):
    # 将输入按行分割
    lines = lexer_output
    
    # 存储所有标记
    tokens = []
    for line in lines:
        if line.strip():  # 忽略空行
            token, token_type = line.strip().split('\t')
            tokens.append((token, token_type))
    
    # 存储找到的赋值语句
    assignments = []
    current_assignment = []
    in_assignment = False
    
    # 遍历所有标记
    for i in range(len(tokens)):
        token, token_type = tokens[i]
        
        # 检测赋值语句的开始（标识符后面跟着等号）
        if token_type == '<IDN>' and i + 1 < len(tokens) and tokens[i+1][0] == '=':
            in_assignment = True
            current_assignment = [token]  # 存储左侧变量
            
        # 如果在赋值语句中，继续收集标记
        elif in_assignment:
            current_assignment.append(token)
            
            # 检测赋值语句的结束（遇到分号）
            if token == ';':
                assignments.append(' '.join(current_assignment))
                current_assignment = []
                in_assignment = False
    
    return assignments


# 2. 提取return语句的代码：

def extract_return_statements(lexer_output):
    # 将输入按行分割
    lines = lexer_output
    
    # 存储所有标记
    tokens = []
    for line in lines:
        if line.strip():  # 忽略空行
            token, token_type = line.strip().split('\t')
            tokens.append((token, token_type))
    
    # 存储找到的return语句
    return_statements = []
    current_statement = []
    in_return = False
    
    # 遍历所有标记
    for i in range(len(tokens)):
        token, token_type = tokens[i]
        
        # 检测return语句的开始
        if token == 'return' and token_type == '<KW>':
            in_return = True
            current_statement = [token]
            
        # 如果在return语句中，继续收集标记
        elif in_return:
            current_statement.append(token)
            
            # 检测return语句的结束（遇到分号）
            if token == ';':
                return_statements.append(' '.join(current_statement))
                current_statement = []
                in_return = False
    
    return return_statements


def extract_function_calls(lexer_output):
    # 解析词法分析输出为token列表
    tokens = []
    for line in lexer_output:
        if line.strip():
            token, token_type = line.strip().split('\t')
            tokens.append((token, token_type))

    function_calls = []
    i = 0
    while i < len(tokens):
        # 寻找函数调用(标识符后跟左括号)
        if tokens[i][1] == '<IDN>' and tokens[i][0] not in key_word and i + 1 < len(tokens) and tokens[i+1][0] == '(':
            func_name = tokens[i][0]
            params = []
            current_param = []
            bracket_count = 0
            i += 2  # 跳过左括号
            
            # 收集参数直到匹配的右括号
            while i < len(tokens):
                token, token_type = tokens[i]
                
                if token == '(':
                    bracket_count += 1
                    current_param.append(token)
                elif token == ')':
                    if bracket_count == 0:
                        if current_param:
                            params.append(' '.join(current_param))
                        break
                    bracket_count -= 1
                    current_param.append(token)
                elif token == ',' and bracket_count == 0:
                    if current_param:
                        params.append(' '.join(current_param))
                    current_param = []
                else:
                    current_param.append(token)
                i += 1
                
            # 记录函数调用信息
            function_calls.append({
                'name': func_name,
                'parameters': params
            })
        i += 1
        
    return function_calls

# 输入的词法分析结果
lexer_output = """
ssl3_send_alert	<IDN>
(	<SE>
s	<IDN>
,	<SE>
SSL3_AL_FATAL	<IDN>
,	<SE>
SSL_AD_UNEXPECTED_MESSAGE	<IDN>
)	<SE>
"""

def extract_statements_pseudo(lexer_output):

    statements = {
        "conditions": [],
        "assignments": [],
        "return": [],
        "calls": []
    }

    conditions = extract_conditions_pseudo(lexer_output)
    # print("Extracted conditions:")
    for i, condition in enumerate(conditions, 1):
        nc = normalize_condition(condition)
        # print(f"{i}. {condition}")
        # print(f"{i}. {nc}")
        statements["conditions"].append(nc.strip(";"))

    conditions = extract_assignments(lexer_output)
    # print("Extracted assignments:")
    for i, condition in enumerate(conditions, 1):
        nc = normalize_condition(condition)
        # print(f"{i}. {condition}")
        # print(f"{i}. {nc}")
        statements["assignments"].append(nc.strip(";"))
        
    conditions = extract_return_statements(lexer_output)
    # print("Extracted return:")
    for i, condition in enumerate(conditions, 1):
        nc = normalize_condition(condition)
        # print(f"{i}. {condition}")
        # print(f"{i}. {nc}")
        statements["return"].append(nc.strip(";"))

    call_conditions = extract_function_calls(lexer_output)
    # print("Extracted call:")
    i = 0
    for condition in call_conditions:
        if "parameters" in condition:
            for papamiter_item in condition["parameters"]:
                i += 1
                # print(f"{i}. {papamiter_item}")
                nc = normalize_condition(papamiter_item)
                # print(f"{i}. {condition}")
                # print(f"{i}. {nc}")
                statements["calls"].append(nc.strip(";"))
    
    return statements



def extract_statements(lexer_output):

    statements = {
        "conditions": [],
        "assignments": [],
        "return": [],
        "calls": []
    }

    conditions = extract_conditions(lexer_output)
    # print("Extracted conditions:")
    for i, condition in enumerate(conditions, 1):
        nc = normalize_condition(condition)
        # print(f"{i}. {condition}")
        # print(f"{i}. {nc}")
        statements["conditions"].append(nc.strip(";"))

    conditions = extract_assignments(lexer_output)
    # print("Extracted assignments:")
    for i, condition in enumerate(conditions, 1):
        nc = normalize_condition(condition)
        # print(f"{i}. {condition}")
        # print(f"{i}. {nc}")
        statements["assignments"].append(nc.strip(";"))
        
    conditions = extract_return_statements(lexer_output)
    # print("Extracted return:")
    for i, condition in enumerate(conditions, 1):
        nc = normalize_condition(condition)
        # print(f"{i}. {condition}")
        # print(f"{i}. {nc}")
        statements["return"].append(nc.strip(";"))

    call_conditions = extract_function_calls(lexer_output)
    # print("Extracted call:")
    i = 0
    for condition in call_conditions:
        if "parameters" in condition:
            for papamiter_item in condition["parameters"]:
                i += 1
                # print(f"{i}. {papamiter_item}")
                nc = normalize_condition(papamiter_item)
                # print(f"{i}. {condition}")
                # print(f"{i}. {nc}")
                statements["calls"].append(nc.strip(";"))
    
    return statements


# 测试代码
if __name__ == "__main__":
    statements = extract_statements(lexer_output)
    print(statements)