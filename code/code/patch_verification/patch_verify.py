import difflib


def are_line_numbers_ascending(match_dict):
    """
    判断match_dict中每个成员的line_number是否从小到大排列。

    Args:
        match_dict (dict): 字典，键为匹配内容，值为匹配结果字典。
                           每个匹配结果字典应包含 'line_number' 键。

    Returns:
        bool: 如果所有的line_number按从小到大排列，返回True；否则，返回False。
    """
    # 提取所有line_number，保持match_dict的键的顺序
    line_numbers = [match['line_number'] for key, match in match_dict.items()]

    # 检查line_numbers是否按从小到大排序（严格递增）
    return all(earlier < later for earlier, later in zip(line_numbers, line_numbers[1:]))


def calculate_similarity(a, b):
    """
    计算两个字符串的相似度，返回0到1之间的浮点数。
    """
    return difflib.SequenceMatcher(None, a, b).ratio()

def str_fuzzy_match(str1, str2, threshold=0.8):
    similarity = calculate_similarity(str1, str2)
    if similarity >= threshold:
        return True
    return False


def generate_code_dicts(dict1, sourcefile, pseudofile):
    """
    该函数接收一个字典 dict1，其中每个 key 是 sourcecode.c 的源码行，
    每个 value 包含对应的伪代码行信息。函数生成两个新的字典：
    source_dict 和 pseudo_dict。
    
    Parameters:
    - dict1 (dict): 输入的 JSON 字典。
    - sourcefile (str): sourcecode.c 文件的路径。
    - pseudofile (str): pseudocode.c 文件的路径。
    
    Returns:
    - source_dict (dict): 包含源代码两两组合之间插入代码的字典。
    - pseudo_dict (dict): 包含伪代码两两组合之间插入代码的字典。
    """
    
    # 读取 sourcecode.c 文件
    try:
        with open(sourcefile, 'r', encoding='utf-8') as f:
            source_lines = f.readlines()
    except FileNotFoundError:
        print(f"错误: 无法找到文件 {sourcefile}")
        return {}, {}
    
    # 读取 pseudocode.c 文件
    try:
        with open(pseudofile, 'r', encoding='utf-8') as f:
            pseudocode_lines = f.readlines()
    except FileNotFoundError:
        print(f"错误: 无法找到文件 {pseudofile}")
        return {}, {}
    
    # 创建 source_dict
    source_dict = {}
    source_line_order = []
    
    # 定位 source_line 在 sourcecode.c 文件中的行号
    for source_line in dict1.keys():
        if "  // patch line" not in source_line:
            search_pattern = source_line + "  // patch line"
        else:
            search_pattern = source_line
        found = False
        for idx, line in enumerate(source_lines, start=1):
            if str_fuzzy_match(search_pattern, line) and "  // patch line" in line:
                source_line_order.append((source_line, idx))
                found = True
                break
        if not found:
            print(f"警告: 在 {sourcefile} 中未找到行 '{search_pattern}'")
    
    # 按照行号排序
    source_line_order.sort(key=lambda x: x[1])
    
    # 生成两两组合并提取插入代码
    for i in range(len(source_line_order) - 1):
        line1, num1 = source_line_order[i]
        line2, num2 = source_line_order[i + 1]
        key = f"line{i+1}_{i+2}"
        if num2 > num1 + 1:
            insert_code = ''.join(source_lines[num1:num2-1])
        else:
            insert_code = ''  # 两行相邻，无插入代码
        source_dict[key] = insert_code.strip()
    
    # 创建 pseudo_dict
    pseudo_dict = {}
    pseudo_entries = []
    
    # 提取 pseudo_line 和对应的 line_number
    for source_line, details in dict1.items():
        pseudo_line = details.get("code_line", "")
        line_number = details.get("line_number", 0)
        if line_number > 0:
            pseudo_entries.append((line_number, pseudo_line))
        else:
            print(f"警告: source_line '{source_line}' 缺少有效的 'line_number'")
    
    # 按照 line_number 排序
    pseudo_entries.sort(key=lambda x: x[0])
    
    # 生成两两组合并提取插入代码
    for i in range(len(pseudo_entries) - 1):
        num1, _ = pseudo_entries[i]
        num2, _ = pseudo_entries[i + 1]
        key = f"line{i+1}_{i+2}"
        if num2 > num1 + 1:
            insert_code = ''.join(pseudocode_lines[num1:num2-1])
        else:
            insert_code = ''  # 两行相邻，无插入代码
        pseudo_dict[key] = insert_code.strip()
    
    return source_dict, pseudo_dict



def remove_comments(code):
        import re
        # Remove single-line comments
        code = re.sub(r'//.*', '', code)
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        return code

def parse_block(code, index):
    # Assumes code[index] == '{'
    brace_stack = []
    brace_stack.append('{')
    index += 1
    length = len(code)
    while index < length and brace_stack:
        c = code[index]
        if c == '{':
            brace_stack.append('{')
        elif c == '}':
            brace_stack.pop()
        elif c == '"' or c == "'":
            # Skip strings and character literals
            quote_char = c
            index +=1
            while index < length:
                if code[index] == '\\':
                    index +=2
                elif code[index] == quote_char:
                    index +=1
                    break
                else:
                    index +=1
            continue
        index +=1
    return index, not brace_stack  # returns new index, True if braces matched

def parse_control_statement(code, index):
    length = len(code)
    # Skip the control statement keyword
    while index < length and code[index].isalnum():
        index +=1
    # Skip whitespace
    while index < length and code[index].isspace():
        index +=1
    # If there is a '(', skip the condition
    if index < length and code[index] == '(':
        paren_count = 1
        index +=1
        while index < length and paren_count > 0:
            if code[index] == '(':
                paren_count +=1
            elif code[index] == ')':
                paren_count -=1
            elif code[index] == '"' or code[index] == "'":
                # Skip strings and character literals
                quote_char = code[index]
                index +=1
                while index < length:
                    if code[index] == '\\':
                        index +=2
                    elif code[index] == quote_char:
                        index +=1
                        break
                    else:
                        index +=1
                continue
            index +=1
    # Skip whitespace
    while index < length and code[index].isspace():
        index +=1
    # Now, check if there is a '{' starting a block
    if index < length and code[index] == '{':
        # Parse the block
        start_index = index
        index, matched = parse_block(code, index)
        return index, matched
    else:
        # No block, just a single statement
        # We can skip to the next ';'
        while index < length and code[index] != ';' and code[index] != '\n':
            index +=1
        if index < length and code[index] == ';':
            index +=1
        return index, True  # No unmatched braces

def process_code(code):
    code = remove_comments(code)
    index = 0
    length = len(code)
    count_unclosed = 0
    while index < length:
        # Skip whitespace
        while index < length and code[index].isspace():
            index +=1
        # Check for control statements
        found_stmt = False
        for stmt in ['if', 'for', 'switch', 'case', 'while', 'else', 'do']:
            stmt_len = len(stmt)
            if code.startswith(stmt, index) and (index + stmt_len == length or not code[index + stmt_len].isalnum() and code[index + stmt_len] != '_'):
                found_stmt = True
                index, matched = parse_control_statement(code, index)
                if not matched:
                    count_unclosed +=1
                break
        if not found_stmt:
            # Not a control statement, move to next character
            index +=1
    return count_unclosed

def match_insert_code(source_code, pseudo_code):
    count_source = process_code(source_code)
    count_pseudo = process_code(pseudo_code)
    return count_source == count_pseudo


def patch_insert_verify(source_dict, pseudo_dict):

    for key, source_code in source_dict.items():
        pseudo_code = pseudo_dict.get(key, "")
        if match_insert_code(source_code, pseudo_code) == False:
            # print(f"错误: 源代码和伪代码的插入代码不匹配。")
            # print(f"源代码插入代码：\n{source_code}")
            # print(f"伪代码插入代码：\n{pseudo_code}")
            return False

    return True


def patch_verify(matched_dict, sourcefile, pseudofile):

    if are_line_numbers_ascending(matched_dict) == False:
        return False, None

    source_dict, pseudo_dict = generate_code_dicts(matched_dict, sourcefile, pseudofile)

    if patch_insert_verify(source_dict, pseudo_dict) == False:
        return False, None
    # print(source_dict)
    # print(pseudo_dict)

    return True, matched_dict