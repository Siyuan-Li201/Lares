import sys
import json
import re
import os

def parse_patch(patch_file_path):
    with open(patch_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    functions_dict = {}
    current_file = ''
    file_version_tags = {}
    vuln_version_tag = ''
    patch_version_tag = ''

    # 正则表达式模式
    index_pattern = re.compile(r'^index\s+([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)')
    hunk_header_pattern = re.compile(r'^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@(.*)')

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('index '):
            # 提取版本标签
            m = index_pattern.match(line)
            if m:
                vuln_version_tag = m.group(1).strip()
                patch_version_tag = m.group(2).strip()
            i += 1
            continue
        elif line.startswith('+++ '):
            # 修改后的文件路径
            m = re.match(r'^\+\+\+\s+(.*)', line)
            if m:
                new_file = m.group(1).strip()
                current_file = new_file
                # 如果当前文件没有版本标签，使用最后一次提取的版本标签
                file_version_tags[current_file] = {
                    'vuln_version_tag': vuln_version_tag,
                    'patch_version_tag': patch_version_tag
                }
            i += 1
            continue
        elif line.startswith('@@'):
            # 匹配补丁块头部
            m = hunk_header_pattern.match(line)
            if m:
                # 提取行号和函数名
                left_start_line = int(m.group(1))
                left_line_count = m.group(2)
                left_line_count = int(left_line_count) if left_line_count else 1

                right_start_line = int(m.group(3))
                right_line_count = m.group(4)
                right_line_count = int(right_line_count) if right_line_count else 1

                func_context = m.group(5).strip()
                function_name = extract_function_name(func_context, lines, i)
                if not function_name:
                    function_name = 'unknown_function'

                # 生成函数唯一键
                function_key = f"{current_file}:{function_name}"

                # 初始化函数信息
                if function_key not in functions_dict:
                    functions_dict[function_key] = {
                        'function_name': function_name,
                        'file_name': current_file,
                        'vuln_version_tag': file_version_tags.get(current_file, {}).get('vuln_version_tag', ''),
                        'patch_version_tag': file_version_tags.get(current_file, {}).get('patch_version_tag', ''),
                        'added_code': {},
                        'deleted_code': {},
                        'patch_type': 'unknown'
                    }
                left_line_num = left_start_line
                right_line_num = right_start_line

                # 处理补丁块中的内容
                i += 1
                while i < len(lines) and not lines[i].startswith('@@') and not lines[i].startswith('diff '):
                    hunk_line = lines[i]
                    if hunk_line.startswith('-'):
                        # 删除的代码
                        line_content = hunk_line[1:].rstrip('\n')
                        functions_dict[function_key]['deleted_code'][left_line_num] = line_content
                        left_line_num += 1
                    elif hunk_line.startswith('+'):
                        # 新增的代码
                        line_content = hunk_line[1:].rstrip('\n')
                        functions_dict[function_key]['added_code'][right_line_num] = line_content
                        right_line_num += 1
                    elif hunk_line.startswith(' '):
                        # 未修改的代码
                        left_line_num += 1
                        right_line_num += 1
                    elif hunk_line.startswith('\\'):
                        # 文件末尾无新行，忽略
                        pass
                    else:
                        # 其他情况，通常不应出现
                        pass
                    i += 1
                # 判断补丁类型
                if functions_dict[function_key]['deleted_code'] and functions_dict[function_key]['added_code']:
                    deleted_len = 0
                    added_len = 0
                    if len(functions_dict[function_key]['deleted_code']) > 0:
                        for k in functions_dict[function_key]['deleted_code']:
                            deleted_len += len(functions_dict[function_key]['deleted_code'][k])
                    if len(functions_dict[function_key]['added_code']) > 0:
                        for k in functions_dict[function_key]['added_code']:
                            added_len += len(functions_dict[function_key]['added_code'][k])
                    if added_len >= 5 and deleted_len < 5:
                        functions_dict[function_key]['patch_type'] = 'add'
                    elif added_len < 5 and deleted_len >= 5:
                        functions_dict[function_key]['patch_type'] = 'delete'
                    elif added_len < 5 and deleted_len < 5:
                        functions_dict[function_key]['patch_type'] = 'unknown'
                    else:
                        functions_dict[function_key]['patch_type'] = 'modify'
                elif functions_dict[function_key]['deleted_code']:
                    functions_dict[function_key]['patch_type'] = 'delete'
                elif functions_dict[function_key]['added_code']:
                    functions_dict[function_key]['patch_type'] = 'add'
                else:
                    functions_dict[function_key]['patch_type'] = 'unknown'
                continue
            else:
                # 补丁块头部格式不正确，跳过
                i += 1
                continue
        else:
            # 非补丁块内容，跳过
            i += 1
            continue
    return functions_dict

def extract_function_name(context, lines, current_index):
    """
    从补丁块上下文中提取函数名，如果函数名不在上下文中，则向下扫描补丁内容寻找函数声明。
    """
    # 尝试从 context 中提取函数名
    function_name_pattern = re.compile(r'(\w+)\s*\(')
    m = function_name_pattern.search(context)
    if m:
        return m.group(1)
    
    # 如果 context 中没有找到函数名，则向下扫描补丁内容寻找函数声明
    for i in range(current_index + 1, len(lines)):
        line = lines[i]
        if line.startswith('+') or line.startswith('-') or line.startswith(' '):
            # 提取函数声明
            line_content = line[1:].strip()
            m = function_name_pattern.search(line_content)
            if m:
                return m.group(1)
        elif line.startswith('@@') or line.startswith('diff '):
            # 到达下一个补丁块或文件时停止扫描
            break
    return 'unknown_function'

def save_json(data, res_path):
    # 创建保存结果的目录（如果不存在）
    os.makedirs(os.path.dirname(res_path), exist_ok=True)
    with open(res_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def main():
    # if len(sys.argv) != 3:
    #     print("用法: python script.py 补丁文件路径 结果保存路径")
    #     sys.exit(1)
    # patch_file_path = sys.argv[1]
    # res_path = sys.argv[2]


    patch_file_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/dataset/patch/test_patch.diff"
    res_path = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/code/get_patch_function/res/result.json"

    parsed_data = parse_patch(patch_file_path)
    save_json(parsed_data, res_path)
    print(f"解析完成，结果已保存到 {res_path}")

if __name__ == "__main__":
    main()