import http.client
import json
import time
import os
import copy
import sys

sys.path.append("code/code/code_compare")
sys.path.append("code")

import lexer_analysis
import settings

def source_slice_old(source_code):
    def find_patch_line_index(lines):
        """Find the index of the first line ending with '  //patch_code'."""
        for i, line in enumerate(lines):
            if line.strip().endswith('  //patch_code'):
                return i
        return -1

    def find_closure_points(lines, start_index, end_index, reverse=False):
        """Track the nesting of braces and find optimal or suboptimal closure points."""
        brace_stack = []
        closure_points = []

        line_range = range(start_index, end_index + 1) if not reverse else range(start_index, end_index - 1, -1)

        for i in line_range:
            line = lines[i]
            for char in line:
                if char == '{':
                    brace_stack.append(i)
                elif char == '}':
                    if brace_stack:
                        open_line = brace_stack.pop()
                        if not brace_stack:  # If stack is empty, it's a complete closure
                            closure_points.append(open_line if not reverse else i)

        return closure_points

    def find_best_cut(closure_points, patch_index, lower_bound, upper_bound):
        """Select the best cut point from closure points within the range."""
        best_point = -1
        for point in closure_points:
            if lower_bound <= point <= upper_bound:
                best_point = point
                break
        return best_point

    # Split source code into lines
    lines = source_code.splitlines()
    patch_line_index = find_patch_line_index(lines)

    if patch_line_index == -1:
        return "Patch line not found."

    total_lines = len(lines)

    # Define search ranges for forward and backward cuts
    forward_search_end = min(patch_line_index + 200, total_lines - 1)
    backward_search_start = max(patch_line_index - 200, 0)

    # Find closure points
    forward_closure_points = find_closure_points(lines, patch_line_index + 1, forward_search_end)
    backward_closure_points = find_closure_points(lines, patch_line_index - 1, backward_search_start, reverse=True)

    # Define cutting bounds
    forward_best_cut = find_best_cut(forward_closure_points, patch_line_index, patch_line_index + 100, forward_search_end)
    backward_best_cut = find_best_cut(backward_closure_points, patch_line_index, backward_search_start, patch_line_index - 100)

    # Default to 100 line cuts if no optimal closure point found
    if forward_best_cut == -1:
        forward_best_cut = min(patch_line_index + 100, total_lines - 1)

    if backward_best_cut == -1:
        backward_best_cut = max(patch_line_index - 100, 0)

    # Final sliced code
    slice_code = "\n".join(lines[backward_best_cut:patch_line_index + 1] + lines[patch_line_index + 1:forward_best_cut + 1])
    return slice_code


def pseudo_slice_old(code_str):
    # 切割后的代码块列表
    code_sliced = []
    # 记录每一行的起始位置，便于行数计算
    code_lines = code_str.splitlines()
    line_start_indices = [0]
    for line in code_lines:
        line_start_indices.append(line_start_indices[-1] + len(line) + 1)
    
    def get_line_number(index):
        """根据字符索引获取行号"""
        for i, start in enumerate(line_start_indices):
            if index < start:
                return i
        return len(line_start_indices) - 1

    def find_closure_points(code):
        """找到所有闭合点及其行号"""
        balance = 0
        closure_points = []
        for i, char in enumerate(code):
            if char == '{':
                balance += 1
            elif char == '}' and balance > 0:
                balance -= 1
            if char == '}' and balance <= 0:
                line_num = get_line_number(i)
                closure_points.append((i, line_num))
            if balance == 0:
                line_num = get_line_number(i)
                closure_points.append((i, line_num))
        return closure_points

    def slice_code(code, start_line):
        """递归切割代码直到满足行数条件"""
        closure_points = find_closure_points(code)
        if not closure_points:
            return
        
        for i, (index, line) in enumerate(closure_points):
            if line - start_line > 400:
                # 找到最优闭合点
                if i > 0 and closure_points[i - 1][1] - start_line > 200:
                    # 在上一个闭合点切割
                    code_sliced.append(code[:closure_points[i - 1][0] + 1])
                    slice_code(code[closure_points[i - 1][0] + 1:], closure_points[i - 1][1] + 1)
                else:
                    # 递归去掉最外层的 '{' 并寻找下一个次优闭合点
                    now_brace_index = code.find('{')
                    if now_brace_index == -1:
                        code_sliced.append(code[:400])
                        slice_code(code[400:], get_line_number(first_brace_index))
                    else:
                        inner_code = code[now_brace_index+1:-1]
                        slice_code(inner_code, start_line)
                return
        
        # 如果没有超过400行的闭合点，直接在最后的闭合点切割
        code_sliced.append(code[:closure_points[-1][0] + 1])

    # 从第一个 '{' 开始处理代码
    first_brace_index = code_str.find('{')
    if first_brace_index >= 0 and get_line_number(first_brace_index) < 400:
        slice_code(code_str[first_brace_index:], 0)
        code_sliced[0] = code_str[:first_brace_index] + code_sliced[0]
    elif get_line_number(first_brace_index) >= 400:
        code_sliced.append(code_str[:400])
        slice_code(code_str[400:], get_line_number(first_brace_index))
        code_sliced[1] = code_str[400:first_brace_index] + code_sliced[0]
    
    
    return code_sliced


def source_slice(source_code, arg_max_line=400):

    if arg_max_line < 200:
        arg_max_line = 200

    lines = source_code.splitlines()
    idx = None
    for i, line in enumerate(lines):
        if line.strip().endswith("//patch_code"):
            idx = i
            break

    if idx is None:
        # Return empty string if "//patch line" is not found
        return ""

    half_lines = arg_max_line // 2

    if half_lines < 100:
        half_lines = 100

    # Calculate start and end indices, ensuring they are within bounds
    start_idx = max(0, idx - half_lines)
    end_idx = min(len(lines), idx + half_lines + 1)

    # Slice the lines and join them back into a string
    code_sliced = '\n'.join(lines[start_idx:end_idx])

    return code_sliced


def source_slice_V2(source_code, arg_max_line=200, arg_min_line=50):
    source_sliced_list = pseudo_slice_V2(source_code, arg_max_line, arg_min_line)

    for source_sliced in source_sliced_list:
        for source_sliced_line in source_sliced.splitlines():
            if "  //patch_code" in source_sliced_line.strip():
                return source_sliced

def source_slice_rev(source_code, patch_line_number, arg_max_line=200, arg_min_line=50):
    source_sliced_list = pseudo_slice_V2(source_code, arg_max_line, arg_min_line)

    lines = source_code.split('\n')

    # 获取函数起始行
    func_line = 0
    for line in lines:
        if line.startswith('// Function starts at line'):
            func_line = int(line.split()[-1])
            break

    if func_line == 0:
        print("Could not find function start line")
        return []

    target_line = patch_line_number - func_line + 1

    i = 0
    for source_sliced in source_sliced_list:
        for source_sliced_line in source_sliced.splitlines():
            i += 1
            if i == target_line:
                return source_sliced


def pseudo_slice_V2(pseudo_code, arg_max_line=400, arg_min_line=100):
    """
    将C语言代码按照大括号闭合情况和行数限制进行切割和合并。

    参数:
    - pseudo_code (str): 需要切割的C语言代码。
    - arg_max_line (int): 每个代码片段的最大行数。
    - arg_min_line (int): 每个代码片段的最小行数。

    返回:
    - code_sliced_list (list): 切割后的代码片段列表。
    """

    def force_split(code_lines):
        """
        强制切割代码。

        参数:
        - code_lines (list): 代码行列表。

        返回:
        - slices (list): 切割后的代码片段列表。
        """
        slices = []
        for i in range(0, len(code_lines), arg_max_line):
            if len(code_lines[i+arg_max_line:]) >= arg_min_line:
                slices.append(code_lines[i:i+arg_max_line])
            else:
                slices.append(code_lines[i:i+arg_max_line-arg_min_line])
                slices.append(code_lines[i+arg_max_line-arg_min_line:])
                break
        return slices

    def split_by_braces(code_lines):
        """
        根据大括号的闭合情况切割代码。

        参数:
        - code_lines (list): 代码行列表。

        返回:
        - slices (list): 按闭合点切割的代码片段列表。
        """
        slices = []
        brace_stack = []
        last_split = 0

        first_index = -1

        first_find = True
        start_split = False

        for i, line in enumerate(code_lines):
            # 统计每行中的 { 和 }
            if first_find and "{" in line:
                first_index = i
                first_find = False
                continue
            brace_stack.extend([ '{' ] * line.count('{'))
            for _ in range(line.count('}')):
                if brace_stack:
                    brace_stack.pop()
                else:
                    # 多余的 }，可以根据需要处理
                    pass

            # 如果栈为空，表示当前闭合点
            if not brace_stack: # and i + 1 - last_split >= arg_min_line:
                if start_split:
                    slices.append(code_lines[last_split:i+1])
                    last_split = i + 1
                    start_split = False
            elif not start_split:
                start_split = True
                slices.append(code_lines[last_split:i+1])
                last_split = i + 1
        # 添加剩余的代码
        if last_split < len(code_lines):
            slices.append(code_lines[last_split:])

        if len(slices) == 1 and len(slices[0]) > arg_max_line:
            if first_index > -1:
                slices = []
                slices.append(code_lines[:first_index+1])
                slices.append(code_lines[first_index+1:])
            if len(slices) == 1 and len(slices[0]) > arg_max_line:
                slices = force_split(slices[0])

        return slices

    def merge_slices(slices):
        """递归合并函数。"""
        for i in range(len(slices)):
            # 检查与前一片段的合并
            if i > 0:
                merged_length = len(slices[i - 1]) + len(slices[i])
                if merged_length <= arg_max_line or (merged_length <= arg_max_line + 2*arg_min_line and (len(slices[i - 1]) <= arg_min_line or len(slices[i]) <= arg_min_line)):
                    # 合并前后片段
                    merged = slices[i - 1] + slices[i]
                    # 创建新的片段列表
                    new_slices = slices[:i - 1] + [merged] + slices[i + 1:]
                    # 递归调用以检查新的前一段和后一段
                    return merge_slices(new_slices)

            # 检查与后一片段的合并
            if i < len(slices) - 1:
                merged_length = len(slices[i]) + len(slices[i + 1])
                if merged_length <= arg_max_line or (merged_length <= arg_max_line + 2*arg_min_line and (len(slices[i]) <= arg_min_line or len(slices[i + 1]) <= arg_min_line)):
                    # 合并当前片段和后一片段
                    merged = slices[i] + slices[i + 1]
                    # 创建新的片段列表
                    new_slices = slices[:i] + [merged] + slices[i + 2:]
                    # 递归调用以检查新的前一段和后一段
                    return merge_slices(new_slices)

        # 如果没有更多可以合并的片段，返回当前列表
        return slices

    def recursive_slice(code_lines):
        """
        递归切割代码片段。

        参数:
        - code_lines (list): 代码行列表。

        返回:
        - result (list): 切割后的代码片段列表。
        """
        if len(code_lines) <= arg_max_line:
            return ['\n'.join(code_lines)]

        slices = split_by_braces(code_lines)

        result = []
        for slice in slices:
            if len(slice) > arg_max_line:
                # 递归切割
                result.extend(recursive_slice(slice))
            else:
                result.append('\n'.join(slice))

        return result

    # 将源代码按行分割
    code_lines = pseudo_code.split('\n')

    # 初始切割
    initial_slices = recursive_slice(code_lines)

    # 合并小片段
    merged_slices = merge_slices([slice.split('\n') for slice in initial_slices])

    # 将合并后的片段重新连接为字符串
    code_sliced_list = ['\n'.join(slice) for slice in merged_slices]

    return code_sliced_list




def pseudo_slice(pseudo_code, arg_max_line=400):
    # Split the pseudo_code into individual lines
    code_lines = pseudo_code.splitlines()
    
    if arg_max_line < 200:
        arg_max_line = 200 # Ensure the minimum line count is at least 200

    # Calculate the step size for the sliding window
    step = int((3/4) * arg_max_line)
    if step < 100:
        step = 100 # Ensure the step is at least 1 to avoid infinite loops
    
    code_sliced_list = []
    start = 0
    
    while start < len(code_lines):
        # Determine the end index for the current window
        end = min(start + arg_max_line, len(code_lines))
        
        # Slice the code lines and join them back into a string
        slice_lines = code_lines[start:end]
        code_sliced_list.append('\n'.join(slice_lines))
        
        # Move the window by the step size
        start += step
    
    return code_sliced_list



def extract_and_merge_lists(json_data):
    # 获取 "new match result" 下的所有值
    match_results = json_data["new match result"].values()
    
    # 合并所有list并去重
    merged_list = []
    for result in match_results:
        merged_list.extend(result)
    
    # 去重并返回结果
    return list(dict.fromkeys(merged_list))

def get_rev_prompt(number, source_file, pseudo_file, llm_file, patch_line_number, res_file):


    arg_max_line = 400


    """
    Perform LLM detection and replace <pseudo_code_label> and <source_code_label> placeholders
    in 'prompt_templete.txt' with processed source and pseudo code.
    """
    # Load source and pseudo code from files
    with open(source_file, "r", encoding="utf-8") as file:
        source_code = file.read()
    with open(pseudo_file, "r", encoding="utf-8") as file:
        pseudo_code = file.read()

    # Process pseudo code for slicing if needed
    # if len(pseudo_code.splitlines()) > arg_max_line:
    #     pseudo_sliced_list = pseudo_slice_V2(pseudo_code)
    # else:
    #     pseudo_sliced_list = [pseudo_code]

    # Process source code for slicing if needed
    if not os.path.exists(llm_file):
        return False
    json_data = extract_json_from_file(llm_file)

    if json_data is None:
        print("match result not found!!")
        return False
    
    pseudo_slice = extract_and_merge_lists(json_data)

    if not pseudo_slice and len(pseudo_slice) == 0:
        print("match result not found!!")
        return False

    if len(source_code.splitlines()) > arg_max_line:
        source_sliced = source_slice_rev(source_code, patch_line_number)
    else:
        source_sliced = source_code

    with open(os.path.join(res_file, "soruce_sliced.txt"), "w", encoding="utf-8") as f:
            f.write(source_sliced)



    # Load template, replace labels, and save the final result
    with open("prompt_templete_reverse.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["source_file"] = source_file
    detection_res["pseudo_file"] = pseudo_file
    detection_res["source_sliced"] = os.path.join(res_file, "soruce_sliced.txt")
    detection_res["pseudo_sliced"] = pseudo_slice
    detection_res["prompt_list"] = []
    detection_res["llm_res_list"] = []



# llm detection
    prompt_new = copy.deepcopy(prompt_content)

    with open(os.path.join(res_file, "pseudo_sliced_" + number + ".txt"), "w", encoding="utf-8") as f:
        f.write(pseudo_code)
    prompt_new = prompt_new.replace("<pseudo_slice_label>", "\n".join(pseudo_slice))
    prompt_new = prompt_new.replace("<pseudo_code_label>", pseudo_code)
    prompt_new = prompt_new.replace("<source_code_label>", source_sliced)

    with open(os.path.join(res_file, "prompt_" + number + ".txt"), "w", encoding="utf-8") as f:
        f.write(prompt_new)

    retry_llm = 1
    while retry_llm:
        llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "llm_res_" + number + ".txt"))
        if llm_success and "new match result" in llm_result:
            print("llm result: ", llm_result)
            break
        retry_llm += 1
        print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        detection_res["prompt_list"].append(os.path.join(res_file, "prompt_" + number + ".txt"))
        detection_res["llm_res_list"].append(os.path.join(res_file, "llm_res_" + number + ".txt"))

    return detection_res


def swap_key_value(vul_res_data):
    # Get the match result dictionary
    match_dict = vul_res_data.get("new match result", {})
    
    # Create a new dictionary with swapped key-value pairs
    swapped_dict = {v: k for k, v in match_dict.items()}
    
    # Replace original match result with swapped dictionary
    vul_res_data["new match result"] = swapped_dict
    
    return vul_res_data

def get_verification_patch_rev_prompt(patch_res_path, vul_res_path, path_diff_path, res_file, number_item, constant_mappings=False):


    arg_max_line = 400

    if not os.path.exists(patch_res_path):
        print("match result not found!!")
        return False
    patch_res_json = extract_json_from_file(patch_res_path)
    if patch_res_json == None:
        print("match result not found!!")
        return False

    patch_res_json = swap_key_value(patch_res_json)
    patch_res_data = extract_and_merge_lists(patch_res_json)


    if not os.path.exists(vul_res_path):
        print("match result not found!!")
        return False
    vul_res_json = extract_json_from_file(vul_res_path)

    if vul_res_json == None:
        print("match result not found!!")
        return False

    vul_res_data = extract_and_merge_lists(vul_res_json)

    

    if not os.path.exists(path_diff_path):
        print("match result not found!!")
        return False
    with open(path_diff_path, "r", encoding="utf-8") as file:
        path_diff_data = file.read()



    # Load template, replace labels, and save the final result
    with open("prompt_templete_verification.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["patch_res_path"] = patch_res_path
    detection_res["vul_res_path"] = vul_res_path
    detection_res["path_diff_path"] = path_diff_path
    detection_res["prompt_path"] = ""
    detection_res["llm_res"] = ""



# llm detection
    prompt_new = copy.deepcopy(prompt_content)

    prompt_new = prompt_new.replace("<patch_diff_label>", path_diff_data)
    if constant_mappings:
        prompt_new = prompt_new.replace("<comments_label>", "//"+"\n//".join(constant_mappings))
    # prompt_new = prompt_new.replace("<patch_result_json>", "\n".join(patch_res_data))
    # prompt_new = prompt_new.replace("<vul_result_json>", "\n".join(vul_res_data))
    prompt_new = prompt_new.replace("<patch_result_json>", str(patch_res_json))
    prompt_new = prompt_new.replace("<vul_result_json>", str(vul_res_json))

    with open(os.path.join(res_file, "prompt_v_"+number_item+".txt"), "w", encoding="utf-8") as f:
        f.write(prompt_new)

    retry_llm = 1
    while retry_llm:
        llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "llm_vres_"+number_item+".txt"))
        if llm_success and "correct result" in llm_result:
            print("llm result: ", llm_result)
            break
        retry_llm += 1
        print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        detection_res["prompt_path"] = os.path.join(res_file, "prompt.txt")
        detection_res["llm_res"] = llm_result

    return detection_res


def get_verification_vul_rev_prompt(patch_res_path, vul_res_path, path_diff_path, res_file, number_item, constant_mappings=False):


    arg_max_line = 400

    if not os.path.exists(patch_res_path):
        print("match result not found!!")
        return False
    patch_res_json = extract_json_from_file(patch_res_path)
    if patch_res_json == None:
        print("match result not found!!")
        return False

    patch_res_data = extract_and_merge_lists(patch_res_json)

    if not os.path.exists(vul_res_path):
        print("match result not found!!")
        return False
    vul_res_json = extract_json_from_file(vul_res_path)

    if vul_res_json == None:
        print("match result not found!!")
        return False
    vul_res_json = swap_key_value(vul_res_json)

    vul_res_data = extract_and_merge_lists(vul_res_json)

    if not os.path.exists(path_diff_path):
        print("match result not found!!")
        return False
    with open(path_diff_path, "r", encoding="utf-8") as file:
        path_diff_data = file.read()



    # Load template, replace labels, and save the final result
    with open("prompt_templete_verification.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["patch_res_path"] = patch_res_path
    detection_res["vul_res_path"] = vul_res_path
    detection_res["path_diff_path"] = path_diff_path
    detection_res["prompt_path"] = ""
    detection_res["llm_res"] = ""



# llm detection
    prompt_new = copy.deepcopy(prompt_content)

    prompt_new = prompt_new.replace("<patch_diff_label>", path_diff_data)
    if constant_mappings:
        prompt_new = prompt_new.replace("<comments_label>", "//"+"\n//".join(constant_mappings))
    # prompt_new = prompt_new.replace("<patch_result_json>", "\n".join(patch_res_data))
    # prompt_new = prompt_new.replace("<vul_result_json>", "\n".join(vul_res_data))
    prompt_new = prompt_new.replace("<patch_result_json>", str(patch_res_json))
    prompt_new = prompt_new.replace("<vul_result_json>", str(vul_res_json))

    with open(os.path.join(res_file, "prompt_p_"+number_item+".txt"), "w", encoding="utf-8") as f:
        f.write(prompt_new)

    retry_llm = 1
    while retry_llm:
        llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "llm_pres_"+number_item+".txt"))
        if llm_success and "correct_result" in llm_result:
            print("llm result: ", llm_result)
            break
        retry_llm += 1
        print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        detection_res["prompt_path"] = os.path.join(res_file, "prompt.txt")
        detection_res["llm_res"] = llm_result

    return detection_res

def get_verification_vul_rev_prompt_v1(patch_res_path, vul_res_path, path_diff_path, res_file):


    arg_max_line = 400

    if not os.path.exists(patch_res_path):
        print("match result not found!!")
        return False
    patch_res_data = extract_json_from_file(patch_res_path)

    if not os.path.exists(vul_res_path):
        print("match result not found!!")
        return False
    vul_res_data = extract_json_from_file(vul_res_path)

    vul_res_data = swap_key_value(vul_res_data)

    if not os.path.exists(path_diff_path):
        print("match result not found!!")
        return False
    with open(path_diff_path, "r", encoding="utf-8") as file:
        path_diff_data = file.read()



    # Load template, replace labels, and save the final result
    with open("prompt_templete_verification.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["patch_res_path"] = patch_res_path
    detection_res["vul_res_path"] = vul_res_path
    detection_res["path_diff_path"] = path_diff_path
    detection_res["prompt_path"] = ""
    detection_res["llm_res"] = ""



# llm detection
    prompt_new = copy.deepcopy(prompt_content)

    prompt_new = prompt_new.replace("<patch_diff_label>", path_diff_data)
    prompt_new = prompt_new.replace("<patch_result_json>", str(patch_res_data))
    prompt_new = prompt_new.replace("<vul_result_json>", str(vul_res_data))

    with open(os.path.join(res_file, "prompt.txt"), "w", encoding="utf-8") as f:
        f.write(prompt_new)

    retry_llm = 1
    while retry_llm:
        llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "llm_res.txt"))
        if llm_success and "is_patched" in llm_result:
            print("llm result: ", llm_result)
            break
        retry_llm += 1
        print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        detection_res["prompt_path"] = os.path.join(res_file, "prompt.txt")
        detection_res["llm_res"] = llm_result

    return detection_res


def get_verification_patch_rev_prompt_v1(patch_res_path, vul_res_path, path_diff_path, res_file):


    arg_max_line = 400

    if not os.path.exists(patch_res_path):
        print("match result not found!!")
        return False
    patch_res_data = extract_json_from_file(patch_res_path)

    if not os.path.exists(vul_res_path):
        print("match result not found!!")
        return False
    vul_res_data = extract_json_from_file(vul_res_path)

    patch_res_data = swap_key_value(patch_res_data)

    if not os.path.exists(path_diff_path):
        print("match result not found!!")
        return False
    with open(path_diff_path, "r", encoding="utf-8") as file:
        path_diff_data = file.read()



    # Load template, replace labels, and save the final result
    with open("prompt_templete_verification.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["patch_res_path"] = patch_res_path
    detection_res["vul_res_path"] = vul_res_path
    detection_res["path_diff_path"] = path_diff_path
    detection_res["prompt_path"] = ""
    detection_res["llm_res"] = ""



# llm detection
    prompt_new = copy.deepcopy(prompt_content)

    prompt_new = prompt_new.replace("<patch_diff_label>", path_diff_data)
    prompt_new = prompt_new.replace("<patch_result_json>", str(patch_res_data))
    prompt_new = prompt_new.replace("<vul_result_json>", str(vul_res_data))

    with open(os.path.join(res_file, "prompt.txt"), "w", encoding="utf-8") as f:
        f.write(prompt_new)

    retry_llm = 1
    while retry_llm:
        llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "llm_res.txt"))
        if llm_success and "is_patched" in llm_result:
            print("llm result: ", llm_result)
            break
        retry_llm += 1
        print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        detection_res["prompt_path"] = os.path.join(res_file, "prompt.txt")
        detection_res["llm_res"] = llm_result

    return detection_res

def constant_list2dict(constant_list):
    constant_dict = {}
    for constant in constant_list:
        if "#define" not in constant:
            key, value = constant.split("=", 1)
            constant_dict[key] = value
        else:
            constant_split_all = []
            constant_split = constant.split(" ")
            constant_split_list = list(constant_split)
            for constant_split_item in constant_split_list:
                constant_split_all.extend(list(constant_split_item.split("\t"))) 
            define_item = []
            for constant_split_item in constant_split_all:
                if constant_split_item != "":
                    define_item.append(constant_split_item)
            constant_dict[define_item[1]] = define_item[2]
    return constant_dict


def get_verification_z3_vul_rev(constant_mappings, patch_res_path, vul_res_path, res_file, number_item, tmp_dir):

        if not os.path.exists(patch_res_path):
            print("match result not found!!")
            return False
        patch_res_json = extract_json_from_file(patch_res_path)
    
        if patch_res_json == None:
            print("match result not found!!")
            return False

        if not os.path.exists(vul_res_path):
            print("match result not found!!")
            return False
        vul_res_json = extract_json_from_file(vul_res_path)
        if vul_res_json == None:
            print("match result not found!!")
            return False

        vul_res_json = swap_key_value(vul_res_json)

        constant_dict = constant_list2dict(constant_mappings)

        patch_res_json_new = {"new match result": {}}
        vul_res_json_new = {"new match result": {}}

        # 更新 patch_res_json 的 "new match result"
        for source_line in patch_res_json["new match result"]:
            updated_line = source_line.split("//")[0].strip()  # 去掉注释并删除首尾空格
            patch_res_json_new["new match result"][updated_line] = patch_res_json["new match result"][source_line]  # 更新原列表或字典

        # 更新 vul_res_json 的 "new match result"
        for source_line in vul_res_json["new match result"]:
            updated_line = source_line.split("//")[0].strip()  # 去掉注释并删除首尾空格
            vul_res_json_new["new match result"][updated_line] = vul_res_json["new match result"][source_line]  # 更新原列表或字典

        # lex_patch_res_path = os.path.join(res_file, "lex_patch_"+number_item+".txt")
        # lex_vul_res_path = os.path.join(res_file, "lex_vul_"+number_item+".txt")

        lexer_analysis.lexical_analysis(patch_res_json_new, os.path.join(res_file, "z3_patch_"+number_item+".txt"), constant_dict, tmp_dir)
        try:
            lexer_analysis.lexical_analysis(vul_res_json_new, os.path.join(res_file, "z3_vul_"+number_item+".txt"), constant_dict, tmp_dir)
        except:
            print("z3 vul failed")
            return False


def get_verification_z3(constant_mappings, patch_res_path, vul_res_path, res_file, number_item, tmp_dir):

        if not os.path.exists(patch_res_path):
            print("match result not found!!")
            return False
        patch_res_json = extract_json_from_file(patch_res_path)
    
        if patch_res_json == None:
            print("match result not found!!")
            return False

        if not os.path.exists(vul_res_path):
            print("match result not found!!")
            return False
        vul_res_json = extract_json_from_file(vul_res_path)
        if vul_res_json == None:
            print("match result not found!!")
            return False
    
        constant_dict = constant_list2dict(constant_mappings)

        patch_res_json_new = {"new match result": {}}
        vul_res_json_new = {"new match result": {}}

        # 更新 patch_res_json 的 "new match result"
        for source_line in patch_res_json["new match result"]:
            updated_line = source_line.split("//")[0].strip()  # 去掉注释并删除首尾空格
            patch_res_json_new["new match result"][updated_line] = patch_res_json["new match result"][source_line]  # 更新原列表或字典

        # 更新 vul_res_json 的 "new match result"
        for source_line in vul_res_json["new match result"]:
            updated_line = source_line.split("//")[0].strip()  # 去掉注释并删除首尾空格
            vul_res_json_new["new match result"][updated_line] = vul_res_json["new match result"][source_line]  # 更新原列表或字典

        # lex_patch_res_path = os.path.join(res_file, "lex_patch_"+number_item+".txt")
        # lex_vul_res_path = os.path.join(res_file, "lex_vul_"+number_item+".txt")

        try:
            lexer_analysis.lexical_analysis(patch_res_json_new, os.path.join(res_file, "z3_patch_"+number_item+".txt"), constant_dict, tmp_dir)
        except:
            print("z3 patch failed")
            return False
        try:
            lexer_analysis.lexical_analysis(vul_res_json_new, os.path.join(res_file, "z3_vul_"+number_item+".txt"), constant_dict, tmp_dir)
        except:
            print("z3 vul failed")
            return False

def get_verification_prompt(constant_mappings, patch_res_path, vul_res_path, path_diff_path, res_file, number_item):


    arg_max_line = 400

    if not os.path.exists(patch_res_path):
        print("match result not found!!")
        return False
    patch_res_json = extract_json_from_file(patch_res_path)

    # patch_res_data = extract_and_merge_lists(patch_res_json)
    if patch_res_json == None:
        print("match result not found!!")
        return False

    if not os.path.exists(vul_res_path):
        print("match result not found!!")
        return False
    vul_res_json = extract_json_from_file(vul_res_path)
    if vul_res_json == None:
        print("match result not found!!")
        return False
    # vul_res_data = extract_and_merge_lists(vul_res_json)

    if not os.path.exists(path_diff_path):
        print("match result not found!!")
        return False
    with open(path_diff_path, "r", encoding="utf-8") as file:
        path_diff_data = file.read()



    # Load template, replace labels, and save the final result
    with open("code/prompt_templete_verification.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["patch_res_path"] = patch_res_path
    detection_res["vul_res_path"] = vul_res_path
    detection_res["path_diff_path"] = path_diff_path
    detection_res["prompt_path"] = ""
    detection_res["llm_res"] = ""



# llm detection
    prompt_new = copy.deepcopy(prompt_content)

    prompt_new = prompt_new.replace("<patch_diff_label>", path_diff_data)
    prompt_new = prompt_new.replace("<comments_label>", "//"+"\n//".join(constant_mappings))
    # prompt_new = prompt_new.replace("<patch_result_json>", "\n".join(patch_res_data))
    # prompt_new = prompt_new.replace("<vul_result_json>", "\n".join(vul_res_data))
    prompt_new = prompt_new.replace("<patch_result_json>", str(patch_res_json))
    prompt_new = prompt_new.replace("<vul_result_json>", str(vul_res_json))

    with open(os.path.join(res_file, "prompt_"+number_item+".txt"), "w", encoding="utf-8") as f:
        f.write(prompt_new)

    retry_llm = 1
    while retry_llm:
        llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "cl07_llm_res_"+number_item+".txt"))
        if llm_success and "correct_result" in llm_result:
            print("llm result: ", llm_result)
            break
        retry_llm += 1
        print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        detection_res["prompt_path"] = os.path.join(res_file, "prompt.txt")
        detection_res["llm_res"] = llm_result

    return detection_res


def persent_compare(patch_res_path, vul_res_path, res_path, number_item):
    if not os.path.exists(patch_res_path):
        print("match result not found!!")
        return False
    patch_res_json = extract_json_from_file(patch_res_path)

    # patch_res_data = extract_and_merge_lists(patch_res_json)
    if patch_res_json == None:
        print("match result not found!!")
        return False

    if not os.path.exists(vul_res_path):
        print("match result not found!!")
        return False
    vul_res_json = extract_json_from_file(vul_res_path)
    if vul_res_json == None:
        print("match result not found!!")
        return False
    # vul_res_data = extract_and_merge_lists(vul_res_json)

    patch_block_num = 0
    patch_all_num = 0
    vul_block_num = 0
    vul_all_num = 0
    for key in patch_res_json["new match result"]:
        if patch_res_json["new match result"][key] == []:
            patch_block_num += 1
            patch_all_num += 1
        else:
            patch_all_num += 1
    for key in vul_res_json["new match result"]:
        if vul_res_json["new match result"][key] == []:
            vul_block_num += 1
            vul_all_num += 1
        else:
            vul_all_num += 1

    if patch_all_num > 0 and vul_all_num > 0:
        patch_percent = patch_block_num / patch_all_num
        vul_percent = vul_block_num / vul_all_num

        if patch_percent < vul_percent and patch_percent < 0.2:
            correct_result = "p result"
        elif patch_percent > vul_percent and vul_percent < 0.2:
            correct_result = "v result"
        else:
            return False
    else:
        return False
    
    json_result = {"correct result":correct_result, "analysis reason": "has more matched result."}

    with open(os.path.join(res_path, "z3_res_"+number_item+".json"), "w") as json_res:
        json.dump(json_result, json_res, indent=4)

    return {"correct result":"v result", "analysis reason": "has more matched result."}


def get_verification_prompt_v3(constant_mappings, patch_res_path, vul_res_path, path_diff_path, res_file):


    arg_max_line = 400

    if not os.path.exists(patch_res_path):
        print("match result not found!!")
        return False
    patch_res_json = extract_json_from_file(patch_res_path)

    patch_res_data = extract_and_merge_lists(patch_res_json)

    if not os.path.exists(vul_res_path):
        print("match result not found!!")
        return False
    vul_res_json = extract_json_from_file(vul_res_path)

    vul_res_data = extract_and_merge_lists(vul_res_json)

    if not os.path.exists(path_diff_path):
        print("match result not found!!")
        return False
    with open(path_diff_path, "r", encoding="utf-8") as file:
        path_diff_data = file.read()



    # Load template, replace labels, and save the final result
    with open("prompt_templete_verification.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["patch_res_path"] = patch_res_path
    detection_res["vul_res_path"] = vul_res_path
    detection_res["path_diff_path"] = path_diff_path
    detection_res["prompt_path"] = ""
    detection_res["llm_res"] = ""

    vul_res_data.extend(patch_res_data)

# llm detection
    prompt_new = copy.deepcopy(prompt_content)

    prompt_new = prompt_new.replace("<patch_diff_label>", path_diff_data)
    prompt_new = prompt_new.replace("<comments_label>", "//"+"\n//".join(constant_mappings))
    # prompt_new = prompt_new.replace("<patch_result_json>", "\n".join(patch_res_data))
    prompt_new = prompt_new.replace("<pseudo_code_label>", "\n".join(vul_res_data))
    # prompt_new = prompt_new.replace("<patch_result_json>", str(patch_res_json['new match result']))
    # prompt_new = prompt_new.replace("<vul_result_json>", str(vul_res_json['new match result']))

    with open(os.path.join(res_file, "prompt.txt"), "w", encoding="utf-8") as f:
        f.write(prompt_new)

    retry_llm = 1
    while retry_llm:
        llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "llm_res.txt"))
        if llm_success and "patched or not" in llm_result:
            print("llm result: ", llm_result)
            break
        retry_llm += 1
        print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        detection_res["prompt_path"] = os.path.join(res_file, "prompt.txt")
        detection_res["llm_res"] = llm_result

    return detection_res




def get_prompt(source_file, pseudo_file, res_file):


    arg_max_line = 400


    """
    Perform LLM detection and replace <pseudo_code_label> and <source_code_label> placeholders
    in 'prompt_templete.txt' with processed source and pseudo code.
    """
    # Load source and pseudo code from files
    with open(source_file, "r", encoding="utf-8") as file:
        source_code = file.read()
    with open(pseudo_file, "r", encoding="utf-8") as file:
        pseudo_code = file.read()

    # Process pseudo code for slicing if needed
    if len(pseudo_code.splitlines()) > arg_max_line:
        pseudo_sliced_list = pseudo_slice_V2(pseudo_code)
    else:
        pseudo_sliced_list = [pseudo_code]

    # Process source code for slicing if needed
    if len(source_code.splitlines()) > arg_max_line:
        source_sliced = source_slice_V2(source_code)
    else:
        source_sliced = source_code

    with open(os.path.join(res_file, "soruce_sliced.txt"), "w", encoding="utf-8") as f:
            f.write(source_sliced)



    # Load template, replace labels, and save the final result
    with open("code/prompt_templete_locate.txt", "r", encoding="utf-8") as file:
        prompt_content = file.read()
    
    detection_res = {}
    detection_res["source_file"] = source_file
    detection_res["pseudo_file"] = pseudo_file
    detection_res["source_sliced"] = os.path.join(res_file, "soruce_sliced.txt")
    detection_res["pseudo_sliced_list"] = []
    detection_res["prompt_list"] = []
    detection_res["llm_res_list"] = []


    i = 0
    for pseudo_sliced in pseudo_sliced_list:
        i += 1

# llm detection
        prompt_new = copy.deepcopy(prompt_content)

        with open(os.path.join(res_file, "pseudo_sliced_" + str(i) + ".txt"), "w", encoding="utf-8") as f:
            f.write(pseudo_sliced)
        prompt_new = prompt_new.replace("<pseudo_code_label>", pseudo_sliced)
        prompt_new = prompt_new.replace("<source_code_label>", source_sliced)

        with open(os.path.join(res_file, "prompt_" + str(i) + ".txt"), "w", encoding="utf-8") as f:
            f.write(prompt_new)

        retry_llm = 1
        while retry_llm:
            llm_success, llm_result = llm_detection(prompt_new, os.path.join(res_file, "llm_res_" + str(i) + ".txt"))
            if llm_success and "new match result" in llm_result:
                print("llm result: ", llm_result)
                break
            retry_llm += 1
            print(f"Claude failed to detect the patch. Retrying...{retry_llm}")
        
        

        detection_res["pseudo_sliced_list"].append(os.path.join(res_file, "pseudo_sliced_" + str(i) + ".txt"))
        detection_res["prompt_list"].append(os.path.join(res_file, "prompt_" + str(i) + ".txt"))
        detection_res["llm_res_list"].append(os.path.join(res_file, "llm_res_" + str(i) + ".txt"))
        with open(os.path.join(res_file, "pseudo_sliced_" + str(i) + ".txt"), "w", encoding="utf-8") as f:
            f.write(pseudo_sliced)


    return detection_res



def fix_json_escapes(s):
    result = ''
    in_quotes = False
    i = 0
    while i < len(s):
        char = s[i]
        # if i == 295:
        #     print("warning")
        # 处理转义字符
        if char == '\n' and i + 1 < len(s):
            if in_quotes:
                # 在引号内部，将 \n 转换为 \\n
                result += '\\'
                result += 'n'
            else:
                # 在引号外部或其他转义字符，保持不变
                result += char
            i += 1
            continue
            
        # 处理引号
        if char == '"':
            # 检查是否是转义的引号
            if i > 0 and s[i-1] == '\\':
                result += char
            else:
                # 真实的引号，切换引号状态
                in_quotes = not in_quotes
                result += char
        else:
            result += char
            
        i += 1
    
    return result


def extract_json_from_text(text):
    json_start = text.find('{')
    if json_start == -1:
        print("未找到JSON数据。")
        return None

    brace_count = 0
    in_string = False
    escape = False

    for index in range(json_start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    json_end = index + 1
                    json_str = text[json_start:json_end]
                    try:
                        data = json.loads(fix_json_escapes(json_str.replace('\t', ' ')).replace('\\\\0', '0').replace('\\0', '0'))
                        return data
                    except json.JSONDecodeError as e:
                        print("JSON解码错误：", e)
                        return None
    print("未能正确匹配到JSON对象的结束。")
    return None

def extract_json_from_file(file_path):
    """
    从指定文件中提取所有的JSON对象。

    :param file_path: 文件路径
    :return: 包含所有JSON对象的列表
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    return extract_json_from_text(content)


def read_json_file(file_path):
    """
    读取JSON文件，提取"new match result"中的value值，保存为list2。
    """
    list2 = []
    key_list = []
    # with open(file_path, 'r', encoding='utf-8') as f:
    #     data = json.load(f)
    data = extract_json_from_file(file_path)

    return data


def llm_verification(prompt_content, res_file, ver_file):

    if not os.path.exists(res_file):
        print("llm detection result is not exists!")
        return False, False

        
    llm_res_data = read_json_file(res_file)
   
    conn = http.client.HTTPSConnection(settings.api_url)
    payload = json.dumps({
        "model": settings.model,
        "messages": [
            {
                "role": "user",
                "content": prompt_content
            }
        ]
    })
    headers = {
        'Authorization': settings.user_key,  # 请替换为您的API密钥
        'Content-Type': 'application/json'
    }
    conn.request("POST", "/v1/chat/completions", payload, headers)
    res = conn.getresponse()
    data = res.read()

    # 解析JSON数据
    data_json = json.loads(data)

    # 检查是否有“content”
    content = None
    if "choices" in data_json:
        for choice in data_json["choices"]:
            if "message" in choice and "content" in choice["message"]:
                content = choice["message"]["content"]
                break

    # 保存数据到文件
    if content is None:
        with open(res_file, "w", encoding="utf-8") as f:
            f.write(data.decode("utf-8"))
            print(data.decode("utf-8"))
        
        print(f"Data not found {res_file}")
        
        return False, None
    else:
        with open(res_file, "w", encoding="utf-8") as f:
            f.write(content)
            # print(content)

        # print(f"Data saved to {res_file}")

        return True, content


def llm_detection(prompt_content, res_file):
   
    timeout_retry = 1
    while timeout_retry:
        try :
            conn = http.client.HTTPSConnection(settings.api_url, timeout=30)
            payload = json.dumps({
                "model": settings.model,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt_content
                    }
                ],
                "temperature": 0.7
            })
            headers = {
                
                'Authorization': settings.user_key,
                'Content-Type': 'application/json'
            }

            conn.request("POST", "/v1/chat/completions", payload, headers)
            res = conn.getresponse()
            data = res.read()
        except Exception as e:
            timeout_retry += 1
            print(f"Claude request timeout. Retrying...{timeout_retry}")
            continue

        # 解析JSON数据
        data_json = json.loads(data)

        # 检查是否有“content”
        content = None
        if "choices" in data_json:
            for choice in data_json["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    content = choice["message"]["content"]
                    break

        # 保存数据到文件
        if content is None:
            with open(res_file, "w", encoding="utf-8") as f:
                f.write(data.decode("utf-8"))
                print(data.decode("utf-8"))
            
            print(f"Data not found {res_file}")
            
            return False, None
        else:
            with open(res_file, "w", encoding="utf-8") as f:
                f.write(content)
                # print(content)

            # print(f"Data saved to {res_file}")

            return True, content


if __name__ == '__main__':
     # 创建目录
    os.makedirs("res", exist_ok=True)

    # 获取当前时间戳
    # timestamp = int(time.time())
    os.chdir("code/code/llm_location/")
    # 设置文件路径
    file_path = f"./temp/"
    res_path = f"./res/filepath.json"

    source_path = "./data/sourcecode.c"
    pseudo_path = "./data/pseudocode.c"

    detection_res = get_prompt(source_path, pseudo_path, file_path)

    print(detection_res)

    with open(res_path, "w", encoding="utf-8") as f:
            json.dump(detection_res, f, indent=4)
