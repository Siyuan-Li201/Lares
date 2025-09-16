
# -*- coding: utf-8 -*-
import json
import difflib
from itertools import product
from patch_verify import patch_verify

def read_c_file(file_path):
    """
    读取C文件，将每行代码保存为字典，包含行号和代码。
    """
    list1 = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f, 1):
            list1.append({'line_number': idx, 'code_line': line.strip()})
    return list1


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
                        data = json.loads(json_str)
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
    new_match_result = data.get("new match result", {})
    for key, value in new_match_result.items():
        list2.append(value)
        key_list.append(key)

    return list2, key_list

def calculate_similarity(a, b):
    """
    计算两个字符串的相似度，返回0到1之间的浮点数。
    """
    return difflib.SequenceMatcher(None, a, b).ratio()


def fuzzy_match_highest(list1, list2, key_list, threshold=0.8):
    """
    对list2中的每个成员，在list1中寻找相似度超过threshold的代码行。
    仅保存相似度最高的匹配结果（如果有多个相同最高得分的匹配，则全部保留）。
    
    返回一个字典，键为list2中的成员，值为匹配结果列表。
    每个匹配结果包含line_number、code_line和similarity。
    """
    match_dict = {}
    

    for item in list2:
        max_similarity = 0.0
        matches = []
        
        # 统计当前 item 中的 \n 数量
        num_newlines = item.count('\n')
        
        # 遍历 list1 中的每个起始点
        for i in range(len(list1)):
            combined_string = ""
            
            # 根据 \n 的数量，拼接对应数量的元素（+1 是因为要包括第一个元素）
            for j in range(i, min(i + num_newlines + 1, len(list1))):
                # 拼接字符串
                if combined_string:
                    combined_string += "\n" + list1[j]['code_line']
                else:
                    combined_string = list1[j]['code_line']
                
                # 计算 item 与拼接后的字符串的相似度
                similarity = calculate_similarity(item, combined_string)
                if similarity >= threshold:
                    if similarity > max_similarity:
                        max_similarity = similarity
                        matches = [{
                            'line_number': list1[i]['line_number'],
                            'code_line': combined_string,
                            'similarity': similarity
                        }]
                    elif similarity == max_similarity:
                        matches.append({
                            'line_number': list1[i]['line_number'],
                            'code_line': combined_string,
                            'similarity': similarity
                        })
        if matches:
            # 按相似度降序排序（虽然所有相似度相同）
            sorted_matches = sorted(matches, key=lambda x: x['similarity'], reverse=True)
            match_dict[key_list[list2.index(item)]] = sorted_matches
        else:
            match_dict[key_list[list2.index(item)]] = []
    return match_dict



def fuzzy_match_highest_v1(list1, list2, key_list, threshold=0.8):
    """
    对list2中的每个成员，在list1中寻找相似度超过threshold的代码行。
    仅保存相似度最高的匹配结果（如果有多个相同最高得分的匹配，则全部保留）。
    
    返回一个字典，键为list2中的成员，值为匹配结果列表。
    每个匹配结果包含line_number、code_line和similarity。
    """
    match_dict = {}
    for item in list2:
        max_similarity = 0.0
        matches = []
        for entry in list1:
            similarity = calculate_similarity(item, entry['code_line'])
            if similarity >= threshold:
                if similarity > max_similarity:
                    max_similarity = similarity
                    matches = [{
                        'line_number': entry['line_number'],
                        'code_line': entry['code_line'],
                        'similarity': similarity
                    }]
                elif similarity == max_similarity:
                    matches.append({
                        'line_number': entry['line_number'],
                        'code_line': entry['code_line'],
                        'similarity': similarity
                    })
        if matches:
            # 按相似度降序排序（虽然所有相似度相同）
            sorted_matches = sorted(matches, key=lambda x: x['similarity'], reverse=True)
            match_dict[key_list[list2.index(item)]] = sorted_matches
        else:
            match_dict[key_list[list2.index(item)]] = []
    return match_dict


def fuzzy_match(list1, list2, key_list, threshold=0.8):
    """
    对list2中的每个成员，在list1中寻找相似度超过threshold的代码行。
    返回一个字典，键为list2中的成员，值为按相似度降序排列的匹配结果列表。
    每个匹配结果包含line_number、code_line和similarity。
    """
    match_dict = {}
    for item in list2:
        matches = []
        for entry in list1:
            similarity = calculate_similarity(item, entry['code_line'])
            if similarity >= threshold:
                matches.append({
                    'line_number': entry['line_number'],
                    'code_line': entry['code_line'],
                    'similarity': similarity
                })
        # 按相似度降序排序
        sorted_matches = sorted(matches, key=lambda x: x['similarity'], reverse=True)
        match_dict[key_list[list2.index(item)]] = sorted_matches
    return match_dict





def find_valid_matches(matched_results, source_file, pseudo_file):
    """
    尝试找到一个matched_dict，使得每个list2的成员选择一个匹配结果，
    并通过module1.patch_verify验证。
    
    如果找到成功的matched_dict，返回True和matched_dict。
    如果所有组合都失败，返回False和None。
    """
    # 过滤掉没有匹配结果的成员
    filtered_matches = {k: v for k, v in matched_results.items() if v}
    
    # 如果有任何一个成员没有匹配结果，则不可能成功
    if len(filtered_matches) - len(matched_results) or len(filtered_matches) < 1:
        print("部分成员没有匹配的代码行，无法进行验证。")
        return False, None
    
    if len(filtered_matches) == 1:
        return True, filtered_matches

    # 获取所有成员的匹配列表
    keys = list(filtered_matches.keys())
    match_lists = [filtered_matches[key] for key in keys]
    
    i = 0
    # 使用生成器按组合顺序生成所有可能的匹配组合
    for combination in product(*match_lists):
        i += 1
        # 构造matched_dict
        matched_dict = {key: match for key, match in zip(keys, combination)}
        
        # 调用patch_verify进行验证
        success, verified_dict = patch_verify(matched_dict, source_file, pseudo_file)
        
        if success:
            # print("成功找到一个有效的匹配组合。")
            return True, verified_dict
        # else:
        #     print(f"匹配组合验证失败: {matched_dict}")
    
    print(i)
    
    # 如果所有组合都失败
    print("未能找到有效的匹配组合。")
    return False, None


def match_patch(source_file, pseudo_file, json_file, match_res, verify_res):
    # 文件路径
    
    
    # json_file = '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/code/llm_location/selected_res/patch_false_claude35.json'

    # 读取文件
    list1 = read_c_file(pseudo_file)
    list2, key_list = read_json_file(json_file)

    # 进行模糊匹配
    # matched_results = fuzzy_match(list1, list2, key_list, threshold=0.85)
    matched_results = fuzzy_match_highest(list1, list2, key_list, threshold=0.85)
    

    # 打印匹配结果
    # for key, matches in matched_results.items():
    #     print(f"匹配内容：{key}")
    #     if matches:
    #         for match in matches:
    #             print(f"  行号: {match['line_number']}, 相似度: {match['similarity']:.2f}, 代码: {match['code_line']}")
    #     else:
    #         print("  未找到匹配的代码行。")
    #     print("-" * 50)

    # 如果需要将结果保存为JSON文件，可以取消注释以下代码
    with open(match_res, 'w', encoding='utf-8') as f:
        json.dump(matched_results, f, ensure_ascii=False, indent=4)

    success, matched_dict = find_valid_matches(matched_results, source_file, pseudo_file)

    # if success:
    #     print("\n验证成功的匹配字典：")
    #     for key, match in matched_dict.items():
    #         print(f"匹配内容：{key}")
    #         print(f"  行号: {match['line_number']}, 相似度: {match['similarity']:.2f}, 代码: {match['code_line']}")
    #         print("-" * 50)
    # else:
    #     print("\n未找到通过验证的匹配组合。")

    # 如果需要将结果保存为JSON文件，可以取消注释以下代码
    if success:
        with open(verify_res, 'w', encoding='utf-8') as f:
            json.dump(matched_dict, f, ensure_ascii=False, indent=4)

            return True, matched_dict
    else:
        return False, None



if __name__ == "__main__":

    filepath = json.load(open('/media/author/4A7AC8957AC87F67/work2024/code/llm_api/res/CVE-2016-4487-1/filepath.json', "r"))

    verify_res = '/media/author/4A7AC8957AC87F67/work2024/code/llm_api/res/CVE-2016-4487-1/verified_matched_dict.json'
    match_res = "/media/author/4A7AC8957AC87F67/work2024/code/llm_api/res/CVE-2016-4487-1/matched_results.json"

    source_file = filepath["source_sliced"]
    pseudo_file_list = filepath["pseudo_sliced_list"]
    llm_res_list = filepath["llm_res_list"]
    
    for i in range(len(pseudo_file_list)):
        match_patch(source_file, pseudo_file_list[i], llm_res_list[i], match_res, verify_res)
