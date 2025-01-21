import os
import sys
import json
from tqdm import tqdm
import glob
import re
from itertools import groupby

sys.path.append("code/patch_verification")
sys.path.append("code/llm_location")
sys.path.append("code/code_compare")

import patch_match
import llm_detection
import z3_prove
import extract_eq
import lexer_analysis



def extract_constant_mappings(filename):
    # 读取JSON文件
    with open(filename, 'r') as f:
        data = json.load(f)
    
    # 提取所有constantMappings的值并展平为一个列表
    all_mappings = []
    for item in data:
        mappings = item.get('constantMappings', [])
        all_mappings.extend(mappings)
    
    # 去重
    unique_mappings = list(set(all_mappings))
    
    return unique_mappings


def patch_verification(data_dir):
    for cve_dir_name in tqdm(os.listdir(data_dir)):

        # if "CVE-2016-4447" not in cve_dir_name:
        #     continue

        cve_dir_path = os.path.join(data_dir, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"

        result_json_path = os.path.join(cve_dir_path, "result.json")
        if not os.path.exists(result_json_path):
            print(f"Warning: result.json not found in {cve_dir_path}")
            continue
        # Read result.json
        with open(result_json_path, 'r', encoding='utf-8') as f:
            try:
                result_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in {result_json_path}")
                continue

        # Get all .idapseudo files
        idapseudo_files = glob.glob(os.path.join(cve_dir_path, "*.lineidapseudo"))
        patch_path_list = glob.glob(os.path.join(cve_dir_path, "*_patched.c"))
        vul_path_list = glob.glob(os.path.join(cve_dir_path, "*_vul.c"))
        constant_file_list = glob.glob(os.path.join(cve_dir_path, "*_code_joern_constant.json"))

        constant_mappings = []
        if len(constant_file_list) > 0:
            for constant_file_item in constant_file_list:
                constant_mappings_temp = extract_constant_mappings(constant_file_item)
                constant_mappings.extend(constant_mappings_temp)
        constant_mappings = list(set(constant_mappings))
        

        path_diff_path = os.path.join(cve_dir_path, "patch.diff")

        # 定义文件名匹配模式
        llm_pattern = r'llm_res_(\d+)\.txt'
        pseudo_pattern = r'pseudo_sliced_(\d+)\.txt'
        
        for pseudo_path in idapseudo_files:
            # Get directory and filename without extension
            dir_path = os.path.dirname(pseudo_path)
            filename = os.path.splitext(os.path.basename(pseudo_path))[0]
            
            # Check for patched code file

            patch_res_dir = os.path.join(dir_path, "apatch_res_" + filename, "temp")
            vul_res_dir = os.path.join(dir_path, "avul_res_" + filename, "temp")
            vul_rev_res_dir = os.path.join(dir_path, "avulrev_res_" + filename)
            patch_rev_res_dir = os.path.join(dir_path, "apatchrev_res_" + filename)

            if os.path.exists(patch_res_dir) and os.path.exists(vul_res_dir):
                # continue
                # 存储文件对
                pfile_pairs = {}
                vfile_pairs = {}

                # Create result directory for patched analysis
                res_dir = os.path.join(dir_path, "ares_" + filename)

                if not os.path.exists(res_dir):
                    os.makedirs(res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(patch_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in pfile_pairs:
                                pfile_pairs[number] = {'llm': None, 'pseudo': None}
                            pfile_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in pfile_pairs:
                                pfile_pairs[number] = {'llm': None, 'pseudo': None}
                            pfile_pairs[number]['pseudo'] = os.path.join(root, filename)


                # 遍历目录
                for root, dirs, files in os.walk(vul_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in vfile_pairs:
                                vfile_pairs[number] = {'llm': None, 'pseudo': None}
                            vfile_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in vfile_pairs:
                                vfile_pairs[number] = {'llm': None, 'pseudo': None}
                            vfile_pairs[number]['pseudo'] = os.path.join(root, filename)

                # for number_item in pfile_pairs:
                #     vul_res_item_path = os.path.join(vul_rev_res_dir, "llm_res_" + number_item + ".txt")
                #     if os.path.exists(vul_res_item_path):
                #         print(f"Detection the {patch_res_dir} and {vul_rev_res_dir}")
                #         if (int(number_item) == 1 and os.path.exists(os.path.join(res_dir, "llm_pres.txt"))) or os.path.exists(os.path.join(res_dir, "llm_pres_" + number_item + ".txt")):
                #             continue
                #         detection_rev_res = llm_detection.get_verification_vul_rev_prompt(pfile_pairs[number_item]['llm'], vul_res_item_path, path_diff_path, res_dir, number_item, constant_mappings)
                
                # for number_item in vfile_pairs:
                #     vul_res_item_path = os.path.join(patch_rev_res_dir, "llm_res_" + number_item + ".txt")
                #     if os.path.exists(vul_res_item_path):
                #         print(f"Detection the {vul_res_dir} and {patch_rev_res_dir}")
                #         if (int(number_item) == 1 and os.path.exists(os.path.join(res_dir, "llm_vres.txt"))) or os.path.exists(os.path.join(res_dir, "llm_vres_" + number_item + ".txt")):
                #             continue
                #         detection_rev_res = llm_detection.get_verification_patch_rev_prompt(vul_res_item_path, vfile_pairs[number_item]['llm'], path_diff_path, res_dir, number_item, constant_mappings)

                for number_item in pfile_pairs:
                    vul_res_item_path = os.path.join(vul_res_dir, "llm_res_" + number_item + ".txt")
                    if os.path.exists(vul_res_item_path):
                        print(f"Detection the {patch_res_dir} and {vul_res_dir}")
                        # if (int(number_item) == 1 and os.path.exists(os.path.join(res_dir, "new_llm_res.txt"))) or os.path.exists(os.path.join(res_dir, "new_llm_res_" + number_item + ".txt")):
                        #     continue
                        detection_rev_res = llm_detection.get_verification_prompt(constant_mappings, pfile_pairs[number_item]['llm'], vul_res_item_path, path_diff_path, res_dir, number_item)
                
            continue

            if os.path.exists(patch_res_dir) and not os.path.exists(vul_res_dir) and os.path.exists(vul_rev_res_dir):
                # continue
                # 存储文件对
                file_pairs = {}

                # Create result directory for patched analysis
                res_dir = os.path.join(dir_path, "ares_" + filename)

                if not os.path.exists(res_dir):
                    os.makedirs(res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(patch_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['pseudo'] = os.path.join(root, filename)

                for number_item in file_pairs:
                    vul_res_item_path = os.path.join(vul_rev_res_dir, "llm_res_" + number_item + ".txt")
                    if os.path.exists(vul_res_item_path):
                        print(f"Detection the {patch_res_dir} and {vul_rev_res_dir}")
                        # if (int(number_item) == 1 and os.path.exists(os.path.join(res_dir, "llm_res.txt"))) or os.path.exists(os.path.join(res_dir, "llm_res_" + number_item + ".txt")) or os.path.exists(os.path.join(res_dir, "llm_pres_" + number_item + ".txt")):
                        #     continue
                        detection_rev_res = llm_detection.get_verification_vul_rev_prompt(file_pairs[number_item]['llm'], vul_res_item_path, path_diff_path, res_dir, number_item)
                


            if not os.path.exists(patch_res_dir) and os.path.exists(vul_res_dir) and os.path.exists(patch_rev_res_dir):

                # 存储文件对
                file_pairs = {}

                # Create result directory for patched analysis
                res_dir = os.path.join(dir_path, "ares_" + filename)

                if not os.path.exists(res_dir):
                    os.makedirs(res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(vul_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['pseudo'] = os.path.join(root, filename)

                for number_item in file_pairs:
                    vul_res_item_path = os.path.join(patch_rev_res_dir, "llm_res_" + number_item + ".txt")
                    if os.path.exists(vul_res_item_path):
                        print(f"Detection the {vul_res_dir} and {patch_rev_res_dir}")
                        # if (int(number_item) == 1 and os.path.exists(os.path.join(res_dir, "llm_res.txt"))) or os.path.exists(os.path.join(res_dir, "llm_res_" + number_item + ".txt")) or os.path.exists(os.path.join(res_dir, "llm_vres_" + number_item + ".txt")):
                        #     continue
                        detection_rev_res = llm_detection.get_verification_patch_rev_prompt(vul_res_item_path, file_pairs[number_item]['llm'], path_diff_path, res_dir, number_item)


def patch_verification_z3(data_dir, tmp_dir):
    for cve_dir_name in tqdm(os.listdir(data_dir)):


        # if "CVE-2016-4447" not in cve_dir_name:
        #     continue


        cve_dir_path = os.path.join(data_dir, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"

        result_json_path = os.path.join(cve_dir_path, "result.json")
        if not os.path.exists(result_json_path):
            print(f"Warning: result.json not found in {cve_dir_path}")
            continue
        # Read result.json
        with open(result_json_path, 'r', encoding='utf-8') as f:
            try:
                result_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in {result_json_path}")
                continue

        # Get all .idapseudo files
        idapseudo_files = glob.glob(os.path.join(cve_dir_path, "*.lineidapseudo"))
        # patch_path_list = glob.glob(os.path.join(cve_dir_path, "*_patched.c"))
        # vul_path_list = glob.glob(os.path.join(cve_dir_path, "*_vul.c"))
        constant_file_list = glob.glob(os.path.join(cve_dir_path, "*_code_joern_constant.json"))

        constant_mappings = []
        if len(constant_file_list) > 0:
            for constant_file_item in constant_file_list:
                constant_mappings_temp = extract_constant_mappings(constant_file_item)
                constant_mappings.extend(constant_mappings_temp)
        constant_mappings = list(set(constant_mappings))
        

        path_diff_path = os.path.join(cve_dir_path, "patch.diff")

        # 定义文件名匹配模式
        llm_pattern = r'llm_res_(\d+)\.txt'
        pseudo_pattern = r'pseudo_sliced_(\d+)\.txt'
        
        for pseudo_path in idapseudo_files:
            # Get directory and filename without extension
            dir_path = os.path.dirname(pseudo_path)
            filename = os.path.splitext(os.path.basename(pseudo_path))[0]
            
            # Check for patched code file

            patch_res_dir = os.path.join(dir_path, "apatch_res_" + filename, "temp")
            vul_res_dir = os.path.join(dir_path, "avul_res_" + filename, "temp")
            vul_rev_res_dir = os.path.join(dir_path, "avulrev_res_" + filename)
            patch_rev_res_dir = os.path.join(dir_path, "apatchrev_res_" + filename)

            if os.path.exists(patch_res_dir) and os.path.exists(vul_res_dir):
                # continue
                # 存储文件对
                file_pairs = {}

                # Create result directory for patched analysis
                res_dir = os.path.join(dir_path, "ares_" + filename)

                if not os.path.exists(res_dir):
                    os.makedirs(res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(patch_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['pseudo'] = os.path.join(root, filename)
                
                for number_item in file_pairs:
                    vul_res_item_path = os.path.join(vul_res_dir, "llm_res_" + number_item + ".txt")
                    if os.path.exists(vul_res_item_path):
                        print(f"Detection the {patch_res_dir} and {vul_res_dir}")
                        # if os.path.exists(os.path.join(res_dir, "z3_patch_"+number_item+".txt")) and os.path.exists(os.path.join(res_dir, "z3_vul_"+number_item+".txt")):
                        #     continue
                        detection_rev_res = llm_detection.get_verification_z3(constant_mappings, file_pairs[number_item]['llm'], vul_res_item_path, res_dir, number_item, tmp_dir)
                
            if os.path.exists(patch_res_dir) and not os.path.exists(vul_res_dir):
                file_pairs = {}

                # Create result directory for patched analysis

                res_dir = os.path.join(dir_path, "ares_" + filename)
                if res_dir != "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data/CVE-2014-3470_ssl3_send_client_key_exchange_3/ares_x86_clang_O2_openssl_1.0.1h_strip_ssl3_send_client_key_exchange_0x0809f5b0":
                    continue

                if not os.path.exists(res_dir):
                    os.makedirs(res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(patch_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['pseudo'] = os.path.join(root, filename)
                
                for number_item in file_pairs:
                    vul_res_item_path = os.path.join(vul_rev_res_dir, "llm_res_" + number_item + ".txt")
                    if os.path.exists(vul_res_item_path):
                        print(f"Detection the {patch_res_dir} and {vul_res_dir}")
                        # if os.path.exists(os.path.join(res_dir, "z3_patch_"+number_item+".txt")) and os.path.exists(os.path.join(res_dir, "z3_vul_"+number_item+".txt")):
                        #     continue
                        detection_rev_res = llm_detection.get_verification_z3_vul_rev(constant_mappings, file_pairs[number_item]['llm'], vul_res_item_path, res_dir, number_item, tmp_dir)

            
            if not os.path.exists(patch_res_dir) and os.path.exists(vul_res_dir):

                # 存储文件对
                file_pairs = {}

                # Create result directory for patched analysis
                res_dir = os.path.join(dir_path, "ares_" + filename)

                if not os.path.exists(res_dir):
                    os.makedirs(res_dir)

                # 遍历目录
                for root, dirs, files in os.walk(vul_res_dir):
                    for filename in files:
                        # 匹配llm文件
                        llm_match = re.match(llm_pattern, filename)
                        if llm_match:
                            number = llm_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['llm'] = os.path.join(root, filename)
                        
                        # 匹配pseudo文件
                        pseudo_match = re.match(pseudo_pattern, filename)
                        if pseudo_match:
                            number = pseudo_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'llm': None, 'pseudo': None}
                            file_pairs[number]['pseudo'] = os.path.join(root, filename)

                for number_item in file_pairs:
                    vul_res_item_path = os.path.join(patch_rev_res_dir, "llm_res_" + number_item + ".txt")
                    if os.path.exists(vul_res_item_path):
                        print(f"Detection the {vul_res_dir} and {patch_rev_res_dir}")
                        # if os.path.exists(os.path.join(res_dir, "z3_patch_"+number_item+".txt")) and os.path.exists(os.path.join(res_dir, "z3_vul_"+number_item+".txt")):
                        #     continue
                        detection_rev_res = llm_detection.get_verification_z3(constant_mappings, vul_res_item_path, file_pairs[number_item]['llm'], res_dir, number_item, tmp_dir)


def combine_dict(dict1, dict2):
    for key in dict2:
        if key not in dict1:
            dict1[key] = dict2[key]
        else:
            dict1[key].extend(dict2[key])

    return dict1



def get_patch_sig_z3(patch_source_dict, vul_source_dict):

    filtered_sig = json.load(open("z3_sig_filter.json", "r"))


    sig_state = False

    sig_dict = {
        'patch': {
            'conditions':[],
            'assignments':[],
            'return':[],
            'calls':[]
            },
        'vul': {
            'conditions':[],
            'assignments':[],
            'return':[],
            'calls':[]
            }
    }

    for key in patch_source_dict:
        if key in vul_source_dict:
            for item1 in patch_source_dict[key]:
                if item1.replace(" ", "") in filtered_sig and item1.replace(" ", "") not in black_list and len(filtered_sig[item1.replace(" ", "")])<10  and "Domain" not in item1 and "Address" not in item1:
                    find_state = False
                    for item2 in vul_source_dict[key]:
                        prove_result, prove_example = z3_prove.check_equivalence(item1, item2)
                        if prove_result:
                            find_state = True
                            sig_state = True
                            break
                    if find_state == False:
                        sig_state = True
                        sig_dict['patch'][key].append(item1)
    
    for key in vul_source_dict:
        if key in patch_source_dict:
            for item1 in vul_source_dict[key]:
                if item1.replace(" ", "") in filtered_sig and item1.replace(" ", "") not in black_list and len(filtered_sig[item1.replace(" ", "")])<10  and "Domain" not in item1 and "Address" not in item1:
                    find_state = False
                    for item2 in patch_source_dict[key]:
                        prove_result, prove_example = z3_prove.check_equivalence(item1, item2)
                        if prove_result:
                            find_state = True
                            sig_state = True
                            break
                    if find_state == False:
                        sig_state = True
                        sig_dict['vul'][key].append(item1)

    return sig_state, sig_dict


def find_sigs_z3(sig_dict, patch_pseudo_dict, vul_pseudo_dict):

    patch_result = []
    vul_result = []

    for key in sig_dict['patch']:
        for item in sig_dict['patch'][key]:
            find_in_patch_state = False
            if key in patch_pseudo_dict:
                for key_item in patch_pseudo_dict[key]:
                    prove_result, prove_example = z3_prove.check_equivalence(item, key_item)
                    if prove_result:
                        find_in_patch_state = True
                        patch_result.append(item)
                        break
            else:
                find_in_patch_state = True
                patch_result.append(item)

    for key in sig_dict['vul']:
        for item in sig_dict['vul'][key]:
            find_in_vul_state = False
            if key in vul_pseudo_dict:
                for key_item in vul_pseudo_dict[key]:
                    prove_result, prove_example = z3_prove.check_equivalence(item, key_item)
                    if prove_result:
                        find_in_vul_state = True
                        vul_result.append(item)
                        break
            else:
                find_in_vul_state = True
                vul_result.append(item)

    if len(patch_result) > 0 and len(vul_result) > 0:
        return False, "not sure", {'type': 'find the sigs', 'patch': patch_result, 'vul': vul_result}
    elif len(patch_result) > 0:
        return True, "patched version", {'type': 'find the sigs', 'patch': patch_result, 'vul': vul_result}
    elif len(vul_result) > 0:
        return True, "pre-patch version", {'type': 'find the sigs', 'patch': patch_result, 'vul': vul_result}
    else:
        return False, "not sure", {'type': 'find the sigs', 'patch': patch_result, 'vul': vul_result}


black_list = [] #["x1==-1)", "x1==-1", "x1==16", "x1=-1", "return=-3", "x1<4", "x1!=4", "x1!=16", "x1-8", "x1>=1", "x1<8", "x1<20", "x1==14"]


def get_eqs_z3(source_dict, pseudo_dict):

    filtered_sig = json.load(open("z3_sig_filter.json", "r"))

    eqs_dict = {
            'conditions':{"eq_num" : 0, "all_num" : 0, "percent" : 0.0, "eq_list":[]},
            'assignments':{"eq_num" : 0, "all_num" : 0, "percent" : 0.0, "eq_list":[]},
            'return':{"eq_num" : 0, "all_num" : 0, "percent" : 0.0, "eq_list":[]},
            'calls':{"eq_num" : 0, "all_num" : 0, "percent" : 0.0, "eq_list":[]}
        }

    for key in source_dict:
        if key in pseudo_dict:
            for item1 in source_dict[key]:
                if not is_valid_number(item1) and item1.replace(" ", "") in filtered_sig and item1.replace(" ", "") not in black_list and len(filtered_sig[item1.replace(" ", "")])<10 and "Domain" not in item1 and "Address" not in item1:
                    find_state = False
                    for item2 in pseudo_dict[key]:
                        if not is_valid_number(item2) and item2.replace(" ", "") in filtered_sig and item1.replace(" ", "") not in black_list and len(filtered_sig[item2.replace(" ", "")])<10 and "Domain" not in item1 and "Address" not in item1:
                            z3_result, reason_dict = z3_prove.check_equivalence(item1, item2)
                            if z3_result:
                                eqs_dict[key]['eq_num'] += 1
                                eqs_dict[key]['eq_list'].append(item1)
                                eqs_dict[key]['all_num'] += 1
                                find_state = True
                                break
                    if find_state == False:
                        eqs_dict[key]['all_num'] += 1
            if eqs_dict[key]['all_num'] > 0:
                eqs_dict[key]['percent'] = eqs_dict[key]['eq_num'] / eqs_dict[key]['all_num']
            else:
                eqs_dict[key]['percent'] = 0.0            
    
    return eqs_dict


def get_correct_result_z3(patch_eqs_dict, vul_eqs_dict):
    correct_result = False

    patch_eq_num = 0
    patch_all_num = 0
    vul_eq_num = 0
    vul_all_num = 0

    for key in patch_eqs_dict:
        patch_eq_num += patch_eqs_dict[key]['eq_num']
        patch_all_num += patch_eqs_dict[key]['all_num']
    
    for key in vul_eqs_dict:
        vul_eq_num += vul_eqs_dict[key]['eq_num']
        vul_all_num += vul_eqs_dict[key]['all_num']
    
    if patch_all_num > 0:
        patch_percent = patch_eq_num / patch_all_num
    else:
        patch_percent = 0
    if vul_all_num > 0:
        vul_percent = vul_eq_num / vul_all_num
    else:
        vul_percent = 0

    # if (patch_percent > vul_percent and min(patch_all_num, vul_all_num) > 3) or (patch_eq_num > vul_eq_num and max(patch_eq_num, vul_eq_num) > 0):
    #     return True, "patched version", {'type': 'more eqs', 'patch': patch_eqs_dict, 'vul': vul_eqs_dict}
    # elif (patch_percent < vul_percent and min(patch_all_num, vul_all_num) > 3) or (patch_eq_num < vul_eq_num and max(patch_eq_num, vul_eq_num) > 0):
    #     return True, "pre-patch version", {'type': 'more eqs', 'patch': patch_eqs_dict, 'vul': vul_eqs_dict}
    # else:
    #     return True, "not sure", {'type': 'more eqs', 'patch': patch_eqs_dict, 'vul': vul_eqs_dict}
    if patch_eq_num > vul_eq_num and max(patch_eq_num, vul_eq_num) > 0:
        return True, "patched version", {'type': 'more eqs', 'patch': patch_eqs_dict, 'vul': vul_eqs_dict}
    elif patch_eq_num < vul_eq_num and max(patch_eq_num, vul_eq_num) > 0:
        return True, "pre-patch version", {'type': 'more eqs', 'patch': patch_eqs_dict, 'vul': vul_eqs_dict}
    else:
        return True, "not sure", {'type': 'more eqs', 'patch': patch_eqs_dict, 'vul': vul_eqs_dict}


def z3_result_compare(patch_json_path, vul_json_path, res_path, number_item):
    # 读取JSON文件
    with open(patch_json_path, 'r') as f:
        patch_data = json.load(f)
    with open(vul_json_path, 'r') as f:
        vul_data = json.load(f)

    correct_result = False

    patch_source_dict = dict()
    patch_pseudo_dict = dict()
    for code_line in patch_data:
        patch_source_dict = combine_dict(patch_source_dict, patch_data[code_line]["source code"])
        patch_pseudo_dict = combine_dict(patch_pseudo_dict, patch_data[code_line]["pseudo code"])
    
    vul_source_dict = dict()
    vul_pseudo_dict = dict()
    for code_line in vul_data:
        vul_source_dict = combine_dict(vul_source_dict, vul_data[code_line]["source code"])
        vul_pseudo_dict = combine_dict(vul_pseudo_dict, vul_data[code_line]["pseudo code"])
    
    # sig_state, sig_dict = get_patch_sig_z3(patch_source_dict, vul_source_dict)

    # if sig_state:
    #     res_flag, result, reason_dict = find_sigs_z3(sig_dict, patch_pseudo_dict, vul_pseudo_dict)
    #     if res_flag:
    #         correct_result = result
    #     reason = reason_dict
    
    if not correct_result:
        # correct_result = "not sure"
        # reason = "not sure"
        reason = "more eqs"

        patch_eqs_dict = get_eqs_z3(patch_source_dict, patch_pseudo_dict)
        vul_eqs_dict = get_eqs_z3(vul_source_dict, vul_pseudo_dict)

        res_flag, result, reason_dict = get_correct_result_z3(patch_eqs_dict, vul_eqs_dict)

        if res_flag:
            correct_result = result
            reason = reason_dict


    # 保存结果
    result = {
        'correct_result': correct_result,
        'analysis reason': reason
    }

    # 保存结果到文件
    res_file_path = os.path.join(res_path, "z3_res_" + number_item + ".json")
    with open(res_file_path, 'w') as f:
        json.dump(result, f, indent=4)
    return result







def patch_verification_result_z3_percent(data_dir):

    for cve_dir_name in tqdm(os.listdir(data_dir)):

        # if "CVE-2016-4447" not in cve_dir_name:
        #     continue

        cve_dir_path = os.path.join(data_dir, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"

        result_json_path = os.path.join(cve_dir_path, "result.json")
        if not os.path.exists(result_json_path):
            print(f"Warning: result.json not found in {cve_dir_path}")
            continue
        # Read result.json
        with open(result_json_path, 'r', encoding='utf-8') as f:
            try:
                result_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in {result_json_path}")
                continue

        # Get all .idapseudo files
        idapseudo_files = glob.glob(os.path.join(cve_dir_path, "*.lineidapseudo"))
        # patch_path_list = glob.glob(os.path.join(cve_dir_path, "*_patched.c"))
        # vul_path_list = glob.glob(os.path.join(cve_dir_path, "*_vul.c"))
        

        detection_rev_res = False

        # 定义文件名匹配模式
        llm_pattern = r'llm_res_(\d+)\.txt'
        pseudo_pattern = r'pseudo_sliced_(\d+)\.txt'
        ze_patch_pattern = r'z3_patch_(\d+)\.txt'
        
        for pseudo_path in idapseudo_files:
            # Get directory and filename without extension
            dir_path = os.path.dirname(pseudo_path)
            filename = os.path.splitext(os.path.basename(pseudo_path))[0]
            patch_res_dir = os.path.join(dir_path, "apatch_res_" + filename, "temp")
            vul_res_dir = os.path.join(dir_path, "avul_res_" + filename, "temp")

            res_dir = os.path.join(dir_path, "ares_" + filename)
            if not os.path.exists(res_dir):
                continue
            
            llm_file_pairs = {}
            # 遍历目录
            for root, dirs, files in os.walk(vul_res_dir):
                for filename in files:
                    # 匹配llm文件
                    llm_match = re.match(llm_pattern, filename)
                    if llm_match:
                        number = llm_match.group(1)
                        if number not in llm_file_pairs:
                            llm_file_pairs[number] = {'llm': None, 'pseudo': None}
                        llm_file_pairs[number]['llm'] = os.path.join(root, filename)
                    
                    # 匹配pseudo文件
                    pseudo_match = re.match(pseudo_pattern, filename)
                    if pseudo_match:
                        number = pseudo_match.group(1)
                        if number not in llm_file_pairs:
                            llm_file_pairs[number] = {'llm': None, 'pseudo': None}
                        llm_file_pairs[number]['pseudo'] = os.path.join(root, filename)

            for number_item in llm_file_pairs:
                vul_res_item_path = os.path.join(patch_res_dir, "llm_res_" + number_item + ".txt")
                if os.path.exists(vul_res_item_path):
                    detection_rev_res = llm_detection.persent_compare(llm_file_pairs[number]['llm'], vul_res_item_path, res_dir, number_item)




            if not detection_rev_res:

                file_pairs = {}
                for root, dirs, files in os.walk(res_dir):
                    for filename in files:
                        # 匹配llm文件
                        z3_match = re.match(ze_patch_pattern, filename)
                        if z3_match:
                            number = z3_match.group(1)
                            if number not in file_pairs:
                                file_pairs[number] = {'patch': None}
                            file_pairs[number]['patch'] = os.path.join(root, filename)

                for number_item in file_pairs:
                    vul_path = os.path.join(res_dir, "z3_vul_" + number_item + ".txt")
                    if os.path.exists(vul_path):
                        print(f"Detection the {vul_path}")
                        # if os.path.exists(os.path.join(res_dir, "z3_res_"+number_item+".json")):
                        #     continue
                        detection_rev_res = z3_result_compare(file_pairs[number]['patch'], vul_path, res_dir, number_item)
                    else:
                        print("The vul file is not exist!")
            else:
                print("The detection is correct!")




def patch_verification_result_z3(data_dir):

    for cve_dir_name in tqdm(os.listdir(data_dir)):
        cve_dir_path = os.path.join(data_dir, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"

        result_json_path = os.path.join(cve_dir_path, "result.json")
        if not os.path.exists(result_json_path):
            print(f"Warning: result.json not found in {cve_dir_path}")
            continue
        # Read result.json
        with open(result_json_path, 'r', encoding='utf-8') as f:
            try:
                result_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in {result_json_path}")
                continue

        # Get all .idapseudo files
        idapseudo_files = glob.glob(os.path.join(cve_dir_path, "*.lineidapseudo"))
        # patch_path_list = glob.glob(os.path.join(cve_dir_path, "*_patched.c"))
        # vul_path_list = glob.glob(os.path.join(cve_dir_path, "*_vul.c"))

    

        # 定义文件名匹配模式
        # llm_pattern = r'llm_res_(\d+)\.txt'
        # pseudo_pattern = r'pseudo_sliced_(\d+)\.txt'
        ze_patch_pattern = r'z3_patch_(\d+)\.txt'
        
        for pseudo_path in idapseudo_files:
            # Get directory and filename without extension
            dir_path = os.path.dirname(pseudo_path)
            filename = os.path.splitext(os.path.basename(pseudo_path))[0]

            res_dir = os.path.join(dir_path, "ares_" + filename)
            if not os.path.exists(res_dir):
                continue
            
            file_pairs = {}
            for root, dirs, files in os.walk(res_dir):
                for filename in files:
                    # 匹配llm文件
                    z3_match = re.match(ze_patch_pattern, filename)
                    if z3_match:
                        number = z3_match.group(1)
                        if number not in file_pairs:
                            file_pairs[number] = {'patch': None}
                        file_pairs[number]['patch'] = os.path.join(root, filename)

            for number_item in file_pairs:
                vul_path = os.path.join(res_dir, "z3_vul_" + number_item + ".txt")
                if os.path.exists(vul_path):
                    print(f"Detection the {vul_path}")
                    if os.path.exists(os.path.join(res_dir, "z3_res_"+number_item+".json")):
                        os.remove(os.path.join(res_dir, "z3_res_"+number_item+".json"))
                    detection_rev_res = z3_result_compare(file_pairs[number]['patch'], vul_path, res_dir, number_item)
                else:
                    print("The vul file is not exist!")



def z3_sig_filter(z3_sig_path, cve_id):

    sigs_dict = dict()

    # 读取JSON文件
    with open(z3_sig_path, 'r') as f:
        sig_data = json.load(f)


    for source_line in sig_data:
        for code_type in sig_data[source_line]:
            for sig_type in sig_data[source_line][code_type]:
                for sig_item in sig_data[source_line][code_type][sig_type]:
                    if sig_item.replace(" ","") not in sigs_dict:
                        sigs_dict[sig_item.replace(" ","")] = [cve_id]
                    else:
                        sigs_dict[sig_item.replace(" ","")].append(cve_id)
    
    return sigs_dict


def is_valid_number(s):
    """
    判断一个字符串是否是数字，包括十进制和十六进制（允许带'u'后缀）。
    """
    # 检查是否有 u 后缀，去掉后缀再解析
    if s.endswith('u') or s.endswith('U'): 
        s = s[:-1]  # 去掉末尾的 'u'/'U'

    # 判断是否为十进制数字
    if s.isdigit():
        return True

    # 判断是否为合法的十六进制数字
    if s.startswith('0x') or s.startswith('0X'):  # 检查是否以 0x / 0X 开头
        try:
            int(s, 16)  # 尝试用 base=16 解析
            return True
        except ValueError:
            return False

    # 不符合十进制或十六进制规则
    return False


def filter_sig_z3(data_dir, tmp_dir):

    all_sig_dict = dict()

    for cve_dir_name in tqdm(os.listdir(data_dir)):
        cve_dir_path = os.path.join(data_dir, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"

        result_json_path = os.path.join(cve_dir_path, "result.json")
        if not os.path.exists(result_json_path):
            print(f"Warning: result.json not found in {cve_dir_path}")
            continue
        # Read result.json
        with open(result_json_path, 'r', encoding='utf-8') as f:
            try:
                result_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in {result_json_path}")
                continue

        # Get all .idapseudo files
        idapseudo_files = glob.glob(os.path.join(cve_dir_path, "*.lineidapseudo"))
        # patch_source_list = glob.glob(os.path.join(cve_dir_path, "*_patched.c"))
        # vul_source_list = glob.glob(os.path.join(cve_dir_path, "*_vul.c"))

        # if len(patch_source_list) > 0:
        #     with open(patch_source_list[0], 'r', encoding='utf-8') as file:
        #         file_contents = file.read()

        #         source_lex = lexer_analysis.lex_analysis_one(file_contents, tmp_dir)

        #         source_lex_constant = []

        #         for line in source_lex.strip().split('\n'):
        #             if line.strip():
        #                 token, token_type = line.strip().split('\t')
        #                 source_lex_constant.append(token+"\t"+token_type+"\n")

                
        #         patch_source_sigs = extract_eq.extract_statements(source_lex_constant)

        # with open(os.path.join(cve_dir_path, "_patched_z3.json"), "w") as jsonfile:
        #     json.dump(patch_source_sigs, jsonfile, indent=4)

        # if len(vul_source_list) > 0:
        #     with open(vul_source_list[0], 'r', encoding='utf-8') as file:
        #         file_contents = file.read()
        #         source_lex = lexer_analysis.lex_analysis_one(file_contents, tmp_dir)

        #         source_lex_constant = []

        #         for line in source_lex.strip().split('\n'):
        #             if line.strip():
        #                 token, token_type = line.strip().split('\t')
        #                 source_lex_constant.append(token+"\t"+token_type+"\n")

                
        #         patch_source_sigs = extract_eq.extract_statements(source_lex_constant)

        # with open(os.path.join(cve_dir_path, "_vul_z3.json"), "w") as jsonfile:
        #     json.dump(vul_source_sigs, jsonfile, indent=4)

        # 定义文件名匹配模式
        # llm_pattern = r'llm_res_(\d+)\.txt'
        # pseudo_pattern = r'pseudo_sliced_(\d+)\.txt'
        ze_patch_pattern = r'z3_patch_(\d+)\.txt'
        
        for pseudo_path in idapseudo_files:
            # Get directory and filename without extension
            dir_path = os.path.dirname(pseudo_path)
            filename = os.path.splitext(os.path.basename(pseudo_path))[0]

            res_dir = os.path.join(dir_path, "ares_" + filename)
            if not os.path.exists(res_dir):
                continue
            
            file_pairs = {}
            for root, dirs, files in os.walk(res_dir):
                for filename in files:
                    # 匹配llm文件
                    z3_match = re.match(ze_patch_pattern, filename)
                    if z3_match:
                        number = z3_match.group(1)
                        if number not in file_pairs:
                            file_pairs[number] = {'patch': None}
                        file_pairs[number]['patch'] = os.path.join(root, filename)

            for number_item in file_pairs:
                vul_path = os.path.join(res_dir, "z3_vul_" + number_item + ".txt")
                if os.path.exists(vul_path):
                    print(f"Detection the {vul_path}")
                    # if os.path.exists(os.path.join(res_dir, "z3_res_"+number_item+".json")):
                    #     continue
                    sig_dict_tmp1 = z3_sig_filter(file_pairs[number]['patch'], result_data["CVE_id"])
                    sig_dict_tmp2 = z3_sig_filter(vul_path, result_data["CVE_id"])

                    for key in sig_dict_tmp1:
                        if key in all_sig_dict:
                            all_sig_dict[key] = list(set(all_sig_dict[key] + sig_dict_tmp1[key]))
                        else:
                            all_sig_dict[key] = sig_dict_tmp1[key]
                    
                    for key in sig_dict_tmp2:
                        if key in all_sig_dict:
                            all_sig_dict[key] = list(set(all_sig_dict[key] + sig_dict_tmp2[key]))
                        else:
                            all_sig_dict[key] = sig_dict_tmp2[key]

                else:
                    print("The vul file is not exist!")

    # 保存结果到文件
    res_file_path = "z3_sig_filter.json"
    with open(res_file_path, 'w') as f:
        json.dump(all_sig_dict, f, indent=4)






patch_verification("/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data")

# patch_verification_z3("/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data", "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/tmp")


# filter_sig_z3("/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data", "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/tmp")


# patch_verification_result_z3("/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data")