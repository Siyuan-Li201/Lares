import os
import sys
import json
from tqdm import tqdm
import glob

sys.path.append("code/patch_verification")
sys.path.append("code/llm_location")

import patch_match
import llm_detection



def patch_detection(source_path, pseudo_path, res_path):

    os.makedirs(res_path, exist_ok=True)
    file_path = os.path.join(res_path, "temp")
    os.makedirs(file_path, exist_ok=True)

    detection_res = llm_detection.get_prompt(source_path, pseudo_path, file_path)

    # detection_res = json.load(open(os.path.join(res_path, "filepath.json"), "r"))

    verify_res = os.path.join(res_path, "verified_matched_dict.json")

    match_res = os.path.join(res_path, "matched_results.json")

    source_file = detection_res["source_sliced"]
    pseudo_file_list = detection_res["pseudo_sliced_list"]
    llm_res_list = detection_res["llm_res_list"]



def patch_detection_old(source_path, pseudo_path, res_path):


    detection_times = 5
    # 初始化 tqdm 进度条
    progress_bar = tqdm(total=detection_times, desc="Processing")

    while detection_times:
        detection_times -= 1
        progress_bar.update(1)

        try_once_dir = os.path.join(res_path, "llm_"+str(detection_times))
        os.makedirs(try_once_dir, exist_ok=True)
        file_path = os.path.join(try_once_dir, "temp")
        os.makedirs(file_path, exist_ok=True)

        detection_res = llm_detection.get_prompt(source_path, pseudo_path, file_path)

        # detection_res = json.load(open(os.path.join(res_path, "filepath.json"), "r"))

        verify_res = os.path.join(try_once_dir, "verified_matched_dict.json")

        match_res = os.path.join(try_once_dir, "matched_results.json")

        source_file = detection_res["source_sliced"]
        pseudo_file_list = detection_res["pseudo_sliced_list"]
        llm_res_list = detection_res["llm_res_list"]

        for i in range(len(pseudo_file_list)):
            detected_flag, matched_dict = patch_match.match_patch(source_file, pseudo_file_list[i], llm_res_list[i], match_res, verify_res)

            if detected_flag:
                progress_bar.update(detection_times)
                print("Matched dict: ", matched_dict)
                print("Patch detected.")

                with open(os.path.join(res_path, "result.json"), 'w', encoding='utf-8') as f:
                    json.dump({"result":"Patched", "sig":matched_dict}, f, ensure_ascii=False, indent=4)
                return True

    print("Patch not detected.")
    with open(os.path.join(res_path, "result.json"), 'w', encoding='utf-8') as f:
        json.dump({"result":"Vul"}, f, ensure_ascii=False, indent=4)
    return False


def patch_detection_one(source_path, pseudo_path, res_path):

    if not os.path.exists(res_path):
        os.makedirs(res_path, exist_ok=True)

    patch_detection(source_path, pseudo_path, res_path)



def process_idapseudo_files(cve_dir_path):
    # Get all .idapseudo files
    idapseudo_files = glob.glob(os.path.join(cve_dir_path, "*.lineidapseudo"))
    
    for pseudo_path in idapseudo_files:
        # Get directory and filename without extension
        dir_path = os.path.dirname(pseudo_path)
        filename = os.path.splitext(os.path.basename(pseudo_path))[0]
        
        # Check for patched code file
        patched_file = glob.glob(os.path.join(dir_path, "*patched_code_enhanced.c"))
        if patched_file:
            # Create result directory for patched analysis
            res_dir = os.path.join(dir_path, "apatch_res_" + filename)
            
            if not os.path.exists(res_dir):
                os.makedirs(res_dir)
            
            # if not os.path.exists(os.path.join(res_dir, "temp", "llm_res_1.txt")):
            try:
        # Call external function for patched code analysis
                patch_detection_one(patched_file[0], pseudo_path, res_dir)
            except:
                print("Error in patch_detection_one")
                continue

        # Check for vulnerable code file    
        vul_file = glob.glob(os.path.join(dir_path, "*vul_code_enhanced.c"))
        if vul_file:
            # Create result directory for vulnerable analysis
            res_dir = os.path.join(dir_path, "avul_res_" + filename) 
            if not os.path.exists(res_dir):
                os.makedirs(res_dir)
            
            # if not os.path.exists(os.path.join(res_dir, "temp", "llm_res_1.txt")):
                # Call external function for vulnerable code analysis
            try:
                patch_detection_one(vul_file[0], pseudo_path, res_dir)
            except:
                print("Error in patch_detection_one")
                continue

def patch_detection_dataset(data_dir):

    for cve_dir_name in tqdm(os.listdir(data_dir)):

        if "CVE-2016-4447" not in cve_dir_name:
            continue

        cve_dir_path = os.path.join(data_dir, cve_dir_name)
        if not os.path.isdir(cve_dir_path) or not cve_dir_name.startswith("CVE"):
            continue  # Skip if not a directory or doesn't start with "CVE"
        process_idapseudo_files(cve_dir_path)


if __name__ == "__main__":
    cve_dir = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data"
    patch_detection_dataset(cve_dir)

    
    