import os
import sys
import json
from tqdm import tqdm

sys.path.append("code/patch_verification")
sys.path.append("code/llm_location")

import patch_match
import llm_detection



def patch_detection(source_path, pseudo_path, res_path):
    
    file_path = os.path.join(res_path, "temp")


    detection_times = 5
    # 初始化 tqdm 进度条
    progress_bar = tqdm(total=detection_times, desc="Processing")

    while detection_times:
        detection_times -= 1
        progress_bar.update(1)

        detection_res = llm_detection.get_prompt(source_path, pseudo_path, file_path)

        # detection_res = json.load(open(os.path.join(res_path, "filepath.json"), "r"))

        verify_res = os.path.join(res_path, "verified_matched_dict.json")

        match_res = os.path.join(res_path, "matched_results.json")

        source_file = detection_res["source_sliced"]
        pseudo_file_list = detection_res["pseudo_sliced_list"]
        llm_res_list = detection_res["llm_res_list"]

        for i in range(len(pseudo_file_list)):
            detected_flag, matched_dict = patch_match.match_patch(source_file, pseudo_file_list[i], llm_res_list[i], match_res, verify_res)

            if detected_flag:
                progress_bar.update(detection_times)
                print("Matched dict: ", matched_dict)
                print("Patch detected.")
                return True



            

    print("Patch not detected.")
    return False


def patch_detection_one(source_path, pseudo_path, res_path):
    if os.path.exists(os.path.join(res_path, "temp")):
        os.system("rm -rf " + res_path)

    os.makedirs(res_path, exist_ok=True)
    os.makedirs(os.path.join(res_path, "temp"), exist_ok=True)

    patch_detection(source_path, pseudo_path, res_path)


if __name__ == "__main__":

    data_path = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/data/CVE-2013-6450_tls1_change_cipher_state_1"


    res_path = "/media/REMOVED/4A7AC8957AC87F67/work2024/code/llm_api/res/CVE-2013-6450_tls1_change_cipher_state_1/clang_x86_O0_vul"


    # ssl3_send_client_key_exchange
    source_path = os.path.join(data_path, "tls1_change_cipher_state_patched_code.c")
    # source_path = os.path.join(data_path, "patch.c")
    # pseudo_path = os.path.join(data_path, "pseudocode_vul.c")
    pseudo_path = os.path.join(data_path, "x86_clang_O0_openssl_1.0.1e_strip_tls1_change_cipher_state_0x080fd000.idapseudo")
    # pseudo_path = os.path.join(data_path, "x86_clang_O0_openssl_1.0.1f_strip_tls1_change_cipher_state_0x080fd3a0.idapseudo")

    patch_detection_one(source_path, pseudo_path, res_path)
    