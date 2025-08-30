import shutil
import sys
sys.path.append("code")

import s1_patch_preprocess
import s2_source_preprocess
import s3_binary_preprocess
import s4_patch_enhance
import s5_patch_location
import s6_reverse_location
import s7_patch_verification
import s8_calculate_score


if __name__ == "__main__":

    # Put binaries from cross-arch in code/dataset/bin to test RQ2
    binaries_cross_arch_path = ""
    shutil.copy(binaries_cross_arch_path, "code/dataset/bin")


    # input path
    data_directory = "code/data"
    #    - patch
    patch_path = "code/dataset/patch/src/"
    patch_info_path = "code/dataset/patch/sig/"
    #    - vul
    vul_path = "code/dataset/patch/cve_data.csv"
    vul_xlsx_file = "code/dataset/patch/cve_data.xlsx"
    #    - source
    source_path = "code/dataset/source"
    #    - binary
    bin_directory = "code/dataset/bin"
    # output path
    result_path = "res"


    # Step0. data preprocess
    s1_patch_preprocess.generate_json_files_from_c(patch_path, patch_info_path, data_directory, vul_path)
    s2_source_preprocess.source_preprocess_main(vul_xlsx_file, patch_info_path, source_path, "code/tmp", data_directory)
    s3_binary_preprocess.patch_prompt_generation(data_directory)
    s3_binary_preprocess.pseudo_prompt_generation(data_directory, bin_directory)
    s3_binary_preprocess.pseudo_code_line_number(data_directory)

    # Step1. patch enhance module
    s4_patch_enhance.source_enhanced_generation(data_directory)
    
    # Step2. patch location module
    s5_patch_location.patch_detection_dataset(data_directory)
    s6_reverse_location.reverse_detection(data_directory)

    # Step3. patch verification module
    s7_patch_verification.patch_verification(data_directory)
    s7_patch_verification.patch_verification_z3(data_directory, "code/tmp")
    s7_patch_verification.patch_verification_result_z3(data_directory)


    # calculate final score
    s8_calculate_score.calculate_all_result(data_directory, result_path)

    