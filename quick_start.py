import sys
sys.path.append("code")

import s4_patch_enhance
import s5_patch_location
import s6_reverse_location
import s7_patch_verification
import s8_calculate_score

run_llm = False # set True when the llm api is ok.

if __name__ == "__main__":
    # input path
    data_directory = "code/data"
    # output path
    result_path = "res"

    # Step1. patch enhance module
    s4_patch_enhance.source_enhanced_generation(data_directory)
    
    # Step2. patch location module
    if run_llm:
        s5_patch_location.patch_detection_dataset(data_directory)
        s6_reverse_location.reverse_detection(data_directory)

    # Step3. patch verification module
    if run_llm:
        s7_patch_verification.patch_verification(data_directory)
    s7_patch_verification.patch_verification_z3(data_directory, "code/tmp")
    s7_patch_verification.patch_verification_result_z3(data_directory)

    # calculate final score
    s8_calculate_score.calculate_all_result(data_directory, result_path)

    