# Lares

The code and dataset of the paper are at [https://anonymous.4open.science/r/Lares-DDDA](https://anonymous.4open.science/r/Lares-DDDA).

We introduce Lares, a novel patch presence testing framework, to verify whether 1-day vulnerabilities are patched. 

- Input: Binary to be detected, Project source path, and Patch diff file.
- Output: Whether the vulnerability is patched.

<br><br>

## 1. Introduction
- The directory code/ contains the complete code of the paper.
- The binaries are at [cross-opti](https://drive.google.com/file/d/1I_JPMhFMZ2axCpy3lRxxb_YpcS8ZjztZ/view?usp=drive_link) and [cross-arch](https://drive.google.com/file/d/120O1XOhSMLEs6PCozT6RNmIMVtOOTsoE/view?usp=drive_link) (Google Drive). The patch dataset are at _/patch/_
- The patches are at _patch/_. The new patches after 20241022 are at _code/dataset/_


<br><br>

## 2. Quick reproduction of the code

#### 2.1 Download the Pre-prepared examples
- Download the code from GitHub. Please keep the _code/data_ directory unmodified, as it stores preconfigured test samples for quickly 
- Download the required pip packages.
```
pip install tqdm
pip install pandas
pip install tree-sitter
pip install openpyxl
pip install z3-solver
```

#### 2.2 Have a quick start
```
python3 quick_start.py
# Patch Enhancement, Patch Location, and Patch Verification
# You can run every step in quick_start.py because the intermediate results are stored in the code/data directory.
# set the _run_llm_ to control whether react the llm process.
```
#### 2.3 Expected results
The result is default at _res/output.csv_
Part of the result is shown in _result.png_
```
cve_id,arch_name,compiler_name,optimization_level,project_name,version_name,function_name,patch_result,groundtruth,detection_result
CVE-2013-6449,x86,clang,O0,openssl,1.0.1e,ssl_get_algorithm2_0x080e7180,pre-patch version,pre-patch version,TN
CVE-2013-6449,x86,clang,O0,openssl,1.0.1f,ssl_get_algorithm2_0x080e7110,patched version,patched version,TP
CVE-2013-6449,x86,clang,O1,openssl,1.0.1e,ssl_get_algorithm2_0x0809e960,pre-patch version,pre-patch version,TN
CVE-2013-6449,x86,clang,O1,openssl,1.0.1f,ssl_get_algorithm2_0x0809e910,patched version,patched version,TP
CVE-2013-6449,x86,clang,O2,openssl,1.0.1e,ssl_get_algorithm2_0x080a2650,pre-patch version,pre-patch version,TN
CVE-2013-6449,x86,clang,O2,openssl,1.0.1f,ssl_get_algorithm2_0x080a2660,patched version,patched version,TP
CVE-2013-6449,x86,clang,O3,openssl,1.0.1e,ssl_get_algorithm2_0x080a9da0,pre-patch version,pre-patch version,TN
CVE-2013-6449,x86,clang,O3,openssl,1.0.1f,ssl_get_algorithm2_0x080a9da0,patched version,patched version,TP

```

<br><br>

## 3. Full process
The complete code can be found on GitHub, including Preprocessing, Patch Enhancement, Patch Location, Patch Verification, and Calculate Score.

#### 3.1 Installation
- Install Python package
- Set LLM user-key and IDA-Pro7.5 path in settings.py

#### 3.2 Prepare the datasets
- put the binaries to detect at _code/dataset/bin/_
- put the patches in _patch/_ at _code/dataset/patch/src/_
- put the source project with _.git_ at _code/dataset/source/_ (Use git clone so Lares can automately change versions)

#### 3.3 Run Lares
```
python3 full_run.py
```

<br><br>

## 4. Replicating the experiments of each RQ.
#### 4.1 Installation
- Install Python package
- Set LLM user-key and IDA-Pro7.5 path in settings.py
#### 4.2 Run evaluation scripts
```
# Replicating the experiments of RQ1
python3 test_rq1.py
# Replicating the experiments of RQ2
python3 test_rq2.py
# Replicating the experiments of RQ3
python3 test_rq3.py
# For RQ4, Calculate the timecost when running test_rq1.py. The LLM API in the example is for testing purposes only, and it may run slightly slower.
```

<br><br>

## 5. Run for your own dataset.
- put the binaries to detect at _code/dataset/bin/_
- put the source with _.git_ at _code/dataset/source/_ (Use git clone so Lares can automately change versions)
- put the patches at _code/dataset/patch/src/_
- add the vulnerability information in _code/dataset/patch/cve_data.csv and cve_data.xlsx
- python3 full_run.py