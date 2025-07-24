# Lares

The code and dataset of the paper are at [https://anonymous.4open.science/r/Lares-DDDA](https://anonymous.4open.science/r/Lares-DDDA).

We introduce Lares, a novel patch presence testing framework, to verify whether 1-day vulnerabilities are patched. 

- Input: Binary to be detected, Project source path, and Patch diff file.
- Output: Whether the vulnerability is patched.

<br><br>

## 1. Introduction
- The directory code/ contains the complete code of the paper.
- The binaries are at [cross-opti](https://drive.google.com/file/d/1I_JPMhFMZ2axCpy3lRxxb_YpcS8ZjztZ/view?usp=drive_link) and [cross-arch](https://drive.google.com/file/d/120O1XOhSMLEs6PCozT6RNmIMVtOOTsoE/view?usp=drive_link). The patch dataset are at _/patch/_

  
<br><br>

## 2. Quick reproduction of the code

#### 2.1 Download the Pre-prepared examples

- The code with pre-prepared examples is here.
- Download the required pip packages.

#### 2.2 Have a quick start
```
python3 7_patch_verification.py
python3 8_calculate_score.py
```
#### 2.3 Expected results


<br><br>

## 3. Full process
