import os, sys, json

sys.path.append("code/code/code_compare/clexer")
sys.path.append("code/code/code_compare")

import scanner
import extract_eq

def lex_analysis_one(code_line, tmp_dir):
    tmp_code_file = os.path.join(tmp_dir, "tmp_code.c")
    tmp_lex_file = os.path.join(tmp_dir, "tmp_lexical.txt")

    with open(tmp_code_file, "w") as file:
        file.write(code_line)

    scanner.scan(tmp_code_file, tmp_lex_file)

    with open(tmp_lex_file, "r") as file:
        data = file.read()

        return data


def combine_dict(dict1, dict2):
    for key in dict2:
        if key not in dict1:
            dict1[key] = dict2[key]
        else:
            dict1[key].extend(dict2[key])

    return dict1

def lexical_analysis(code_json, output_file_path, constant_dict, tmp_dir):

    statements_dict = dict()

    if "new match result" in code_json:
        new_match_result = code_json["new match result"]
        for source_line in  new_match_result:
            pseudo_line_list = new_match_result[source_line]

            source_lex = lex_analysis_one(source_line, tmp_dir)

            source_lex_constant = []

            for line in source_lex.strip().split('\n'):
                if line.strip():
                    token, token_type = line.strip().split('\t')
                    if token in constant_dict:
                        source_lex_constant.append(constant_dict[token]+"\t"+token_type+"\n")
                    else:
                        source_lex_constant.append(token+"\t"+token_type+"\n")

            
            source_statement = extract_eq.extract_statements(source_lex_constant)

            
            if isinstance(pseudo_line_list, list):
                pseudo_statement_all = dict()
                for pseudo_line in pseudo_line_list:
                    pseudo_lex = lex_analysis_one(pseudo_line.split("//")[0], tmp_dir)
                    
                    pseudo_lex_new = []
                    for line in pseudo_lex.strip().split('\n'):
                        if line.strip():
                            token, token_type = line.strip().split('\t')
                            pseudo_lex_new.append(token+"\t"+token_type+"\n")

                    pseudo_statement = extract_eq.extract_statements_pseudo(pseudo_lex_new)
                    pseudo_statement_all = combine_dict(pseudo_statement_all, pseudo_statement)
            else:
                pseudo_line = pseudo_line_list
                pseudo_lex = lex_analysis_one(pseudo_line.split("//")[0], tmp_dir)
                    
                pseudo_lex_new = []
                for line in pseudo_lex.strip().split('\n'):
                    if line.strip():
                        token, token_type = line.strip().split('\t')
                        pseudo_lex_new.append(token+"\t"+token_type+"\n")
                pseudo_statement = extract_eq.extract_statements_pseudo(pseudo_lex_new)
                pseudo_statement_all = pseudo_statement


            statements_dict[source_line] = {
                "source code": source_statement,
                "pseudo code": pseudo_statement_all,
            }
                
    with open(output_file_path, "w") as file:
        file.write(json.dumps(statements_dict, indent=4))

    return statements_dict


