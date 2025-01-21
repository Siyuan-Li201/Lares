import subprocess
import shutil
import json
import os

def run_joern_analysis(sourcePath, cpgPath, functionName, targetLines, resPath):
    # Run joern-parse command
    if not os.path.exists(cpgPath):
        parse_cmd = f"joern-parse --language c {sourcePath} --output {cpgPath}"
        try:
            subprocess.run(parse_cmd, shell=True, check=True)
            print("joern-parse executed successfully")
        except subprocess.CalledProcessError as e:
            print(f"joern-parse failed with error: {e}")
            return False
            
    # Copy and modify template file
    try:
        shutil.copyfile("joern_analysis_template.sc", "joern_analysis_tmp.sc")
        
        # Read template content
        with open("joern_analysis_tmp.sc", "r") as f:
            content = f.read()
            
        # Replace variables
        content = content.replace("<cpgPath_arg>", f'"{cpgPath}"')
        content = content.replace("<functionName_arh>", f'"{functionName}"') 
        content = content.replace("<targetLines_arg>", str(targetLines))
        content = content.replace("<resPath_arg>", f'"{resPath}"')
        
        # Write modified content
        with open("joern_analysis_tmp.sc", "w") as f:
            f.write(content)
            
        print("Template file modified successfully")
            
    except Exception as e:
        print(f"Failed to modify template file: {e}")
        return False
    
    # Run joern script
    script_cmd = "joern --script joern_analysis_tmp.sc"
    try:
        subprocess.run(script_cmd, shell=True, check=True)
        print("joern script executed successfully")
    except subprocess.CalledProcessError as e:
        print(f"joern script failed with error: {e}")
        return False
        
    # Read and print result json
    try:
        if os.path.exists(resPath):
            with open(resPath, "r") as f:
                result = json.load(f)
                print("Analysis result:")
                print(json.dumps(result, indent=2))
        else:
            print(f"Result file not found at {resPath}")
            return False
    except Exception as e:
        print(f"Failed to read result file: {e}")
        return False
        
    return True

if __name__ == "__main__":
    # Example usage
    sourcePath = "test.c"
    cpgPath = "cpg.bin" 
    functionName = "main"
    targetLines = [10, 20]
    resPath = "result.json"
    
    run_joern_analysis(sourcePath, cpgPath, functionName, targetLines, resPath)