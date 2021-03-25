import os, sys, time

def main(domains=[]):
    TOOL_NAME = "findomain"

    targets = domains
    results = []

    for target in targets:
        if not target.startswith("http"):
            os.system(f"./chalicelib/bin/{TOOL_NAME} -t {target} -q >> chalicelib/{TOOL_NAME}/output-all.txt")
            os.system(f"sort -u chalicelib/{TOOL_NAME}/output-all.txt > chalicelib/{TOOL_NAME}/output.txt")
        else:
            pass
            
    file = open(f"chalicelib/{TOOL_NAME}/output.txt","r")
    lines = file.read().splitlines()

    for line in lines:
        results.append(line)

    os.system(f"rm chalicelib/{TOOL_NAME}/output-all.txt chalicelib/{TOOL_NAME}/output.txt")

    if len(results) > 0:
        print()
        print(f"{TOOL_NAME.upper()} ~ Found: %s matches." % (len(results)))
        print()
        return {
            "matches": len(results),
            "result": results,
        }
    else:
        return {"matches": 0, "result": []}