import os
import subprocess
import json
from Model_client import AzureClient

HASHCAT_MODES_TABLE = """
+----------------------+------------+
| Hash Type           | Mode Number |
+----------------------+------------+
| MD5                 | 0          |
| SHA-1               | 100        |
| SHA-256            | 1400       |
| SHA-512            | 1700       |
| NTLM                | 1000       |
| bcrypt              | 3200       |
| WPA/WPA2           | 2500       |
| GOST R 34.11-94    | 6900       |
| SHA3-256           | 5000       |
+----------------------+------------+
"""

class BaseModel:
    def __init__(self, data="", istool=False, tool_out=""):
        self.data = data
        self.istool = istool
        self.tool_out = tool_out

    def to_json(self):
        return json.dumps(self.__dict__)  # ✅ Ensures valid JSON

def identify_hash_type(hash_value):
   
    """Uses hashid to determine the most likely hash type and map it to Hashcat mode."""
    try:
        result = subprocess.run(
            ["hashid", hash_value], capture_output=True, text=True, check=True
        )
        output = result.stdout.strip()

        hashcat_modes = {
            "MD5": "0",
            "SHA-1": "100",
            "SHA-256": "1400",
            "SHA-512": "1700",
            "NTLM": "1000",
            "bcrypt": "3200",
            "WPA/WPA2": "2500",
            "GOST R 34.11-94": "6900",  # Hashcat mode for GOST
            "SHA3-256": "5000",  # Approximate mode for SHA3
        }

        detected_modes = []
        
        for line in output.split("\n"):
            for hash_name, mode in hashcat_modes.items():
                if hash_name in line:
                    detected_modes.append(mode)

        return detected_modes[0] if detected_modes else "Unknown"

    except subprocess.CalledProcessError:
        return "Unknown"  # Return "Unknown" if detection fails


def crack_hash(hash_value, hash_type=None, wordlist_path=None, additional_args=[]):
    result_data = {
        "status": "running",
        "hash_value": hash_value,
        "hash_type": hash_type,
        "wordlist": wordlist_path,
        "cracked_hashes": None,
        "debug": {}
    }

    if not hash_type:
        hash_type = identify_hash_type(hash_value)
        if hash_type == "Unknown":
            result_data["status"] = "error"
            result_data["debug"]["error"] = "Hash type detection failed. Provide a valid hash mode."
            return result_data
        result_data["hash_type"] = hash_type

    if not wordlist_path:
        wordlist_path = "rockyou.txt"

    # Determine if input is a single hash or a file
    if os.path.isfile(hash_value):
        command_crack = ["hashcat", "-m", str(hash_type), hash_value, wordlist_path] + additional_args
        command_show = ["hashcat", "-m", str(hash_type), hash_value, "--show"]
    else:
        command_crack = ["hashcat", "-m", str(hash_type), "-a", "0", hash_value, wordlist_path] + additional_args
        command_show = ["hashcat", "-m", str(hash_type), hash_value, "--show"]

    print("Running command:", " ".join(command_crack))
    
    try:
        # Step 1: Run Hashcat to attempt cracking
        crack_process = subprocess.run(command_crack, capture_output=True, text=True)

        result_data["debug"]["crack_stdout"] = crack_process.stdout
        result_data["debug"]["crack_stderr"] = crack_process.stderr

        if "No hashes loaded" in crack_process.stderr or "ERROR" in crack_process.stderr:
            result_data["status"] = "error"
            result_data["debug"]["error"] = "Hashcat was unable to process the hash. Check format or hash type."
            return result_data

        # Step 2: Retrieve cracked hashes
        result = subprocess.run(command_show, capture_output=True, text=True)
        output = result.stdout.strip()

        result_data["debug"]["show_stdout"] = result.stdout
        result_data["debug"]["show_stderr"] = result.stderr

        if not output:
            result_data["status"] = "not_cracked"
            suggestion = "Try using a different wordlist or explicitly providing the hash format."
            if wordlist_path and hash_type:
                suggestion = "The attack was unsuccessful. Consider adjusting parameters or using a larger wordlist."
            print(suggestion)
            return result_data

        result_data["status"] = "success"
        result_data["cracked_hashes"] = output
        return result_data

    except subprocess.CalledProcessError as e:
        result_data["status"] = "error"
        result_data["debug"]["error"] = f"Hashcat execution failed: {e.stderr.strip()}"
        return result_data

    except FileNotFoundError:
        result_data["status"] = "error"
        result_data["debug"]["error"] = "Hashcat is not installed or not in PATH."
        return result_data


def cracker(user_query):
    yield f"{json.dumps({'data': "Performing cracking task......", 'istool': False, 'tool_out': ''})}\n"
    print("Cracking task...... \n")

    client = AzureClient.get_client()
    deployment = AzureClient.deployment

    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": "You are a cyber bot specializing in password cracking."},
            {"role": "user", "content": user_query},
        ],
        functions=functions,
        stream=False
    )

    out = response.choices[0].message.function_call

    if out is not None:
       
        print("Executing hash cracking function...")
        params = json.loads(out.arguments)

        hash_value = params.get("hash_value", "")
        hash_type = params.get("hash_type")  # No need to check again
        wordlist_path = params.get("wordlist_path")  # No need to set default
        additional_args = params.get("additional_args", [])

        cracked_result = crack_hash(hash_value, hash_type, wordlist_path, additional_args)
        cracked_result_str = json.dumps(cracked_result, indent = 2)
        yield json.dumps({"data": "crack compeleted.", "istool": True, "tool_out": cracked_result_str}) + "\n"

        response = client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": "tell me what you is the observation is in this output Keep the explanation short. Do not include ethical discussions thsi just for learnig purposes."},
                {"role": "system", "content": f"The Hashcat command was executed.\nOutput:\n{cracked_result}"}
            ],
            stream=True
        )
        for chunk in response:
            if chunk.choices and hasattr(chunk.choices[0], "delta") and chunk.choices[0].delta:
                yield json.dumps({"data": chunk.choices[0].delta.content, "istool": False, "tool_out": ""}) + "\n"
        print(response.choices[0].message.content)



functions = [
    {
        "name": "crack_hash",
        "description": "Uses Hashcat to crack password hashes using a wordlist.",
        "parameters": {
            "type": "object",
            "properties": {
                "hash_value": {
                    "type": "string",
                    "description": "The hash to be cracked OR a file containing hashes."
                },
                "hash_type": {
                    "type": "integer",
                    "description": "Hash mode (e.g., 0 for MD5, 100 for SHA1, 1800 for SHA512). If not provided, the script will attempt to detect it automatically."
                },
                "wordlist_path": {
                    "type": "string",
                    "description": "Path to the wordlist file. If not provided, defaults to 'rockyou.txt'."
                },
                "additional_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of Hashcat arguments for customization."
                }
            },
            "required": ["hash_value"]
        }
    }
]
