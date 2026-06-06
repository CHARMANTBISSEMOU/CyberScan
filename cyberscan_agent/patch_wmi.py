import os

file_path = "win_scanner.py"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add import pythoncom
if "import pythoncom" not in content:
    content = content.replace("import ctypes\nfrom datetime", "import ctypes\nimport pythoncom\nfrom datetime")

# 2. Add pythoncom.CoInitialize() to get_system_info
if "def get_system_info():\n    \"\"\"Récupère les infos OS, pare-feu détaillé, mises à jour manquantes\"\"\"\n    try:\n        pythoncom.CoInitialize()" not in content:
    content = content.replace(
        "def get_system_info():\n    \"\"\"Récupère les infos OS, pare-feu détaillé, mises à jour manquantes\"\"\"\n    result = {",
        "def get_system_info():\n    \"\"\"Récupère les infos OS, pare-feu détaillé, mises à jour manquantes\"\"\"\n    try:\n        pythoncom.CoInitialize()\n    except Exception:\n        pass\n    result = {"
    )

# 3. Add pythoncom.CoInitialize() to get_hardware_info
if "def get_hardware_info():\n    \"\"\"Récupère RAM, CPU et Disques\"\"\"\n    try:\n        pythoncom.CoInitialize()" not in content:
    content = content.replace(
        "def get_hardware_info():\n    \"\"\"Récupère RAM, CPU et Disques\"\"\"\n    hw = {",
        "def get_hardware_info():\n    \"\"\"Récupère RAM, CPU et Disques\"\"\"\n    try:\n        pythoncom.CoInitialize()\n    except Exception:\n        pass\n    hw = {"
    )

# 4. Add pythoncom.CoInitialize() to get_usb_devices
if "def get_usb_devices():\n    \"\"\"Récupère les périphériques USB connectés via WMI\"\"\"\n    try:\n        pythoncom.CoInitialize()" not in content:
    content = content.replace(
        "def get_usb_devices():\n    \"\"\"Récupère les périphériques USB connectés via WMI\"\"\"\n    usb_devices = []",
        "def get_usb_devices():\n    \"\"\"Récupère les périphériques USB connectés via WMI\"\"\"\n    try:\n        pythoncom.CoInitialize()\n    except Exception:\n        pass\n    usb_devices = []"
    )

# 5. Add pythoncom.CoInitialize() to get_antivirus_status
if "def get_antivirus_status():\n    \"\"\"Vérifie le statut de l'antivirus (Windows Defender ou autre)\"\"\"\n    try:\n        pythoncom.CoInitialize()" not in content:
    content = content.replace(
        "def get_antivirus_status():\n    \"\"\"Vérifie le statut de l'antivirus (Windows Defender ou autre)\"\"\"\n    result = {",
        "def get_antivirus_status():\n    \"\"\"Vérifie le statut de l'antivirus (Windows Defender ou autre)\"\"\"\n    try:\n        pythoncom.CoInitialize()\n    except Exception:\n        pass\n    result = {"
    )

# 6. Add pythoncom.CoInitialize() to get_installed_programs
if "def get_installed_programs():\n    \"\"\"Liste les programmes installés via le registre" not in content or "pythoncom.CoInitialize" not in content.split("def get_installed_programs():")[1]:
    content = content.replace(
        "def get_installed_programs():\n    \"\"\"Liste les programmes installés via le registre (instantané, remplace Win32_Product qui prend 2+ min)\"\"\"\n    programs = []",
        "def get_installed_programs():\n    \"\"\"Liste les programmes installés via le registre (instantané, remplace Win32_Product qui prend 2+ min)\"\"\"\n    try:\n        pythoncom.CoInitialize()\n    except Exception:\n        pass\n    programs = []"
    )

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)
print("win_scanner.py patched successfully.")
