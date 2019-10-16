import os
from regipy.registry import RegistryHive
from datetime import datetime



def get_reg_timeline(date_min, duration_hours, hivespath="."):
    for i in os.listdir(hivespath):
        #pastis
        if i.startswith("51") or "NTUSER" in i:
            print("")
            print("--------------------------")
            print("        HIVE %s" % (i))
            print("--------------------------")
            print("")
            reg = RegistryHive(i)
            for entry in reg.recurse_subkeys():
                mtime = entry.timestamp.replace(tzinfo=None)
                delta = date_min - mtime
                x = delta.total_seconds()
                if x > 0:
                    continue
                if abs(divmod(delta.total_seconds(), 3600)[0]) > duration_hours:
                    continue
                print("%s\\%s" % (entry.path, entry.subkey_name))
                print("\t%s" % (entry.timestamp))

def get_persistence(hivespath="."):
    for i in os.listdir(hivespath):
        if "NTUSER" in i:
            reg = RegistryHive(hivespath+"\\"+i)
            print(i)
            try:
                sk = reg.get_key("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" )
                for v in sk.get_values():
                    print("HKUSRRUN : %s : %s" % (v.name, v.value))
            except:
                continue
                pass
            sk = reg.get_key("\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" )
            for v in sk.get_values():
                print("HKUSRRUNONCE : %s : %s" % (v.name, v.value))
            sk = reg.get_key("\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" )
            for v in sk.get_values():
                print("HKUSRRUNW64 : %s : %s" % (v.name, v.value))
            sk = reg.get_key("\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
            for v in sk.get_values():
                print("HKUSRRUNONCEW64 : %s : %s" % (v.name, v.value))

    reg = RegistryHive(hivespath+"\\SOFTWARE")
    sk = reg.get_key("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
    for v in sk.get_values():
        print("HKLMRUN : %s : %s" % (v.name, v.value))
    sk = reg.get_key("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run")
    for v in sk.get_values():
        print("HKLMRUNX64 : %s : %s" % (v.name, v.value))
    sk = reg.get_key("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    for v in sk.get_values():
        print("HKLMRUNONCE : %s : %s" % (v.name, v.value))
    sk = reg.get_key("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    for v in sk.get_values():
        print("HKLMRUNONCEW64 : %s : %s" % (v.name, v.value))

    for sk in reg.get_key('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options').iter_subkeys():
        sk2 = reg.get_key('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s' % (sk.name) )
        for v in sk2.get_values():
            if v.name.lower() == "debugger":
                print("REGIFEO : %s : %s" % (v.name, v.value))

    sk = reg.get_key("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
    for v in sk.get_values():
        if v.name == "Shell":
            if v.value.lower().rstrip(",")  not in ("explorer.exe", "c:\\windows\\system32\\explorer.exe"):
                print("HIJACK : %s : %s" % (v.name, v.value))
        elif v.name == "ShellInfrastructure":
            if v.value.lower().rstrip(",")  not in ("sihost.exe", "c:\\windows\\system32\\sihost.exe"):
                print("HIJACK : %s : %s" % (v.name, v.value))
        elif v.name == "Userinit":
            if v.value.lower().rstrip(",") not in ("userinit.exe", "c:\\windows\\system32\\userinit.exe"):
                print("HIJACK : %s : %s" % (v.name, v.value))

    sk = reg.get_key("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
    for v in sk.get_values():
        if v.name == "AppInit_DLLs":
                print("APPINITDLLS : %s : %s" % (v.name, v.value))
                break



    reg = RegistryHive(hivespath+"\\SYSTEM")
    try:
        sk = reg.get_key("SYSTEM\\ControlSet001\\Control\\Lsa\\OSConfig")
        for v in sk.get_values():
            if v.name == "Security Packages":
                    print("SECPACKAGESO : %s : %s" % (v.name, v.value))
                    break
    except:
        pass
    sk = reg.get_key("SYSTEM\\ControlSet001\\Control\\Lsa")
    for v in sk.get_values():
        if v.name == "Security Packages":
                print("SECPACKAGES : %s : %s" % (v.name, v.value))
                break

    for sk in reg.get_key('SYSTEM\\ControlSet001\\Services').iter_subkeys():
        sk2 = reg.get_key('SYSTEM\\ControlSet001\\Services\\%s' % (sk.name) )
        for v in sk2.get_values():
            if v.name.lower() == "imagepath":
                print("SERVICE : %s : %s" % (v.name, v.value))
            elif v.name.lower() == "servicedll":
                print("SERVICEDLL : %s : %s" % (v.name, v.value))
        try:
            sk2 = reg.get_key('SYSTEM\\ControlSet0001\\Services\\%s\\Parameters' % (sk.name) )
            for v in sk2.get_values():
                if v.name.lower() == "servicedll":
                    print("SERVICEDLLP : %s : %s" % (v.name, v.value))
        except:
            pass


date_min = datetime(2016, 1, 01, 0, 0, 0)
duration_hours = 24
get_reg_timeline(date_min, duration_hours)
get_persistence()
