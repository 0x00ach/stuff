for x in s.plugins.vad().collect():
    if len(x) == 11:
        pid = str(x[0].pid)
        memory_type = str(x[7])
        mapped_data_type = str(x[8])
        rights = str(x[9])
        module = str(x[10])
        start_addr = hex(x[2].Start)
        if "EXECUTE" in rights:
            if memory_type == "Mapped" and mapped_data_type == "Exe" and rights == "EXECUTE_WRITECOPY":
                 continue
            print pid+":"+start_addr+":"+memory_type + ":" +mapped_data_type + ":"+rights + ":"+module 
