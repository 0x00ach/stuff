import sys, os, json, time, threading, struct, platform

try:
    from pylab import *
    from rtlsdr import RtlSdr
except Exception as e:
    print "ImportError %s"%(e)
    print "Please install pylab, pyrtlsdr"
    print "Linux (pip): pip install pymatlab pyrtlsdr"
    print "Windows (pip): %pythondir%\\Scripts\\pip2.7.exe install pymatlab pyrtlsdr"
    sys.exit(1)

 
    
def get_terminal_size():
    """ getTerminalSize()
     - get width and height of console
     - works on linux,os x,windows,cygwin(windows)
     originally retrieved from:
     http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
    """
    current_os = platform.system()
    tuple_xy = None
    if current_os == 'Windows':
        tuple_xy = _get_terminal_size_windows()
        if tuple_xy is None:
            tuple_xy = _get_terminal_size_tput()
            # needed for window's python in cygwin's xterm!
    if current_os in ['Linux', 'Darwin'] or current_os.startswith('CYGWIN'):
        tuple_xy = _get_terminal_size_linux()
    if tuple_xy is None:
        print "default"
        tuple_xy = (80, 25)      # default value
    return tuple_xy
 
 
def _get_terminal_size_windows():
    try:
        from ctypes import windll, create_string_buffer
        # stdin handle is -10
        # stdout handle is -11
        # stderr handle is -12  
        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
        if res:
            (bufx, bufy, curx, cury, wattr,
             left, top, right, bottom,
             maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
            sizex = right - left + 1
            sizey = bottom - top + 1
            return sizex, sizey
    except:
        pass
        
        
gCacheFile = "cache.json"
gOutputFile = "output.txt"
gConfigFile = "config.json"
gSdr = None
gDetectionSoil = 0.05
gBandwidth = 2000000.0
gLearningPassesCount = 10
gSampleRate = 2400000
gGain = "auto"
gFrequencyRanges = []
gFrequencyIgnoreRanges = []
gApplicationName = "RTLSDRMONITOR"
gOutConsoleTextarea = ''
gMaxDbPower = 3
gRefreshDelay = 0.3
gMaxNameLength = 0
gUseCacheFile = False
gLastSweepTime = 0
gLogToFile = True

gCacheFileParam = "cachefile"
gOutputFileParam = "outfile"
gGainParam = "gain"
gSampleRateParam = "sample_rate"
gFrequencyRangesParam = "monitor_ranges"
gApplicationNameParam = "appName"
gMaxDbPowerParam = "default_max_db_power"
gRefreshDelayParam = "refreshdelay"
gUseCacheFileParam = "use_cachefile"
gDetectionSoilParam = "default_detection_soil"
gBandwidthParam = "bandwidth"
gLearningPassesCountParam = "learning_passes"
gLogToFileParam = "logToFile"
gFrequencyIgnoreRangesParam = "ignore_ranges"

def guifufute():
    global gApplicationName, gFrequencyRanges, gOutConsoleTextarea, gRefreshDelay, gMaxNameLength, gLastSweepTime, gGain, gBandwidth
    
    while True:
        term_x, term_y = get_terminal_size()
        # dirty
        if os.name == 'nt':
            os.system("cls")
        else:
            os.system('clear')
        width = gMaxNameLength+3+10+2+8
        splitter = width*'-'+'\n'
        bff = ''
        bff += gApplicationName+'\n'
        bff += splitter
        bff += 'Sweep %ds | Gain %s | Bndwth %.2fMHz | Rate %.2fM/s\n' % (gLastSweepTime, str(gGain), gBandwidth/1000000, gSampleRate/1000000)
        for crange in gFrequencyRanges:
            powr = int(crange["power"] * 10 / crange["maxDbPower"])
            if powr > 10:
                powr = 10
            if crange["power"] != 0 and powr == 0:
                powr = 1
            bff += crange['name']+' : '+(gMaxNameLength-len(crange["name"]))*' '+'['+powr*'#'+(10-powr)*' '+'] %.3fdb\n' % (crange["power"])
            bff += '    '+str(int(crange['start']))+'MHz\n'
            if crange['last'] != '':
                bff += '    Last hit: '+crange['last']+'\n'
        bff += splitter
        lines_display_count = term_y - bff.count('\n')-3
        pos = len(gOutConsoleTextarea)
        for c in range(lines_display_count):
            pos = gOutConsoleTextarea.rfind('\n',0,pos)
        if pos == 0:
            pos = -1
        bff += gOutConsoleTextarea[pos+1:]
        bff += splitter
        print bff
        time.sleep(gRefreshDelay)
    
def cleanoutpt():
    global gOutputFile
    open(gOutputFile,"wb")
    
def init_gSdr():
    global gSdr, gSampleRate, gGain, gui_thread, gLogToFile
    gui_thread = threading.Thread(target=guifufute)
    gui_thread.start()
    outpt("[+] Start!", False)
    outpt("[+] Loading configuration...", False)
    load_config()
    if gLogToFile is not False:
        outpt("[+] Reinitializing output file...", False)
        cleanoutpt()
    outpt("[+] Spawning GUI...")
    outpt(get_specs())
    outpt("[+] Starting RTLSDR...")
    gSdr = RtlSdr()
    gSdr.sample_rate = gSampleRate  # Hz
    gSdr.gGain = gGain
    return
    
def get_specs():
    global gSdr, gBandwidth, gGain, gDetectionSoil, gLearningPassesCount, gFrequencyRanges, gMaxNameLength, gFrequencyIgnoreRanges
    x = "Sample rate: "+str(gSampleRate)+"\n"
    x += "Gain: "+str(gGain)+" db\n"
    x += "Bandwith: "+str(gBandwidth)+"\n"
    x += "Default detection soil: "+str(gDetectionSoil)+"\n"
    x += "Learning loops: "+str(gLearningPassesCount)+"\n"
    x += "Loaded gFrequencyRanges:\n"
    
    for n in gFrequencyRanges:
        if len(n["name"]) > gMaxNameLength:
            gMaxNameLength = len(n["name"])
        x += '\t'+n["name"]+'\n'
        x += '\t\t'+str(n["start"])+'MHz => '+str(n["end"])+'MHz\n'
        x += '\t\t'+str(n["soil"])+'db detection soil\n'
    x += "Ignore ranges:\n"
    for n in gFrequencyIgnoreRanges:
         x += '\t'+str(n["start"])+'MHz => '+str(n["end"])+'MHz\n'
    return x
    
def close_gSdr():
    global gSdr
    gSdr.close()
    return
    
    
def read_range(range_start, range_end, samples_per_node=1024):
    global gSdr, gBandwidth, gFrequencyIgnoreRanges
    ignr = []
    for freq in gFrequencyIgnoreRanges:
        if (freq["start"] >= range_start and freq["start"] <= range_end) or (freq["end"] >= range_start and freq["end"] <= range_end):
            ignr.append([freq["start"]/1000000,freq["end"]/1000000])

    data = {}
    while range_start < range_end:
        gSdr.fc = range_start + (gBandwidth) / 2
        samples = gSdr.read_samples(samples_per_node*256)
        # Fs / Fc => pour rendering graphique si on veut
        power, freqs = psd(samples, NFFT=samples_per_node, Fs=gSdr.sample_rate/1000000, Fc=gSdr.fc/1000000)
        for x in range(len(power)):
            if freqs[x] > range_end/1000000 or freqs[x] < range_start/1000000:
                continue
            if len(ignr) != 0:
                ignf = False
                for n in ignr:
                    if freqs[x] >= n[0] and freqs[x] <= n[1]:
                        ignf = True
                        break
                if ignf is True:
                    continue
            data["%.3f" % (freqs[x])] = power[x]
        range_start = range_start + gBandwidth
    return data
    
def learn_from_frequencyRanges():
    global gSdr, gFrequencyRanges, gLearningPassesCount, full_data, gCacheFile, gUseCacheFile
    if gUseCacheFile is True:
        try:
            x = open(gCacheFile,"rb").read()
            full_data = json.loads(x)
            outpt("Using cached data!")
            return
        except:
            outpt("Could not read the cache file!")
            pass
        
    # 1st scan
    full_data = {}
    outpt("First scan!")
    for crange in gFrequencyRanges:
        full_data.update(read_range(crange["start"], crange["end"], 4096))
    outpt("Let's do it "+str(gLearningPassesCount)+" more times")
    # learning
    for x in range(gLearningPassesCount):
        tmp = {}
        for crange in gFrequencyRanges:
            tmp.update(read_range(crange["start"], crange["end"], 4096))
        for kay in tmp:
            if full_data.has_key(kay):
                if full_data[kay] > tmp[kay]:
                    continue
            full_data[kay] = tmp[kay]
        outpt('\t'+str(x)+' OK')
    open(gCacheFile,"wb").write(json.dumps(full_data))
    return
    
    
def outpt(msg, fileLog=True):
    global gOutputFile, gOutConsoleTextarea, gLogToFile
    if not msg.endswith("\n"):
        msg += '\n'
    gOutConsoleTextarea += msg
    gOutConsoleTextarea = gOutConsoleTextarea[-1000:]
    if fileLog is not True or gLogToFile is not True:
        return
    open(gOutputFile,"ab").write(msg)
    
    
def monitor_for_emission(timeout=10):
    global gSdr, gFrequencyRanges, gLastSweepTime
    if type(timeout) is not int:
        timeout = -1
    if timeout < 0:
        timeout = 0xFFFFFFFF
    t = time.time()
    while time.time() - t < timeout:
        x = time.time()
        for n in range(len(gFrequencyRanges)):
            mxpowr = 0
            mxlst = ''
            ndata = read_range(gFrequencyRanges[n]["start"], gFrequencyRanges[n]["end"])
            for kay in ndata:
                if full_data[kay]+gFrequencyRanges[n]["soil"] < ndata[kay]:
                    msg = time.strftime("%a, %d %b %Y %H:%M:%S")+" :: EMISSION: "+str(kay)+" MHz ("+gFrequencyRanges[n]["name"]+")\n"
                    msg +=  "\tDb diff: "+str(ndata[kay]+full_data[kay])+"\n"
                    outpt(msg)
                    if mxpowr < ndata[kay]+full_data[kay]:
                        mxpowr = ndata[kay]+full_data[kay]
                        mxlst = time.strftime("%H:%M:%S")+' => '+str(kay)+'MHz %.3f db ' % (ndata[kay]+full_data[kay])
            if mxlst != '':
                gFrequencyRanges[n]["last"] = mxlst
            gFrequencyRanges[n]['power'] = mxpowr
        gLastSweepTime = int(time.time()-x)
        
def load_config():
    global gConfigFile, gCacheFile, gOutputFile, gDetectionSoil, gBandwidth, gLearningPassesCount, gSampleRate, gGain, gFrequencyRanges
    global gMaxDbPower, gRefreshDelay, gUseCacheFile, gRefreshDelayParam, gUseCacheFileParam, gDetectionSoilParam, gLearningPassesCountParam
    global gCacheFileParam, gOutputFileParam, gGainParam, gSampleRateParam, gFrequencyRangesParam, gApplicationNameParam, gMaxDbPowerParam
    global gLogToFile, gLogToFileParam, gFrequencyIgnoreRangesParam, gFrequencyIgnoreRanges
    
    x = open(gConfigFile,"rb").read()
    x = json.loads(x)
    if type(x) is not dict:
        return
    if x.has_key(gCacheFileParam):
        gCacheFile = x[gCacheFileParam]
    if x.has_key(gUseCacheFileParam):
        gUseCacheFile = x[gUseCacheFileParam]
        if gUseCacheFile == 1:
            gUseCacheFile = True
    if x.has_key(gRefreshDelayParam):
        gRefreshDelay = float(x[gRefreshDelayParam])
    if x.has_key(gMaxDbPowerParam):
        if float(x[gMaxDbPowerParam]) > 0:
            gMaxDbPower = float(x[gMaxDbPowerParam])
    if x.has_key(gOutputFileParam):
        gOutputFile = x[gOutputFileParam]
    if x.has_key(gDetectionSoilParam):
        if float(x[gDetectionSoilParam]) > 0:
            gDetectionSoil = float(x[gDetectionSoilParam])
    if x.has_key(gBandwidthParam):
        if int(x[gBandwidthParam]) > 0:
            gBandwidth = int(x[gBandwidthParam])
    if x.has_key(gLearningPassesCountParam):
        if int(x[gLearningPassesCountParam]) > 0:
            gLearningPassesCount = int(x[gLearningPassesCountParam])
    if x.has_key(gSampleRateParam):
        if int(x[gSampleRateParam]) > 0:
            gSampleRate = int(x[gSampleRateParam])
    if x.has_key(gLogToFileParam):
        gLogToFile = x[gLogToFileParam]
        if gLogToFile == 1:
            gLogToFile = True
        elif gLogToFile == 0:
            gLogToFile = False
    if x.has_key(gGainParam):
        if type(x[gGainParam]) is str:
            if x[gGainParam] == "auto":
                gGain = "auto"
        elif int(x[gGainParam]) >= 0:
            gGain = int(x[gGainParam])
    if x.has_key(gApplicationNameParam):
        gApplicationName = x[gApplicationNameParam]
    if x.has_key(gFrequencyRangesParam):
        gFrequencyRanges = x[gFrequencyRangesParam]
        if type(gFrequencyRanges) is list:
            for n in range(len(gFrequencyRanges)):
                if type(gFrequencyRanges[n]) is not dict:
                    continue
                if gFrequencyRanges[n].has_key("start") is False or gFrequencyRanges[n].has_key("end") is False:
                    outpt("[!] Range error (missing start or end)!")
                    del gFrequencyRanges[n]
                    continue
                if not gFrequencyRanges[n].has_key("soil"):
                    gFrequencyRanges[n]["soil"] = gDetectionSoil
                if not gFrequencyRanges[n].has_key("maxDbPower"):
                    gFrequencyRanges[n]["maxDbPower"] = gMaxDbPower
                if not gFrequencyRanges[n].has_key("name"):
                    gFrequencyRanges[n]["name"] = str(gFrequencyRanges[n]["start"]+"MHz")
                gFrequencyRanges[n]["power"] = 0
                gFrequencyRanges[n]["last"] = ''
    if x.has_key(gFrequencyIgnoreRangesParam):
        gFrequencyIgnoreRanges = x[gFrequencyIgnoreRangesParam]
        if type(gFrequencyIgnoreRanges) is list:
            for n in range(len(gFrequencyIgnoreRanges)):
                if type(gFrequencyIgnoreRanges[n]) is not dict:
                    continue
                if gFrequencyIgnoreRanges[n].has_key("start") is False or gFrequencyIgnoreRanges[n].has_key("end") is False:
                    outpt("[!] Range error (missing start or end)!")
                    del gFrequencyIgnoreRanges[n]
                    continue
    if gFrequencyRanges is None or len(gFrequencyRanges) == 0:
        outpt("[!] Nothing to do!")
        sys.exit(1)
    return True
       
        
def main():
    init_gSdr()
    outpt("[+] Learning...")
    learn_from_frequencyRanges()
    outpt("[+] Emission detection started!")
    monitor_for_emission(-1)
    outpt("")
    outpt("[+] Cleanup")
    close_gSdr()
    
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            print """Usage: %s [config file]
-----------------------------------------------------------------
config file: JSON file, defaults to 'config.json'. Example above.
-----------------------------------------------------------------
{
    "%s":"caching.json",
    "%s":"output.txt",
    "%s":1,
    "%s":0.05,
    "%s":2000000.0,
    "%s":10,
    "%s":2400000,
    "%s":19,
    "%s":3,
    "%s":4,
    "%s":1,
    "%s":"SIGINT",
    "%s":[
        {"start":433000000.0,"end":440000000.0,"name":"PMR 433","soil":0.6, "maxDbPower":2},
        {"start":880000000.0,"end":915000000.0}
    ],
    "%s":[
        {"start":86400000,"end":86410000}
    ]
}
------------------------------------
%s: caching JSON file, to store the "learned" frequencies peaks. Defaults to %s
%s: log file (stores the raw output). Defaults to %s
%s: enables the log file. Defaults to %s
%s: default db difference soil to trigger an alert. Defaults to %d db
%s: the maximum db which can be reached (used to display the progress bars). Defaults to %d
%s: tuner gBandwidth, to scan a maximum of frequency range in one scan. Defaults to %dHz
%s: learning passes count. The more they are, the most accurate it will be. Defaults to %d passes
%s: the sample rate. Defaults to %d
%s: the gGain, "auto" is supported. Defaults to %s
%s: the refresh delay, in seconds. Defaults to %d
%s: set to 1 to use the cachefile (skips the learning phase if found). Defaults to %d
%s: the application name (displayed on top). Defaults to %s
%s: list of frequency ranges to monitor for events. Mandatory, as it defines what to do. Each entry has the folowing parameters:
    start: the start frequency, in Hz
    end: the end frequency, in Hz
    name: the name (optional, defaults to the start freq)
    soil: a custom detection soil (optional)
    maxDbPower: a custom max db power for progress bar rendering (optional)
%s: list of frequency ranges to ignore
    start: the start frequency, in Hz
    end: the end frequency, in Hz
            """  % (sys.argv[0],
            gCacheFileParam,gOutputFileParam,gLogToFileParam,gDetectionSoilParam,gBandwidthParam,gLearningPassesCountParam,gSampleRateParam,gGainParam,gMaxDbPowerParam,gRefreshDelayParam,gUseCacheFileParam,gApplicationNameParam,gFrequencyRangesParam,gFrequencyIgnoreRangesParam,
            gCacheFileParam,gCacheFile,
            gOutputFileParam,gOutputFile,
            gLogToFileParam,gLogToFile,
            gDetectionSoilParam,gDetectionSoil,
            gMaxDbPowerParam,gMaxDbPower,
            gBandwidthParam,gBandwidth,
            gLearningPassesCountParam,gLearningPassesCount,
            gSampleRateParam,gSampleRate,
            gGainParam,str(gGain), 
            gRefreshDelayParam,gRefreshDelay, 
            gUseCacheFileParam,gUseCacheFile, 
            gApplicationNameParam,gApplicationName,
            gFrequencyRangesParam,
            gFrequencyIgnoreRangesParam)
            sys.exit(0)
        gConfigFile = sys.argv[1]
    main()
