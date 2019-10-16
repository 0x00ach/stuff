import Evtx.Evtx as evtx
import Evtx.Views as e_views
import os

for i in os.listdir("."):
    if "evtx" in i:
        try:
            with evtx.Evtx(i) as log:
                    fh = open(i+".xml","wb")
                    fh.write(e_views.XML_HEADER+"\n")
                    fh.write("<Events>\n")
                    for record in log.records():
                         fh.write(record.xml()+"\n")
                    fh.write("</Events>")
                    print i+" done!"
        except:
            pass
