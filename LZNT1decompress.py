import struct
import sys

def unpack_from(fmt, buf, offset=0):
    """Unpack binary data, using struct.unpack(...)"""
    slice = buffer(buf, offset, struct.calcsize(fmt))
    return struct.unpack(fmt, slice)

class lznt1Error(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

def _dCompressBlock(x):
    size = len(x)
    u = ''
    while len(x):
        p = x[0]

        if p == 0: # These are symbol are tokens
            u += x[1:9]
            x = x[9:]
        else:  # There is a phrase token
            idx = 8
            x = x[1:]
            while idx and len(x):
                ustart = len(u)
                if not (p & 1):
                    u += chr(x[0])
                    x = x[1:]
                else:
                    pt = unpack_from('H', x)[0]
                    pt = pt & 0xffff
                    i = (len(u)-1)  # Current Pos
                    l_mask = 0xfff
                    p_shift = 12
                    while i >= 0x10:
                        l_mask >>= 1
                        p_shift -= 1
                        i >>= 1

                    length = (pt & l_mask) + 3
                    bp = (pt  >> p_shift) + 1

                    if length >= bp:
                        tmp = u[-bp:]
                        while length >= len(tmp):
                            u += tmp
                            length -= len(tmp)
                        u += tmp[:length]
                    else:
                        insert = u[-bp : -bp + length]
                        u = u + insert

                    x = x[2:]
                p >>= 1
                idx -= 1
    return u

def dCompressBuf(blob):
    good = True
    unc = ''
    while good:
        try:
            hdr = blob[0:2]
            blob = blob[2:]

            length = struct.unpack('H', hdr)[0]
            length &= 0xfff
            length += 1
            if length > len(blob):
                raise lznt1Error("invalid block len")
                good = False
            else:
                y = blob[:length]
                blob = blob[length:]
                unc += _dCompressBlock(y)
        except:
            good = False

    return unc

data = bytearray.fromhex("414141414141")
#print "raw data : " + data
print "decomp data : "+ dCompressBuf(data)

