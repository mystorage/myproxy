import pysodium
import Utils
import Globals

n = b"adslfkwe"
k = b"adslfkweadslfkweadslfkweadslfkwe"

obfs = b'ehlo [127.0.1.1]\r\n'
obfslen = len(obfs)

HEAD_DATA_LEN_BYTE = 4

DEBUG = Globals.DEBUG


def ed(m):
    try:
        return pysodium.crypto_stream_chacha20_xor(m, n, k)
    except ValueError:
        return ""


def cookdata(rawdata):
    if DEBUG:
        return rawdata, b""

    data = ed(rawdata)
    cooked = obfs + Utils.itb4(len(data) + HEAD_DATA_LEN_BYTE) + data

    return cooked


def getrawdata(data):
    if DEBUG:
        return data, b""

    hasdata = False
    rawdata = b''
    while True:
        datalen = len(data) - obfslen
        if datalen >= HEAD_DATA_LEN_BYTE and datalen >= Utils.b4ti(data[obfslen:obfslen+4]):
            hasdata = True
            data = data[obfslen:]
            l = Utils.b4ti(data)
            endata = data[HEAD_DATA_LEN_BYTE:l]
            rawdata += ed(endata)
            data = data[l:]
        else:
            break

    if hasdata:
        return rawdata, data
    else:
        return None, data
