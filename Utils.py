import Globals
import pyuv


def itb4(i):
    b = bytearray()
    b.append((i >> 24) & 0xFF)
    b.append((i >> 16) & 0xFF)
    b.append((i >> 8) & 0xFF)
    b.append(i & 0xFF)
    return b


def b4ti(b):
    i = 0
    i |= b[0] << 24
    i |= b[1] << 16
    i |= b[2] << 8
    i |= b[3]
    return i


def bai(b, i):
    ib = itb4(i)
    b.append(ib[0])
    b.append(ib[1])
    b.append(ib[2])
    b.append(ib[3])


def printsockdata(sock, data):
    if Globals.DEBUG:
        addr, port = sock.getsockname()
        raddr, rport = sock.getpeername()
        print("Start======================")
        print(str.format("{0}:{1} <- {2}:{3}", addr, port, raddr, rport))
        print(data)
        print("========================End")
    else:
        pass


def handle_error(error):
    if error is not None:
        if Globals.DEBUG:
            print("Error: " + pyuv.errno.strerror(error))
        return True
    return False


if __name__ == "__main__":
    tb = b'\xab\xef\x08\xa8'
    ti = 0xabef08a8
    if itb4(ti) == tb and b4ti(tb) == ti:
        print("Test Pass!!")
    else:
        print("Test Failed!!")
