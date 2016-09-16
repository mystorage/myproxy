import socket
import ipaddress
import pyuv
import signal
import Encrypt
import Utils

LISTEN_PORT = 6782

REQUEST_CONNECTING = 1
IN_CONNECTING = 2
SEND_DATA = 3

clients_pool = {}
proxys_pool = {}
loop = None
server = None
signal_h = None

printsockdata = Utils.printsockdata
handle_error = Utils.handle_error


def remove_client(client, close=False):
    info = clients_pool[client]
    sproxy = info['proxy']

    del clients_pool[client]
    if close:
        client.close()

    if sproxy is not None:
        if sproxy in proxys_pool:
            del proxys_pool[sproxy]
        if close:
            sproxy.close()


def getaddrport(data):
    if len(data) < 10:
        return

    if data[3] == 1 and len(data) == 10:  # ipv4
        addr = str.format('{0}.{1}.{2}.{1}', data[4], data[5], data[6], data[7])
    elif data[3] == 3 and len(data) == data[4] + 7:  # domain
        addr = (data[5:-2]).decode('utf-8').strip()
        addr = socket.gethostbyname(addr)
    else:
        return

    port = data[-1] + data[-2] * 256
    return addr, port


def on_proxy_read(sproxy, data, error):
    printsockdata(sproxy, data)

    if sproxy not in proxys_pool:
        return

    pinfo = proxys_pool[sproxy]
    client = pinfo['client']

    if handle_error(error) or data is None:
        remove_client(client, close=True)
    else:
        client.write(Encrypt.cookdata(data))


def on_proxy_connected(sproxy, error):
    if sproxy not in proxys_pool:
        return

    pinfo = proxys_pool[sproxy]
    client = pinfo['client']
    info = pinfo['client_info']
    if handle_error(error):
        remove_client(client, close=True)
    else:
        info["stage"] = SEND_DATA
        sproxy.start_read(on_proxy_read)

        host, port = sproxy.getsockname()
        host = socket.gethostbyname(host)
        host_int = int(ipaddress.IPv4Address(host))

        wdata = bytearray(b'\x05\x00\x00\x01')
        wdata.append((host_int >> 24) & 0xFF)
        wdata.append((host_int >> 16) & 0xFF)
        wdata.append((host_int >> 8) & 0xFF)
        wdata.append(host_int & 0xFF)
        wdata.append((port >> 8) & 0xFF)
        wdata.append(port & 0xFF)
        client.write(Encrypt.cookdata(b'' + wdata))


def on_read(client, data, error):
    if handle_error(error) or data is None:
        remove_client(client, close=True)
    else:
        info = clients_pool[client]
        stage = info['stage']
        if stage == REQUEST_CONNECTING:
            data = info['data'] + data
            rawdta, leftdata = Encrypt.getrawdata(data)

            if rawdta:
                taddr, tport = getaddrport(rawdta)
                if taddr and tport:
                    info['data'] = leftdata

                    sproxy = pyuv.TCP(client.loop)
                    sproxy.connect((taddr, tport), on_proxy_connected)
                    proxys_pool[sproxy] = {'client': client, 'client_info': info}

                    info['proxy'] = sproxy
                    info['stage'] = IN_CONNECTING
                else:  # Bad data format
                    remove_client(client, close=True)
            else:
                info['data'] = data
        elif stage == SEND_DATA:
            data = info['data'] + data
            rawdta, leftdata = Encrypt.getrawdata(data)

            if rawdta:
                sproxy = info['proxy']
                sproxy.write(rawdta)
                info['data'] = leftdata
            else:
                info['data'] = data
        else:
            info['data'] += data


def on_connection(s, error):
    if handle_error(error):
        pass
    else:
        client = pyuv.TCP(server.loop)
        server.accept(client)
        clients_pool[client] = {'stage': REQUEST_CONNECTING, 'data': b'', 'proxy': None}
        client.start_read(on_read)


def signal_cb(handle, signum):
    signal_h.close()
    server.close()
    print("Server stooped!")
    loop.stop()


def main():
    global loop, server, signal_h
    loop = pyuv.Loop.default_loop()
    server = pyuv.TCP(loop)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(on_connection)

    signal_h = pyuv.Signal(loop)
    signal_h.start(signal_cb, signal.SIGINT)

    loop.run()


if __name__ == "__main__":
    main()
