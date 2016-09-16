import pyuv
import Encrypt
import signal

import Utils

printsockdata = Utils.printsockdata
handle_error = Utils.handle_error

LISTEN_PORT = 8899
SERVICE_IP = "127.0.0.1"
SERVICE_PORT = 6782

HANDSHAKE = 0
REQUEST_CONNECTING = 1
SEND_DATA = 2

clients_pool = {}
proxys_pool = {}
loop = None
server = None
signal_h = None


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


def on_proxy_read(sproxy, data, error):
    printsockdata(sproxy, data)

    if sproxy not in proxys_pool:
        return

    pinfo = proxys_pool[sproxy]
    client = pinfo['client']

    if handle_error(error) or data is None:
        remove_client(client, close=True)
    else:
        alldata = pinfo['data'] + data
        rawdata, leftdata = Encrypt.getrawdata(alldata)
        if rawdata:
            client.write(rawdata)
            pinfo['data'] = leftdata
        else:
            pinfo['data'] = alldata


def on_proxy_connected(sproxy, error):
    if sproxy not in proxys_pool:
        return

    pinfo = proxys_pool[sproxy]
    client = pinfo['client']
    info = pinfo['client_info']
    if handle_error(error):
        remove_client(client, close=True)
    else:
        sproxy.start_read(on_proxy_read)
        edata = Encrypt.cookdata(info['data'])
        sproxy.write(edata)

        info["stage"] = SEND_DATA
        info['data'] = b''


def on_read(client, data, error):
    printsockdata(client, data)

    if handle_error(error) or data is None:
        remove_client(client, close=True)
    else:
        info = clients_pool[client]
        stage = info['stage']
        curdata = data
        if stage == HANDSHAKE:
            data = info['data'] + data
            if len(data) == 3:
                if data[0] != 5 or data[2] != 0:  # protocol version or authentication method not supported
                    remove_client(client, close=True)
                else:
                    info['data'] = b''
                    info['stage'] = REQUEST_CONNECTING
                    client.write(b'\x05\x00')
            else:
                info['data'] += curdata
        elif stage == REQUEST_CONNECTING:
            data = info['data'] + data
            if (data[3] == 1 and len(data) == 10) or (data[3] == 3 and len(data) == data[4] + 7):  # ipv4 or domain
                info['data'] = data
                sproxy = pyuv.TCP(client.loop)
                sproxy.connect((SERVICE_IP, SERVICE_PORT), on_proxy_connected)
                proxys_pool[sproxy] = {'client': client, 'client_info': info, 'data': b''}

                info['proxy'] = sproxy
            else:
                info['data'] += curdata
        elif stage == SEND_DATA:
            sproxy = info['proxy']
            sproxy.write(Encrypt.cookdata(data))


def on_connection(server, error):
    if handle_error(error):
        pass
    else:
        client = pyuv.TCP(server.loop)
        server.accept(client)
        clients_pool[client] = {'stage': HANDSHAKE, 'data': b'', 'proxy': None}
        client.start_read(on_read)


def signal_cb(handle, signum):
    for item in clients_pool.items():
        remove_client(item[0])
    signal_h.close()
    server.close()
    print("Server stooped!")
    loop.stop()


def main():
    global loop
    loop = pyuv.Loop.default_loop()

    global server
    server = pyuv.TCP(loop)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(on_connection)

    global signal_h
    signal_h = pyuv.Signal(loop)
    signal_h.start(signal_cb, signal.SIGINT)

    loop.run()


if __name__ == "__main__":
    main()
