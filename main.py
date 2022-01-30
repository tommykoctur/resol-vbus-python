from resol import *

if __name__ == '__main__':
    if config.connection == "serial":
        sock = serial.Serial(config.port, baudrate=config.baud_rate, timeout=0)
    elif config.connection == "lan":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(config.address)
        login()
    elif config.connection == "stdin":
        sock = sys.stdin
    else:
        sys.exit('Unknown connection type. Please check config.')

    result = dict()
    load_data(result)

    print(json.dumps(result))

    if config.connection == "lan":
        try:
            sock.shutdown(0)
        except Exception as e:
            print(e)
            pass
    sock.close()
    sock = None
