#!/usr/bin/env python3

import re
import ssl
import sys
import socket

PORT_1 = 80
PORT_2 = 443

def check_http1(host):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((host, PORT_1))
    request = f"GET / HTTP/1.1\r\nHOST:{sys.argv[1]}\r\n\r\n"
    server.settimeout(2)
    server.sendall(request.encode())
    msg = server.recv(8192).decode(errors='ignore')

    print("\n==== http1.1 response ====\n")
    ### By uncommenting next line, the response of http 1.1 request will be seen ###
    print(msg)
    cookies = re.findall("[Ss]et-[Cc]ookie: .*;", msg)  # finding cookies by using regex

    code = int(msg.split()[1])
    if code >= 400:
        ### When http status code 4xx, 5xx Error, this will raise ConnectionError
        print("Error Code :", code, "https not supported")
        raise ConnectionError()

    """ Can't get full message with only one line of 'recv'
    from some website such as www.instagram.com
    So, to make sure that receives full message from server
    receiving message and add cookies to a cookie list 
    also if exceeded time set up then will automatically stop
    (not to spend too much time for test)"""
    try:
        while True:
            msg = server.recv(8192).decode(errors='ignore')
            if not msg:
                break
            ### By uncommenting next line, the response of https request will be seen ###
            print(msg)
            cookies = cookies + re.findall("[Ss]et-[Cc]ookie: .*;", msg)  # finding cookies by using regex
    except OSError:
        print("Request time out")

    server.close()
    return cookies

def check_http2(host):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'http/2'])

    server = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=sys.argv[1])
    server.connect((host, PORT_2))
    print("\n==== http2.0 response ====\n")
    # print(server.recv(10000).decode())

    if server.selected_alpn_protocol() != None:
        server.close()
        return True

    server.close()
    return False

def check_https(host):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = ssl.wrap_socket(server)
    server.connect((host, PORT_2))
    server.settimeout(2)
    server.send(f"GET / HTTP/1.1\r\nHOST:{sys.argv[1]}\r\n\r\n".encode())

    msg = server.recv(8192).decode(errors='ignore')

    print("==== https response ====\n")
    ### By uncommenting next line, the response of https request will be seen ###
    print(msg)
    cookies = re.findall("[Ss]et-[Cc]ookie: .*;", msg)        # finding cookies by using regex

    code = int(msg.split()[1])
    if code >= 400:
        ### When http status code 4xx, 5xx Error, this will raise ConnectionError
        print("Error Code :", code, "https not supported")
        raise ConnectionError()

    """ Can't get full message with only one line of 'recv'
    from some website such as www.instagram.com
    So, to make sure that receives full message from server
    receiving message and add cookies to a cookie list 
    also if exceeded time set up then will automatically stop
    (not to spend too much time for test)"""
    try:
        while True:
            msg = server.recv(8192).decode(errors='ignore')
            if not msg:
                break
            ### By uncommenting next line, the response of https request will be seen ###
            print(msg)
            cookies = cookies + re.findall("[Ss]et-[Cc]ookie: .*;", msg)        # finding cookies by using regex
    except OSError:
        print("Request time out")

    server.close()
    return cookies

def print_result(cookies_http1, http2, cookies_https):
    print("\n===== Final result =====\nwebsite:", sys.argv[1], end="\n\n")
    if cookies_https != None:
        print("1. Supports of HTTPS: yes")
    else:
        print("1. Supports of HTTPS: no")
    if cookies_http1 != None:
        print("2. Supports of http1.1: yes")
    else:
        print("2. Supports of http1.1: no")
    if http2:
        print("3. Supports of http2: yes")
    else:
        print("3. Supports of http2: no")
    print("4. List of Cookies:")

    """splitting cookie contents by using regex, also checking upper, lower cases
    also not to duplicate cookies from http1.1 and https test
    it is separated by if and elif block """
    if cookies_https:
        for cookie in cookies_https:
            if re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie):
                ### print out cookie content w/ string slicing
                print("cookie name:", re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie)[0][12:-1:], end="")
            if re.findall("[Ee]xpires=.*;", cookie):
                print(", expires time:", re.findall("[Ee]xpires=[\w\s,:-]*", cookie)[0][8::], end="")
            if re.findall("[Dd]omain=.*;", cookie):
                print(", domain name:", re.findall("[Dd]omain=[\w\.]*", cookie)[0][7::], end="")
            print()
    elif cookies_http1:
        for cookie in cookies_http1:
            if re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie):
                ### print out cookie content w/ string slicing
                print("cookie name:", re.findall("[Ss]et-[Cc]ookie: [\w-]*=", cookie)[0][12:-1:], end="")
            if re.findall("[Ee]xpires=.*;", cookie):
                print(", expires time:", re.findall("[Ee]xpires=[\w\s,:-]*", cookie)[0][8::], end="")
            if re.findall("[Dd]omain=.*;", cookie):
                print(", domain name:", re.findall("[Dd]omain=[\w\.]*", cookie)[0][7::], end="")
            print()

def main():
    try:
        host = socket.gethostbyname(sys.argv[1])
    except:
        ### catching some possible error such as OSError, UnicodeError
        print("Not available server name provided as an argument\nPlease run program with proper hostname")
        # print_result(None, False, None)
        exit()

    try:
        cookies_https = check_https(host)
        # print("HTTPs check passed", end="\n\n")
    except:
        cookies_https = None
        # print("https not supported", end="\n\n")

    try:
        cookies_http1 = check_http1(host)
        # print("HTTP1 check passed", end="\n\n")
    except:
        cookies_http1 = None
        # print("http1.1 not supported", end="\n\n")

    try:
        http2 = check_http2(host)
        # print("HTTP2 check passed", end="\n\n")
    except:
        http2 = False
        # print("http2 not supported", end="\n\n")

    print_result(cookies_http1, http2, cookies_https)


if __name__ == "__main__":
    main()