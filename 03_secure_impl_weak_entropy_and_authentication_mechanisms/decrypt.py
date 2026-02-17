import random
import sys
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def decrypt(input_file, output_file, seed):
    random.seed(seed)
    key = random.randbytes(16)
    aes = AES.new(key, AES.MODE_GCM)

    with open(input_file, 'rb') as f_in:
        data = f_in.read()
    
    nonce = data[0:16]      # 16 bytes
    tag = data[16:32]       # 16 bytes
    ciphertext = data[32:]  # len(data) bytes

    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)

    data = aes.decrypt_and_verify(ciphertext, tag)

    with open(output_file, 'wb') as f_out:
        f_out.write(data)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'usage: {sys.argv[0]} <src-file> <dst-file>', file=sys.stderr)
        exit(1)
    
    seconds = 1770940800.0
    for i in range(60*60*24):
        print(time.ctime(seconds))
        try:
            decrypt(sys.argv[1], sys.argv[2], seconds)
        except:
            seconds += 1
            continue
        break
