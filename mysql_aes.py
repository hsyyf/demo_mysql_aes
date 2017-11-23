# -*- coding: utf-8 -*-
"""
    author: Q.Y.
    dependent: pycrypto
"""

from Crypto.Cipher import AES

from Crypto.Util.Padding import pad, unpad


def _padding(string):
    if not isinstance(string, bytes):
        string = bytes(string, 'ascii')
    return pad(string, block_size=16)


def _mysql_aes_key(origin_key):
    final_key = bytearray(16)
    for i, c in enumerate(origin_key):
        final_key[i % 16] ^= ord(origin_key[i])
    return bytes(final_key)


def mysql_aes_encrypt(value,base_key):
    real_key = _mysql_aes_key(base_key)
    obj = AES.new(key=real_key, mode=AES.MODE_ECB)

    return obj.encrypt(_padding(value))


def mysql_aes_decrypt(value, base_key):
    real_key = _mysql_aes_key(base_key )
    obj = AES.new(key=real_key, mode=AES.MODE_ECB)

    if not isinstance(value, bytes):
        value = bytes(value, 'ascii')

    return unpad(obj.decrypt(value), block_size=16)


if __name__ == '__main__':
    _ = mysql_aes_encrypt("aa1122", base_key="11qaazxzz")
    print(''.join([hex(i) for i in _]))
    _ = mysql_aes_decrypt(_, base_key="11qaazxzz")
    print(_)
