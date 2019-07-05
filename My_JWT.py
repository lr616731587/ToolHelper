import base64
import copy
import hmac
import json
import time


class Jwt:
    def __init__(self):
        pass

    @staticmethod
    def encode(payload, key, exp=300):
        """
        base64.urlsafe_b64encode
        :param payload:
        :param key:
        :param exp:
        :return:
        """
        har = {
            'alg': 'HS256',
            'typ': 'JWT'
        }

        # separators 第一个参数标识 JSON每个键值之间用什么相连， 第二个标识key和value用什么相连
        # sort_key 每次json串按key排序输出
        har = json.dumps(har, separators=(',', ':'), sort_keys=True)
        b_har = Jwt.b64encode(har.encode())

        payload = copy.deepcopy(payload)
        payload['exp'] = int(time.time() + exp)
        pld = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        b_pld = Jwt.b64encode(pld.encode())

        sign = b_har + b'.' + b_pld
        if isinstance(key, str):
            key= key.encode()

        h = hmac.new(key, sign, digestmod='SHA256')
        data = h.digest()

        b_sign = Jwt.b64encode(data)

        return b_har + b'.' + b_pld + b'.' + b_sign

    @staticmethod
    def b64encode(s):
        return base64.urlsafe_b64encode(s).replace(b'=', b'')

    @staticmethod
    def b64decode(bs):
        """
        补回原长
        :param bs:
        :return:
        """
        third = 4 - (len(bs) % 4)
        bs += b'=' * third
        return base64.urlsafe_b64decode(bs)

    @staticmethod
    def decode(token, key):
        bs = token.split(b'.')
        sign = bs[0] + b'.' + bs[1]
        if isinstance(key, str):
            key = key.encode()
        h = hmac.new(key, sign, digestmod='SHA256')
        b_sign = Jwt.b64encode(h.digest())
        f = bs[0] + b'.' + bs[1] + b'.' + b_sign
        if f != token:
            raise JwtSignError('You token is valid')
        bss = Jwt.b64decode(bs[1])
        bss = json.loads(bss)
        if bss['exp'] < int(time.time() + 300):
            print(time.time() + 300)
            print(bss['exp'])
            raise JwtSignError('you token is expired')
        return True


class JwtSignError(Exception):
    def __init__(self, error_masg):
        self.error = error_masg

    def __str__(self):
        return '<JwtError error {}>'.format(self.error)


