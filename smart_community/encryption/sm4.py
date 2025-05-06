from gmssl import sm4

class SM4:
    def __init__(self, key):
        self.crypt = sm4.CryptSM4()
        self.key = key

    def encrypt(self, data):
        self.crypt.set_key(self.key, sm4.SM4_ENCRYPT)
        return self.crypt.crypt_ecb(data)

    def decrypt(self, data):
        self.crypt.set_key(self.key, sm4.SM4_DECRYPT)
        return self.crypt.crypt_ecb(data)