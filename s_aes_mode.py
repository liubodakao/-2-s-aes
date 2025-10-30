from s_aes_core import SAES

class SAESMode:
    def __init__(self):
        self.saes = SAES()

    # 双重加密
    def double_encrypt(self, plaintext, k1, k2):
        cipher1 = self.saes.encrypt(plaintext, k1)
        return self.saes.encrypt(cipher1, k2)

    def double_decrypt(self, ciphertext, k1, k2):
        plain1 = self.saes.decrypt(ciphertext, k2)
        return self.saes.decrypt(plain1, k1)

    # 三重加密
    def triple_encrypt(self, plaintext, k1, k2, k3):
        cipher1 = self.saes.encrypt(plaintext, k1)
        cipher2 = self.saes.encrypt(cipher1, k2)
        return self.saes.encrypt(cipher2, k3)

    def triple_decrypt(self, ciphertext, k1, k2, k3):
        plain1 = self.saes.decrypt(ciphertext, k3)
        plain2 = self.saes.decrypt(plain1, k2)
        return self.saes.decrypt(plain2, k1)

    # CBC模式
    def cbc_encrypt(self, text, key, iv):
        # 填充文本为2字节的倍数
        if len(text) % 2 != 0:
            text += ' '

        encrypted_blocks = []
        previous = iv

        for i in range(0, len(text), 2):
            # 将两个字符转换为16位数字
            block = (ord(text[i]) << 8) | ord(text[i + 1])
            # 与前一个密文块异或（第一个块与IV异或）
            block ^= previous
            encrypted = self.saes.encrypt(block, key)
            encrypted_blocks.append(encrypted)
            previous = encrypted

        return encrypted_blocks

    def cbc_decrypt(self, encrypted_blocks, key, iv):
        decrypted_text = ""
        previous = iv

        for encrypted in encrypted_blocks:
            decrypted = self.saes.decrypt(encrypted, key)
            # 与前一个密文块异或（第一个块与IV异或）
            plain_block = decrypted ^ previous
            decrypted_text += chr((plain_block >> 8) & 0xFF) + chr(plain_block & 0xFF)
            previous = encrypted

        return decrypted_text.strip()

    # 中间相遇攻击
    def mitm_attack(self, plaintext, ciphertext, max_results=10):
        encryption_table = {}
        found_keys = []

        # 构建加密表
        for k1 in range(65536):
            intermediate = self.saes.encrypt(plaintext, k1)
            encryption_table[intermediate] = k1

        # 查找匹配的密钥对
        for k2 in range(65536):
            intermediate = self.saes.decrypt(ciphertext, k2)
            if intermediate in encryption_table:
                k1 = encryption_table[intermediate]
                found_keys.append((k1, k2))
                if len(found_keys) >= max_results:
                    break

        return found_keys

    # ASCII加解密
    def ascii_encrypt(self, text, key):
        if len(text) % 2 != 0:
            text += ' '

        encrypted_bytes = []
        for i in range(0, len(text), 2):
            block = (ord(text[i]) << 8) | ord(text[i + 1])
            encrypted = self.saes.encrypt(block, key)
            encrypted_bytes.extend([(encrypted >> 8) & 0xFF, encrypted & 0xFF])

        return ''.join(chr(b) for b in encrypted_bytes)

    def ascii_decrypt(self, text, key):
        decrypted_text = ""
        for i in range(0, len(text), 2):
            block = (ord(text[i]) << 8) | ord(text[i + 1])
            decrypted = self.saes.decrypt(block, key)
            decrypted_text += chr((decrypted >> 8) & 0xFF) + chr(decrypted & 0xFF)

        return decrypted_text.strip()