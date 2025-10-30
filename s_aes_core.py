class SAES:
    def __init__(self):
        # S-box
        self.s_box = [
            [0x9, 0x4, 0xA, 0xB],
            [0xD, 0x1, 0x8, 0x5],
            [0x6, 0x2, 0x0, 0x3],
            [0xC, 0xE, 0xF, 0x7]
        ]
        self.inv_s_box = [
            [0xA, 0x5, 0x9, 0xB],
            [0x1, 0x7, 0x8, 0xF],
            [0x6, 0x0, 0x2, 0x3],
            [0xC, 0x4, 0xD, 0xE]
        ]

    def gf_mult(self, a, b):
        """GF(2^4) multiplication modulo x^4 + x + 1"""
        result = 0
        for _ in range(4):
            if b & 1:
                result ^= a
            hi_bit_set = a & 0x8
            a <<= 1
            if hi_bit_set:
                a ^= 0x13  # x^4 + x + 1 = 10011 = 0x13
            b >>= 1
        return result & 0xF

    def key_expansion(self, key):
        """Expand 16-bit key to 48-bit (three 16-bit round keys)"""
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF

        # RCON values
        rcon1 = 0x80
        rcon2 = 0x30

        def g(word, rcon):
            # Rotate nibbles
            rotated = ((word & 0x0F) << 4) | ((word & 0xF0) >> 4)
            # Substitute nibbles
            sub_nib1 = self.sub_nibble((rotated >> 4) & 0x0F, self.s_box)
            sub_nib2 = self.sub_nibble(rotated & 0x0F, self.s_box)
            sub_word = (sub_nib1 << 4) | sub_nib2
            # XOR with RCON
            return sub_word ^ rcon

        w2 = (w0 ^ g(w1, rcon1)) & 0xFF
        w3 = (w2 ^ w1) & 0xFF
        w4 = (w2 ^ g(w3, rcon2)) & 0xFF
        w5 = (w4 ^ w3) & 0xFF

        # Combine into round keys
        k0 = ((w0 << 8) | w1) & 0xFFFF
        k1 = ((w2 << 8) | w3) & 0xFFFF
        k2 = ((w4 << 8) | w5) & 0xFFFF

        return k0, k1, k2

    def bytes_to_state(self, bytes_data):
        """Convert two bytes to state matrix"""
        byte0, byte1 = bytes_data
        # 状态矩阵排列:
        # [s00, s01] 其中 s00=位0-3, s01=位8-11
        # [s10, s11] 其中 s10=位4-7, s11=位12-15
        s00 = (byte0 >> 4) & 0x0F  # 位0-3
        s10 = byte0 & 0x0F  # 位4-7
        s01 = (byte1 >> 4) & 0x0F  # 位8-11
        s11 = byte1 & 0x0F  # 位12-15
        return [[s00, s01], [s10, s11]]

    def state_to_bytes(self, state):
        """Convert state matrix to two bytes"""
        s00, s01 = state[0]
        s10, s11 = state[1]
        # 重组为两个字节
        byte0 = (s00 << 4) | s10  # 位0-7: s00(高4位) + s10(低4位)
        byte1 = (s01 << 4) | s11  # 位8-15: s01(高4位) + s11(低4位)
        return [byte0, byte1]

    def sub_nibble(self, nibble, s_box):
        """Substitute a 4-bit nibble using the given S-box"""
        row = (nibble >> 2) & 0x03
        col = nibble & 0x03
        return s_box[row][col]

    def sub_bytes(self, state, s_box):
        """Byte substitution transformation"""
        new_state = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                new_state[i][j] = self.sub_nibble(state[i][j], s_box)
        return new_state

    def shift_rows(self, state):
        """Shift rows transformation"""
        s00, s01 = state[0]
        s10, s11 = state[1]

        # 第0行不变，第1行交换s10和s11
        new_state = [
            [s00, s01],  # 第0行不变
            [s11, s10]  # 第1行交换
        ]
        return new_state

    def mix_columns(self, state):
        """Mix columns transformation"""
        s00, s01 = state[0]
        s10, s11 = state[1]

        # 对每列应用矩阵乘法 [1, 4; 4, 1]
        new_s00 = s00 ^ self.gf_mult(4, s10)
        new_s10 = self.gf_mult(4, s00) ^ s10
        new_s01 = s01 ^ self.gf_mult(4, s11)
        new_s11 = self.gf_mult(4, s01) ^ s11

        return [[new_s00, new_s01], [new_s10, new_s11]]

    def inv_mix_columns(self, state):
        """Inverse mix columns transformation"""
        s00, s01 = state[0]
        s10, s11 = state[1]

        # 对每列应用逆矩阵乘法 [9, 2; 2, 9]
        new_s00 = self.gf_mult(9, s00) ^ self.gf_mult(2, s10)
        new_s10 = self.gf_mult(2, s00) ^ self.gf_mult(9, s10)
        new_s01 = self.gf_mult(9, s01) ^ self.gf_mult(2, s11)
        new_s11 = self.gf_mult(2, s01) ^ self.gf_mult(9, s11)

        return [[new_s00, new_s01], [new_s10, new_s11]]

    def add_round_key(self, state, round_key):
        """Add round key to state"""
        key_bytes = [(round_key >> 8) & 0xFF, round_key & 0xFF]
        key_state = self.bytes_to_state(key_bytes)

        new_state = [[0, 0], [0, 0]]
        for i in range(2):
            for j in range(2):
                new_state[i][j] = state[i][j] ^ key_state[i][j]

        return new_state

    def encrypt(self, plaintext, key):
        """Encrypt 16-bit plaintext with 16-bit key"""
        # Key expansion
        k0, k1, k2 = self.key_expansion(key)

        # Initial state
        state_bytes = [(plaintext >> 8) & 0xFF, plaintext & 0xFF]
        state = self.bytes_to_state(state_bytes)
        print('初始的状态',state[0][0],state[1][0],state[0][1],state[1][1])

        # Round 0: AddRoundKey
        state = self.add_round_key(state, k0)
        print('轮密钥加后初始化的结果', state[0][0], state[1][0], state[0][1], state[1][1])
        # Round 1: SubBytes, ShiftRows, MixColumns, AddRoundKey
        state = self.sub_bytes(state, self.s_box)
        print('第一轮字节替换', state[0][0], state[1][0], state[0][1], state[1][1])
        state = self.shift_rows(state)
        print('第一轮左移结果', state[0][0], state[1][0], state[0][1], state[1][1])
        state = self.mix_columns(state)
        print('第一轮列混淆结果', state[0][0], state[1][0], state[0][1], state[1][1])
        state = self.add_round_key(state, k1)
        print('第一轮轮密钥加结果', state[0][0], state[1][0], state[0][1], state[1][1])

        # Round 2: SubBytes, ShiftRows, AddRoundKey
        state = self.sub_bytes(state, self.s_box)
        print('第二轮字节替换', state[0][0], state[1][0], state[0][1], state[1][1])
        state = self.shift_rows(state)
        print('第二轮左移结果', state[0][0], state[1][0], state[0][1], state[1][1])
        state = self.add_round_key(state, k2)
        print('第二轮轮密钥加结果', state[0][0], state[1][0], state[0][1], state[1][1])

        # Convert state back to 16-bit
        result_bytes = self.state_to_bytes(state)
        ciphertext = (result_bytes[0] << 8) | result_bytes[1]
        return ciphertext & 0xFFFF

    def decrypt(self, ciphertext, key):
        """Decrypt 16-bit ciphertext with 16-bit key"""
        # Key expansion
        k0, k1, k2 = self.key_expansion(key)


        # Initial state
        state_bytes = [(ciphertext >> 8) & 0xFF, ciphertext & 0xFF]
        state = self.bytes_to_state(state_bytes)


        # Round 2 inverse: AddRoundKey, InvShiftRows, InvSubBytes
        state = self.add_round_key(state, k2)
        state = self.shift_rows(state)  # ShiftRows is its own inverse
        state = self.sub_bytes(state, self.inv_s_box)

        # Round 1 inverse: AddRoundKey, InvMixColumns, InvShiftRows, InvSubBytes
        state = self.add_round_key(state, k1)
        state = self.inv_mix_columns(state)
        state = self.shift_rows(state)
        state = self.sub_bytes(state, self.inv_s_box)

        # Round 0 inverse: AddRoundKey
        state = self.add_round_key(state, k0)

        # Convert state back to 16-bit
        result_bytes = self.state_to_bytes(state)
        plaintext = (result_bytes[0] << 8) | result_bytes[1]
        return plaintext & 0xFFFF

    def print_state(self, state, description=""):
        """Helper function to print state matrix for debugging"""
        if description:
            print(f"{description}:")
        print(f"  [{state[0][0]:X} {state[0][1]:X}]")
        print(f"  [{state[1][0]:X} {state[1][1]:X}]")
        print()