from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QGridLayout)


class UITabs:
    @staticmethod
    def create_basic_tab():
        widget = QWidget()
        layout = QVBoxLayout()

        # 输入组
        input_group = QGroupBox("输入")
        input_layout = QGridLayout()

        input_layout.addWidget(QLabel("明文(16位):"), 0, 0)
        plaintext_edit = QLineEdit()
        plaintext_edit.setPlaceholderText("输入16位二进制或十六进制数")
        input_layout.addWidget(plaintext_edit, 0, 1)

        input_layout.addWidget(QLabel("密钥(16位):"), 1, 0)
        key_edit = QLineEdit()
        key_edit.setPlaceholderText("输入16位二进制或十六进制数")
        input_layout.addWidget(key_edit, 1, 1)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮
        button_layout = QHBoxLayout()
        encrypt_btn = QPushButton("加密")
        decrypt_btn = QPushButton("解密")
        button_layout.addWidget(encrypt_btn)
        button_layout.addWidget(decrypt_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()

        output_layout.addWidget(QLabel("密文:"))
        ciphertext_output = QLineEdit()
        ciphertext_output.setReadOnly(True)
        output_layout.addWidget(ciphertext_output)

        output_layout.addWidget(QLabel("解密结果:"))
        decrypt_output = QLineEdit()
        decrypt_output.setReadOnly(True)
        output_layout.addWidget(decrypt_output)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        widget.setLayout(layout)

        # 返回组件以便连接信号槽
        return widget, plaintext_edit, key_edit, encrypt_btn, decrypt_btn, ciphertext_output, decrypt_output

    @staticmethod
    def create_ascii_tab():
        widget = QWidget()
        layout = QVBoxLayout()

        # 输入组
        input_group = QGroupBox("输入")
        input_layout = QGridLayout()

        input_layout.addWidget(QLabel("ASCII文本:"), 0, 0)
        ascii_input = QTextEdit()
        ascii_input.setMaximumHeight(80)
        input_layout.addWidget(ascii_input, 0, 1)

        input_layout.addWidget(QLabel("密钥(16位):"), 1, 0)
        ascii_key = QLineEdit()
        input_layout.addWidget(ascii_key, 1, 1)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮
        button_layout = QHBoxLayout()
        ascii_encrypt_btn = QPushButton("加密ASCII")
        ascii_decrypt_btn = QPushButton("解密ASCII")
        button_layout.addWidget(ascii_encrypt_btn)
        button_layout.addWidget(ascii_decrypt_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()

        output_layout.addWidget(QLabel("加密结果:"))
        ascii_encrypted = QTextEdit()
        ascii_encrypted.setMaximumHeight(80)
        output_layout.addWidget(ascii_encrypted)

        output_layout.addWidget(QLabel("解密结果:"))
        ascii_decrypted = QTextEdit()
        ascii_decrypted.setMaximumHeight(80)
        output_layout.addWidget(ascii_decrypted)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        widget.setLayout(layout)
        return widget, ascii_input, ascii_key, ascii_encrypt_btn, ascii_decrypt_btn, ascii_encrypted, ascii_decrypted

    @staticmethod
    def create_double_tab():
        widget = QWidget()
        layout = QVBoxLayout()

        # 输入组
        input_group = QGroupBox("双重加密")
        input_layout = QGridLayout()

        input_layout.addWidget(QLabel("明文(16位):"), 0, 0)
        double_plain = QLineEdit()
        input_layout.addWidget(double_plain, 0, 1)

        input_layout.addWidget(QLabel("密钥K1(16位):"), 1, 0)
        k1_edit = QLineEdit()
        input_layout.addWidget(k1_edit, 1, 1)

        input_layout.addWidget(QLabel("密钥K2(16位):"), 2, 0)
        k2_edit = QLineEdit()
        input_layout.addWidget(k2_edit, 2, 1)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮
        button_layout = QHBoxLayout()
        double_encrypt_btn = QPushButton("双重加密")
        double_decrypt_btn = QPushButton("双重解密")
        button_layout.addWidget(double_encrypt_btn)
        button_layout.addWidget(double_decrypt_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()

        output_layout.addWidget(QLabel("密文:"))
        double_cipher = QLineEdit()
        double_cipher.setReadOnly(True)
        output_layout.addWidget(double_cipher)

        output_layout.addWidget(QLabel("解密结果:"))
        double_decrypt_output = QLineEdit()
        double_decrypt_output.setReadOnly(True)
        output_layout.addWidget(double_decrypt_output)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        widget.setLayout(layout)
        return widget, double_plain, k1_edit, k2_edit, double_encrypt_btn, double_decrypt_btn, double_cipher, double_decrypt_output

    @staticmethod
    def create_mitm_tab():
        widget = QWidget()
        layout = QVBoxLayout()

        # 输入组
        input_group = QGroupBox("中间相遇攻击")
        input_layout = QGridLayout()

        input_layout.addWidget(QLabel("已知明文:"), 0, 0)
        known_plain = QLineEdit()
        input_layout.addWidget(known_plain, 0, 1)

        input_layout.addWidget(QLabel("对应密文:"), 1, 0)
        known_cipher = QLineEdit()
        input_layout.addWidget(known_cipher, 1, 1)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 攻击按钮
        mitm_btn = QPushButton("执行中间相遇攻击")
        layout.addWidget(mitm_btn)

        # 结果
        result_group = QGroupBox("攻击结果")
        result_layout = QVBoxLayout()

        result_layout.addWidget(QLabel("找到的密钥对:"))
        mitm_results = QTextEdit()
        mitm_results.setMaximumHeight(120)
        result_layout.addWidget(mitm_results)

        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        widget.setLayout(layout)
        return widget, known_plain, known_cipher, mitm_btn, mitm_results

    @staticmethod
    def create_triple_tab():
        widget = QWidget()
        layout = QVBoxLayout()

        # 输入组
        input_group = QGroupBox("三重加密")
        input_layout = QGridLayout()

        input_layout.addWidget(QLabel("明文(16位):"), 0, 0)
        triple_plain = QLineEdit()
        input_layout.addWidget(triple_plain, 0, 1)

        input_layout.addWidget(QLabel("密钥K1(16位):"), 1, 0)
        triple_k1 = QLineEdit()
        input_layout.addWidget(triple_k1, 1, 1)

        input_layout.addWidget(QLabel("密钥K2(16位):"), 2, 0)
        triple_k2 = QLineEdit()
        input_layout.addWidget(triple_k2, 2, 1)

        input_layout.addWidget(QLabel("密钥K3(16位):"), 3, 0)
        triple_k3 = QLineEdit()
        input_layout.addWidget(triple_k3, 3, 1)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮
        button_layout = QHBoxLayout()
        triple_encrypt_btn = QPushButton("三重加密")
        triple_decrypt_btn = QPushButton("三重解密")
        button_layout.addWidget(triple_encrypt_btn)
        button_layout.addWidget(triple_decrypt_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()

        output_layout.addWidget(QLabel("密文:"))
        triple_cipher = QLineEdit()
        triple_cipher.setReadOnly(True)
        output_layout.addWidget(triple_cipher)

        output_layout.addWidget(QLabel("解密结果:"))
        triple_decrypt_output = QLineEdit()
        triple_decrypt_output.setReadOnly(True)
        output_layout.addWidget(triple_decrypt_output)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        widget.setLayout(layout)
        return widget, triple_plain, triple_k1, triple_k2, triple_k3, triple_encrypt_btn, triple_decrypt_btn, triple_cipher, triple_decrypt_output

    @staticmethod
    def create_cbc_tab():
        widget = QWidget()
        layout = QVBoxLayout()

        # 输入组
        input_group = QGroupBox("CBC模式")
        input_layout = QGridLayout()

        input_layout.addWidget(QLabel("明文:"), 0, 0)
        cbc_plain = QTextEdit()
        cbc_plain.setMaximumHeight(60)
        input_layout.addWidget(cbc_plain, 0, 1)

        input_layout.addWidget(QLabel("密钥(16位):"), 1, 0)
        cbc_key = QLineEdit()
        input_layout.addWidget(cbc_key, 1, 1)

        input_layout.addWidget(QLabel("初始向量IV(16位):"), 2, 0)
        cbc_iv = QLineEdit()
        input_layout.addWidget(cbc_iv, 2, 1)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮
        button_layout = QHBoxLayout()
        cbc_encrypt_btn = QPushButton("CBC加密")
        cbc_decrypt_btn = QPushButton("CBC解密")
        tamper_btn = QPushButton("篡改密文测试")
        button_layout.addWidget(cbc_encrypt_btn)
        button_layout.addWidget(cbc_decrypt_btn)
        button_layout.addWidget(tamper_btn)

        layout.addLayout(button_layout)

        # 输出组
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()

        output_layout.addWidget(QLabel("加密结果:"))
        cbc_encrypted = QTextEdit()
        cbc_encrypted.setMaximumHeight(60)
        output_layout.addWidget(cbc_encrypted)

        output_layout.addWidget(QLabel("解密结果:"))
        cbc_decrypted = QTextEdit()
        cbc_decrypted.setMaximumHeight(60)
        output_layout.addWidget(cbc_decrypted)

        output_layout.addWidget(QLabel("篡改测试结果:"))
        tamper_result = QTextEdit()
        tamper_result.setMaximumHeight(60)
        output_layout.addWidget(tamper_result)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        widget.setLayout(layout)
        return widget, cbc_plain, cbc_key, cbc_iv, cbc_encrypt_btn, cbc_decrypt_btn, tamper_btn, cbc_encrypted, cbc_decrypted, tamper_result