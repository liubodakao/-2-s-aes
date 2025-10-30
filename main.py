import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QTabWidget, QMessageBox)
from s_aes_core import SAES
from s_aes_mode import SAESMode
from gui import UITabs

class SAESApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.saes = SAES()
        self.mode_handler = SAESMode()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('S-AES加密系统')
        self.setGeometry(100, 100, 800, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # 创建标签页控件
        tabs = QTabWidget()
        layout.addWidget(tabs)

        # 创建各个标签页并保存组件引用
        self.create_tabs(tabs)

    def create_tabs(self, tabs):
        # 基础加解密标签页
        tab1, self.plaintext_edit, self.key_edit, self.encrypt_btn, self.decrypt_btn, self.ciphertext_output, self.decrypt_output = UITabs.create_basic_tab()
        self.encrypt_btn.clicked.connect(self.basic_encrypt)
        self.decrypt_btn.clicked.connect(self.basic_decrypt)
        tabs.addTab(tab1, "基础加解密")

        # ASCII加解密标签页
        tab2, self.ascii_input, self.ascii_key, self.ascii_encrypt_btn, self.ascii_decrypt_btn, self.ascii_encrypted, self.ascii_decrypted = UITabs.create_ascii_tab()
        self.ascii_encrypt_btn.clicked.connect(self.ascii_encrypt)
        self.ascii_decrypt_btn.clicked.connect(self.ascii_decrypt)
        tabs.addTab(tab2, "ASCII加解密")

        # 双重加解密标签页
        tab3, self.double_plain, self.k1_edit, self.k2_edit, self.double_encrypt_btn, self.double_decrypt_btn, self.double_cipher, self.double_decrypt_output = UITabs.create_double_tab()
        self.double_encrypt_btn.clicked.connect(self.double_encrypt)
        self.double_decrypt_btn.clicked.connect(self.double_decrypt)
        tabs.addTab(tab3, "双重加解密")

        # 中间相遇攻击标签页
        tab4, self.known_plain, self.known_cipher, self.mitm_btn, self.mitm_results = UITabs.create_mitm_tab()
        self.mitm_btn.clicked.connect(self.mitm_attack)
        tabs.addTab(tab4, "中间相遇攻击")

        # 三重加解密标签页
        tab5, self.triple_plain, self.triple_k1, self.triple_k2, self.triple_k3, self.triple_encrypt_btn, self.triple_decrypt_btn, self.triple_cipher, self.triple_decrypt_output = UITabs.create_triple_tab()
        self.triple_encrypt_btn.clicked.connect(self.triple_encrypt)
        self.triple_decrypt_btn.clicked.connect(self.triple_decrypt)
        tabs.addTab(tab5, "三重加解密")

        # CBC工作模式标签页
        tab6, self.cbc_plain, self.cbc_key, self.cbc_iv, self.cbc_encrypt_btn, self.cbc_decrypt_btn, self.tamper_btn, self.cbc_encrypted, self.cbc_decrypted, self.tamper_result = UITabs.create_cbc_tab()
        self.cbc_encrypt_btn.clicked.connect(self.cbc_encrypt)
        self.cbc_decrypt_btn.clicked.connect(self.cbc_decrypt)
        self.tamper_btn.clicked.connect(self.tamper_test)
        tabs.addTab(tab6, "CBC工作模式")

    def parse_input(self, text):
        """解析二进制或十六进制输入"""
        text = text.strip()
        if text.startswith('0x'):
            return int(text[2:], 16)
        elif text.startswith('0b'):
            return int(text[2:], 2)
        elif all(c in '01' for c in text) and len(text) == 16:
            return int(text, 2)
        else:
            return int(text, 16)

    def format_output(self, value, bits=16):
        """格式化输出为二进制和十六进制"""
        binary = format(value, f'0{bits}b')
        hex_val = format(value, f'0{bits // 4}x')
        return f"二进制: {binary} (0x{hex_val})"

    # 基础加解密方法
    def basic_encrypt(self):
        try:
            plaintext = self.parse_input(self.plaintext_edit.text())
            key = self.parse_input(self.key_edit.text())

            ciphertext = self.saes.encrypt(plaintext, key)
            self.ciphertext_output.setText(self.format_output(ciphertext))

        except Exception as e:
            QMessageBox.warning(self, "错误", f"加密失败: {str(e)}")

    def basic_decrypt(self):
        try:
            ciphertext = self.parse_input(self.ciphertext_output.text().split(' ')[1])
            key = self.parse_input(self.key_edit.text())

            plaintext = self.saes.decrypt(ciphertext, key)
            self.decrypt_output.setText(self.format_output(plaintext))

        except Exception as e:
            QMessageBox.warning(self, "错误", f"解密失败: {str(e)}")

    # ASCII加解密方法
    def ascii_encrypt(self):
        try:
            text = self.ascii_input.toPlainText()
            key = self.parse_input(self.ascii_key.text())

            encrypted_text = self.mode_handler.ascii_encrypt(text, key)
            self.ascii_encrypted.setPlainText(encrypted_text)

        except Exception as e:
            QMessageBox.warning(self, "错误", f"ASCII加密失败: {str(e)}")

    def ascii_decrypt(self):
        try:
            text = self.ascii_encrypted.toPlainText()
            key = self.parse_input(self.ascii_key.text())

            decrypted_text = self.mode_handler.ascii_decrypt(text, key)
            self.ascii_decrypted.setPlainText(decrypted_text)

        except Exception as e:
            QMessageBox.warning(self, "错误", f"ASCII解密失败: {str(e)}")

    # 双重加密方法
    def double_encrypt(self):
        try:
            plaintext = self.parse_input(self.double_plain.text())
            k1 = self.parse_input(self.k1_edit.text())
            k2 = self.parse_input(self.k2_edit.text())

            ciphertext = self.mode_handler.double_encrypt(plaintext, k1, k2)
            self.double_cipher.setText(self.format_output(ciphertext))

        except Exception as e:
            QMessageBox.warning(self, "错误", f"双重加密失败: {str(e)}")

    def double_decrypt(self):
        try:
            ciphertext = self.parse_input(self.double_cipher.text().split(' ')[1])
            k1 = self.parse_input(self.k1_edit.text())
            k2 = self.parse_input(self.k2_edit.text())

            plaintext = self.mode_handler.double_decrypt(ciphertext, k1, k2)
            self.double_decrypt_output.setText(self.format_output(plaintext))

        except Exception as e:
            QMessageBox.warning(self, "错误", f"双重解密失败: {str(e)}")

    # 中间相遇攻击
    def mitm_attack(self):
        try:
            plaintext = self.parse_input(self.known_plain.text())
            ciphertext = self.parse_input(self.known_cipher.text())

            found_keys = self.mode_handler.mitm_attack(plaintext, ciphertext)

            # 显示结果
            result_text = ""
            for i, (k1, k2) in enumerate(found_keys):
                result_text += f"密钥对 {i + 1}: K1={format(k1, '016b')}(0x{format(k1, '04x')}), "
                result_text += f"K2={format(k2, '016b')}(0x{format(k2, '04x')})\n"

            if not found_keys:
                result_text = "未找到匹配的密钥对"

            self.mitm_results.setPlainText(result_text)

        except Exception as e:
            QMessageBox.warning(self, "错误", f"中间相遇攻击失败: {str(e)}")

    # 三重加密方法
    def triple_encrypt(self):
        try:
            plaintext = self.parse_input(self.triple_plain.text())
            k1 = self.parse_input(self.triple_k1.text())
            k2 = self.parse_input(self.triple_k2.text())
            k3 = self.parse_input(self.triple_k3.text())

            ciphertext = self.mode_handler.triple_encrypt(plaintext, k1, k2, k3)
            self.triple_cipher.setText(self.format_output(ciphertext))

        except Exception as e:
            QMessageBox.warning(self, "错误", f"三重加密失败: {str(e)}")

    def triple_decrypt(self):
        try:
            ciphertext = self.parse_input(self.triple_cipher.text().split(' ')[1])
            k1 = self.parse_input(self.triple_k1.text())
            k2 = self.parse_input(self.triple_k2.text())
            k3 = self.parse_input(self.triple_k3.text())

            plaintext = self.mode_handler.triple_decrypt(ciphertext, k1, k2, k3)
            self.triple_decrypt_output.setText(self.format_output(plaintext))

        except Exception as e:
            QMessageBox.warning(self, "错误", f"三重解密失败: {str(e)}")

    # CBC模式方法
    def cbc_encrypt(self):
        try:
            text = self.cbc_plain.toPlainText()
            key = self.parse_input(self.cbc_key.text())
            iv = self.parse_input(self.cbc_iv.text())

            encrypted_blocks = self.mode_handler.cbc_encrypt(text, key, iv)
            # 转换为十六进制字符串显示
            hex_result = ' '.join(format(b, '04x') for b in encrypted_blocks)
            self.cbc_encrypted.setPlainText(hex_result)

        except Exception as e:
            QMessageBox.warning(self, "错误", f"CBC加密失败: {str(e)}")

    def cbc_decrypt(self):
        try:
            hex_text = self.cbc_encrypted.toPlainText()
            key = self.parse_input(self.cbc_key.text())
            iv = self.parse_input(self.cbc_iv.text())

            # 解析十六进制块
            hex_blocks = hex_text.split()
            encrypted_blocks = [int(block, 16) for block in hex_blocks]

            decrypted_text = self.mode_handler.cbc_decrypt(encrypted_blocks, key, iv)
            self.cbc_decrypted.setPlainText(decrypted_text)

        except Exception as e:
            QMessageBox.warning(self, "错误", f"CBC解密失败: {str(e)}")

    def tamper_test(self):
        try:
            # 测试CBC模式下的篡改
            text = "Test message for tampering!"
            key = self.parse_input(self.cbc_key.text()) if self.cbc_key.text() else 0x2D55
            iv = self.parse_input(self.cbc_iv.text()) if self.cbc_iv.text() else 0x1234

            # 加密
            encrypted_blocks = self.mode_handler.cbc_encrypt(text, key, iv)

            # 篡改一个块（改变一个字节）
            tampered_blocks = encrypted_blocks.copy()
            if len(tampered_blocks) > 1:
                # 篡改第二个块
                tampered_blocks[1] ^= 0xFF00

            # 解密切换的块
            decrypted_tampered = self.mode_handler.cbc_decrypt(tampered_blocks, key, iv)

            # 显示比较结果
            result = f"原始文本: {text}\n"
            result += f"篡改后解密: {decrypted_tampered}\n"
            result += f"影响范围: 篡改的块和下一个块都会受影响"

            self.tamper_result.setPlainText(result)

        except Exception as e:
            QMessageBox.warning(self, "错误", f"篡改测试失败: {str(e)}")


def main():
    app = QApplication(sys.argv)
    window = SAESApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()