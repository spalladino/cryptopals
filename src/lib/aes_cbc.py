from encoding import *
from utils import *

from xor import xor
from aes_ecb import encrypt_aes_ecb, decrypt_aes_ecb
from pkcs7 import pkcs7_pad, InvalidPaddingException

BLOCKSIZE = 16

def encrypt_aes_cbc(data, key, iv=string2bytearray("\x00" * 16), pad=False):
  output = []
  if pad: data = pkcs7_pad(data, BLOCKSIZE)
  elif len(data) % BLOCKSIZE != 0: raise InvalidPaddingException("AES CBC encryption requires data multiple of {0}".format(BLOCKSIZE))

  xor_str = iv
  for block in blocks(data, BLOCKSIZE):
    encrypted = encrypt_aes_ecb(xor(block, xor_str), key)
    xor_str = encrypted
    output += encrypted

  return list2bytearray(output)


def decrypt_aes_cbc(data, key, iv=string2bytearray("\x00" * 16)):
  output = []
  xor_str = iv

  for block in blocks(data, BLOCKSIZE):
    decrypted = xor(decrypt_aes_ecb(block, key), xor_str)
    output += decrypted
    xor_str = block

  return list2bytearray(output)


class TestCBC(unittest.TestCase):
  """Tests CBC encryption/decryption"""

  def test_encrpyt_decrypt(self):
    data = string2bytearray("12345678901234567890123456789012")
    key = "YELLOW SUBMARINE".lower()
    self.assertEqual(decrypt_aes_cbc(encrypt_aes_cbc(data, key), key), data)

  def test_encrpyt_decrypt_padding(self):
    data = string2bytearray("123456789012345678901234567890")
    expected = string2bytearray("123456789012345678901234567890\x02\x02")
    key = "YELLOW SUBMARINE".lower()
    self.assertEqual(decrypt_aes_cbc(encrypt_aes_cbc(data, key, pad=True), key), expected)


def challenge10():
  """
  10. Implement CBC Mode

  In CBC mode, each ciphertext block is added to the next plaintext
  block before the next call to the cipher core.

  The first plaintext block, which has no associated previous ciphertext
  block, is added to a "fake 0th ciphertext block" called the IV.

  Implement CBC mode by hand by taking the ECB function you just wrote,
  making it encrypt instead of decrypt (verify this by decrypting
  whatever you encrypt to test), and using your XOR function from
  previous exercise.

  DO NOT CHEAT AND USE OPENSSL TO DO CBC MODE, EVEN TO VERIFY YOUR
  RESULTS. What's the point of even doing this stuff if you aren't going
  to learn from it?

  The buffer at:

      https://gist.github.com/3132976

  is intelligible (somewhat) when CBC decrypted against "YELLOW
  SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
  """

  key = "YELLOW SUBMARINE"
  iv = string2bytearray("\x00" * 16)
  data = base64file2bytearray('../../resources/aes_cbc.txt')
  print decrypt_aes_cbc(data, key, iv).tostring()


if __name__ == '__main__':
  challenge10()
  unittest.main()
