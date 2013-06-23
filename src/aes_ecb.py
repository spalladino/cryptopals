from encoding import *
from Crypto.Cipher import AES

def encrypt_aes_ecb(bytes, key):
  """Encrypts bytes with AES 128 in ECB mode with specified key"""
  mode = AES.MODE_ECB
  encryptor  = AES.new(key, mode)
  return string2bytearray(encryptor.encrypt(bytes.tostring()))


def decrypt_aes_ecb(bytes, key):
  """Decrypts bytes encrypted with AES 128 in ECB mode with specified key"""
  mode = AES.MODE_ECB
  decryptor  = AES.new(key, mode)
  return string2bytearray(decryptor.decrypt(bytes.tostring()))


class TestECB(unittest.TestCase):
  """Tests ECB encryption/decryption"""
  
  def test_encrpyt_decrypt(self):
    data = string2bytearray("12345678901234567890123456789012")
    key = "YELLOW SUBMARINE"
    self.assertEqual(decrypt_aes_ecb(encrypt_aes_ecb(data, key), key), data)


def challenge7():
  """
  AES in ECB Mode

  The Base64-encoded content at the following location:

      https://gist.github.com/3132853

  Has been encrypted via AES-128 in ECB mode under the key

      "YELLOW SUBMARINE".

  (I like "YELLOW SUBMARINE" because it's exactly 16 bytes long).

  Decrypt it.

  Easiest way:

  Use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
  """
  key = "YELLOW SUBMARINE"
  data = base64file2bytearray('../resources/aes_ecb.txt')
  print decrypt_aes_ecb(data, key).tostring()
    

if __name__ == '__main__':
  challenge7()
  unittest.main()