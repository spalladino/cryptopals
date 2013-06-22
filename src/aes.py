from encoding import *
from Crypto.Cipher import AES


def decrypt_aes_ecb(bytes, key):
  """Decrypts bytes encrypted with AES 128 in ECB mode with specified key"""
  mode = AES.MODE_ECB
  decryptor  = AES.new(key, mode)
  return decryptor.decrypt(bytes.tostring())


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
  with open('../resources/aes_ecb.txt', 'r') as f:
    data = "".join([line.strip() for line in f.readlines()])
    data = base642bytearray(data)
    print decrypt_aes_ecb(data, key)
    

if __name__ == '__main__':
  challenge7()