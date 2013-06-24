import unittest
import random

from encoding import *
from utils import *

from pkcs7 import pkcs7_pad
from detect_ecb import ecb_score
from aes_cbc import encrypt_aes_cbc
from aes_ecb import encrypt_aes_ecb


def encryption_oracle(data, force_key=None, force_mode=None):
  key = force_key or randbytes(16).tostring()
  mode = random.choice('ecb','cbc') if force_mode is None else force_mode
  
  prefix = randbytes(random.randint(5,10))
  suffix = randbytes(random.randint(5,10))
  to_encrypt = pkcs7_pad(prefix + data + suffix, 16)

  if mode == 'cbc':
    return encrypt_aes_cbc(to_encrypt, key, iv=randbytes(16))
  elif mode == 'ecb':
    return encrypt_aes_ecb(to_encrypt, key)
  else:
    raise StandardError("Mode not supported: " + mode)


def guess_encryption(data):
  """Attempts to guess encryption mode of a byte array, either ecb or cbc"""
  # TODO: Fine-tune tolerance
  return 'ecb' if ecb_score(data) > 0.001 else 'cbc'


class TestChallenge11(unittest.TestCase):
  """
  Write an oracle function and use it to detect ECB.

  Now that you have ECB and CBC working:

  Write a function to generate a random AES key; that's just 16 random
  bytes.

  Write a function that encrypts data under an unknown key --- that is,
  a function that generates a random key and encrypts under it.

  The function should look like:

  encryption_oracle(your-input)
   => [MEANINGLESS JIBBER JABBER]

  Under the hood, have the function APPEND 5-10 bytes (count chosen
  randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.

  Now, have the function choose to encrypt under ECB 1/2 the time, and
  under CBC the other half (just use random IVs each time for CBC). Use
  rand(2) to decide which to use.

  Now detect the block cipher mode the function is using each time.
  """

  def setUp(self):
    with open('../resources/oracle.txt', 'r') as f:
      self.data = string2bytearray(f.read())

  def test_guess_ecb(self):
    encrypted = encryption_oracle(self.data, force_mode='ecb')
    self.assertEqual(guess_encryption(encrypted), 'ecb')

  def test_guess_cbc(self):
    encrypted = encryption_oracle(self.data, force_mode='cbc')
    self.assertEqual(guess_encryption(encrypted),'cbc')

if __name__ == '__main__':
    unittest.main()