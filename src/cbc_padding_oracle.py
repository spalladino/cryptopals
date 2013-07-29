from lib.encoding import *
from random import choice
from lib.oracle import random_key
from lib.aes_cbc import decrypt_aes_cbc, encrypt_aes_cbc
from lib.pkcs7 import pkcs7_valid, pkcs7_pad

key = random_key()

strings = [
  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]

def encrypt_random_string():
  """Picks a random string from the sample and encrypts it using a constant key, returning the encrypted string and the iv"""
  iv = string2bytearray(random_key())
  to_encrypt = pkcs7_pad(base642bytearray(choice(strings)))
  return (encrypt_aes_cbc(to_encrypt, key, iv), iv)

def check_encrypted_padding(encrypted, iv):
  """Decrypts the encrypted string using the iv and returns whether the padding was correct"""
  decrypted = decrypt_aes_cbc(encrypted, key, iv)
  return pkcs7_valid(decrypted)


class TestChallenge17(unittest.TestCase):

  def test_encrypt_and_check(self):
    self.assertTrue(check_encrypted_padding(*encrypt_random_string()))

  def test_check_incorrect(self):
    iv = string2bytearray(random_key())
    to_encrypt = string2bytearray("A" * 62 + "\x03\x03")
    encrypted = encrypt_aes_cbc(to_encrypt, key, iv)
    self.assertFalse(check_encrypted_padding(encrypted, iv))


def challenge17():
  """
  17. The CBC padding oracle

  Combine your padding code and your CBC code to write two functions.

  The first function should select at random one of the following 10
  strings:

  MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
  MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
  MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
  MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
  MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
  MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
  MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
  MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
  MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
  MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

  generate a random AES key (which it should save for all future
  encryptions), pad the string out to the 16-byte AES block size and
  CBC-encrypt it under that key, providing the caller the ciphertext and
  IV.

  The second function should consume the ciphertext produced by the
  first function, decrypt it, check its padding, and return true or
  false depending on whether the padding is valid.

  This pair of functions approximates AES-CBC encryption as its deployed
  serverside in web applications; the second function models the
  server's consumption of an encrypted session token, as if it was a
  cookie.

  It turns out that it's possible to decrypt the ciphertexts provided by
  the first function.

  The decryption here depends on a side-channel leak by the decryption
  function.

  The leak is the error message that the padding is valid or not.

  You can find 100 web pages on how this attack works, so I won't
  re-explain it. What I'll say is this:

  The fundamental insight behind this attack is that the byte 01h is
  valid padding, and occur in 1/256 trials of "randomized" plaintexts
  produced by decrypting a tampered ciphertext.

  02h in isolation is NOT valid padding.

  02h 02h IS valid padding, but is much less likely to occur randomly
  than 01h.

  03h 03h 03h is even less likely.

  So you can assume that if you corrupt a decryption AND it had valid
  padding, you know what that padding byte is.

  It is easy to get tripped up on the fact that CBC plaintexts are
  "padded". Padding oracles have nothing to do with the actual padding
  on a CBC plaintext. It's an attack that targets a specific bit of code
  that handles decryption. You can mount a padding oracle on ANY CBC
  block, whether it's padded or not.
  """

  encrypted, iv = encrypt_random_string()
  first_block = encrypted[0:16]
  print len(first_block)
  print check_encrypted_padding(first_block, iv)

  pass

if __name__ == '__main__':
  challenge17()
  unittest.main()

