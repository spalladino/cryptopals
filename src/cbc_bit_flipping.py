import unittest
import random

from pprint import pprint
from lib.aes_method import ecb_score
from lib.aes_cbc import encrypt_aes_cbc, decrypt_aes_cbc
from lib.xor import xor, complement

from lib.utils import *
from lib.encoding import *
from lib.distance import *

key = randbytes(16).tostring()


def create_cookie(userdata):
  """Creates a plain text cookie with comments from supplied userdata"""
  return "comment1=cooking%20MCs;userdata=" + userdata.replace(';', '%3B').replace('=', '%3D') + ";comment2=%20like%20a%20pound%20of%20bacon"


def create_encrypted_cookie(userdata):
  """Creates a CBC encrypted cookie with comments from supplied userdata"""
  cookie = create_cookie(userdata)
  return encrypt(cookie)


def encrypt(data):
  """Encrypts data using CBC and a fixed key"""
  return encrypt_aes_cbc(string2bytearray(data), key, pad=True)


def is_admin(encrypted):
  """Given an encrypted cookie, checks whether admin=true is set"""
  return ";admin=true;" in decrypt_aes_cbc(encrypted, key).tostring()


class TestChallenge16(unittest.TestCase):
  """Tests for utility classes for challenge 16"""

  def test_create_cookie(self):
    input = "foo=bar;baz=bat"
    expected = "comment1=cooking%20MCs;userdata=foo%3Dbar%3Bbaz%3Dbat;comment2=%20like%20a%20pound%20of%20bacon"
    self.assertEqual(create_cookie(input), expected)

  def test_is_admin(self):
    input = encrypt("foo=bar;admin=true;baz=bat;")
    self.assertEqual(is_admin(input), True)

  def test_is_admin_not_set(self):
    input = encrypt("foo=bar;baz=bat;")
    self.assertEqual(is_admin(input), False)

  def test_cannot_forge_admin(self):
    input = create_encrypted_cookie("foo;admin=true;")
    self.assertEqual(is_admin(input), False)

  def test_is_not_admin(self):
    input = encrypt("foo=bar;admin=false;baz=bat;")
    self.assertEqual(is_admin(input), False)


def challenge16():
  """
  16. CBC bit flipping

  Generate a random AES key.

  Combine your padding code and CBC code to write two functions.

  The first function should take an arbitrary input string, prepend the
  string:
          "comment1=cooking%20MCs;userdata="
  and append the string:
      ";comment2=%20like%20a%20pound%20of%20bacon"

  The function should quote out the ";" and "=" characters.

  The function should then pad out the input to the 16-byte AES block
  length and encrypt it under the random AES key.

  The second function should decrypt the string and look for the
  characters ";admin=true;" (or, equivalently, decrypt, split the string
  on ;, convert each resulting string into 2-tuples, and look for the
  "admin" tuple. Return true or false based on whether the string exists.

  If you've written the first function properly, it should not be
  possible to provide user input to it that will generate the string the
  second function is looking for.

  Instead, modify the ciphertext (without knowledge of the AES key) to
  accomplish this.

  You're relying on the fact that in CBC mode, a 1-bit error in a
  ciphertext block:

  * Completely scrambles the block the error occurs in

  * Produces the identical 1-bit error (/edit) in the next ciphertext
   block.

  Before you implement this attack, answer this question: why does CBC
  mode have this property?
  """
  encrypted = create_encrypted_cookie("A" * 32)

  bytes_to_change = xor(string2bytearray("A" * 16), string2bytearray("AAAB;admin=true;"))
  mangled_block =   xor(encrypted[32:48], bytes_to_change)

  encrypted[32:48] = mangled_block

  print is_admin(encrypted)


if __name__ == '__main__':
  challenge16()
  unittest.main()
