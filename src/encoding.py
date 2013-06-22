import unittest
from base64 import b64encode, b64decode
from array import array
from binascii import hexlify

def hex2bytearray(hex):
  """Converts string in hex to byte array"""
  return array('B', hex.decode('hex'))

def bytearray2hex(ary):
  """Converts byte array hex string"""
  return hexlify(ary)
  
def bytearray2base64(ary):
  """Converts byte array to base 64 string"""
  return b64encode(ary)

def base642bytearray(str):
  """Converts base 64 string to byte array"""
  return array('B', b64decode(str))
  
def hex2base64(hex_string):
  """Converts hex string to base 64 string"""
  ary = hex2bytearray(hex_string)
  return bytearray2base64(ary)

def string2bytearray(string):
  return array('B', string)

class TestChallenge1(unittest.TestCase):
  """
  1. Convert hex to base64 and back.

  The string:

    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

  should produce:

    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

  Now use this code everywhere for the rest of the exercises. Here's a
  simple rule of thumb:

    Always operate on raw bytes, never on encoded strings. Only use hex
    and base64 for pretty-printing.
  """
  
  def test_hex2base64(self):
    # I'm killing your brain like a poisonous mushroom
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    self.assertEqual(hex2base64(input), expected)


if __name__ == '__main__':
    unittest.main()