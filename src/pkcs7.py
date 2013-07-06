import unittest

from encoding import *


def pkcs7_pad_string(string, block_length=16):
  """Pads a string using PKCS7"""
  return pkcs7_pad(string2bytearray(string), block_length).tostring()


def pkcs7_pad(bytes, block_length=16):
  """Pads a byte array using PKCS7"""
  n = len(bytes)
  padding = block_length - (n % block_length)
  if padding == block_length: return bytes
  bytes[n:n+padding] = list2bytearray([padding] * padding)
  return bytes


def pkcs7_strip(bytes):
  """Strips PKCS7 padding from a byte array"""
  last = bytes[-1]
  if all(byte == last for byte in bytes[-last:]):
    return bytes[:-last]
  else:
    raise Exception("Invalid padding for byte sequence")


def pkcs7_strip_string(string):
  """Strips PKCS7 padding from a string"""
  return pkcs7_strip(string2bytearray(string)).tostring()


class TestChallenge15(unittest.TestCase):
  """
  15. PKCS#7 padding validation

  Write a function that takes a plaintext, determines if it has valid
  PKCS#7 padding, and strips the padding off.

  The string:

      "ICE ICE BABY\x04\x04\x04\x04"

  has valid padding, and produces the result "ICE ICE BABY".

  The string:

      "ICE ICE BABY\x05\x05\x05\x05"

  does not have valid padding, nor does:

       "ICE ICE BABY\x01\x02\x03\x04"

  If you are writing in a language with exceptions, like Python or Ruby,
  make your function throw an exception on bad padding.
  """

  def test_pkcs7_strip(self):
    input = string2bytearray("ICE ICE BABY\x04\x04\x04\x04")
    expected = string2bytearray("ICE ICE BABY")
    self.assertEqual(pkcs7_strip(input), expected)

  def test_pkcs7_strip_string(self):
    input = "ICE ICE BABY\x04\x04\x04\x04"
    expected = "ICE ICE BABY"
    self.assertEqual(pkcs7_strip_string(input), expected)

  def test_pkcs7_strip_invalid_padding(self):
    input = string2bytearray("ICE ICE BABY\x05\x05\x05\x05")
    self.assertRaises(Exception, pkcs7_strip, (input))



class TestChallenge9(unittest.TestCase):
  """
  9. Implement PKCS#7 padding

  Pad any block to a specific block length, by appending the number of
  bytes of padding to the end of the block. For instance,

    "YELLOW SUBMARINE"

  padded to 20 bytes would be:

    "YELLOW SUBMARINE\x04\x04\x04\x04"

  The particulars of this algorithm are easy to find online.
  """

  def test_pkcs7(self):
    input = string2bytearray("YELLOW SUBMARINE")
    expected = string2bytearray("YELLOW SUBMARINE\x04\x04\x04\x04")
    self.assertEqual(pkcs7_pad(input, 20), expected)

  def test_pkcs7_with_array_longer_than_block(self):
    input = string2bytearray("YELLOW SUBMARINE")
    expected = string2bytearray("YELLOW SUBMARINE\x04\x04\x04\x04")
    self.assertEqual(pkcs7_pad(input, 5), expected)

  def test_pkcs7_with_array_multiple_of_block(self):
    input = string2bytearray("YELLOW SUBMARINE")
    expected = string2bytearray("YELLOW SUBMARINE")
    self.assertEqual(pkcs7_pad(input, 4), expected)


if __name__ == '__main__':
  unittest.main()