import unittest

from encoding import *

def pkcs7_pad(bytes, block_length):
  n = len(bytes)
  padding = block_length - (n % block_length)
  if padding == block_length: return bytes
  bytes[n:n+padding] = list2bytearray([padding] * padding)
  return bytes


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