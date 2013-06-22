import unittest

from encoding import *

def xor(a,b):
  """Calculates XOR between same-length byte arrays a and b"""
  if len(a) != len(b): raise StandardError("Both buffers to XOR should have equal length") 
  return array('B', [a[i] ^ b[i] for i in range(len(a))])


class TestChallenge2(unittest.TestCase):
  """
  2. Fixed XOR

  Write a function that takes two equal-length buffers and produces
  their XOR sum.

  The string:

   1c0111001f010100061a024b53535009181c

  ... after hex decoding, when xor'd against:

   686974207468652062756c6c277320657965

  ... should produce:

   746865206b696420646f6e277420706c6179
  """
  
  def test_xor(self):
    a = hex2bytearray("1c0111001f010100061a024b53535009181c")
    b = hex2bytearray("686974207468652062756c6c277320657965")
    expected = hex2bytearray("746865206b696420646f6e277420706c6179")

    self.assertEqual(xor(a,b), expected)


if __name__ == '__main__':
    unittest.main()