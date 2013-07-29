import unittest

from encoding import *


def hamming(a,b):
  """Computes hamming distance between both byte arrays of same length"""
  if len(a) != len(b):
    raise StandardError("Both buffers to compute distance should have equal length") 
  
  sum = 0
  for i in range(len(a)):
    for j in range(8):
      x = (a[i] >> j) & 1
      y = (b[i] >> j) & 1
      if x != y: sum += 1
  
  return sum
  
  
def normalized_hamming(a,b):
  """Computes hamming distance and normalizes using string length"""
  return float(hamming(a,b)) / len(a*8)
 
 
class TestDistance(unittest.TestCase):
  
  def test_hamming(self):
    a = string2bytearray("this is a test")
    b = string2bytearray("wokka wokka!!!")
    
    self.assertEqual(hamming(a,b), 37)
    self.assertEqual(normalized_hamming(a,b), 37.0 / (14*8))


if __name__ == '__main__':
    unittest.main()