import random

from encoding import *

def blocks(data, block_size):
  """Returns blocks of block_size length from data"""
  return [data[i:i+block_size] for i in xrange(0, len(data), block_size)]

def randbytes(length):
  """Returns block of random bytes"""
  return list2bytearray([random.randint(0,255) for i in xrange(length)])