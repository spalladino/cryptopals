import random

from encoding import *

def blocks(data, block_size):
  """Returns blocks of block_size length from data"""
  return [data[i:i+block_size] for i in xrange(0, len(data), block_size)]

def randbytes(length, max_length=None):
  """Returns block of random bytes"""
  length = length if max_length is None else random.randint(length, max_length)
  return list2bytearray([random.randint(0,255) for i in xrange(length)])

def generateblocks(block_size):
  """Iterates over all possible blocks of specified size in order, starting with zeroes"""
  if block_size == 0:
    yield []
    return
  for i in range(256):
    for tail in generateblocks(block_size - 1):
      yield ([i] + tail)
