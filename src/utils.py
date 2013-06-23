def blocks(data, block_size):
  """Returns blocks of block_size length from data"""
  return [data[i:i+block_size] for i in xrange(0, len(data), block_size)]