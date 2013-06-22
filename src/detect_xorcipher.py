import freqs

from encoding import *
from xor import xor
from xorcipher import single_char_xor_cipher


def detect_single_char_xor_cipher(bytes_list, num_cands=5):
  """Returns most likely strings to have been encrpyted by single char XOR"""
  candidates = []
  for bytes in bytes_list:
    [(score, key, char)] = single_char_xor_cipher(bytes)
    candidates.append((score, key, bytes))
  
  return sorted(candidates, reverse=True)[0:num_cands]

  
def challenge4():
  """
  4. Detect single-character XOR

  One of the 60-character strings at:

    https://gist.github.com/3132713

  has been encrypted by single-character XOR. Find it. (Your code from #3 should help.)
  """
  with open('../resources/detect_single_char_xor.txt', 'r') as f:
    data = [hex2bytearray(line.strip()) for line in f.readlines()]
    # print "\n".join([str((score, key, bytes.tostring())) for (score, key, bytes) in detect_single_char_xor_cipher(data, 10)])
    [(score, key, bytes)] = detect_single_char_xor_cipher(data, 1)
    print bytearray2hex(bytes)
    print key
  

if __name__ == '__main__':
  challenge4()