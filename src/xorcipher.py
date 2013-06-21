import freqs

from xor import xor
from encoding import *

def single_char_xor_cipher(bytes):
  """
  3. Single-character XOR Cipher

  The hex encoded string:

  1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

  ... has been XOR'd against a single character. Find the key, decrypt
  the message.

  Write code to do this for you. How? Devise some method for "scoring" a
  piece of English plaintext. (Character frequency is a good metric.)
  Evaluate each output and choose the one with the best score.

  Tune your algorithm until this works.
  """
  text = bytes.tostring()
  keys = []
  for c in range(256):
    mask = [c] * len(bytes)
    key = xor(bytes, mask).tostring()
    keys.append((freqs.score(key), key, c))

  candidates = sorted(keys, reverse=True)[0:5]
  return candidates
    

if __name__ == '__main__':
  input = hex2bytearray("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  print '\n'.join([str(t) for t in single_char_xor_cipher(input)])