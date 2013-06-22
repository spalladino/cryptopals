import freqs

from xor import xor
from encoding import *

def break_single_char_xor_cipher(bytes, num_cands=1, freqs_score_alpha=0.5):
  """Returns most likely candidates for XOR single char key"""
  keys = []
  for c in range(256):
    mask = [c] * len(bytes)
    key = xor(bytes, mask).tostring()
    keys.append((freqs.score(key,freqs_score_alpha), key, c))

  candidates = sorted(keys, reverse=True)[0:num_cands]
  return candidates

def challenge3():
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
  input = hex2bytearray("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  [(score, text, mask)] = break_single_char_xor_cipher(input, 1)
  print text
  print chr(mask)

if __name__ == '__main__':
  challenge3()