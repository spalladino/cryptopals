from pprint import pprint
from encoding import *
from aes_ecb import *


def ecb_score(bytes):
  """Returns a score on how likely this sequence is to have been produced by ECB by detecting 128-bits repeating blocks"""
  chunks = [bytes[i:i+16] for i in xrange(0, len(bytes), 16)]
  score = 0
  for index,chunk in enumerate(chunks):
    for other_chunk in chunks[index+1:]:
      if chunk == other_chunk:
        score += 1
  return float(score) / len(chunks)


def aes_method(bytes, min_score_for_ecb=1):
  """Returns whether the AES method used is ECB or CBC"""
  score = ecb_score(bytes)
  method = 'ecb' if score > min_score_for_ecb else 'cbc'
  return method, score


def detect_ecb(bytes_list):
  """Attempts to guess which byte array in the list was encoded with ECB"""
  guesses = [(ecb_score(bytes), bytes) for bytes in bytes_list]
  guesses.sort(reverse=True)
  if guesses[0][0] == guesses[1][0]: raise StandardError("There is no byte sequence with dominant ECB score")
  return guesses[0]


def challenge8():
  """
  8. Detecting ECB

  At the following URL are a bunch of hex-encoded ciphertexts:

     https://gist.github.com/3132928

  One of them is ECB encrypted. Detect it.

  Remember that the problem with ECB is that it is stateless and
  deterministic; the same 16 byte plaintext block will always produce
  the same 16 byte ciphertext.
  """
  with open('../resources/detect_ecb.txt', 'r') as f:
    data = [hex2bytearray(line.strip()) for line in f.readlines()]
    score, bytes = detect_ecb(data)
    print "Score: {0}".format(score)
    print bytearray2hex(bytes)
    

if __name__ == '__main__':
  challenge8()