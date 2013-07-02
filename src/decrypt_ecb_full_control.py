import unittest
import random

from pprint import pprint
from oracle import encryption_oracle
from detect_ecb import ecb_score

from utils import *
from random import *
from encoding import *
from aes_ecb import *
from distance import *

key = randbytes(16).tostring()

def encrypt(bytes, wrap_bytes=False):
  """Enctyprs with constant key using ECB"""
  return encryption_oracle(bytes, key, 'ecb', use_prefix=wrap_bytes, use_suffix=wrap_bytes)

def keysize_candidates(bytes, num_cands=5, num_chunks=12, min=8, max=24):
  """Returns candidates for keysize as list of (score, size), where the lower the score, the better"""
  if num_chunks * max > len(bytes):
    raise StandardError("Number of chunks times max key size exceedes input size")

  candidates = []
  for keysize in xrange(min, max+1):
    chunks = [bytes[chunk_index * keysize : (chunk_index+1) * keysize] for chunk_index in range(num_chunks)]
    distances = [normalized_hamming(chunks[i], chunks[i+1]) for i in range(num_chunks-1)]
    average = float(sum(distances)) / float(len(distances))
    candidates.append((average, keysize))
  return sorted(candidates)[0:num_cands]


def challenge12():
  """
  12. Byte-at-a-time ECB decryption, Full control version

  Copy your oracle function to a new function that encrypts buffers
  under ECB mode using a consistent but unknown key (for instance,
  assign a single random key, once, to a global variable).

  Now take that same function and have it append to the plaintext,
  BEFORE ENCRYPTING, the following string:

    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK

  SPOILER ALERT: DO NOT DECODE THIS STRING NOW. DON'T DO IT.

  Base64 decode the string before appending it. DO NOT BASE64 DECODE THE
  STRING BY HAND; MAKE YOUR CODE DO IT. The point is that you don't know
  its contents.

  What you have now is a function that produces:

    AES-128-ECB(your-string || unknown-string, random-key)

  You can decrypt "unknown-string" with repeated calls to the oracle
  function!

  Here's roughly how:

  a. Feed identical bytes of your-string to the function 1 at a time ---
  start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
  block size of the cipher. You know it, but do this step anyway.

  b. Detect that the function is using ECB. You already know, but do
  this step anyways.

  c. Knowing the block size, craft an input block that is exactly 1 byte
  short (for instance, if the block size is 8 bytes, make
  "AAAAAAA"). Think about what the oracle function is going to put in
  that last byte position.

  d. Make a dictionary of every possible last byte by feeding different
  strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
  "AAAAAAAC", remembering the first block of each invocation.

  e. Match the output of the one-byte-short input to one of the entries
  in your dictionary. You've now discovered the first byte of
  unknown-string.

  f. Repeat for the next byte.
  """
  unknown_string = base642bytearray("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

  # Key size is guessed using same technique as in break xor, with a fixed input, and not feeding one byte at a time
  encrypted = encrypt(string2bytearray("A" * 400))
  [(_, keysize)] = keysize_candidates(encrypted, num_cands=1)
  print "Keysize is", keysize

  # Ensure it is using ECB
  score = ecb_score(encrypted)
  method = 'ecb' if score > 0.1 else 'cbc'
  print "Method is", method, "with score", score
  
  # Guess the unknown string byte by byte
  decrypted = ""
  n = len(unknown_string)
  for index in xrange(n):
    padded_size = n + keysize - n % keysize
    short_string = string2bytearray("A" * (padded_size - len(decrypted) - 1))
    encrypted_short_string = encrypt(short_string + unknown_string)

    for guess in xrange(256):
      guess_string = string2bytearray("A" * (padded_size - len(decrypted) - 1) + decrypted + chr(guess))
      test = encrypt(guess_string)

      if test == encrypted_short_string[0:len(test)]:
        decrypted += chr(guess)
        break

  print
  print decrypted
  

if __name__ == '__main__':
  challenge12()