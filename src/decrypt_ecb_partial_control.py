import unittest
import random

from pprint import pprint
from oracle import encryption_oracle

from detect_ecb import *
from utils import *
from random import *
from encoding import *
from aes_ecb import *
from distance import *

unknown_string = base642bytearray("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
key = randbytes(16).tostring()
prefix = randbytes(4,160)


def encrypt(bytes):
  """Encrypts with constant key using ECB"""
  return encryption_oracle(prefix + bytes + unknown_string, key, 'ecb', use_prefix=False, use_suffix=False)


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


def find_attacker_size(keysize, plain_chunk):
  """Attempts to guess which is the size of attacker-controlled string needed to ensure target-string begins in new block"""
  previous_num_plain_chunks = None

  for size in xrange(400, 400+keysize+1):
    encrypted = encrypt(string2bytearray("A" * size))
    chunks = [encrypted[i:i+keysize] for i in xrange(keysize*10, len(encrypted), keysize)]
    num_plain_chunks = len([chunk for chunk in chunks if chunk == plain_chunk])
    
    # When the number of "AAAA..." chunks increases by one, it means we have moved the target string to a new block
    if previous_num_plain_chunks is not None and num_plain_chunks == previous_num_plain_chunks+1:
      return size, (num_plain_chunks+10) * keysize
    else:
      previous_num_plain_chunks = num_plain_chunks


def challenge14():
  """
  14. Byte-at-a-time ECB decryption, Partial control version

  Take your oracle function from #12. Now generate a random count of
  random bytes and prepend this string to every plaintext. You are now
  doing:

    AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

  Same goal: decrypt the target-bytes.

  What's harder about doing this?

  How would you overcome that obstacle? The hint is: you're using
  all the tools you already have; no crazy math is required.

  Think about the words "STIMULUS" and "RESPONSE".
  """
  # Key size is guessed using same technique as in break xor, with a fixed input, and not feeding one byte at a time
  encrypted = encrypt(string2bytearray("A" * 400))
  [(_, keysize)] = keysize_candidates(encrypted, num_cands=1)
  print "Guessed keysize is", keysize

  # Ensure it is using ECB
  method, score = aes_method(encrypted)
  print "Method is", method, "with score", score
  
  # Start by finding out how a bunch of A's look like encrypted under target key
  # We assume that after keysize * 10 there is no 'prefix' left
  plain_chunk = encrypted[keysize * 10 : keysize * 11]

  # Now we need to know exactly when the A's end and the target string begins, by looking at the chunks
  attacker_size, padded_size = find_attacker_size(keysize, plain_chunk)
  print "Size of attacker string to ensure that the target string begins in a new block is", attacker_size, "and total size of prefix+attacker is", padded_size

  # Guess the unknown string byte by byte as in full control version
  n = len(unknown_string) + 200
  decrypted = ""

  for index in xrange(n):
    short_string = string2bytearray("A" * (attacker_size - len(decrypted) - 1))
    encrypted_short_string = encrypt(short_string)

    match_found = False
    for guess in xrange(256):
      guess_string = string2bytearray("A" * (attacker_size - len(decrypted) - 1) + decrypted + chr(guess))
      test = encrypt(guess_string)

      if test[keysize*10:padded_size] == encrypted_short_string[keysize*10:padded_size]:
        decrypted += chr(guess)
        match_found = True
        break
    
    if not match_found:
      break

  print
  print decrypted
  

if __name__ == '__main__':
  challenge14()