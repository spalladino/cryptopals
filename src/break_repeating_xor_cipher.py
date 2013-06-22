import freqs

from pprint import pprint
from encoding import *
from distance import *
from break_xor_cipher import *
from repeatingxor import *
from xor import xor

def keysize_candidates(bytes, num_cands=1, num_chunks=2, min=2, max=40):
  """Returns candidates for XOR keysize as list of (score, size), where the lower the score, the better"""
  if num_chunks * max > len(bytes):
    raise StandardError("Number of chunks times max key size exceedes input size")

  candidates = []
  for keysize in xrange(min, max+1):
    chunks = [bytes[chunk_index * keysize : (chunk_index+1) * keysize] for chunk_index in range(num_chunks)]
    distances = [normalized_hamming(chunks[i], chunks[i+1]) for i in range(num_chunks-1)]
    average = float(sum(distances)) / len(distances)
    candidates.append((average, keysize))
  return sorted(candidates)[0:num_cands]

  
def transpose(bytes, size):
  """Breaks byte array into blocks of specified size and transposes them"""
  return [ [bytes[j] for j in xrange(i,len(bytes),size)] for i in xrange(size) ]
  

def break_repeating_xor_cipher(bytes, num_cands=5):
  """Attempts to break variable length repeating XOR key"""
  candidates = []
  for (_, keysize) in keysize_candidates(bytes, num_cands=5, num_chunks=4):
    key =[]
    for block in transpose(bytes, keysize):
      [(single_score, _, char)] = break_single_char_xor_cipher(block, freqs_score_alpha=1.0)
      key.append(char)
    
    text = repeating_xor(bytes, key).tostring()
    candidates.append((freqs.score(text), array('B',key).tostring(), text))
  
  return sorted(candidates, reverse=True)[0:num_cands]

  
def challenge6():
  """
  6. Break repeating-key XOR

  The buffer at the following location:

   https://gist.github.com/3132752

  is base64-encoded repeating-key XOR. Break it.

  Here's how:

  a. Let KEYSIZE be the guessed length of the key; try values from 2 to
  (say) 40.

  b. Write a function to compute the edit distance/Hamming distance
  between two strings. The Hamming distance is just the number of
  differing bits. The distance between:

    this is a test

  and:

    wokka wokka!!!

  is 37.

  c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
  SECOND KEYSIZE worth of bytes, and find the edit distance between
  them. Normalize this result by dividing by KEYSIZE.

  d. The KEYSIZE with the smallest normalized edit distance is probably
  the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
  values. Or take 4 KEYSIZE blocks instead of 2 and average the
  distances.

  e. Now that you probably know the KEYSIZE: break the ciphertext into
  blocks of KEYSIZE length.

  f. Now transpose the blocks: make a block that is the first byte of
  every block, and a block that is the second byte of every block, and
  so on.

  g. Solve each block as if it was single-character XOR. You already
  have code to do this.

  e. For each block, the single-byte XOR key that produces the best
  looking histogram is the repeating-key XOR key byte for that
  block. Put them together and you have the key.
  """
  with open('../resources/break_repeatingxor.txt', 'r') as f:
    data = "".join([line.strip() for line in f.readlines()])
    data = base642bytearray(data)
    [(score, key, text)] = break_repeating_xor_cipher(data, 1)
    
    # Terminator X: Bring the noise
    print key
    print text

    
if __name__ == '__main__':
  challenge6()