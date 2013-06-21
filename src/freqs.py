import unittest
import math
import types

# Source: http://en.wikipedia.org/wiki/Letter_frequency

freqs = {'a': 0.08167,   
  'b': 0.01492,  
  'c': 0.02782,  
  'd': 0.04253,  
  'e': 0.12702, 
  'f': 0.02228,  
  'g': 0.02015,  
  'h': 0.06094,  
  'i': 0.06966,  
  'j': 0.00153,  
  'k': 0.00772,  
  'l': 0.04025,  
  'm': 0.02406,  
  'n': 0.06749,  
  'o': 0.07507,  
  'p': 0.01929,  
  'q': 0.00095,  
  'r': 0.05987,  
  's': 0.06327,  
  't': 0.09056,  
  'u': 0.02758,  
  'v': 0.00978,  
  'w': 0.02360,  
  'x': 0.00150,  
  'y': 0.01974,  
  'z': 0.00074}

start_freqs = {'a': 0.11602, 
  'b': 0.04702,  
  'c': 0.03511,  
  'd': 0.02670,  
  'e': 0.02007,  
  'f': 0.03779,  
  'g': 0.01950,  
  'h': 0.07232,  
  'i': 0.06286,  
  'j': 0.00597,  
  'k': 0.00590,  
  'l': 0.02705,  
  'm': 0.04374,  
  'n': 0.02365,  
  'o': 0.06264,  
  'p': 0.02545,  
  'q': 0.00173,  
  'r': 0.01653,  
  's': 0.07755,  
  't': 0.16671, 
  'u': 0.01487,  
  'v': 0.00649,  
  'w': 0.06753,  
  'x': 0.00037,  
  'y': 0.01620,  
  'z': 0.00034}

def is_english_character(c):
  return ord(c) > 31 and ord(c) < 127
  

def freq(char):
  """Returns expected frequency of char in english language"""
  return freqs(char.lower())

def freqs_for(text):
  """Returns dictionary of frequencies for chars in text or list"""
  res = {c: 0 for c in freqs.keys()}
  n = 0
  
  if isinstance(text, types.StringType): 
    text = text.lower()
  
  for char in text: 
    if char in res:
      res[char] += 1
      n += 1
  
  if n > 0:
    for char, value in res.items():
      res[char] = float(value) / n
  
  return res

def score_start_freqs(text):
  """Return score based on frequency of starting letters"""
  # Uses inverse of norm2 of distance between frequency vectors
  start_chars = [word[0] for word in text.lower().split()]
  text_start_freqs = freqs_for(start_chars)
  return 1.0 / math.sqrt(sum([(start_freqs[c] - text_start_freqs[c]) ** 2 for c in freqs.keys()]))


def score_freqs(text):
  """Return score based on frequency of letters in text"""
  # Uses inverse of norm2 of distance between frequency vectors
  text_freqs = freqs_for(text)
  return 1.0 / math.sqrt(sum([(freqs[c] - text_freqs[c]) ** 2 for c in freqs.keys()]))

def score(text, alpha=0.5, non_eng_penalization=2, non_char_penalization=0.5):
  """
  Calculates score based on freqs and start freqs, 
  where alpha is the weight for text frequencies and 1-alpha for word start frequencies,
  penalizing for each non-english or symbol character in the string
  """
  s = score_freqs(text) * alpha + score_start_freqs(text) * (1-alpha)
  non_eng = float(len([c for c in text if is_english_character(c)])) / len(text)
  non_char = float(len([c for c in text.lower() if c in freqs.keys()])) / len(text)
  return s * (non_eng ** non_eng_penalization) * (non_char ** non_char_penalization)

class TestFreqs(unittest.TestCase):  
  
  def test_freqs_for_string(self):
    actual = freqs_for("Hello")
    self.assertEqual(actual['h'], 0.2)
    self.assertEqual(actual['e'], 0.2)
    self.assertEqual(actual['l'], 0.4)
    self.assertEqual(actual['o'], 0.2)

  def test_score_freqs(self):
    self.assertGreater(score_freqs("ETAON RISHD"), score_freqs("VKJXQ Z"))

  def test_score_start_freqs(self): 
    self.assertGreater(score_start_freqs("Tzzzz Aqqqq"), score_start_freqs("Jeeeee Kaaaa"))


if __name__ == '__main__':
    unittest.main()