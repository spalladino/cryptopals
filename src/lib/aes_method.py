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
