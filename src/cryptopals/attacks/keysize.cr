module Cryptopals::Attacks::Keysize

  def self.detect_keysizes(input : Bytes, range = (1..32))
    range.map do |keysize|
      chunks = [
        input[0, keysize],
        input[keysize, keysize],
        input[2 * keysize, keysize],
        input[3 * keysize, keysize]
      ]

      score = (chunks[0].hamming_distance(chunks[1]) \
               + chunks[1].hamming_distance(chunks[2]) \
               + chunks[2].hamming_distance(chunks[3])).to_f32 / keysize

      { keysize: keysize, score: score }
    end.sort_by(&.[:score])
  end

end
