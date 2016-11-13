struct Slice(T)

  def xor(other : Slice(T)) : Slice(T)
    raise "Length must match for XOR (expected #{self.size} but was #{other.size})" unless self.size == other.size
    result = Slice(T).new(self.size)
    self.size.times do |i|
      result[i] = (self[i] ^ other[i]).to_u8
    end
    result
  end

  def xor(other : Char) : Slice(T)
    xor(other.ord.to_u8)
  end

  def xor(other : T) : Slice(T)
    result = Slice(T).new(self.size)
    self.size.times do |i|
      result[i] = (self[i] ^ other).to_u8
    end
    result
  end

  def ^(other)
    xor(other)
  end

end

module Cryptopals

  module XorCipher

    def self.single_char_xor_strings(input)
      (0..255).map do |bytemask|
        xored = String.new(input.xor(bytemask.to_u8))
        { string: xored , mask: bytemask }
      end.compact.sort_by { |r| - r[:string].freqscore }
    end

    def self.repeating_key_xor(input : Bytes, key : Bytes) : Bytes
      output = Bytes.new(input.size)
      keysize = key.size
      input.each_with_index do |byte, index|
        output[index] = input[index] ^ key[index % keysize]
      end
      output
    end

  end

end
