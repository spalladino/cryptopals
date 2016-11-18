module Cryptopals::Attacks::XorCipher

  def self.single_char_xor_strings(input)
    (0_u8..255_u8).map do |bytemask|
      xored = String.new(input.xor(bytemask))
      { string: xored, mask: bytemask, score: xored.freqscore }
    end.compact.reject{|r| r[:score] == Float32::MAX}.sort_by(&.[:score])
  end

end
