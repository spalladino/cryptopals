module Cryptopals

  module XorCipher

    def self.single_char_xor_strings(input)
      (0..255).map do |bytemask|
        xored = String.new(input.xor(bytemask.to_u8))
        { string: xored , mask: bytemask }
      end.compact.sort_by { |r| - r[:string].freqscore }
    end

  end

end
