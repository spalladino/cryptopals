module Cryptopals

  module PKCS

    def self.pad(input : Bytes, size = 8) : Bytes
      newsize = ((input.size / size) + 1) * size
      padded = Slice(UInt8).new(newsize)
      padded.copy_from(input.to_unsafe, input.size)
      fillvalue = (newsize - input.size).to_u8
      (input.size...newsize).each { |i| padded[i] = fillvalue }
      padded
    end

  end

end
