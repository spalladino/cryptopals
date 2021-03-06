module Cryptopals

  module PKCS

    def self.pad(input : Bytes, size = 16) : Bytes
      newsize = ((input.size / size) + 1) * size
      padded = Slice(UInt8).new(newsize)
      padded.copy_from(input.to_unsafe, input.size)
      fillvalue = (newsize - input.size).to_u8
      (input.size...newsize).each { |i| padded[i] = fillvalue }
      padded
    end

    def self.unpad(input : Bytes, size = 16) : Bytes
      last = input[-1]
      raise "Invalid padding: invalid last byte #{last} for unpadding on size #{size}" if last > size || last == 0
      (input + (input.size - last)).each_with_index do |b, i|
        raise "Invalid padding: expected byte #{last} but found #{b} on position #{i + input.size - last}" unless b == last
      end
      input[0, (input.size - last)]
    end

    def self.valid_padding?(input : Bytes, size = 16) : Bool
      last = input[-1]
      return false if last > size || last == 0
      (input + (input.size - last)).each_with_index do |b, i|
        return false unless b == last
      end
      return true
    end

  end

end

struct Slice(T)
  def pad(size = 16)
    Cryptopals::PKCS.pad(self, size)
  end

  def unpad(size = 16)
    Cryptopals::PKCS.unpad(self, size)
  end
end
