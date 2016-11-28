require "io/byte_format"
require "./aes"

module Cryptopals

  module CTR

    def self.crypt(input : Bytes, key : Bytes, nonce : UInt64 = 0_u64)
      output = Bytes.new(input.size)
      (0...input.size).step(16) do |index|
        size = [16, input.size - index].min
        block = input[index, size]
        plain_keystream_block = keyblock(nonce, (index / 16).to_u64)
        encrypted_keystream_block = Cryptopals::AES.encrypt_ecb_128(plain_keystream_block, key)
        xored = block.xor(encrypted_keystream_block[0, size])
        (output + index).copy_from(xored)
      end
      output
    end

    private def self.keyblock(nonce : UInt64, counter : UInt64)
      Bytes.new(16).tap do |bytes|
        MemoryIO.new(bytes).tap do |io|
          IO::ByteFormat::LittleEndian.encode(nonce, io)
          IO::ByteFormat::LittleEndian.encode(counter, io)
        end
      end
    end

  end

end
