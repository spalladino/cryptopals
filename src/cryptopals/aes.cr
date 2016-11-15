require "openssl/cipher"

module Cryptopals

  module AES

    def self.decrypt_ecb_128(key : Bytes, ciphertext : Bytes)
      cipher = OpenSSL::Cipher.new("AES-128-ECB")
      result = MemoryIO.new
      cipher.decrypt
      cipher.key = key
      result.write(cipher.update(ciphertext))
      result.write(cipher.final)
      result.to_slice
    end

  end

end
