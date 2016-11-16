require "openssl/cipher"

module Cryptopals

  module AES

    def self.decrypt_ecb_128(key : Bytes, ciphertext : Bytes)
      crypt_ecb_128(key, ciphertext, false)
    end

    def self.encrypt_ecb_128(key : Bytes, plaintext : Bytes)
      crypt_ecb_128(key, plaintext, true)
    end

    private def self.crypt_ecb_128(key : Bytes, text : Bytes, encrypt : Bool)
      cipher = OpenSSL::Cipher.new("AES-128-ECB")
      result = MemoryIO.new
      encrypt ? cipher.encrypt : cipher.decrypt
      cipher.key = key
      result.write(cipher.update(text))
      result.write(cipher.final)
      result.to_slice
    end

  end

end
