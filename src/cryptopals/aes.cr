require "openssl/cipher"

module Cryptopals

  module AES

    def self.encrypt_cbc(plaintext : Bytes, key : Bytes)
    end

    def self.decrypt_ecb_128(ciphertext : Bytes, key : Bytes)
      crypt_ecb_128(ciphertext, key, false)
    end

    def self.encrypt_ecb_128(plaintext : Bytes, key : Bytes)
      crypt_ecb_128(plaintext, key, true)
    end

    private def self.crypt_ecb_128(text : Bytes, key : Bytes, encrypt : Bool)
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
