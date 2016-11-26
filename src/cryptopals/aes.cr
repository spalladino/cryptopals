require "openssl/cipher"

module Cryptopals

  module AES

    enum Mode
      ECB
      CBC
    end

    def self.encrypt(mode : Mode, plaintext : Bytes, key : Bytes, iv : Bytes = Slice(UInt8).new(16))
      case mode
      when Mode::ECB then encrypt_ecb_128(plaintext, key)
      when Mode::CBC then encrypt_cbc_128(plaintext, key, iv)
      else raise "Unknown mode #{mode}"
      end
    end

    def self.decrypt(mode : Mode, ciphertext : Bytes, key : Bytes, iv : Bytes = Slice(UInt8).new(16))
      case mode
      when Mode::ECB then decrypt_ecb_128(ciphertext, key)
      when Mode::CBC then decrypt_cbc_128(ciphertext, key, iv)
      else raise "Unknown mode #{mode}"
      end
    end

    def self.decrypt_cbc_128(ciphertext : Bytes, key : Bytes, iv : Bytes = Slice(UInt8).new(16))
      raise "Invalid key size: #{key.size}" unless key.size == 16
      raise "Invalid iv size: #{iv.size}" unless iv.size == 16

      result = Slice(UInt8).new(ciphertext.size)
      previous = iv
      (0...ciphertext.size).step(16) do |index|
        block = ciphertext[index, 16]
        decrypted = decrypt_ecb_128(block, key).xor(previous)
        target = result + index
        target.copy_from(decrypted.to_unsafe, 16)
        previous = block
      end
      result
    end

    def self.encrypt_cbc_128(plaintext : Bytes, key : Bytes, iv : Bytes = Slice(UInt8).new(16))
      raise "Invalid key size: #{key.size}" unless key.size == 16
      raise "Invalid iv size: #{iv.size}" unless iv.size == 16
      raise "Unpadded plaintext: #{plaintext.size}" unless plaintext.size % 16 == 0

      result = Slice(UInt8).new(plaintext.size)
      previous = iv
      (0...plaintext.size).step(16) do |index|
        block = plaintext[index, 16]
        encrypted = encrypt_ecb_128(block.xor(previous), key)
        target = result + index
        target.copy_from(encrypted.to_unsafe, 16)
        previous = encrypted
      end
      result
    end

    def self.decrypt_ecb_128(ciphertext : Bytes, key : Bytes)
      raise "Invalid key size: #{key.size}" unless key.size == 16
      cipher("AES-128-ECB", false, ciphertext, key)
    end

    def self.encrypt_ecb_128(plaintext : Bytes, key : Bytes)
      raise "Invalid key size: #{key.size}" unless key.size == 16
      cipher("AES-128-ECB", true, plaintext, key)
    end

    private def self.cipher(cipher_algorithm : String, encrypt : Bool, text : Bytes, key : Bytes, iv = nil)
      cipher = OpenSSL::Cipher.new(cipher_algorithm)
      result = MemoryIO.new
      encrypt ? cipher.encrypt : cipher.decrypt
      cipher.padding = false
      cipher.key = key
      cipher.iv = iv if iv
      result.write(cipher.update(text))
      result.write(cipher.final)
      result.to_slice
    end

  end

end
