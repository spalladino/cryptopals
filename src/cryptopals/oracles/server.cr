require "secure_random"

module Cryptopals::Oracles

  class Server

    @mode : Cryptopals::AES::Mode

    def initialize(mode : Cryptopals::AES::Mode? = nil)
      @key = SecureRandom.random_bytes(16)
      @mode = mode || ((rand(2) == 1) ? Cryptopals::AES::Mode::CBC : Cryptopals::AES::Mode::ECB)
    end

    def encrypt(input : Bytes)
      padded = Cryptopals::PKCS.pad(input.to_slice, 16)
      iv = SecureRandom.random_bytes(16)
      encrypted = Cryptopals::AES.encrypt(@mode, padded, @key, iv)
      return { encrypted: encrypted, mode: @mode, iv: iv }
    end

    def valid?(iv : Bytes, input : Bytes)
      decrypted = Cryptopals::AES.decrypt(@mode, input, @key, iv)
      Cryptopals::PKCS.valid_padding?(decrypted)
    end

  end

end
