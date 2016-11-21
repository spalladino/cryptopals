require "secure_random"

module Cryptopals::Oracles::AES

  class Oracle

    @mode : Cryptopals::AES::Mode

    def initialize(mode : Cryptopals::AES::Mode? = nil, @prefix : Bytes? = nil, @suffix : Bytes? = nil)
      @key = SecureRandom.random_bytes(16)
      @iv = SecureRandom.random_bytes(16)
      @mode = mode || ((rand(2) == 1) ? Cryptopals::AES::Mode::CBC : Cryptopals::AES::Mode::ECB)
    end

    def encrypt(input : Bytes)
      full_input = MemoryIO.new
      if prefix = @prefix
        full_input.write(prefix)
      end
      full_input.write(input)
      if suffix = @suffix
        full_input.write(suffix)
      end
      full_input = Cryptopals::PKCS.pad(full_input.to_slice, 16)

      encrypted = Cryptopals::AES.encrypt(@mode, full_input, @key, @iv)
      return { encrypted: encrypted, input: input, full_input: full_input.to_slice, key: @key, mode: @mode, iv: @iv }
    end

  end

end
