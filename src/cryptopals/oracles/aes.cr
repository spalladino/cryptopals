require "secure_random"

module Cryptopals::Oracles::AES

  def self.encryption_oracle(input : Bytes)
    key = SecureRandom.random_bytes(16)
    iv = SecureRandom.random_bytes(16)
    mode = (rand(2) == 1) ? Cryptopals::AES::Mode::CBC : Cryptopals::AES::Mode::ECB

    randomized_input = MemoryIO.new
    randomized_input.write(SecureRandom.random_bytes(rand(5..10)))
    randomized_input.write(input)
    randomized_input.write(SecureRandom.random_bytes(rand(5..10)))
    randomized_input = Cryptopals::PKCS.pad(randomized_input.to_slice, 16)

    encrypted = Cryptopals::AES.encrypt(mode, randomized_input, key, iv)
    return { encrypted: encrypted, input: input, randomized_input: randomized_input.to_slice, key: key, mode: mode }
  end

end
