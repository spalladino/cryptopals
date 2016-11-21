require "secure_random"

module Cryptopals::Oracles::Profile

  class Oracle

    def initialize()
      @key = SecureRandom.random_bytes(16)
    end

    def profile_for(email : String) : String
      "email=#{email.gsub(/&|=/, "")}&uid=10&role=user"
    end

    def parse_profile(profile_string : String)
      NamedTuple(email: String, uid: String, role: String).from(profile_string.split("&").map(&.split("=")).to_h)
    end

    def decrypt_profile(encrypted_profile_string : Bytes)
      decrypted = String.new(Cryptopals::AES.decrypt_ecb_128(encrypted_profile_string, @key).unpad(16))
      parse_profile(decrypted)
    end

    def encrypted_profile_for(email : String) : Bytes
      profile = profile_for(email).to_slice.pad(16)
      Cryptopals::AES.encrypt_ecb_128(profile, @key)
    end

  end

end
