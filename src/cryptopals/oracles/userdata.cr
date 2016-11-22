require "secure_random"

module Cryptopals::Oracles::UserData

  class Oracle

    def initialize()
      @key = SecureRandom.random_bytes(16)
      @iv = SecureRandom.random_bytes(16)
    end

    def cookie_for(userdata : String) : String
      "comment1=cooking%20MCs;userdata=#{userdata.gsub(/;|=/, "")};comment2=%20like%20a%20pound%20of%20bacon"
    end

    def is_admin?(encrypted_cookie : Bytes)
      decrypt_cookie(encrypted_cookie)["admin"]? == "true"
    end

    def parse_cookie(cookie : String)
      cookie.split(";").map(&.split("=")).select{ |pair| pair.size == 2 }.to_h
    end

    def decrypt_cookie(encrypted_cookie : Bytes)
      decrypted = String.new(Cryptopals::AES.decrypt_cbc_128(encrypted_cookie, @key, @iv).unpad(16))
      parse_cookie(decrypted)
    end

    def encrypted_cookie_for(userdata : String) : Bytes
      cookie = cookie_for(userdata).to_slice.pad(16)
      Cryptopals::AES.encrypt_cbc_128(cookie, @key, @iv)
    end

  end

end
