require "../spec_helper"

# AES in ECB mode
# ---------------
#
# The Base64-encoded content in file c7.input.txt has been encrypted via AES-128 in ECB mode under the key
# ```
# "YELLOW SUBMARINE".
# ```
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
#
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
#
describe "1.7" do
  it "decrypts aes in ecb mode" do
    input = Base64.decode(File.read("./spec/set1/data/c7.input.txt").strip).to_slice
    key = "YELLOW SUBMARINE"
    result = String.new(Cryptopals::AES.decrypt_ecb_128(input, key.to_slice))
    result[0...33].should eq("I'm back and I'm ringin' the bell")
  end
end
