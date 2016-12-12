require "../spec_helper"
require "base64"

# Break fixed-nonce CTR statistically
# ===================================
#
# In `c20.input.txt` you will find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.
#
# Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.
#
# Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.
#
# To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).
#
# Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
#
describe "3.20" do
  it "breaks fixed-nonce CTR mode statistically" do
    # Generate random key and encrypt everything with nonce = 0
    key = SecureRandom.random_bytes(16)
    inputs = File.read("./spec/set3/data/c20.input.txt").split("\n").map(&.strip).reject(&.empty?).map { |line| Base64.decode(line) }
    ciphertexts = inputs.map do |input|
      Cryptopals::CTR.crypt(input.to_slice, key)
    end

    # Break it
    truncate_size = ciphertexts.map(&.size).min
    truncated_ciphertexts = ciphertexts.map { |c| c[0, truncate_size].to_a }
    keys_attempts = 4

    keys_per_block = truncated_ciphertexts.transpose.map do |block|
      Cryptopals::Attacks::XorCipher.single_char_xor_strings(block.to_slice).first(keys_attempts).map(&.[:mask])
    end

    keys = (0...keys_attempts).to_a.repeated_combinations(truncate_size).map do |indices|
      keys_per_block.map_with_index { |keys, i| keys.at(indices[i]) { 0_u8 } }
    end.reject { |key| key.any? { |k| k == 0_u8 } }

    results = keys.map do |key|
      translated = truncated_ciphertexts[0...1].map { |c| String.new(Cryptopals::XorCipher.repeating_key_xor(c.as_slice, key.to_slice)) }.join("\n")
      {string: translated, key: key.to_slice, score: translated.freqscore}
    end

    expected = "I'm rated \"R\"...this is a warning, ya better void"
    results.map { |r| r[:string][0, 49] }.any? { |r| r.hamming_distance(expected) < 5 }.should be_true
  end
end
