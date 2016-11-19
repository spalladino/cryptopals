require "../spec_helper"

# Break repeating-key XOR
# ----------------------
#
# There's a file `c6.input.txt`. It's been base64'd after being encrypted with repeating-key XOR.
#
# Decrypt it.
#
# Here's how:
#
# 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
# 2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between: `this is a test` and `wokka wokka!!!` is 37. Make sure your code agrees before you proceed.
# 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
# 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
# 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
# 6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
# 7. Solve each block as if it was single-character XOR. You already have code to do this.
# 8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
#
# This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
#
describe "1.6" do
  it "should calculate hamming distance" do
    "this is a test".hamming_distance("wokka wokka!!!").should eq(37)
  end

  it "breaks repeating key XOR cipher" do
    # Open file and decode base64
    input = Base64.decode(File.read("./spec/set1/data/c6.input.txt").strip).to_slice

    # Guess keysize
    keysize_candidates = Cryptopals::Attacks::Keysize.detect_keysizes(input, (2..40))[0..3]

    # Try breaking the text for each keysize candidate
    results = Array(NamedTuple(string: String, key: Bytes, score: Float32)).new

    keysize_candidates.each do |keysize|
      keys_per_block = input.in_groups_of(keysize[:keysize], filled_up_with: 0_u8).transpose.map do |block|
        Cryptopals::Attacks::XorCipher.single_char_xor_strings(block.to_slice).first(5).map(&.[:mask])
      end

      keys = [0,1,2,3,4].repeated_combinations(keysize[:keysize]).map do |indices|
        keys_per_block.map_with_index { |keys, i| keys.at(indices[i]) { 0_u8 } }
      end.reject { |key| key.any? { |k| k == 0_u8 } }

      keys.each do |key|
        translated = String.new(Cryptopals::XorCipher.repeating_key_xor(input, key.to_slice))
        results << { string: translated, key: key.to_slice, score: translated.freqscore }
      end
    end

    # Sort the results by score
    # results.sort_by(&.[:score]).first(100).each {|r| puts "#{String.new(r[:key])}\n#{r[:string]}\n" }
    expected = {string: "I'm back and I'm ringin' the bell", key: "Terminator X: Bring the noise"}
    results.sort_by(&.[:score]).first(10).map { |r| {string: r[:string][0...33], key: String.new(r[:key])} }.should contain(expected)
  end
end
