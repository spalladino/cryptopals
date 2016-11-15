require "../spec_helper"

# Detect single-character XOR
# ----------------------------
#
# One of the 60-character strings in file `c4.input.txt` has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from #3 should help.)
#
describe "1.4" do
  it "detects single-byte XOR cipher" do
    inputs = File.read("./spec/set1/data/c4.input.txt").split("\n").map(&.strip).reject(&.empty?)
    strings = inputs.flat_map do |input|
      Cryptopals::XorCipher.single_char_xor_strings(input.hex_to_bytes)
    end.sort_by { |r| r[:string].freqscore }

    # puts strings[0..100].map{|r| "#{r[:mask].chr} | #{r[:string].freqscore} | #{r[:string]}"}.join("\n")
    strings[0..10].map{|r| {string: r[:string], mask: r[:mask]}}.should contain({string: "Now that the party is jumping\n", mask: '5'.ord})
  end
end
