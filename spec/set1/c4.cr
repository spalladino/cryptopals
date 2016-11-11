require "../spec_helper"

describe "1.4" do
  it "detects single-byte XOR cipher" do
    inputs = File.read("./spec/set1/data/c4.input.txt").split("\n").map(&.strip).reject(&.empty?)
    strings = inputs.flat_map do |input|
      Cryptopals::XorCipher.single_char_xor_strings(input.hex_to_bytes)
    end.sort_by { |r| - r[:string].freqscore }

    # puts strings[0..20].map{|r| "#{r[:mask].chr} | #{r[:string].freqscore} | #{r[:string]}"}.join("\n")
    strings[0..20].should contain({string: "Now that the party is jumping\n", mask: '5'.ord})
  end
end
