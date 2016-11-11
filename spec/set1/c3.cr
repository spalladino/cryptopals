require "../spec_helper"

describe "1.3" do
  it "cracks single-byte XOR cipher" do
    input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".hex_to_bytes
    possible = Cryptopals::XorCipher.single_char_xor_strings(input)

    # puts possible[0..10].map{|r| "#{r[:mask].chr} | #{r[:string]}"}.join("\n")
    possible.should contain({string: "Cooking MC's like a pound of bacon", mask: 'X'.ord})
  end
end
