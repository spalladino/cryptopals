require "../spec_helper"

describe "1.3" do
  it "cracks single-byte XOR cipher" do
    input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".hex_to_bytes

    possible = (0..255).map do |bytemask|
      xored = String.new(input.xor(bytemask.to_u8))
      { string: xored , mask: bytemask }
    end.compact.sort_by { |r| - r[:string].freqscore }

    # puts possible[0..10].map{|r| "#{r[:mask].chr} | #{r[:string]}"}.join("\n")
    possible.should contain({string: "Cooking MC's like a pound of bacon", mask: 'X'.ord})
  end
end
