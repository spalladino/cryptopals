require "../spec_helper"

# Fixed XOR
# ---------
#
# Write a function that takes two equal-length buffers and produces their XOR combination.
#
# If your function works properly, then when you feed it the string:
# ```
# 1c0111001f010100061a024b53535009181c
# ```
# ... after hex decoding, and when XOR'd against:
# ```
# 686974207468652062756c6c277320657965
# ```
# ... should produce:
# ```
# 746865206b696420646f6e277420706c6179
# ```
#
describe "1.2" do
  it "performs xor between two arrays" do
    op1 = "1c0111001f010100061a024b53535009181c".hex_to_bytes
    op2 = "686974207468652062756c6c277320657965".hex_to_bytes
    expected = "746865206b696420646f6e277420706c6179".hex_to_bytes
    (op1 ^ op2).should eq(expected)
  end
end
