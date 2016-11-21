require "../spec_helper"

# Implement PKCS#7 padding
# ------------------------
#
# A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.
#
# One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.
#
# So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,
# ```
# "YELLOW SUBMARINE"
# ```
#
# ... padded to 20 bytes would be:
# ```
# "YELLOW SUBMARINE\x04\x04\x04\x04"
# ```
#
describe "2.9" do
  it "pads yellow submarine to 20 bytes" do
    actual = Cryptopals::PKCS.pad("YELLOW SUBMARINE".to_slice, 20)
    String.new(actual).should eq("YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}")
  end

  it "pads yellow submarine to 8 bytes" do
    actual = Cryptopals::PKCS.pad("YELLOW SUBMARINE".to_slice, 8)
    String.new(actual).should eq("YELLOW SUBMARINE\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}\u{8}")
  end
end
