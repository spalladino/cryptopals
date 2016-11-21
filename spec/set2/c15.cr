require "../spec_helper"
require "secure_random"

# PKCS#7 padding validation
# -------------------------
#
# Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
#
# The string:
# ```
# "ICE ICE BABY\x04\x04\x04\x04"
# ```
# ... has valid padding, and produces the result "ICE ICE BABY".
#
# The string:
# ```
# "ICE ICE BABY\x05\x05\x05\x05"
# ```
# ... does not have valid padding, nor does:
# ```
# "ICE ICE BABY\x01\x02\x03\x04"
# ```
# If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.
#
# Crypto nerds know where we're going with this. Bear with us.
#
describe "2.15" do

  it "correctly strips padding" do
    input = "ICE ICE BABY\u0004\u0004\u0004\u0004"
    String.new(input.to_slice.unpad(16)).should eq("ICE ICE BABY")
  end

  it "correctly strips padding for inputs multiple of blocksize" do
    input = "FOO BAR \u0008\u0008\u0008\u0008\u0008\u0008\u0008\u0008"
    String.new(input.to_slice.unpad(8)).should eq("FOO BAR ")
  end

  it "checks invalid byte in padding" do
    input = "ICE ICE BABY\u0005\u0005\u0005\u0005"
    expect_raises { input.to_slice.unpad(16) }
  end

  it "checks different bytes in padding" do
    input = "ICE ICE BABY\u0001\u0002\u0003\u0004"
    expect_raises { input.to_slice.unpad(16) }
  end

  it "validates padding for inputs multiple of blocksize" do
    input = "FOO BAR "
    expect_raises { input.to_slice.unpad(8) }  
  end

end
