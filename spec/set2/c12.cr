require "../spec_helper"

# Byte-at-a-time ECB decryption (Simple)
# --------------------------------------
# Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
#
# Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:
#
# ```
# Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
# aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
# dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
# YnkK
# ```
#
# Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.
#
# What you have now is a function that produces:
#
# ```
# AES-128-ECB(your-string || unknown-string, random-key)
# ```
#
# It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
#
# Here's roughly how:
#
# 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
# 2. Detect that the function is using ECB. You already know, but do this step anyways.
# 3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
# 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
# 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
# 6. Repeat for the next byte.
#
describe "2.12" do

  it "decrypts ECB a byte at a time" do

    # Setup oracle
    fixed = Base64.decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    oracle = Cryptopals::Oracles::AES::Oracle.new(mode: Cryptopals::AES::Mode::ECB, suffix: fixed)
    oracle_fun = ->(input : Bytes) { oracle.encrypt(input)[:encrypted].not_nil! }

    # Detect keysize
    keysize = 128.times.flat_map do |i|
      encrypted = oracle_fun.call ("A" * i).to_slice
      Cryptopals::Attacks::Keysize.detect_keysizes(encrypted).first(3)
    end.sort_by(&.[:score]).first[:keysize]
    keysize.should eq(16)

    # Detect mode
    encrypted = oracle_fun.call ("A" * 256).to_slice
    Cryptopals::Attacks::AES.detect_mode(encrypted)[:mode].should eq(Cryptopals::AES::Mode::ECB)

    # Break it
    broken = Cryptopals::Attacks::AES.break_ecb_byte_at_a_time(oracle_fun)
    broken.should eq(fixed)
  end

end
