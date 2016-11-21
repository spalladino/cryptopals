require "../spec_helper"
require "secure_random"

# Byte-at-a-time ECB decryption (Harder)
# --------------------------------------
#
# Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:
# ```
# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
# ```
#
# Same goal: decrypt the target-bytes.
#
describe "2.14" do

  it "decrypts ECB a byte at a time with a prefix" do

    # Setup oracle
    fixed = Base64.decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    prefix = SecureRandom.random_bytes(rand(5..10))
    oracle = Cryptopals::Oracles::AES::Oracle.new(mode: Cryptopals::AES::Mode::ECB, prefix: prefix, suffix: fixed)
    oracle_fun = ->(input : Bytes) { oracle.encrypt(input)[:encrypted].not_nil! }

    # Get how a block of all "A"s looks like
    input_fun = ->(count : Int32) { ("A" * count).to_slice }
    pattern = oracle_fun.call(input_fun.call(100))[32,16]

    # Start increasing the number of "A"s until a whole new identical block appears, that's the boundary we're looking for
    padding_size = 0
    target_index = 0
    (100..116).each do |input_count|
      output = oracle_fun.call(input_fun.call(input_count))
      matching = output.in_groups_of(16, filled_up_with: 0_u8).each_with_index.select { |(chunk, i)| chunk.as_slice == pattern }.to_a
      if (padding_size != matching.size && padding_size != 0)
        target_index = (matching.last[1] + 1) * 16
        padding_size = input_count
        break
      else
        padding_size = matching.size
      end
    end

    # Wrap the oracle function so it always adds the extra padding, and returns the encrypted text starting after the prefix and padding
    wrapped_oracle_fun = ->(input : Bytes) do
      padded_input = Bytes.new(padding_size + input.size, 'A'.ord.to_u8)
      (padded_input + padding_size).copy_from(input)
      oracle.encrypt(padded_input)[:encrypted].not_nil! + target_index
    end

    # Break it
    broken = Cryptopals::Attacks::AES.break_ecb_byte_at_a_time(wrapped_oracle_fun)
    broken.should eq(fixed)
    # puts String.new(broken)

  end

end
