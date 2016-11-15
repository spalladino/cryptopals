require "../spec_helper"

# Detect AES in ECB mode
# ----------------------
#
# In file `c8.input.txt` are a bunch of hex-encoded ciphertexts.
#
# One of them has been encrypted with ECB.
#
# Detect it.
#
# Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
#
describe "1.8" do
  it "detects aes in ecb mode" do
    inputs = File.read("./spec/set1/data/c8.input.txt").split("\n").map(&.strip).reject(&.empty?).map { |line| Base64.decode(line).to_slice }

    results = inputs.map do |input|
      blocks_counts = Hash(Bytes, Int32).new(-1)
      input.in_groups_of(16, 0_u8).each do |block|
        blocks_counts[block.to_slice] += 1
      end
      { input: Base64.strict_encode(input), score: blocks_counts.values.sum }
    end

    # puts results.select{|r| r[:score] > 0}.sort_by(&.[:score].-)
    results.select{|r| r[:score] > 0}.sort_by(&.[:score].-).first[:input].should eq("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
  end
end
