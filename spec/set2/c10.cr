require "../spec_helper"

# Implement CBC mode
# ------------------
#
# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.
#
# In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.
#
# The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.
#
# Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.
#
# The file `c10.input.txt` is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
#
describe "2.10" do

  it "encrypts AES ECB" do
    text = "I'm back and I'm ringin the bell".to_slice
    key = "YELLOW SUBMARINE".to_slice
    encrypted = Cryptopals::AES.encrypt_ecb_128(text, key)
    decrypted = Cryptopals::AES.decrypt_ecb_128(encrypted, key)
    decrypted.should eq(text)
  end

  it "decrypts AES CBC" do
    input = Base64.decode(File.read("./spec/set2/data/c10.input.txt").strip).to_slice
    key = "YELLOW SUBMARINE".to_slice
    String.new(Cryptopals::AES.decrypt_cbc_128(input, key))[0..32].should eq("I'm back and I'm ringin' the bell")
  end

  it "encrypts and decrypts AES CBC" do
    text = "I'm back and I'm ringin the bell".to_slice
    key = "YELLOW SUBMARINE".to_slice
    encrypted = Cryptopals::AES.encrypt_cbc_128(text, key)
    decrypted = Cryptopals::AES.decrypt_cbc_128(encrypted, key)
    decrypted.should eq(text)
  end

  it "encrypts and decrypts AES CBC with iv" do
    text = "I'm back and I'm ringin the bell".to_slice
    key = "YELLOW SUBMARINE".to_slice
    iv =  "HELLO WORLD 1234".to_slice
    encrypted = Cryptopals::AES.encrypt_cbc_128(text, key, iv)
    decrypted = Cryptopals::AES.decrypt_cbc_128(encrypted, key, iv)
    decrypted.should eq(text)
  end

end
