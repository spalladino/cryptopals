require "../spec_helper"
require "base64"

# Implement CTR, the stream cipher mode
# -------------------------------------
#
# The string:
# ```
# L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
# ```
#
# ... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:
# ```
#       key=YELLOW SUBMARINE
#       nonce=0
#       format=64 bit unsigned little endian nonce,
#              64 bit little endian block count (byte count / 16)
# ```
#
# CTR mode is very simple.
#
# Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.
#
# For instance, for the first 16 bytes of a message with these parameters:
# ```
# keystream = AES("YELLOW SUBMARINE",
#                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
# ```
#
# ... for the next 16 bytes:
# ```
# keystream = AES("YELLOW SUBMARINE",
#                 "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
# ```
#
# ... and then:
# ```
# keystream = AES("YELLOW SUBMARINE",
#                 "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
# ```
# CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.
#
# Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.
#
# Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.
#
describe "3.18" do

  it "implements CTR mode" do
    input = Base64.decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = "YELLOW SUBMARINE".to_slice
    decrypted = Cryptopals::CTR.crypt(input, key)
    String.new(decrypted).should eq("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
  end

end
