require "../spec_helper"

# ECB cut-and-paste
# -----------------
#
# Write a `k=v` parsing routine, as if for a structured cookie. The routine should take:
# ```
# foo=bar&baz=qux&zap=zazzle
# ```
#
# ... and produce:
# ```
# {
#   foo: 'bar',
#   baz: 'qux',
#   zap: 'zazzle'
# }
# ```
# (you know, the object; I don't care if you convert it to JSON).
#
# Now write a function that encodes a user profile in that format, given an email address. You should have something like:
# ```
# profile_for("foo@bar.com")
# ```
#
# ... and it should produce:
# ```
# {
#   email: 'foo@bar.com',
#   uid: 10,
#   role: 'user'
# }
# ```
# ... encoded as:
# ```
# email=foo@bar.com&uid=10&role=user
# ```
# Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to `"foo@bar.com&role=admin"`.
#
# Now, two more easy functions. Generate a random AES key, then:
#
# 1. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
# 2. Decrypt the encoded user profile and parse it.
#
# Using only the user input to `profile_for()` (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a `role=admin` profile.
#
describe "2.13" do

  it "generates correct profiles" do
    oracle = Cryptopals::Oracles::Profile::Oracle.new
    encrypted = oracle.encrypted_profile_for("foo@bar.com")
    decrypted = oracle.decrypt_profile(encrypted)
    decrypted[:email].should eq("foo@bar.com")
    decrypted[:uid].should eq("10")
    decrypted[:role].should eq("user")
  end

  it "ECB cut-and-paste" do
    oracle = Cryptopals::Oracles::Profile::Oracle.new

    # Get how a block of "admin" plus padding looks like being encrypted
    prefix = "A" * (16 - "email=".size)
    input = prefix + String.new("admin".to_slice.pad(16))
    (input.size + "email=".size).should eq(32)
    encrypted = oracle.encrypted_profile_for(input)
    admin_cipher = encrypted[16, 16]
    admin_cipher.size.should eq(16)

    # Build a string such that the role value ends up in a block by itself
    slack = "email=&uid=10&role="
    email = "A" * (16 - slack.size % 16)
    ((email.size + slack.size) % 16).should eq(0)

    # Get the profile for such string and replace the last block
    encrypted = oracle.encrypted_profile_for(email)
    (encrypted + (encrypted.size - 16)).copy_from(admin_cipher)
    oracle.decrypt_profile(encrypted)[:role].should eq("admin")
  end

end
