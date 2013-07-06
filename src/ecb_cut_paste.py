import unittest
import random
import urlparse
import urllib
import re

from pprint import pprint
from oracle import encryption_oracle
from detect_ecb import ecb_score

from pkcs7 import *
from utils import *
from random import *
from encoding import *
from aes_ecb import *
from distance import *

key = randbytes(16).tostring()

def decrypt_and_parse(encrypted):
  """Decrypts and parses and encrypted profile byte array"""
  decrypted = decrypt_aes_ecb(encrypted, key)
  unpadded = pkcs7_strip(decrypted)
  return parse_qs(unpadded.tostring())

def encrypt_profile_for(email):
  """Creates profile for an email and enctrypts it"""
  return encrypt(string2bytearray(profile_for(email)))

def encrypt(bytes):
  """Encrypts with constant key using ECB"""
  return encryption_oracle(bytes, key, 'ecb', use_prefix=False, use_suffix=False)

def parse_qs(string):
  """Parses a query string"""
  return dict(urlparse.parse_qsl(string, keep_blank_values=True))

def profile_for(email):
  """Creates an encoded profile for an email"""
  email = re.sub("&|=", '', email)
  obj = [('email', email), ('uid', 10), ('role', 'user')]
  #return urllib.urlencode(obj)
  return "&".join(["{0}={1}".format(k,v) for k,v in obj])


class TestChallenge13(unittest.TestCase):
  """Tests profile_for and encrypt/decrypt functions"""

  def test_decrypt_and_parse(self):
    encrypted = encrypt_profile_for('spalladino@gmail.com')
    decrypted = decrypt_and_parse(encrypted)
    self.assertEqual(decrypted['email'], 'spalladino@gmail.com')
    self.assertEqual(decrypted['role'], 'user')
    self.assertEqual(decrypted['uid'], '10')


def challenge13():
  """
  13. ECB cut-and-paste

  Write a k=v parsing routine, as if for a structured cookie. The
  routine should take:

     foo=bar&baz=qux&zap=zazzle

  and produce:

    {
      foo: 'bar',
      baz: 'qux',
      zap: 'zazzle'
    }

  (you know, the object; I don't care if you convert it to JSON).

  Now write a function that encodes a user profile in that format, given
  an email address. You should have something like:

    profile_for("foo@bar.com")

  and it should produce:

    {
      email: 'foo@bar.com',
      uid: 10,
      role: 'user'
    }

  encoded as:

    email=foo@bar.com&uid=10&role=user

  Your "profile_for" function should NOT allow encoding metacharacters
  (& and =). Eat them, quote them, whatever you want to do, but don't
  let people set their email address to "foo@bar.com&role=admin".

  Now, two more easy functions. Generate a random AES key, then:

   (a) Encrypt the encoded user profile under the key; "provide" that
   to the "attacker".

   (b) Decrypt the encoded user profile and parse it.

  Using only the user input to profile_for() (as an oracle to generate
  "valid" ciphertexts) and the ciphertexts themselves, make a role=admin
  profile.
  """
  keysize = 16
  
  padded_role = pkcs7_pad_string("admin", keysize)
  fake_email = "A" * (keysize - len("email=")) + padded_role
  profile = profile_for(fake_email)

  encrypted = encrypt(string2bytearray(profile))
  encrypted_role_chunk = encrypted[16:32]

  real_profile = profile_for('spalladino123456789@gmail.com')
  encrypted = encrypt(string2bytearray(real_profile))
  encrypted[48:] = encrypted_role_chunk

  print "Decrypted profile:", decrypt_and_parse(encrypted)


if __name__ == '__main__':
  # unittest.main()
  challenge13()
