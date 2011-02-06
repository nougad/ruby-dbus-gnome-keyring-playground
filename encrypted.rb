#!/usr/bin/env ruby
require 'dbus'
require 'pp'

bus = DBus::SessionBus.instance
service = bus.service("org.freedesktop.secrets")
secret = service.object("/org/freedesktop/secrets")
secret.introspect
secret.default_iface = "org.freedesktop.Secret.Service"

r = secret.SearchItems([["hostname","https://www.google.com"]])
# split result in unlocked and locked array
# TODO sometimes strange behavior - sometimes item is locked, sometimes not
unlocked, locked = r
# use first unlocked (should test if no item is unlocked)
item = service.object(unlocked.first)
item.default_iface = "org.freedesktop.Secret.Item"
item.introspect

########################################################
# I'am trying to use encrypted Session API.
# WARNING: Still don't get any useful result
# Don't try to understand my tests



PRIME = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
BITS  = 1024
BYTES = BITS/8
BASE  = 2

=begin
# Trying with dhkeyexchange gem
require 'dhkeyexchange'
key = DHKey.new(BASE, PRIME)
class DHKey
  def secret f
    key.their_public_key = f
    shared_key
  end
end
=end

require 'dh.rb'
key = DH.new BASE, PRIME, 999999

pubkey = key.my_public_key.to_i

# int to byte array
def to_byte_arr num, length
  i = (8*length)-8
  result = Array.new
  while i >= 0 do
    result << ((num>>i) & 255)
    i-=8
  end
  return result
end

# Byte array to int
def to_int(k)
  num = 0
  (k.size-1).downto(0) do |x|
    num |= k[x]<<((k.size-x-1)*8)
  end
  return num
end


arr_pubkey = to_byte_arr(pubkey, 128)

raise "invalid size" if arr_pubkey.size != BYTES

r = secret.OpenSession("dh-ietf1024-aes128-cbc-pkcs7", ["ay", arr_pubkey])
other_pubkey_arr, session_path = r
puts r.inspect

raise "invalid size" if arr_pubkey.size != r.first.size

other_pubkey = other_pubkey_arr.inject(0) do |sum,e| sum << 8 | e end

raise "invalid key" unless key.valid? other_pubkey
shared_key = key.secret(other_pubkey)

puts "our shared: " + shared_key.to_s


session = service.object(session_path)
session.default_iface = "org.freedesktop.Secret.Session"
puts session.introspect

r = item.GetSecret(session_path)
pp r

path, secret_arr, param_arr = r.first

# WARNING: now follows only random guessing

real_key = shared_key.to_s(16)
#real_key = to_byte_arr(shared_key, 128).inject("") do |sum,e| sum + e.chr end
secret = secret_arr.inject("") do |sum,e| sum + e.chr end
iv = param_arr.inject("") do |sum,e| sum + e.chr end

puts "key: " + tkey=to_int(to_byte_arr(shared_key, 128)[0..15]).to_s(16)
puts "iv: " + tiv=to_int(param_arr).to_s(16)
puts "secret: " + to_int(secret_arr).to_s(16)

# write secret into a file and output openssl command for decryption
# of course no useful result
File.open "secret", "w" do |f|
  f.write secret
end
puts "openssl aes-128-cbc -in secret -d -iv #{tiv} -K #{tkey} -p"


real_key = real_key[0..15]

#=begin
# Trying aes with openssl
require 'openssl'
def decrypt(encrypted_data, key, iv, cipher_type)
  aes = OpenSSL::Cipher::Cipher.new(cipher_type)
  aes.decrypt
  aes.key = key
  aes.iv = iv if iv != nil
  aes.update(encrypted_data) + aes.final
end

pp decrypt(secret, real_key, iv, "aes-128-cbc")
#=end

=begin
# Trying with ruby-aes gem
require 'ruby-aes'
Aes.check_iv(iv)
Aes.check_key(real_key, 128)
puts Aes.decrypt_block(128, 'CBC', real_key, iv, secret).inspect
=end

session.Close()

