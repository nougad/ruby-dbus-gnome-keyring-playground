#!/usr/bin/env ruby
# Try to parse the binary keyring
# Purpose: provide a simple CLI client such like pwsafe
# for gnome-keyring without and gtk/dbus dependencies
# encoding: utf-8

f = File.open("/home/feitel/.gnome2/keyrings/login.keyring", "r:binary").read

class Parser
  attr_reader :data, :pos
  def initialize string
    @data = string
    @pos = 0
  end
  def string bytes
    byte bytes
  end
  def unsigned bytes
    a = byte(bytes)
    y = 0
    a.each_byte do |x| y = (y<<8 | x) end
    return y
  end
  def lstring
    l = unsigned32
    return string(l)
  end
  def unsigned32 count=1
    unsigned(count * 4)
  end
  def byte bytes=1
    # FIXME not every char has only one byte
    r = @data[@pos,bytes]
    @pos += bytes
    return r
  end
  def time
    return Time.at(unsigned32(2))
  end
  def hash
    byte(16)
  end
end

require "pp"

@r = Hash.new
def g value, name
  @r[name] = value
  pp "#{name} -- #{value}"
  value
end

p = Parser.new(f)
g(p.string(16),     :intro) == "GnomeKeyring\n\r\0\n" or raise "incorrect intro"
g(p.byte(2),        :version)
g(p.byte,           :crypto)
g(p.byte,           :hash)
g(p.lstring,        :keying_name)
g(p.time,           :ctime)
g(p.time,           :mtime)
g(p.unsigned32,     :flags)
g(p.unsigned32,     :lock_timeout)
hash_iterations = g(p.unsigned32,     :hash_iterations)
salt =            g(p.byte(8),        :salt)
g(p.unsigned(4*4),  :reserved) == 0 or raise "reserved not zero"
num_items = g(p.unsigned32, :num_items)
num_items.times do |x|
  g(p.unsigned32, "item#{x}_id".to_sym)
  # TODO type?
  g(p.unsigned32, "item#{x}_type".to_sym)
  attr_num = g(p.unsigned32, "item#{x}_num_attributes".to_sym)
  attr_num.times do |y|
    g(p.lstring , "item#{x}_attribute#{x}_name".to_sym)
    attr_type = g(p.unsigned32, "item#{x}_attribute#{x}_type".to_sym)
    case attr_type
      # TODO correct??
      when 0: g(p.lstring, "item#{x}_attribute#{x}_hash".to_sym)
      when 1: g(p.unsigned32, "item#{x}_attribute#{x}_hash".to_sym)
      else raise "unknown type #{attr_type}"
    end
  end
end
num_encrypted_bytes = g(p.unsigned32  , :num_encrypted_bytes)
encrypted_bytes = g(p.byte(num_encrypted_bytes)    , :encrytped_hash)
# FIXME not every char has only one byte
raise "invalid length" unless p.pos == p.data.size


password = ""

# TODO all following doesn't work
# I have to ask on Mailing-List for more informations


require 'openssl'
require 'digest/sha1'
c = OpenSSL::Cipher::Cipher.new("aes-128-cbc")
c.decrypt

k = password + salt

hash_iterations.times do
  k = Digest::SHA256.hexdigest(k)
end

c.key = k[0..31]
c.iv  = k[32..63]

d = c.update(encrypted_bytes)
d << c.final
puts "decrypted: #{d}\n"

