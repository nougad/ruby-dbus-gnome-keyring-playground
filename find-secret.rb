#!/usr/bin/env ruby
# output passwords for search
# call: find-secret.rb server=example.org user=u33 protocol=smtp
require 'dbus'
require 'pp'

search = []
ARGV.each do |x|
  key, value = x.split("=")
  search << [key, value]
end

File.open("/tmp/ddd", "a") do |f| f.puts ARGV.inspect end

bus = DBus::SessionBus.instance
service = bus.service("org.freedesktop.secrets")
secret = service.object("/org/freedesktop/secrets")
secret.introspect
secret.default_iface = "org.freedesktop.Secret.Service"
unlocked, locked = secret.SearchItems(search)

puts "unlocked: #{unlocked.inspect}\nlocked: #{locked.inspect}" if $DEBUG

# TODO unlock locked

s = unlocked.first
item = service.object(s)
item.default_iface = "org.freedesktop.Secret.Item"
item.introspect

_empty_string, session_path = secret.OpenSession("plain", "")
session = service.object(session_path)
session.default_iface = "org.freedesktop.Secret.Session"
session.introspect
_session_path, _parameter, value = item.GetSecret(session_path).first

puts value.pack("c*")
session.Close()

