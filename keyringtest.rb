#!/usr/bin/env ruby
# Playground for some API tests
require 'dbus'
require 'pp'

bus = DBus::SessionBus.instance
service = bus.service("org.freedesktop.secrets")
secret = service.object("/org/freedesktop/secrets")

## secret
# prints xml service description for service
puts secret.introspect
secret.default_iface = "org.freedesktop.Secret.Service"

## collection
r = secret["org.freedesktop.DBus.Properties"].GetAll("")
# prints all collections
pp r
login_object = r.first["Collections"].first # use first collection (should look for correct name)
collection = service.object(login_object)
collection.default_iface = "org.freedesktop.Secret.Collection"
# prints collection xml service description
puts collection.introspect
# prints all properties of collection
pp collection["org.freedesktop.DBus.Properties"].GetAll("")

unlocked, prompt_path = secret.Unlock(r.first["Collections"])
# playing with prompt but don't understand it
prompt = service.object(prompt_path)
prompt.default_iface = "org.freedesktop.Secret.Prompt"
prompt.introspect
prompt.Prompt("1")

## item
# searching secret with property "hostname = https://www.google.com"
r = secret.SearchItems([["hostname","https://www.google.com"]])
pp r

# split result in unlocked and locked array
# TODO sometimes strange behavior - sometimes item is locked, sometimes not
unlocked, locked = r

# use first unlocked (should test if no item is unlocked)
item = service.object(unlocked.first)
item.default_iface = "org.freedesktop.Secret.Item"
# print xml service description of item
puts item.introspect
# prints all properties of item
pp item["org.freedesktop.DBus.Properties"].GetAll("")

## would delete Item
#pp collection.Delete()


def byte_arr_to_string arr
  arr.pack("c*")
end

# asking secret unencrypted
r = secret.OpenSession("plain", "")
pp r

empty_string, session_path = r
session = service.object(session_path)
session.default_iface = "org.freedesktop.Secret.Session"
# prints session xml interface
puts session.introspect

r = item.GetSecret(session_path).first
pp r

session, parameter, value = r
puts byte_arr_to_string(value)

session.Close()

