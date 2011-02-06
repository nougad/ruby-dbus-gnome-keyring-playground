#!/usr/bin/env ruby
# Observes "login" collection and prints every second if it is locked or not
require 'dbus'
require 'pp'

def get_object(service, object, interface)
  o = service.object(object)
  o.default_iface = interface
  o.introspect
  return o
end

def get_props(item)
  return item["org.freedesktop.DBus.Properties"].GetAll("").first
end

bus = DBus::SessionBus.instance
service = bus.service("org.freedesktop.secrets")
secret = get_object(service, "/org/freedesktop/secrets", "org.freedesktop.Secret.Service")

login_path = get_props(secret)["Collections"].first
loop do
  collection = get_object(service, login_path, "org.freedesktop.Secret.Collection")
  pp get_props(collection)["Locked"]
  sleep 1
end
