#!/usr/bin/env ruby
## only a quick hack to get all passwords from gnome-keyring
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

def byte_arr_to_s(arr)
  arr.inject("") do |sum,e| sum + e.chr end
end

def print_secret(session_path, item)
  itemprops = get_props(item)
  session_path, props, secret = item.GetSecret(session_path).first
  itemprops["password"] = byte_arr_to_s(secret)
  pp itemprops
end

bus = DBus::SessionBus.instance
service = bus.service("org.freedesktop.secrets")
secret = get_object(service, "/org/freedesktop/secrets", "org.freedesktop.Secret.Service")

output, session_path = secret.OpenSession("plain","")
session = get_object(service, session_path, "org.freedesktop.Secret.Session")

get_props(secret)["Collections"].each do |login_path|
  collection = get_object(service, login_path, "org.freedesktop.Secret.Collection")
  props = get_props(collection)

  next if props["Locked"] == true or props["Items"].empty?

  props["Items"].each do |item_path|
    item = get_object(service, item_path, "org.freedesktop.Secret.Item")
    print_secret session_path, item
  end
end

session.Close

