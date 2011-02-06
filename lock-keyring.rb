#!/usr/bin/env ruby
# Locks all collections
require 'dbus'

bus = DBus::SessionBus.instance
service = bus.service("org.freedesktop.secrets")
secret = service.object("/org/freedesktop/secrets")

secret.default_iface = "org.freedesktop.Secret.Service"
secret.introspect
r = secret["org.freedesktop.DBus.Properties"].GetAll("")
secret.Lock(r.first["Collections"])

