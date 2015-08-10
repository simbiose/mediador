package = "mediador"
version = "0.1-0"

description = {
  summary  = "Mediador, determine address of proxied request and ip handling",
  homepage = "http://rocks.simbio.se/mediador",
  license  = "MIT"
}

source = {
  url    = "git://github.com/simbiose/mediador.git",
  branch = "v0.1"
}

dependencies = {"luabitop"}

build = {
  type    = "builtin",
  modules = {
    mediador = 'mediador.lua'
  }
}