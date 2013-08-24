# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "shamir-secret-sharing"

Gem::Specification.new do |s|
  s.name        = "shamir-secret-sharing"
  s.version     = ShamirSecretSharing::VERSION
  s.authors     = ["lian"]
  s.email       = ["meta.rb@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{Gem for Shamir's Secret Sharing}
  s.description = %q{Gem for Shamir's Secret Sharing}

  s.rubyforge_project = "shamir-secret-sharing"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.required_rubygems_version = ">= 1.3.6"
end
