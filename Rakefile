begin
  require 'bundler/gem_tasks'
rescue LoadError
end

RUBY = 'ruby' unless defined?(RUBY)

task :default => :tests

# test runner                                                                                                                                                                                                                [0/61]
desc 'Run all bacon specs with pretty output'
task :tests do
  sh RUBY, 'lib/shamir-secret-sharing.rb'
end
