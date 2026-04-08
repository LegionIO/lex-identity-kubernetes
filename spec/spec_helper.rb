# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
end

require 'bundler/setup'

module Legion
  module Extensions
    module Helpers
      module Lex; end
    end
  end

  module Logging
    def self.warn(msg); end
    def self.info(msg); end
    def self.debug(msg); end
  end

  module Settings
    def self.[](_key)
      nil
    end

    def self.dig(*_keys)
      nil
    end

    def self.merge_settings(_key, _defaults); end
  end

  module JSON
    def self.dump(obj)
      require 'json'
      ::JSON.generate(obj)
    end

    def self.load(str)
      require 'json'
      ::JSON.parse(str, symbolize_names: true)
    end
  end
end

require 'legion/extensions/identity/kubernetes'

RSpec.configure do |config|
  config.example_status_persistence_file_path = '.rspec_status'
  config.disable_monkey_patching!
  config.expect_with(:rspec) { |c| c.syntax = :expect }
end
