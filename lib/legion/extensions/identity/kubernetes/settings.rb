# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Kubernetes
        module Settings
          DEFAULTS = {
            token_path:      '/var/run/secrets/kubernetes.io/serviceaccount/token',
            namespace_path:  '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
            vault_role:      'legionio',
            vault_auth_path: 'kubernetes'
          }.freeze

          def self.load
            return unless defined?(Legion::Settings)

            Legion::Settings.merge_settings(:kubernetes, DEFAULTS)
          end

          def self.get
            return DEFAULTS unless defined?(Legion::Settings)

            settings = Legion::Settings.dig(:identity, :kubernetes)
            return DEFAULTS if settings.nil?

            DEFAULTS.merge(settings)
          end
        end
      end
    end
  end
end
