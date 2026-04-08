# frozen_string_literal: true

require 'base64'

module Legion
  module Extensions
    module Identity
      module Kubernetes
        module Identity
          SA_TOKEN_PATH     = '/var/run/secrets/kubernetes.io/serviceaccount/token'
          SA_NAMESPACE_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'

          def self.provider_name
            :kubernetes
          end

          def self.provider_type
            :auth
          end

          def self.facing
            :machine
          end

          def self.priority
            95
          end

          def self.trust_weight
            100
          end

          def self.capabilities
            %i[authenticate vault_auth]
          end

          def self.resolve(canonical_name: nil) # rubocop:disable Lint/UnusedMethodArgument
            token = read_sa_token
            return nil unless token

            if vault_available?
              vault_resolve(token)
            else
              unverified_resolve(token)
            end
          end

          def self.provide_token
            token = read_sa_token
            return nil unless token

            claims = decode_jwt_claims(token)
            expires_at = claims && claims[:exp] ? Time.at(claims[:exp]) : nil

            Legion::Identity::Lease.new(
              provider:   :kubernetes,
              credential: token,
              expires_at: expires_at,
              renewable:  true,
              issued_at:  Time.now,
              metadata:   { namespace: read_namespace }
            )
          end

          def self.vault_auth(token: nil)
            token ||= read_sa_token
            return nil unless token

            logical = if defined?(Legion::Crypt::LeaseManager)
                        Legion::Crypt::LeaseManager.instance.vault_logical
                      elsif defined?(::Vault)
                        ::Vault.logical
                      end
            return nil unless logical

            logical.write(
              "auth/#{settings[:vault_auth_path] || 'kubernetes'}/login",
              role: settings[:vault_role] || 'legionio',
              jwt:  token
            )
          rescue StandardError => e
            Legion::Logging.warn("K8s Vault auth failed: #{e.message}") if defined?(Legion::Logging) # rubocop:disable Legion/HelperMigration/DirectLogging,Legion/HelperMigration/LoggingGuard
            nil
          end

          def self.normalize(val)
            val.to_s.downcase.strip.gsub(/[^a-z0-9_-]/, '-').gsub(/-{2,}/, '-').gsub(/^-|-$/, '')
          end

          def self.settings
            Kubernetes::Settings.get
          end
          private_class_method :settings

          def self.vault_available?
            defined?(Legion::Crypt::LeaseManager) &&
              Legion::Crypt::LeaseManager.instance.respond_to?(:vault_logical)
          end
          private_class_method :vault_available?

          def self.vault_resolve(token)
            response = vault_auth(token: token)
            return unverified_resolve(token) unless response

            policies  = response.auth&.policies || []
            metadata  = response.auth&.metadata || {}
            namespace = metadata[:kubernetes_namespace] || read_namespace
            sa_name   = metadata[:kubernetes_service_account] || 'unknown'

            {
              canonical_name: normalize("#{namespace}-#{sa_name}"),
              kind:           :machine,
              source:         :kubernetes,
              persistent:     true,
              groups:         policies,
              metadata:       { namespace: namespace, service_account: sa_name, verified: true }
            }
          end
          private_class_method :vault_resolve

          def self.unverified_resolve(token)
            claims = decode_jwt_claims(token)
            return nil unless claims

            Legion::Logging.warn('K8s identity resolved without cryptographic verification — groups empty') if defined?(Legion::Logging) # rubocop:disable Legion/HelperMigration/DirectLogging,Legion/HelperMigration/LoggingGuard

            parts     = claims[:sub].to_s.split(':')
            namespace = parts[2] || read_namespace
            sa_name   = parts[3] || 'unknown'

            {
              canonical_name: normalize("#{namespace}-#{sa_name}"),
              kind:           :machine,
              source:         :kubernetes,
              persistent:     true,
              groups:         [],
              metadata:       { namespace: namespace, service_account: sa_name, verified: false }
            }
          end
          private_class_method :unverified_resolve

          def self.read_sa_token
            path = settings[:token_path] || SA_TOKEN_PATH
            return nil unless File.exist?(path)

            File.read(path).strip
          end
          private_class_method :read_sa_token

          def self.read_namespace
            path = settings[:namespace_path] || SA_NAMESPACE_PATH
            return nil unless File.exist?(path)

            File.read(path).strip
          end
          private_class_method :read_namespace

          def self.decode_jwt_claims(token)
            payload = token.split('.')[1]
            return nil unless payload

            padded = payload + ('=' * ((4 - (payload.length % 4)) % 4))
            Legion::JSON.load(Base64.urlsafe_decode64(padded)) # rubocop:disable Legion/HelperMigration/DirectJson
          rescue StandardError => e
            Legion::Logging.debug("K8s JWT decode failed: #{e.message}") if defined?(Legion::Logging) # rubocop:disable Legion/HelperMigration/DirectLogging,Legion/HelperMigration/LoggingGuard
            nil
          end
          private_class_method :decode_jwt_claims
        end
      end
    end
  end
end
