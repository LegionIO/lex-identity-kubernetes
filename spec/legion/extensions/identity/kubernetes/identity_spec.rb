# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Kubernetes::Identity do
  subject(:identity) { described_class }

  let(:valid_token) { build_sa_token(sub: 'system:serviceaccount:legionio:legion-worker', exp: Time.now.to_i + 3600) }
  let(:token_path) { '/var/run/secrets/kubernetes.io/serviceaccount/token' }
  let(:namespace_path) { '/var/run/secrets/kubernetes.io/serviceaccount/namespace' }

  def build_sa_token(sub:, exp:)
    require 'base64'
    header  = Base64.urlsafe_encode64('{"alg":"RS256","typ":"JWT"}', padding: false)
    payload = Base64.urlsafe_encode64(JSON.generate({ sub: sub, exp: exp }), padding: false)
    "#{header}.#{payload}.fakesig"
  end

  before do
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:read).and_call_original
  end

  # --- provider contract interface ---

  describe '.provider_name' do
    it 'returns :kubernetes' do
      expect(identity.provider_name).to eq(:kubernetes)
    end
  end

  describe '.provider_type' do
    it 'returns :auth' do
      expect(identity.provider_type).to eq(:auth)
    end

    it 'is not :fallback' do
      expect(identity.provider_type).not_to eq(:fallback)
    end

    it 'is not :profile' do
      expect(identity.provider_type).not_to eq(:profile)
    end
  end

  describe '.facing' do
    it 'returns :machine' do
      expect(identity.facing).to eq(:machine)
    end
  end

  describe '.priority' do
    it 'returns 95' do
      expect(identity.priority).to eq(95)
    end

    it 'is higher than approle (100) is higher priority but kubernetes is 95' do
      expect(identity.priority).to be >= 90
    end
  end

  describe '.trust_weight' do
    it 'returns 100 (most trusted machine provider)' do
      expect(identity.trust_weight).to eq(100)
    end
  end

  describe '.capabilities' do
    it 'includes :authenticate' do
      expect(identity.capabilities).to include(:authenticate)
    end

    it 'includes :vault_auth' do
      expect(identity.capabilities).to include(:vault_auth)
    end

    it 'does not include :profile' do
      expect(identity.capabilities).not_to include(:profile)
    end

    it 'does not include :groups (groups come from Vault response only)' do
      expect(identity.capabilities).not_to include(:groups)
    end
  end

  # --- resolve (unverified path — no Vault) ---

  describe '.resolve' do
    context 'when SA token file does not exist' do
      before { allow(File).to receive(:exist?).with(token_path).and_return(false) }

      it 'returns nil' do
        expect(identity.resolve).to be_nil
      end
    end

    context 'when SA token file exists and Vault is not available' do
      before do
        allow(File).to receive(:exist?).with(token_path).and_return(true)
        allow(File).to receive(:read).with(token_path).and_return(valid_token)
        allow(File).to receive(:exist?).with(namespace_path).and_return(false)
        stub_const('Legion::Crypt::LeaseManager', nil) if defined?(Legion::Crypt::LeaseManager)
      end

      it 'returns a hash' do
        expect(identity.resolve).to be_a(Hash)
      end

      it 'sets canonical_name from namespace and service account name' do
        expect(identity.resolve[:canonical_name]).to eq('legionio-legion-worker')
      end

      it 'sets kind to :machine' do
        expect(identity.resolve[:kind]).to eq(:machine)
      end

      it 'sets source to :kubernetes' do
        expect(identity.resolve[:source]).to eq(:kubernetes)
      end

      it 'sets persistent to true' do
        expect(identity.resolve[:persistent]).to be true
      end

      it 'sets groups to empty array (unverified path — RBAC safety)' do
        expect(identity.resolve[:groups]).to eq([])
      end

      it 'includes metadata hash' do
        expect(identity.resolve[:metadata]).to be_a(Hash)
      end

      it 'sets verified: false in metadata' do
        expect(identity.resolve[:metadata][:verified]).to be false
      end

      it 'sets namespace in metadata' do
        expect(identity.resolve[:metadata][:namespace]).to eq('legionio')
      end

      it 'sets service_account in metadata' do
        expect(identity.resolve[:metadata][:service_account]).to eq('legion-worker')
      end

      it 'logs a warning about unverified resolution' do
        expect(Legion::Logging).to receive(:warn).with(/without cryptographic verification/)
        identity.resolve
      end
    end

    context 'when token has a malformed sub claim' do
      let(:bad_token) { build_sa_token(sub: 'malformed', exp: Time.now.to_i + 3600) }

      before do
        allow(File).to receive(:exist?).with(token_path).and_return(true)
        allow(File).to receive(:read).with(token_path).and_return(bad_token)
        allow(File).to receive(:exist?).with(namespace_path).and_return(false)
      end

      it 'falls back gracefully with unknown sa_name' do
        result = identity.resolve
        expect(result).to be_a(Hash)
        expect(result[:metadata][:service_account]).to eq('unknown')
      end
    end

    context 'when namespace file exists and sub is partial' do
      let(:partial_token) { build_sa_token(sub: 'system:serviceaccount', exp: Time.now.to_i + 3600) }

      before do
        allow(File).to receive(:exist?).with(token_path).and_return(true)
        allow(File).to receive(:read).with(token_path).and_return(partial_token)
        allow(File).to receive(:exist?).with(namespace_path).and_return(true)
        allow(File).to receive(:read).with(namespace_path).and_return('default')
      end

      it 'uses the namespace file as fallback for namespace' do
        result = identity.resolve
        expect(result[:metadata][:namespace]).to eq('default')
      end
    end

    context 'when SA token cannot be decoded' do
      before do
        allow(File).to receive(:exist?).with(token_path).and_return(true)
        allow(File).to receive(:read).with(token_path).and_return('not.a.valid.jwt')
        allow(File).to receive(:exist?).with(namespace_path).and_return(false)
      end

      it 'returns nil' do
        expect(identity.resolve).to be_nil
      end
    end
  end

  # --- provide_token ---

  describe '.provide_token' do
    context 'when SA token file does not exist' do
      before { allow(File).to receive(:exist?).with(token_path).and_return(false) }

      it 'returns nil' do
        expect(identity.provide_token).to be_nil
      end
    end

    context 'when SA token file exists' do
      before do
        allow(File).to receive(:exist?).with(token_path).and_return(true)
        allow(File).to receive(:read).with(token_path).and_return(valid_token)
        allow(File).to receive(:exist?).with(namespace_path).and_return(true)
        allow(File).to receive(:read).with(namespace_path).and_return('legionio')

        stub_const('Legion::Identity::Lease', Class.new do
          attr_reader :provider, :credential, :expires_at, :renewable, :issued_at, :metadata

          def initialize(provider:, credential:, expires_at:, renewable:, issued_at:, metadata:)
            @provider   = provider
            @credential = credential
            @expires_at = expires_at
            @renewable  = renewable
            @issued_at  = issued_at
            @metadata   = metadata
          end
        end)
      end

      it 'returns a Lease object' do
        expect(identity.provide_token).to be_a(Legion::Identity::Lease)
      end

      it 'sets provider to :kubernetes' do
        expect(identity.provide_token.provider).to eq(:kubernetes)
      end

      it 'sets credential to the raw SA token' do
        expect(identity.provide_token.credential).to eq(valid_token)
      end

      it 'sets expires_at from JWT exp claim' do
        lease = identity.provide_token
        expect(lease.expires_at).to be_a(Time)
        expect(lease.expires_at).to be > Time.now
      end

      it 'sets renewable to true (projected tokens auto-rotate)' do
        expect(identity.provide_token.renewable).to be true
      end

      it 'sets issued_at' do
        expect(identity.provide_token.issued_at).to be_a(Time)
      end

      it 'includes namespace in metadata' do
        expect(identity.provide_token.metadata[:namespace]).to eq('legionio')
      end
    end

    context 'when token has no exp claim' do
      let(:no_exp_token) { build_sa_token(sub: 'system:serviceaccount:legionio:worker', exp: nil) }
      let(:no_exp_token_real) do
        require 'base64'
        header  = Base64.urlsafe_encode64('{"alg":"RS256","typ":"JWT"}', padding: false)
        payload = Base64.urlsafe_encode64(JSON.generate({ sub: 'system:serviceaccount:legionio:worker' }), padding: false)
        "#{header}.#{payload}.fakesig"
      end

      before do
        allow(File).to receive(:exist?).with(token_path).and_return(true)
        allow(File).to receive(:read).with(token_path).and_return(no_exp_token_real)
        allow(File).to receive(:exist?).with(namespace_path).and_return(false)

        stub_const('Legion::Identity::Lease', Class.new do
          attr_reader :expires_at

          def initialize(expires_at:, **)
            @expires_at = expires_at
          end
        end)
      end

      it 'sets expires_at to nil when exp claim is absent' do
        expect(identity.provide_token.expires_at).to be_nil
      end
    end
  end

  # --- vault_auth ---

  describe '.vault_auth' do
    context 'when neither LeaseManager nor Vault is defined' do
      before do
        allow(File).to receive(:exist?).with(token_path).and_return(true)
        allow(File).to receive(:read).with(token_path).and_return(valid_token)
      end

      it 'returns nil' do
        expect(identity.vault_auth).to be_nil
      end
    end

    context 'when called with an explicit token and no Vault' do
      it 'returns nil' do
        expect(identity.vault_auth(token: 'some-token')).to be_nil
      end
    end

    context 'when SA token file does not exist and no explicit token' do
      before { allow(File).to receive(:exist?).with(token_path).and_return(false) }

      it 'returns nil' do
        expect(identity.vault_auth).to be_nil
      end
    end
  end

  # --- normalize ---

  describe '.normalize' do
    it 'lowercases the value' do
      expect(identity.normalize('MyNamespace')).to eq('mynamespace')
    end

    it 'strips leading and trailing whitespace' do
      expect(identity.normalize('  ns  ')).to eq('ns')
    end

    it 'replaces dots with hyphens' do
      expect(identity.normalize('my.namespace')).to eq('my-namespace')
    end

    it 'replaces colons with hyphens' do
      expect(identity.normalize('system:serviceaccount:ns:sa')).to eq('system-serviceaccount-ns-sa')
    end

    it 'replaces consecutive hyphens with single hyphen' do
      expect(identity.normalize('ns--sa')).to eq('ns-sa')
    end

    it 'strips leading hyphens' do
      expect(identity.normalize('-ns')).to eq('ns')
    end

    it 'strips trailing hyphens' do
      expect(identity.normalize('ns-')).to eq('ns')
    end

    it 'preserves underscores' do
      expect(identity.normalize('service_account')).to eq('service_account')
    end

    it 'preserves hyphens in the middle' do
      expect(identity.normalize('my-service')).to eq('my-service')
    end

    it 'preserves digits' do
      expect(identity.normalize('worker42')).to eq('worker42')
    end

    it 'handles empty string' do
      expect(identity.normalize('')).to eq('')
    end

    it 'handles nil by converting to string' do
      expect(identity.normalize(nil)).to eq('')
    end

    it 'produces valid canonical_name from typical K8s SA sub' do
      result = identity.normalize('legionio-legion-worker')
      expect(result).to match(/\A[a-z0-9][a-z0-9_-]*\z/)
    end
  end

  # --- module-level contract ---

  describe 'Legion::Extensions::Identity::Kubernetes' do
    subject(:mod) { Legion::Extensions::Identity::Kubernetes }

    it 'declares itself as an identity provider' do
      expect(mod.identity_provider?).to be true
    end

    it 'is not remote invocable' do
      expect(mod.remote_invocable?).to be false
    end

    it 'delegates provider_name to Identity' do
      expect(mod.provider_name).to eq(:kubernetes)
    end

    it 'delegates provider_type to Identity' do
      expect(mod.provider_type).to eq(:auth)
    end

    it 'delegates facing to Identity' do
      expect(mod.facing).to eq(:machine)
    end
  end

  # --- settings ---

  describe 'Settings' do
    subject(:settings) { Legion::Extensions::Identity::Kubernetes::Settings }

    it 'has a default token_path' do
      expect(settings::DEFAULTS[:token_path]).to eq('/var/run/secrets/kubernetes.io/serviceaccount/token')
    end

    it 'has a default namespace_path' do
      expect(settings::DEFAULTS[:namespace_path]).to eq('/var/run/secrets/kubernetes.io/serviceaccount/namespace')
    end

    it 'has a default vault_role' do
      expect(settings::DEFAULTS[:vault_role]).to eq('legionio')
    end

    it 'has a default vault_auth_path' do
      expect(settings::DEFAULTS[:vault_auth_path]).to eq('kubernetes')
    end

    describe '.get' do
      it 'returns defaults when Legion::Settings is not configured' do
        expect(settings.get).to eq(settings::DEFAULTS)
      end
    end
  end
end
