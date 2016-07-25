# name: salesforce-auth
# about: salesforce login support for Discourse
# version: 0.1
# authors: Sam Saffron

require 'auth/oauth2_authenticator'
require 'omniauth-oauth2'
require 'openssl'
require 'base64'

class SalesforceAuthenticator < ::Auth::OAuth2Authenticator

  def register_middleware(omniauth)
    omniauth.provider :salesforce,
        setup: lambda { |env|
              strategy = env["omniauth.strategy"]
              strategy.options[:client_id] = SiteSetting.salesforce_client_id
              strategy.options[:client_secret] = SiteSetting.salesforce_client_secret
        }
  end

  def after_authenticate(auth_token)
    result = super

    if result.user && result.user.id && (country = auth_token[:info][:country])
      country_field = UserCustomField.find_by(user_id: result.user.id, name: 'country')

      # just in case
      country = country.to_s
      if country_field
        country_field.update_columns(value: country) unless country_field.value == country
      else
        UserCustomField.create(user_id: result.user.id, name: 'country', value: country)
      end
    end

    if result.user && result.email && (result.user.email != result.email)
      begin
        result.user.update_columns(email: result.email)
      rescue
        used_by = User.find_by(email: result.email).try(:username)
        Rails.logger.warn("FAILED to update email for #{user.username} to #{result.email} cause it is in use by #{used_by}")
      end
    end

    result
  end
end



after_initialize do
  class ::OmniAuth::Strategies::Salesforce
    option :client_options, authorize_url: '/ind/services/oauth2/authorize',
                            site:  SiteSetting.salesforce_url,
                            token_url: '/ind/services/oauth2/token'
  end
end

#
# Class is mostly cut and paste from MIT https://raw.githubusercontent.com/realdoug/omniauth-salesforce/master/lib/omniauth/strategies/salesforce.rb
class OmniAuth::Strategies::Salesforce < OmniAuth::Strategies::OAuth2
  # Give your strategy a name.
  option :name, "salesforce"

  MOBILE_USER_AGENTS =  'webos|ipod|iphone|ipad|android|blackberry|mobile'

  option :client_options, {
    :authorize_url => '/ind/services/oauth2/authorize',
    :token_url     => '/ind/services/oauth2/token'
  }
  option :authorize_options, [
    :scope,
    :display,
    :immediate,
    :state,
    :prompt,
    :redirect_uri,
    :login_hint
  ]

  def request_phase
    req = Rack::Request.new(@env)
    options.update(req.params)
    ua = req.user_agent.to_s
    if !options.has_key?(:display)
      mobile_request = ua.downcase =~ Regexp.new(MOBILE_USER_AGENTS)
      options[:display] = mobile_request ? 'touch' : 'page'
    end
    super
  end

  def auth_hash
    signed_value = access_token.params['id'] + access_token.params['issued_at']
    raw_expected_signature = OpenSSL::HMAC.digest('sha256', options.client_secret.to_s, signed_value)
    expected_signature = Base64.strict_encode64 raw_expected_signature
    signature = access_token.params['signature']
    fail! "Salesforce user id did not match signature!" unless signature == expected_signature
    super
  end

  uid { raw_info['id'] }

  info do
    {
      'name'            => raw_info['display_name'],
      'email'           => raw_info['email'],
      'nickname'        => raw_info['nick_name'],
      'first_name'      => raw_info['first_name'],
      'last_name'       => raw_info['last_name'],
      'location'        => '',
      'description'     => '',
      'image'           => raw_info['photos']['thumbnail'] + "?oauth_token=#{access_token.token}",
      'phone'           => '',
      'urls'            => raw_info['urls'],
      'country'         => raw_info['custom_attributes'] && raw_info['custom_attributes']['country']
    }
  end

  credentials do
    hash = {'token' => access_token.token}
    hash.merge!('instance_url' => access_token.params["instance_url"])
    hash.merge!('refresh_token' => access_token.refresh_token) if access_token.refresh_token
    hash
  end

  def raw_info
    access_token.options[:mode] = :header
    @raw_info ||= access_token.post(access_token['id']).parsed
  end

  extra do
    raw_info.merge({
      'instance_url' => access_token.params['instance_url'],
      'pod' => access_token.params['instance_url'],
      'signature' => access_token.params['signature'],
      'issued_at' => access_token.params['issued_at']
    })
  end

end

auth_provider title: 'Sign in with Salesforce',
              message: 'Log in using your Salesforce account. (Make sure your popup blocker is disabled.)',
              full_screen_login: true,
              authenticator: SalesforceAuthenticator.new('salesforce',
                                                          trusted: true,
                                                          auto_create_account: true)
register_css <<CSS
.btn.salesforce { background-color: #999; }
CSS

