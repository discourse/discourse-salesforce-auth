# name: salesforce-auth
# about: salesforce login support for Discourse
# version: 0.1
# authors: Sam Saffron

require 'auth/oauth2_authenticator'
require 'omniauth-oauth2'

class SalesforceAuthenticator < ::Auth::OAuth2Authenticator

  def register_middleware(omniauth)
    omniauth.provider :salesforce,
        setup: lambda { |env|
              strategy = env["omniauth.strategy"]
              strategy.options[:client_id] = SiteSetting.salesforce_client_id
              strategy.options[:client_secret] = SiteSetting.salesforce_client_secret
        }
  end
end



after_initialize do
  class ::OmniAuth::Strategies::Salesforce
    option :client_options, authorize_url: '/oauth2/authorize',
                            site:  SiteSetting.salesforce_url,
                            token_url: '/oauth2/token'
  end
end

class OmniAuth::Strategies::Salesforce < OmniAuth::Strategies::OAuth2
  # Give your strategy a name.
  option :name, "salesforce"

  # This is where you pass the options you would pass when
  # initializing your consumer from the OAuth gem.
  #
  #

  # These are called after authentication has succeeded. If
  # possible, you should try to set the UID without making
  # additional calls (if the user id is returned with the token
  # or as a URI parameter). This may not be possible with all
  # providers.
  uid { raw_info['id'].to_s }

  info do
    {
      :name => raw_info['name'],
      :email => raw_info['email']
    }
  end

  extra do
    {
      'raw_info' => raw_info
    }
  end

  def raw_info
    @raw_info ||= access_token.get('/oauth/me.json').parsed
  end
end

auth_provider title: 'Sign in with Salesforce',
              message: 'Log in using your Salesforce account. (Make sure your popup blocker is disabled.)',
              frame_width: 920,
              frame_height: 800,
              authenticator: SalesforceAuthenticator.new('salesforce',
                                                          trusted: true,
                                                          auto_create_account: true)
register_css <<CSS
.btn.salesforce { background-color: #999; }
CSS

