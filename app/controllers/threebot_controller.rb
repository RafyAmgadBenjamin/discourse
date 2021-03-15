require "base64"
require "json"
require "net/http"
require "securerandom"

require "rbnacl"

# this adds ed25519 to curve25519 conversion helpers
module RbNaCl
  module Signatures
    module Ed25519
      class VerifyKey
        sodium_function :to_curve25519_public_key,
                        :crypto_sign_ed25519_pk_to_curve25519,
                        %i[pointer pointer]

        def to_public_key
          buffer = Util.zeros(Boxes::Curve25519XSalsa20Poly1305::PublicKey::BYTES)
          self.class.crypto_sign_ed25519_pk_to_curve25519(buffer, @key)
          Boxes::Curve25519XSalsa20Poly1305::PublicKey.new(buffer)
        end
      end

      class SigningKey
        sodium_function :to_curve25519_private_key,
                        :crypto_sign_ed25519_sk_to_curve25519,
                        %i[pointer pointer]

        def to_private_key
          buffer = Util.zeros(Boxes::Curve25519XSalsa20Poly1305::PrivateKey::BYTES)
          self.class.crypto_sign_ed25519_sk_to_curve25519(buffer, @signing_key)
          Boxes::Curve25519XSalsa20Poly1305::PrivateKey.new(buffer)
        end
      end
    end
  end
end

class ThreebotController < ApplicationController
  skip_before_action :check_xhr, only: [:login]
  skip_before_action :check_xhr, only: [:callback]
  helper_method :sign_in

  @@auth_url = "https://login.threefold.me"
  @@openkyc = "https://openkyc.live/verification/verify-sei"

  def signing_key
    RbNaCl::SigningKey.new(Base64.decode64(Rails.application.config.signing_key))
  end

  def login
    if !current_user.nil?
      flash[:danger] = "Please log in."
      redirect_to "/"
    end

    state = SecureRandom.uuid.gsub("-", "")
    params = {
      :appid => request.host_with_port,
      :scope => JSON.generate({ :user => true, :email => true }),
      :publickey => Base64.strict_encode64(signing_key.verify_key.to_public_key.to_s),
      :redirecturl => "threebot/callback",
      :state => state,
    }

    session[:auth_state] = params[:state]
    redirect_to "#{@@auth_url}?#{params.to_query}"
  end

  def get_user_public_key(double_name)
    resp = Net::HTTP.get_response(URI("#{@@auth_url}/api/users/#{double_name}"))
    if resp.kind_of?(Net::HTTPOK)
      return JSON.parse(resp.body)["publicKey"]
    end

    raise resp.body
  end

  def verify_email(sei)
    resp = Net::HTTP.post(URI(@@openkyc), { "signedEmailIdentifier": sei }.to_json, { "Content-Type" => "application/json" })
    unless resp.kind_of?(Net::HTTPOK)
      raise "email is not verified"
    end
  end

  def validate_fields(data, fields)
    fields.each do |field|
      unless data.key?(field)
        raise "missing '#{field}'"
      end
    end
  end

  # decrypt verified data
  # @param verify_key [VerifyKey] used to verify this data
  # @param data [Hash] e.g. {data => {"nonce" => "...", "ciphertext" => "..."}}
  #
  # @return [Hash] containing scope fields e.g. email and username
  def decrypt_verified_data(verify_key, data)
    nonce = Base64.strict_decode64(data["data"]["nonce"])
    ciphertext = Base64.strict_decode64(data["data"]["ciphertext"])

    private_key = signing_key.to_private_key
    public_key = verify_key.to_public_key
    box = RbNaCl::Boxes::Curve25519XSalsa20Poly1305.new(public_key, private_key)
    decrypted = box.decrypt(nonce, ciphertext)
    JSON.parse(decrypted)
  end

  # verify login attempt
  # @param attempt [Hash] must containing `doubleName` and `signedAttempt`
  #
  # @raise in case verifying the login attempt failed
  #
  # @return [Hash] containing user info as `email` and `username`
  def verify(attempt)
    validate_fields(attempt, ["signedAttempt", "doubleName"])

    signed_data = Base64.strict_decode64(attempt["signedAttempt"])
    double_name = attempt["doubleName"]
    public_key = get_user_public_key(double_name)
    verify_key = RbNaCl::VerifyKey.new(Base64.strict_decode64(public_key))

    # signed_data have the signature attached, so, split them
    signature, signed_data = signed_data[0...verify_key.signature_bytes], signed_data[verify_key.signature_bytes..-1]
    # will raise an error if verification failed
    verify_key.verify(signature, signed_data)
    verified_data = JSON.parse(signed_data)
    validate_fields(verified_data, ["data", "signedState", "doubleName"])

    state = verified_data["signedState"]
    if state != session[:auth_state]
      raise "state has been changed"
    end

    decrypted = decrypt_verified_data(verify_key, verified_data)
    validate_fields(decrypted, ["email"])
    verify_email(decrypted["email"]["sei"])
    { "email": decrypted["email"]["email"], "username": double_name }
  end

  def login_or_create_user(email, username)
    user = User.find_by_email(email)

    if user
      user.update_timezone_if_missing(params[:timezone])

      secure_session[UsersController::HONEYPOT_KEY] = nil
      secure_session[UsersController::CHALLENGE_KEY] = nil

      # save user email in session, to show on account-created page
      session[SessionController::ACTIVATE_USER_KEY] = user.id

      # If the user was created as active, they might need to be approved
      user.create_reviewable if user.active?

      user.update_timezone_if_missing(params[:timezone])
      log_on_user(user)
      @current_user = user
      session[:user_id] = user.id
    else
      # create new user
      user = User.new(email: email)
      user.password = SecureRandom.hex(20)
      user.username = username.gsub(".3bot", "")
      user.name = user.username
      user.active = true

      authentication = UserAuthenticator.new(user, session)
      authentication.start
      activation = UserActivator.new(user, request, session, cookies)
      activation.start

      if user.save
        authentication.finish
        activation.finish
        user.update_timezone_if_missing(params[:timezone])

        secure_session[UsersController::HONEYPOT_KEY] = nil
        secure_session[UsersController::CHALLENGE_KEY] = nil

        # save user email in session, to show on account-created page
        session["user_created_message"] = activation.message
        session[SessionController::ACTIVATE_USER_KEY] = user.id

        # If the user was created as active, they might need to be approved
        user.create_reviewable if user.active?

        user.update_timezone_if_missing(params[:timezone])
        log_on_user(user)
        @current_user = user
        session[:user_id] = user.id
      end
    end
  end

  def callback
    err = params[:error]
    if err == "CancelledByUser"
      Rails.logger.warn "Login attempt cancelled by user"
      flash[:danger] = "Login was cancelled by user."
      return redirect_to "/"
    end

    begin
      attempt = JSON.parse(request.query_parameters["signedAttempt"])
      user_info = verify(attempt)
    rescue => err
      Rails.logger.error "login verification error: #{err.message}"
      flash[:danger] = err.message
      return redirect_to "/"
    end

    login_or_create_user(user_info[:email], user_info[:username])
    redirect_to "/"
  end
end
