(ns ring.middleware.anti-forgery
  "Ring middleware to prevent CSRF attacks with an anti-forgery token."
  (:require [crypto.random :as random]
            [crypto.equality :as crypto]
            [buddy.sign.jwt :as jwt]
            [clj-time.core :as time]
            [clj-time.coerce])
  (:import (clojure.lang ExceptionInfo)))

(def ^{:doc "Binding that stores an anti-forgery token that must be included
            in POST forms if the handler is wrapped in wrap-anti-forgery."
       :dynamic true}
  *anti-forgery-token*)

(def ^:private crypt-options {:alg :rsa-oaep
                              :enc :a128cbc-hs256})

(defn- new-token []
  (random/base64 60))

(defn- session-token [request]
  (get-in request [:session ::anti-forgery-token]))

(defn- create-encrypted-csrf-token [public-key secret expires]
  (jwt/encrypt {:nonce   (crypto.random/base64 256)
                :secret  secret
                :expires (clj-time.coerce/to-long
                           (time/plus (time/now)
                                      expires))}
               public-key
               crypt-options))

(defn- find-or-create-token [request {:keys [encrypted-token? public-key private-key secret expiration]
                                      :or   {encrypted-token? false}
                                      :as   options}]
  (if encrypted-token?
    (create-encrypted-csrf-token public-key secret expiration) #_"foo"
    (or (session-token request) (new-token))))

(defn- add-session-token [response request token {:keys [encrypted-token?]
                                                  :or   {encrypted-token? false}
                                                  :as   options}]
  (if response
    (if encrypted-token?
      response
      (let [old-token (session-token request)]
        (if (= old-token token)
          response
          (-> response
              (assoc :session (:session response (:session request)))
              (assoc-in [:session ::anti-forgery-token] token)))))))

(defn- form-params [request]
  (merge (:form-params request)
         (:multipart-params request)))

(defn- default-request-token [request]
  (or (-> request form-params (get "__anti-forgery-token"))
      (-> request :headers (get "x-csrf-token"))
      (-> request :headers (get "x-xsrf-token"))))

(defn- valid-token? [request read-token]
  (let [user-token   (read-token request)
        stored-token (session-token request)]
    (and user-token
         stored-token
         (crypto/eq? user-token stored-token))))

(defn- valid-encrypted-token? [private-key stored-secret request read-token]
  (when-let [token (read-token request)]
    (try
      (let [{:keys [secret expires]} (jwt/decrypt token
                                                  private-key
                                                  crypt-options)]
        ;; TODO: check whether throwing an exception is good enough
        (and
          (crypto/eq? secret stored-secret)
          (time/before? (time/now)
                        (clj-time.coerce/from-long expires))))
      (catch ExceptionInfo e
        false))))

(defn- get-request? [{method :request-method}]
  (or (= method :head)
      (= method :get)
      (= method :options)))

(defn- valid-request? [request read-token {:keys [encrypted-token? private-key secret expiration]
                                           :or   {encrypted-token? false}
                                           :as   options}]
  (or (get-request? request)
      (if encrypted-token?
        (valid-encrypted-token? private-key secret request read-token)
        (valid-token? request read-token))))

(def ^:private default-error-response
  {:status  403
   :headers {"Content-Type" "text/html"}
   :body    "<h1>Invalid anti-forgery token</h1>"})

(defn- constant-handler [response]
  (fn
    ([_] response)
    ([_ respond _] (respond response))))

(defn- make-error-handler [options]
  (or (:error-handler options)
      (constant-handler (:error-response options default-error-response))))

(defn wrap-anti-forgery
  "Middleware that prevents CSRF attacks. Any POST request to the handler
  returned by this function must contain a valid anti-forgery token, or else an
  access-denied response is returned.

  The anti-forgery token can be placed into a HTML page via the
  *anti-forgery-token* var, which is bound to a random key unique to the
  current session. By default, the token is expected to be in a form field
  named '__anti-forgery-token', or in the 'X-CSRF-Token' or 'X-XSRF-Token'
  headers.

  Accepts the following options:

  :read-token       - a function that takes a request and returns an anti-forgery
                      token, or nil if the token does not exist

  :error-response   - the response to return if the anti-forgery token is
                      incorrect or missing

  :error-handler    - a handler function to call if the anti-forgery token is
                      incorrect or missing.

  :encrypted-token? - defaults to false
  :public-key       - a public key to encrypt the JWT
  :private-key      - a private key to decrypt the JWT
  :secret           - a secret to verify the token really is issued by our server
  :expiration       - an expiration time for the token (as org.joda.time.ReadablePeriod, e.g. (clj-time.core/hour 1))

  Only one of :error-response, :error-handler may be specified."
  ([handler]
   (wrap-anti-forgery handler {}))
  ([handler options]
   {:pre [(not (and (:error-response options) (:error-handler options)))]}
   (let [read-token    (:read-token options default-request-token)
         error-handler (make-error-handler options)]
     (fn
       ([request]
        (let [token (find-or-create-token request options)]
          (binding [*anti-forgery-token* token]
            (if (valid-request? request read-token options)
              (add-session-token (handler request) request token options)
              (error-handler request)))))
       ([request respond raise]
        (let [token (find-or-create-token request options)]
          (binding [*anti-forgery-token* token]
            (if (valid-request? request read-token options)
              (handler request #(respond (add-session-token % request token options)) raise)
              (error-handler request respond raise)))))))))
