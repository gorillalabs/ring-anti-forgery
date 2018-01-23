(ns ring.middleware.anti-forgery.strategy.session
  "Implements a synchronizer token pattern, see
https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens"
  (:require [ring.middleware.anti-forgery.strategy :as strategy]
            [crypto.equality :as crypto]
            [crypto.random :as random]))

(defn- session-token [request]
  (get-in request [:session :ring.middleware.anti-forgery/anti-forgery-token]))

(defn- add-session-token [session-sms response request token]
  (if response
    (let [old-token (session-token request)]
      (if (= old-token token)
        response
        (-> response
            (assoc :session (:session response (:session request)))
            (assoc-in [:session :ring.middleware.anti-forgery/anti-forgery-token] token))))))

(defn- create-token [request]
  (random/base64 60))

(deftype SessionSMS []
  strategy/StateManagementStrategy

  (get-token [this request]
    (or (session-token request)
        (create-token request)))

  (valid-token? [_ request token]
    (let [stored-token (session-token request)]
      (and stored-token
           (crypto/eq? token stored-token))))

  (write-token [this request response token]
    (add-session-token this response request (force token))))
