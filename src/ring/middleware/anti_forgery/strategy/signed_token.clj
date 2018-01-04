(ns ring.middleware.anti-forgery.strategy.signed-token
  (:require [ring.middleware.anti-forgery.strategy :as strategy]
            [clj-time.core :as time]
            [buddy.sign.jwt :as jwt]
            [crypto.equality :as crypto]
            [clojure.tools.logging :as log])
  (:import (clojure.lang ExceptionInfo)))

(def ^:private crypt-options {:alg :rs512})


(deftype SignedTokenSMS [public-key private-key expiration-period get-subject-fn]
  strategy/StateManagementStrategy

  (valid-token? [_ request read-token]
    (when-let [token (read-token request)]
      (try
        (let [{:keys [sub secret]} (jwt/unsign token
                                               public-key
                                               crypt-options)]

          ;; check subject (must either be empty (now, not at token claim) or equal to the one in the claims)
          (when-let [subject (get-subject-fn request)]
            (when-not (crypto/eq? sub subject)
              (throw (ex-info (str "Subject does not match " sub)
                              {:type :validation :cause :sub}))))

          true
          )
        (catch ExceptionInfo e
          (when-not (= (:type (ex-data e)) :validation)
            (throw e))
          (when-not (= (:cause (ex-data e)) :exp)
            (log/warn
              e
              "Security warning: Potential CSRF-Attack"
              (ex-data e)))
          false))))

  (create-token [_ request]
    (let [claims {:iat (clj-time.coerce/to-epoch (time/now)) ;; Issued at (see https://tools.ietf.org/html/rfc7519#section-4.1.6)
                  :exp (clj-time.coerce/to-epoch (time/plus (time/now) expiration-period)) ;; Expires (see https://tools.ietf.org/html/rfc7519#section-4.1.4)
                  }
          claims-with-optional-subject (if-let [subject (get-subject-fn request)]
                                         (assoc claims :sub subject)
                                         claims)
          ]
      #_(println public-key)
      #_(println private-key)
      #_(println claims-with-optional-subject)
      (jwt/sign claims-with-optional-subject
                private-key
                crypt-options)))

  (find-or-create-token [this request]
    (strategy/create-token this request))

  (delay-token-creation [_] true)

  (wrap-response [_ response request token]
    response))
