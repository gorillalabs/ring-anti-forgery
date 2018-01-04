(ns ring.middleware.test.anti-forgery
  (:require [ring.middleware.anti-forgery :as af]
            [ring.middleware.anti-forgery.strategy.encrypted-token :as encrypted-token]
            [ring.middleware.anti-forgery.strategy.signed-token :as signed-token]
            [buddy.core.keys :as keys]
            [clj-time.core :as time]
            [ring.middleware.anti-forgery.strategy :as strategy]
            [ring.middleware.anti-forgery.strategy.session :as session])
  (:use clojure.test
        ring.middleware.anti-forgery
        ring.mock.request))

(def ^:private expires-in-one-hour (time/hours 1))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Things necessary to test signed-token-strategy
;;

(def ^:private pubkey (keys/public-key "dev-resources/test-certs/pubkey.pem"))
(def ^:private privkey (keys/private-key "dev-resources/test-certs/privkey.pem" "antiforgery"))
(def ^:private other-private-key (keys/private-key "dev-resources/test-certs/privkey-other.pem" "other"))

(def ^:private signed-token-sms (signed-token/->SignedTokenSMS pubkey privkey expires-in-one-hour :identity))

(def ^:private signed-token-options {:state-management-strategy signed-token-sms})


(defn create-signed-csrf-token
  ([privkey expiration]
   (strategy/find-or-create-token (signed-token/->SignedTokenSMS nil privkey expiration :identity) nil))
  ([privkey expiration subject]
   (strategy/find-or-create-token (signed-token/->SignedTokenSMS nil privkey expiration :identity) {:identity subject})))

(defn- valid-signed-token? [public-key token]
  (strategy/valid-token?
    (signed-token/->SignedTokenSMS public-key nil nil :identity)
    token
    identity))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Things necessary to test encrypted-token-strategy
;;

(def ^:private secret "secret-to-validate-token-after-decryption-to-make-sure-i-encrypted-stuff")

(def ^:private encrypted-token-sms (encrypted-token/->EncryptedTokenSMS
                                     (encrypted-token/sha256 secret)
                                     expires-in-one-hour :identity))

(def ^:private encrypted-token-options {:state-management-strategy encrypted-token-sms})

(defn create-encrypted-csrf-token
  ([secret expiration]
   (strategy/find-or-create-token (encrypted-token/->EncryptedTokenSMS (encrypted-token/sha256 secret) expiration :identity) nil))
  ([secret expiration subject]
   (strategy/find-or-create-token (encrypted-token/->EncryptedTokenSMS (encrypted-token/sha256 secret) expiration :identity) {:identity subject})))

(defn- valid-encrypted-token? [secret token]
  (strategy/valid-token?
    (encrypted-token/->EncryptedTokenSMS (encrypted-token/sha256 secret) nil :identity)
    token
    identity))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Generic helpers
;;

(defn- status=* [handler status req]
  (= status (:status (handler req))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; Tests follow below
;;

(deftest forgery-protection-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (are [status req] (= (:status (handler req)) status)
                      403 (-> (request :post "/")
                              (assoc :form-params {"__anti-forgery-token" "foo"}))
                      403 (-> (request :post "/")
                              (assoc :session {::af/anti-forgery-token "foo"})
                              (assoc :form-params {"__anti-forgery-token" "bar"}))
                      200 (-> (request :post "/")
                              (assoc :session {::af/anti-forgery-token "foo"})
                              (assoc :form-params {"__anti-forgery-token" "foo"})))))

(deftest forgery-protection-via-signed-token-test
  (let [expired-one-hour-ago (time/hours -1)

        response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) signed-token-options)
        status= (partial status=* handler)]

    (testing "without anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/"))
                        403 (-> (request :post "/")
                                (assoc :identity "user-id"))))

    (testing "with ill-formated anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" "bar"}))))

    (testing "with non-decryptable anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token other-private-key expired-one-hour-ago)}))))
    (testing "with expired anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expired-one-hour-ago)}))))
    (testing "with anti-forgery-token for wrong subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour "user-id")})
                                (assoc :identity "another-user-id"))))
    (testing "with anti-forgery-token for no subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour)})
                                (assoc :identity "user-id"))))

    (testing "with correct anti-forgery-token if no subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour)}))))

    (testing "with correct anti-forgery-token if subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :identity "user-id")
                                (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour "user-id")}))))
    ))


(deftest forgery-protection-via-encrypted-token-test
  (let [expired-one-hour-ago (time/hours -1)

        response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) encrypted-token-options)
        status= (partial status=* handler)]

    (testing "without anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/"))
                        403 (-> (request :post "/")
                                (assoc :identity "user-id"))))

    (testing "with ill-formated anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" "bar"}))))

    (testing "with non-decryptable anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                ;; anti-forgery-token not decryptable with our key
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token "another-secret" expired-one-hour-ago)}))))

    (testing "with expired anti-forgery-token"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expired-one-hour-ago)}))))
    (testing "with anti-forgery-token for wrong subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour "user-id")})
                                (assoc :identity "another-user-id"))))
    (testing "with anti-forgery-token for no subject"
      (are [status req] (status= status req)
                        403 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour)})
                                (assoc :identity "user-id"))))

    (testing "with correct anti-forgery-token if no subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour)}))))

    (testing "with correct anti-forgery-token if subject is given.
    (Attention: Has different nounce, but that's ok)"
      (are [status req] (status= status req)
                        200 (-> (request :post "/")
                                (assoc :identity "user-id")
                                (assoc :form-params {"__anti-forgery-token" (create-encrypted-csrf-token secret expires-in-one-hour "user-id")}))))
    ))

(deftest request-method-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (are [status req] (= (:status (handler req)) status)
                      200 (request :head "/")
                      200 (request :get "/")
                      200 (request :options "/")
                      403 (request :post "/")
                      403 (request :put "/")
                      403 (request :patch "/")
                      403 (request :delete "/"))))

(deftest request-method-via-signed-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) signed-token-options)]
    (are [status req] (= (:status (handler req)) status)
                      200 (request :head "/")
                      200 (request :get "/")
                      200 (request :options "/")
                      403 (request :post "/")
                      403 (request :put "/")
                      403 (request :patch "/")
                      403 (request :delete "/"))))

(deftest request-method-via-encrypted-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response) encrypted-token-options)]
    (are [status req] (= (:status (handler req)) status)
                      200 (request :head "/")
                      200 (request :get "/")
                      200 (request :options "/")
                      403 (request :post "/")
                      403 (request :put "/")
                      403 (request :patch "/")
                      403 (request :delete "/"))))

(deftest csrf-header-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))
        sess-req (-> (request :post "/")
                     (assoc :session {::af/anti-forgery-token "foo"}))]
    (are [status req] (= (:status (handler req)) status)
                      200 (assoc sess-req :headers {"x-csrf-token" "foo"})
                      200 (assoc sess-req :headers {"x-xsrf-token" "foo"}))))

(deftest multipart-form-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (is (= (-> (request :post "/")
               (assoc :session {::af/anti-forgery-token "foo"})
               (assoc :multipart-params {"__anti-forgery-token" "foo"})
               handler
               :status)
           200))))

(deftest token-in-session-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly response))]
    (is (contains? (:session (handler (request :get "/")))
                   ::af/anti-forgery-token))
    (is (not= (get-in (handler (request :get "/"))
                      [:session ::af/anti-forgery-token])
              (get-in (handler (request :get "/"))
                      [:session ::af/anti-forgery-token])))))

(deftest token-binding-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    *anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler) (request :get "/"))]
      (is (= (get-in response [:session ::af/anti-forgery-token])
             (:body response))))))


(deftest new-token-via-signed-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    (new-token signed-token-sms request)})]
    (let [response ((wrap-anti-forgery handler signed-token-options) (request :get "/"))]
      (is (valid-signed-token? pubkey (:body response))))))


(deftest token-binding-via-signed-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    @*anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler signed-token-options) (request :get "/"))]
      (is (valid-signed-token? pubkey (:body response))))))


(deftest token-binding-via-encrypted-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    @*anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler encrypted-token-options) (request :get "/"))]
      (is (valid-encrypted-token? secret (:body response))))))

(deftest nil-response-test
  (letfn [(handler [request] nil)]
    (let [response ((wrap-anti-forgery handler) (request :get "/"))]
      (is (nil? response)))))

(deftest no-lf-in-token-test
  (letfn [(handler [request]
            {:status  200
             :headers {}
             :body    *anti-forgery-token*})]
    (let [response ((wrap-anti-forgery handler) (request :get "/"))
          token (get-in response [:session ::af/anti-forgery-token])]
      (is (not (.contains token "\n"))))))

(deftest single-token-per-session-test
  (let [expected {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (constantly expected))
        actual (handler
                 (-> (request :get "/")
                     (assoc-in [:session ::af/anti-forgery-token] "foo")))]
    (is (= actual expected))))

(deftest not-overwrite-session-test
  (let [response {:status 200 :headers {} :body nil}
        handler (wrap-anti-forgery (constantly response))
        session (:session (handler (-> (request :get "/")
                                       (assoc-in [:session "foo"] "bar"))))]
    (is (contains? session ::af/anti-forgery-token))
    (is (= (session "foo") "bar"))))

(deftest session-response-test
  (let [response {:status 200 :headers {} :session {"foo" "bar"} :body nil}
        handler (wrap-anti-forgery (constantly response))
        session (:session (handler (request :get "/")))]
    (is (contains? session ::af/anti-forgery-token))
    (is (= (session "foo") "bar"))))

(deftest no-session-response-via-signed-token-test
  (let [response {:status 200 :headers {} :session {"foo" "bar"} :body nil}
        handler (wrap-anti-forgery (constantly response) signed-token-options)
        session (:session (handler (request :get "/")))]
    (is (not (contains? session ::af/anti-forgery-token)))
    (is (= (session "foo") "bar"))))

(deftest custom-error-response-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        error-resp {:status 500, :headers {}, :body "Bar"}
        handler (wrap-anti-forgery (constantly response)
                                   {:error-response error-resp})]
    (is (= (dissoc (handler (request :get "/")) :session)
           response))
    (is (= (dissoc (handler (request :post "/")) :session)
           error-resp))))

(deftest custom-error-handler-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        error-resp {:status 500, :headers {}, :body "Bar"}
        handler (wrap-anti-forgery (constantly response)
                                   {:error-handler (fn [request] error-resp)})]
    (is (= (dissoc (handler (request :get "/")) :session)
           response))
    (is (= (dissoc (handler (request :post "/")) :session)
           error-resp))))

(deftest disallow-both-error-response-and-error-handler
  (is (thrown?
        AssertionError
        (wrap-anti-forgery (constantly {:status 200})
                           {:error-handler  (fn [request] {:status 500 :body "Handler"})
                            :error-response {:status 500 :body "Response"}}))))

(deftest custom-read-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery
                  (constantly response)
                  {:read-token #(get-in % [:headers "x-forgery-token"])})
        req (-> (request :post "/")
                (assoc :session {::af/anti-forgery-token "foo"})
                (assoc :headers {"x-forgery-token" "foo"}))]
    (is (= (:status (handler req))
           200))
    (is (= (:status (handler (assoc req :headers {"x-csrf-token" "foo"})))
           403))))

(deftest random-tokens-test
  (let [handler (fn [_] {:status 200, :headers {}, :body *anti-forgery-token*})
        get-response (fn [] ((wrap-anti-forgery handler) (request :get "/")))
        tokens (map :body (repeatedly 1000 get-response))]
    (is (every? #(re-matches #"[A-Za-z0-9+/]{80}" %) tokens))
    (is (= (count tokens) (count (set tokens))))))

(deftest forgery-protection-cps-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (fn [_ respond _] (respond response)))]

    (testing "missing token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 403))))

    (testing "valid token"
      (let [req (-> (request :post "/")
                    (assoc :session {::af/anti-forgery-token "foo"})
                    (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 200))))))



(deftest forgery-protection-cps-via-signed-token-test
  (let [response {:status 200, :headers {}, :body "Foo"}
        handler (wrap-anti-forgery (fn [_ respond _] (respond response)) signed-token-options)]

    (testing "missing token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" "foo"}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 403))))

    (testing "valid token"
      (let [req (-> (request :post "/")
                    (assoc :form-params {"__anti-forgery-token" (create-signed-csrf-token privkey expires-in-one-hour)}))
            resp (promise)
            ex (promise)]
        (handler req resp ex)
        (is (not (realized? ex)))
        (is (= (:status @resp) 200))))))
