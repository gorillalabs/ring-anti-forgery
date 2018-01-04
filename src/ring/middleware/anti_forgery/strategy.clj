(ns ring.middleware.anti-forgery.strategy)

(defprotocol StateManagementStrategy
  (create-token [this request])
  (find-or-create-token [this request])
  (valid-token? [this request read-token])
  (wrap-response [this response request token])
  (delay-token-creation [this]))
