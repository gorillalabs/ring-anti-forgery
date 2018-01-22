(ns ring.middleware.anti-forgery.strategy)

(defprotocol StateManagementStrategy
  "CSRF protection is based on the fact, that some state is embedded
  in the client webpage (e.g. as hidden form field)
  and the server is able to validate that state.

  OWASP documents a number of patterns how to create and validate that state
  in the form of a 'token', each with its own advantages and disadvantages.

  StateManagmentStrategy is the protocol to abstract the process
  of token creation and validation."

  (token [strategy request]
    "Returns a token to be used. Users of ring.middleware.anti-forgery should use the appropriate utility functions
    from `ring.util.anti-forgery` namespace.")

  (valid-token? [strategy request read-token]
    "Given the `request` and the `read-token` function to retrieve the token from the request, `valid-token?` returns
    true if the token used in that request is valid. Returns false otherwise.")

  (write-token [strategy response request token]
    "Some state management strategies do need to remember state (e.g., by storing it to some storage accessible
    in different requests). `write-token` is the method to handle state persistence, if necessary."))

(defprotocol DelayTokenCreation
  "Some state creation strategies are too compute intense to create new tokens in advance without knowing whether
  they will be used at all. Instead, new tokens should only be created upon consumption. As this is more a property
  of the creation process, and not so much on the personal gusto of the user of `ring.middleware.anti-forgery`,
  this is driven by this indicator protocol. Just add `DelayTokenCreation` to delay token creation by default.")
