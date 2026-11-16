(ns yoro.otehon-delivery-host
  "Trusted local host for private-message delivery."
  (:require [awai.otehon-delivery-host :as delivery]
            [awai.browser-block-authorization :as authorization]
            [awai.kotobase-block-adapter :as blocks]))

(defn bind!
  "Bind the local Passkey and dango checks. The caller authenticates the
   policy, signed delivery basis, recipient grants and byte count."
  [host db credential-id holder]
  (delivery/bind-local-revocations! host db credential-id holder 65536 (:local-revocation-scope host)))

(defn client!
  "Construct the ciphertext block client with a host-owned broker and abort
   signal. Loopback HTTP is exclusively for explicitly selected local tests;
   production callers must pass false and a reviewed canonical broker."
  [origin broker get-selector put-selector signal allow-loopback-for-tests?]
  (blocks/client origin broker get-selector put-selector signal allow-loopback-for-tests?))

(defn approved-delivery!
  "Construct the trusted local host, identity approval and peer client using
   the same selected peer origin, broker and lifetime signal."
  [host db credential-id holder {:keys [policy! now! interact! identity-origin tenant-id audience
                                         broker start-selector redeem-selector get-selector put-selector
                                         signal allow-loopback-for-tests?]}]
  (let [bound (bind! host db credential-id holder)
        authorize! (authorization/authorizer
                     {:current! (:delivery-current! bound) :now! now! :interact! interact!}
                     policy! identity-origin tenant-id audience broker start-selector redeem-selector signal
                     allow-loopback-for-tests?)]
    {:host (assoc bound :authorization! authorize!)
     :client (client! audience broker get-selector put-selector signal allow-loopback-for-tests?)}))
