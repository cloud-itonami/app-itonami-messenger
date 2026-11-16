(ns yoro.otehon-delivery-host
  "Trusted local host for private-message delivery."
  (:require [awai.otehon-delivery-host :as delivery]
            [awai.kotobase-block-adapter :as blocks]))

(defn bind!
  "Bind the local Passkey and dango checks. The caller authenticates the
   policy, signed delivery basis, recipient grants and byte count."
  [host db credential-id holder]
  (delivery/bind! host db credential-id holder 65536))

(defn client!
  "Construct the ciphertext block client with a host-owned broker and abort
   signal. Loopback HTTP is exclusively for explicitly selected local tests;
   production callers must pass false and a reviewed canonical broker."
  [origin broker get-selector put-selector signal allow-loopback-for-tests?]
  (blocks/client origin broker get-selector put-selector signal allow-loopback-for-tests?))
