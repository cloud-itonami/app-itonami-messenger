(ns yoro.otehon-delivery-host
  "Trusted local host for private-message delivery."
  (:require [awai.otehon-delivery-host :as delivery]))

(defn bind!
  "Bind the local Passkey and dango checks. The caller authenticates the
   policy, signed delivery basis, recipient grants and byte count."
  [host db credential-id holder]
  (delivery/bind! host db credential-id holder 65536))
