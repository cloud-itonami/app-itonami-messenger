(ns yoro.private-message-delivery-test
  (:require [yoro.private-message :as message] [awai.browser-shared-object :as wire]
            [dango.chain :as dango] [ed25519.sign :as ed]
            [envelope.keystore :as keys] [envelope.seal-sync :as crypto]
            [multiformats.core :as mf]))

(defn check [condition] (when-not condition (throw (js/Error. "Yoro delivery test failed"))))
(defn denied [f] (-> (js/Promise.resolve nil) (.then f)
                     (.then (fn [_] (throw (js/Error. "unexpected delivery"))) (fn [_] true))))
(def seed (vec (repeat 32 1)))
(def resource "kotoba://storage/synthetic")
(def sender "did:key:sender")
(def recipient "did:key:recipient")
(def a (crypto/generate-hybrid-recipient))
(def b (crypto/generate-hybrid-recipient))
(defn grant [holder key n]
  {:holder holder :pub (:pub key) :pq-pub (:pq-pub key)
   :presentation (dango/present (dango/root {:issuer-seed seed :next-seed (vec (repeat 32 n))
                   :grant {:caps #{[:data/read resource]} :holder holder :before 200} :caveats []}))})
(def value {:id "message-1" :thread "thread-1" :author sender :text "private delivery test" :sent-at 100})
(def expected {:resource resource :recipients #{sender recipient} :author sender :thread "thread-1" :id "message-1"})
(defn clone [b] (js/Uint8Array.from b))

(-> (js/Promise.all #js [(keys/fingerprint a) (keys/fingerprint b)])
    (.then (fn [[afp bfp]]
      (let [policy {:roots #{(ed/public-key seed)} :revoked #{} :fresh-until 150 :bindings {sender afp recipient bfp}}
            sealing {:sender sender :resource resource :now! (fn [] 100) :policy! (fn [] policy)}
            stored (atom {}) writes (atom 0) current (atom true) allowed (atom nil)
            client {:put-block! (fn [cid bytes auth]
                                  (check (= auth "Biscuit synthetic")) (swap! writes inc)
                                  (swap! stored assoc cid (clone bytes)) (js/Promise.resolve cid))
                    :get-block (fn [cid] (js/Promise.resolve (some-> (get @stored cid) clone)))}
            host {:delivery-current! (fn [] @current)
                  :admit-cid! (fn [cid basis] (and (= cid @allowed) (= expected basis)))
                  :authorization! (fn [_] (js/Promise.resolve "Biscuit synthetic"))
                  :admit! (fn [basis _] (= expected basis))}]
        (-> (message/seal! sealing value [(grant sender a 2) (grant recipient b 3)])
            (.then (fn [sealed]
              (let [cid (mf/cidv1-raw (wire/encode sealed))]
                (reset! allowed cid)
                (-> (denied #(message/publish! host client sealed (assoc expected :thread "other")))
                    (.then (fn [_] (check (zero? @writes)) (message/publish! host client sealed expected)))
                    (.then (fn [published]
                      (check (= cid published)) (check (= 1 @writes))
                      (check (not (.includes (js/Buffer.from (get @stored cid)) (:text value))))
                      (message/receive! host client cid expected recipient (select-keys b [:priv :pq-priv]))))
                    (.then (fn [opened] (check (= value opened))
                      (let [revoking (assoc host :authorization! (fn [_] (reset! current false) (js/Promise.resolve "Biscuit synthetic")))]
                        (denied #(message/publish! revoking client sealed expected)))))
                    (.then (fn [_] (check (= 1 @writes)) (reset! current true)
                      (denied #(message/receive! host client cid (assoc expected :id "other") recipient (select-keys b [:priv :pq-priv])))))
                    (.then (fn [_] (reset! current false)
                      (denied #(message/receive! host client cid expected recipient (select-keys b [:priv :pq-priv])))))
                    (.then (fn [_] (reset! current true)
                      (let [calls (atom 0) changing (assoc host :admit! (fn [_ _] (= 1 (swap! calls inc))))]
                        (denied #(message/receive! changing client cid expected recipient (select-keys b [:priv :pq-priv]))))))
                    (.then (fn [_]
                      (let [bytes (clone (get @stored cid))]
                        (aset bytes 0 (bit-xor 1 (aget bytes 0))) (swap! stored assoc cid bytes)
                        (denied #(message/receive! host client cid expected recipient (select-keys b [:priv :pq-priv]))))))))))))))
    (.then (fn [_] (println (js/JSON.stringify #js {:passed true :scope "synthetic Yoro encrypted block delivery"}))))
    (.catch (fn [error] (js/console.error error) (set! (.-exitCode js/process) 1))))
