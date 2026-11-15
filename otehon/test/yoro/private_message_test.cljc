(ns yoro.private-message-test
  (:require [yoro.private-message :as message] [dango.chain :as dango]
            [ed25519.sign :as ed] [envelope.keystore :as keys]
            [envelope.seal-sync :as crypto]))
(defn check [v] (when-not v (throw (js/Error. "Yoro message test failed"))))
(defn denied [f] (-> (js/Promise.resolve nil) (.then f)
                     (.then (fn [_] (throw (js/Error. "unexpected message approval"))) (fn [_] true))))
(def seed (vec (repeat 32 1)))
(def resource "kotoba://storage/synthetic")
(def sender "did:key:synthetic-sender")
(def reader "did:key:synthetic-reader")
(def a (crypto/generate-hybrid-recipient))
(def b (crypto/generate-hybrid-recipient))
(defn recipient [holder key next-seed]
  {:holder holder :pub (:pub key) :pq-pub (:pq-pub key)
   :presentation (dango/present (dango/root {:issuer-seed seed :next-seed (vec (repeat 32 next-seed))
                    :grant {:caps #{[:data/read resource]} :holder holder :before 200} :caveats []}))})
(def recipients [(recipient sender a 2) (recipient reader b 3)])
(def msg {:id "m1" :thread "t1" :author sender :text "private synthetic message" :sent-at 100})
(-> (js/Promise.all #js [(keys/fingerprint a) (keys/fingerprint b)])
    (.then (fn [[afp bfp]]
      (let [policy {:roots #{(ed/public-key seed)} :revoked #{} :fresh-until 150 :bindings {sender afp reader bfp}}
            host {:sender sender :resource resource :now! (fn [] 100) :policy! (fn [] policy)}
            expected {:resource resource :recipients #{sender reader} :author sender}
            admit {:admit! (fn [e _] (= e expected))}]
        (-> (message/seal! host msg recipients)
            (.then (fn [sealed]
              (check (not (.includes (pr-str (:envelope sealed)) (:text msg))))
              (-> (message/open! admit sealed expected reader (select-keys b [:priv :pq-priv]))
                  (.then (fn [opened] (check (= msg opened))
                    (js/Promise.all
                     #js [(denied #(message/seal! host (assoc msg :author reader) recipients))
                          (denied #(message/seal! host msg [(second recipients)]))
                          (denied #(message/seal! (assoc host :policy! (fn [] (assoc policy :fresh-until 100))) msg recipients))
                          (denied #(message/open! admit sealed (assoc expected :author reader) reader (select-keys b [:priv :pq-priv])))
                          (denied #(message/open! admit sealed expected reader (select-keys a [:priv :pq-priv])))]))))))))))
    (.then (fn [_] (println (js/JSON.stringify #js {:passed true :scope "synthetic Yoro private message and policy"}))))
    (.catch (fn [e] (js/console.error e) (set! (.-exitCode js/process) 1))))
