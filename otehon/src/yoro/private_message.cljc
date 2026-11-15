(ns yoro.private-message
  "Bounded local Yoro message envelope composition. The trusted host owns
   authenticated identities, current dango policy and signed object admission.
   This namespace performs no network, consent or key discovery."
  (:require [awai.browser-authorized-envelope :as envelope]
            [awai.browser-recipient-envelope :as recipient-envelope]))

(defn refuse [] (throw (ex-info "private message refused" {})))
(defn text? [x n] (and (string? x) (<= 1 (count x) n)))
(defn message? [m]
  (and (map? m) (= #{:id :thread :author :text :sent-at} (set (keys m)))
       (text? (:id m) 128) (text? (:thread m) 128) (text? (:author m) 256)
       (text? (:text m) 32000) (js/Number.isSafeInteger (:sent-at m)) (<= 0 (:sent-at m))))

(defn prepare-passkey-seal!
  "Prepare an authenticated recipient proof. Trusted host displays sender,
   complete recipients and operation, then invokes :confirm! in a direct user
   gesture. This does not supply network consent or delivery."
  [host message nonce pub pq-pub presentation others]
  (when-not (and (map? host) (text? (:sender host) 256) (text? (:resource host) 256)
                 (map? (:recipient-host host)) (message? message) (= (:sender host) (:author message))
                 (vector? others) (every? map? others)) (refuse))
  (let [ids (conj (set (map :holder others)) (get-in host [:recipient-host :holder]))]
    (when-not (and (= (count ids) (inc (count others))) (contains? ids (:sender host))) (refuse))
    (-> (recipient-envelope/prepare! host nonce pub pq-pub presentation others)
        (.then (fn [prepared]
          (when-not (= ids (set (:recipients prepared))) (refuse))
          (assoc (dissoc prepared :confirm!) :confirm!
            (fn []
              (let [plain (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js message)))]
                (try (-> ((:confirm! prepared) plain) (.finally (fn [] (.fill plain 0))))
                     (catch :default e (.fill plain 0) (throw e)))))))))))

(defn seal!
  "Seal the entire message for the explicit authorized recipients. host's
   :sender and :resource must come from the trusted user-side host; they are
   not assertions accepted from a message, peer or application descriptor."
  [host message recipients]
  (when-not (and (map? host) (text? (:sender host) 256) (text? (:resource host) 256)
                 (message? message) (= (:sender host) (:author message))
                 (vector? recipients) (some #(= (:sender host) (:holder %)) recipients))
    (refuse))
  (let [plain (.encode (js/TextEncoder.) (js/JSON.stringify (clj->js message)))]
    (-> (js/Promise.resolve nil)
        (.then (fn [] (envelope/seal host (:resource host) plain recipients)))
        (.finally (fn [] (.fill plain 0))))))

(defn open!
  "expected and host :admit! must be authenticated independently of storage.
   expected author, thread and message ID come from that verified basis;
   admission checks its signature, object, recipients and current policy."
  [host object expected recipient identity]
  (when-not (and (map? host) (fn? (:admit! host))
                 (map? expected) (= #{:resource :recipients :author :thread :id} (set (keys expected)))
                 (text? (:author expected) 256) (text? (:thread expected) 128) (text? (:id expected) 128)) (refuse))
  (let [admit! (:admit! host)
        scoped-host (assoc host :admit! (fn [_ candidate] (admit! expected candidate)))]
  (-> (envelope/open scoped-host object (select-keys expected [:resource :recipients]) recipient identity)
      (.then (fn [plain]
        (try
          (let [decoded (.decode (js/TextDecoder. "utf-8" #js {:fatal true}) plain)
                message (js->clj (js/JSON.parse decoded) :keywordize-keys true)]
            (when-not (and (message? message) (= (:author expected) (:author message))
                           (= (:thread expected) (:thread message)) (= (:id expected) (:id message))) (refuse))
            message)
          (finally (.fill plain 0))))))))
