package org.telegram.messenger.partisan.rgcrypto.storage;

import android.content.Context;
import android.util.SparseArray;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.FileLog;

import com.google.crypto.tink.KeysetHandle;

import org.telegram.messenger.partisan.rgcrypto.RgCryptoIds;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeys;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoRecipientPublic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class RgCryptoKeyringCache {
    private static final Object LOCK = new Object();
    private static final SparseArray<RgCryptoKeyringCache> INSTANCES = new SparseArray<>();

    private final Supplier<RgCryptoKeyringStore> storeFactory;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ConcurrentHashMap<String, List<RgCryptoRecipientPublic>> recipientsByPeer = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, KeysetHandle> signingByPeerAndKid = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> signingKidsByPeer = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> peersBySigningKid = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> trustKeysByPeer = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> trustByPeerAndKid = new ConcurrentHashMap<>();

    private RgCryptoKeyringCache(Context context, int account) {
        Context applicationContext = context.getApplicationContext();
        this.storeFactory = () -> new RgCryptoKeyringStore(applicationContext, account);
    }

    RgCryptoKeyringCache(Supplier<RgCryptoKeyringStore> storeFactory) {
        this.storeFactory = storeFactory;
    }

    public static RgCryptoKeyringCache get(Context context, int account) {
        synchronized (LOCK) {
            RgCryptoKeyringCache instance = INSTANCES.get(account);
            if (instance == null) {
                instance = new RgCryptoKeyringCache(context, account);
                INSTANCES.put(account, instance);
            }
            return instance;
        }
    }

    public void refreshForPeers(List<String> peerIds) {
        refreshForPeers(peerIds, null);
    }

    public void refreshForPeers(List<String> peerIds, Runnable onComplete) {
        refreshForPeers(peerIds, onComplete, null);
    }

    public void refreshForPeers(List<String> peerIds, Runnable onComplete, Runnable onError) {
        List<String> requestedPeers = new ArrayList<>();
        if (peerIds != null) {
            for (String peerId : peerIds) {
                requestedPeers.add(RgCryptoIds.normalizePeerId(peerId));
            }
        }
        // Even an empty refresh is queued, so it can act as a barrier after clearAll().
        executor.execute(() -> {
            try {
                if (!requestedPeers.isEmpty()) {
                    RgCryptoKeyringStore store = storeFactory.get();
                    for (String peerId : requestedPeers) {
                        refreshPeer(store, peerId);
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
                for (String peerId : requestedPeers) {
                    recipientsByPeer.remove(peerId);
                    updateSigningKidIndex(peerId, Collections.emptySet());
                    updateTrustKeys(peerId, Collections.emptySet());
                }
                if (onError != null) {
                    AndroidUtilities.runOnUIThread(onError);
                }
                return;
            }
            if (onComplete != null) {
                AndroidUtilities.runOnUIThread(onComplete);
            }
        });
    }

    private void refreshPeer(RgCryptoKeyringStore store, String peerId) throws Exception {
        List<RgCryptoKeyringEntry> entries = store.getByPeer(peerId);
        List<RgCryptoRecipientPublic> recipients = new ArrayList<>();
        Map<String, KeysetHandle> signingKeys = new HashMap<>();
        Map<String, Integer> trustStates = new HashMap<>();
        for (RgCryptoKeyringEntry entry : entries) {
            KeysetHandle signing = RgCryptoKeys.parsePublicKeyset(entry.signingKeysetJson);
            KeysetHandle encryption = RgCryptoKeys.parsePublicKeyset(entry.encryptionKeysetJson);
            String signingKid = entry.signingKid != null ? entry.signingKid : RgCryptoKeys.kidFromKeyset(signing);
            String encryptionKid = entry.encryptionKid != null ? entry.encryptionKid : RgCryptoKeys.kidFromKeyset(encryption);
            signingKeys.put(signingKid, signing);
            trustStates.put(trustKey(peerId, signingKid, encryptionKid), entry.trustState);
            if (entry.trustState == RgCryptoTrustState.TRUSTED && entry.signatureValid == RgCryptoSignatureState.VALID) {
                recipients.add(new RgCryptoRecipientPublic(entry.encryptionKeyId, encryption, encryptionKid));
            }
        }
        // Publish only fully parsed peer entries; failures leave no partially indexed keys.
        for (Map.Entry<String, KeysetHandle> signing : signingKeys.entrySet()) {
            signingByPeerAndKid.put(signingKeyKey(peerId, signing.getKey()), signing.getValue());
        }
        trustByPeerAndKid.putAll(trustStates);
        updateSigningKidIndex(peerId, new HashSet<>(signingKeys.keySet()));
        updateTrustKeys(peerId, new HashSet<>(trustStates.keySet()));
        recipientsByPeer.put(peerId, recipients);
    }

    public List<RgCryptoRecipientPublic> getRecipientsForPeers(List<String> peerIds) {
        if (peerIds == null || peerIds.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList<RgCryptoRecipientPublic> out = new ArrayList<>();
        for (String peerId : peerIds) {
            String normalized = RgCryptoIds.normalizePeerId(peerId);
            List<RgCryptoRecipientPublic> list = recipientsByPeer.get(normalized);
            if (list != null) {
                out.addAll(list);
            }
        }
        return out;
    }

    public KeysetHandle getSigningKeyset(String peerId, String signingKid) {
        if (peerId == null) {
            return null;
        }
        return signingByPeerAndKid.get(signingKeyKey(RgCryptoIds.normalizePeerId(peerId), signingKid));
    }

    public boolean hasAnySigningKeys(String peerId) {
        if (peerId == null) {
            return false;
        }
        Set<String> kids = signingKidsByPeer.get(RgCryptoIds.normalizePeerId(peerId));
        return kids != null && !kids.isEmpty();
    }

    public boolean hasSigningKid(String peerId, String signingKid) {
        if (peerId == null || signingKid == null) {
            return false;
        }
        Set<String> kids = signingKidsByPeer.get(RgCryptoIds.normalizePeerId(peerId));
        return kids != null && kids.contains(signingKid);
    }

    public void clearAll() {
        executor.execute(() -> {
            recipientsByPeer.clear();
            signingByPeerAndKid.clear();
            signingKidsByPeer.clear();
            peersBySigningKid.clear();
            trustKeysByPeer.clear();
            trustByPeerAndKid.clear();
        });
    }

    public int getTrustState(String peerId, String signingKid, String encryptionKid) {
        if (peerId == null || signingKid == null) {
            return RgCryptoTrustState.UNKNOWN;
        }
        Integer trust = trustByPeerAndKid.get(trustKey(RgCryptoIds.normalizePeerId(peerId), signingKid, encryptionKid));
        return trust != null ? trust : RgCryptoTrustState.UNKNOWN;
    }

    public boolean isSigningKidReusedByOtherPeer(String peerId, String signingKid) {
        if (signingKid == null) {
            return false;
        }
        Set<String> peers = peersBySigningKid.get(signingKid);
        if (peers == null || peers.isEmpty()) {
            return false;
        }
        if (peerId == null) {
            return peers.size() > 0;
        }
        String normalized = RgCryptoIds.normalizePeerId(peerId);
        return peers.size() > 1 || !peers.contains(normalized);
    }

    private String signingKeyKey(String peerId, String signingKid) {
        return peerId + "#" + signingKid;
    }

    private String trustKey(String peerId, String signingKid, String encryptionKid) {
        return peerId + "#" + signingKid + "#" + (encryptionKid != null ? encryptionKid : "");
    }

    private void updateSigningKidIndex(String peerId, Set<String> newKids) {
        Set<String> oldKids = signingKidsByPeer.put(peerId, newKids);
        if (oldKids != null) {
            for (String oldKid : oldKids) {
                if (newKids == null || !newKids.contains(oldKid)) {
                    signingByPeerAndKid.remove(signingKeyKey(peerId, oldKid));
                    Set<String> peers = peersBySigningKid.get(oldKid);
                    if (peers != null) {
                        peers.remove(peerId);
                        if (peers.isEmpty()) {
                            peersBySigningKid.remove(oldKid);
                        }
                    }
                }
            }
        }
        if (newKids != null) {
            for (String kid : newKids) {
                peersBySigningKid.computeIfAbsent(kid, k -> ConcurrentHashMap.newKeySet()).add(peerId);
            }
        }
    }

    private void updateTrustKeys(String peerId, Set<String> newKeys) {
        Set<String> oldKeys = trustKeysByPeer.put(peerId, newKeys);
        if (oldKeys != null) {
            for (String oldKey : oldKeys) {
                if (newKeys == null || !newKeys.contains(oldKey)) {
                    trustByPeerAndKid.remove(oldKey);
                }
            }
        }
    }
}
