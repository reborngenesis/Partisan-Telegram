package org.telegram.messenger.partisan.rgcrypto.storage;

import android.content.Context;

import org.telegram.messenger.partisan.rgcrypto.RgCryptoIds;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeyCard;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoRecipientPublic;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeys;
import org.telegram.messenger.partisan.rgcrypto.RgCrypto;

import com.google.crypto.tink.KeysetHandle;

import java.util.ArrayList;
import java.util.List;

public final class RgCryptoKeyringStore {
    private final RgCryptoKeyringDao dao;

    public RgCryptoKeyringStore(Context context, int account) {
        this(RgCryptoKeyringDatabase.getInstance(context, account).keyringDao());
    }

    RgCryptoKeyringStore(RgCryptoKeyringDao dao) {
        this.dao = dao;
    }

    public List<RgCryptoKeyringEntry> getByPeer(String peerId) {
        return dao.getByPeer(RgCryptoIds.normalizePeerId(peerId));
    }

    public RgCryptoKeyringEntry getByKeyIds(String peerId, String deviceId, int signingKeyId, int encryptionKeyId) {
        return dao.getByKeyIds(RgCryptoIds.normalizePeerId(peerId),
                RgCryptoIds.normalizeDeviceId(deviceId), signingKeyId, encryptionKeyId);
    }

    public RgCryptoKeyringEntry getByKids(String peerId, String deviceId, String signingKid, String encryptionKid) {
        return dao.getByKids(RgCryptoIds.normalizePeerId(peerId),
                RgCryptoIds.normalizeDeviceId(deviceId), signingKid, encryptionKid);
    }

    public KeysetHandle getSigningKeyset(String peerId, String signingKid) throws Exception {
        RgCryptoKeyringEntry entry = dao.getByPeerAndSigningKid(RgCryptoIds.normalizePeerId(peerId), signingKid);
        if (entry == null) {
            return null;
        }
        return RgCryptoKeys.parsePublicKeyset(entry.signingKeysetJson);
    }

    public ImportResult importKeyCard(String peerId, String keyCardJson, int trustState, boolean keepTrustIfExists)
            throws Exception {
        RgCrypto.initialize();
        RgCryptoKeyCard card = RgCryptoKeyCard.fromJson(keyCardJson);
        boolean signatureOk = false;
        try {
            signatureOk = card.verifySelf();
        } catch (Exception ignored) {
            signatureOk = false;
        }
        int signatureState = signatureOk ? RgCryptoSignatureState.VALID : RgCryptoSignatureState.INVALID;
        long now = System.currentTimeMillis();
        String normalizedPeer = RgCryptoIds.normalizePeerId(peerId);
        String normalizedDevice = RgCryptoIds.normalizeDeviceId(card.deviceId);

        int encryptionKeyId = RgCryptoKeys.primaryKeyId(RgCryptoKeys.parsePublicKeyset(card.encryptionKeysetJson));
        RgCryptoKeyringEntry existing = dao.getByKeyIds(normalizedPeer, normalizedDevice, card.signingKeyId,
                encryptionKeyId);

        int finalTrust = RgCryptoTrustState.UNTRUSTED;
        if (keepTrustIfExists && existing != null) {
            finalTrust = existing.trustState;
        }
        if (finalTrust == RgCryptoTrustState.TRUSTED && signatureState != RgCryptoSignatureState.VALID) {
            finalTrust = RgCryptoTrustState.UNTRUSTED;
        }
        RgCryptoKeyringEntry entry = RgCryptoKeyringEntry.fromKeyCard(normalizedPeer, card, finalTrust,
                signatureState, now);
        if (existing != null) {
            entry.createdAt = existing.createdAt;
        }
        dao.upsert(entry);
        if (entry.signingKid != null && entry.encryptionKid != null) {
            dao.revokeOtherDeviceKeys(normalizedPeer, normalizedDevice, entry.signingKid, entry.encryptionKid,
                    RgCryptoTrustState.REVOKED, now);
        }
        return new ImportResult(entry, signatureOk);
    }

    public void updateTrustState(String peerId, String deviceId, int signingKeyId, int encryptionKeyId, int trustState) {
        String normalizedPeer = RgCryptoIds.normalizePeerId(peerId);
        String normalizedDevice = RgCryptoIds.normalizeDeviceId(deviceId);
        if (trustState == RgCryptoTrustState.TRUSTED) {
            RgCryptoKeyringEntry entry = dao.getByKeyIds(normalizedPeer, normalizedDevice, signingKeyId, encryptionKeyId);
            if (entry == null || entry.signatureValid != RgCryptoSignatureState.VALID) {
                throw new IllegalStateException("Only existing keys with valid signatures can be trusted");
            }
        }
        if (dao.updateTrustState(normalizedPeer, normalizedDevice, signingKeyId, encryptionKeyId,
                trustState, System.currentTimeMillis()) != 1) {
            throw new IllegalStateException("Key no longer exists");
        }
    }

    public void updateSignatureState(String peerId, String deviceId, int signingKeyId, int encryptionKeyId,
                                     int signatureValid) {
        dao.updateSignatureState(RgCryptoIds.normalizePeerId(peerId), RgCryptoIds.normalizeDeviceId(deviceId),
                signingKeyId, encryptionKeyId, signatureValid, System.currentTimeMillis());
    }

    public int deleteByKeyIds(String peerId, String deviceId, int signingKeyId, int encryptionKeyId) {
        return dao.deleteByKeyIds(RgCryptoIds.normalizePeerId(peerId), RgCryptoIds.normalizeDeviceId(deviceId),
                signingKeyId, encryptionKeyId);
    }

    public List<RgCryptoRecipientPublic> trustedRecipients(String peerId) throws Exception {
        List<RgCryptoKeyringEntry> entries = dao.getByPeer(RgCryptoIds.normalizePeerId(peerId));
        List<RgCryptoRecipientPublic> recipients = new ArrayList<>();
        for (RgCryptoKeyringEntry entry : entries) {
            if (entry.trustState != RgCryptoTrustState.TRUSTED) {
                continue;
            }
            if (entry.signatureValid != RgCryptoSignatureState.VALID) {
                continue;
            }
            recipients.add(new RgCryptoRecipientPublic(entry.encryptionKeyId,
                    RgCryptoKeys.parsePublicKeyset(entry.encryptionKeysetJson),
                    entry.encryptionKid));
        }
        return recipients;
    }

    public List<RgCryptoRecipientPublic> trustedRecipientsForPeers(List<String> peerIds) throws Exception {
        List<RgCryptoRecipientPublic> recipients = new ArrayList<>();
        if (peerIds == null) {
            return recipients;
        }
        for (String peerId : peerIds) {
            recipients.addAll(trustedRecipients(peerId));
        }
        return recipients;
    }

    public void clearAll() {
        dao.clearAll();
    }

    public static final class ImportResult {
        public final RgCryptoKeyringEntry entry;
        public final boolean signatureValid;

        public ImportResult(RgCryptoKeyringEntry entry, boolean signatureValid) {
            this.entry = entry;
            this.signatureValid = signatureValid;
        }
    }
}
