package org.bouncycastle.openpgp.wot.key;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link PgpKeyRegistry}.
 *
 * @author Marco หงุ่ยตระกูล-Schulze - marco at codewizards dot co
 */
public class PgpKeyRegistryImpl implements PgpKeyRegistry
{
    private static final Logger logger = LoggerFactory.getLogger(PgpKeyRegistryImpl.class);

    private final File pubringFile;
    private final File secringFile;

    private long pubringFileLastModified = Long.MIN_VALUE;
    private long secringFileLastModified = Long.MIN_VALUE;

    private Map<PgpKeyFingerprint, PgpKey> pgpKeyFingerprint2pgpKey; // all keys
    private Map<PgpKeyId, PgpKey> pgpKeyId2pgpKey; // all keys
    private Map<PgpKeyId, PgpKey> pgpKeyId2masterKey; // only master-keys

    private Map<PgpKeyId, Set<PgpKeyId>> signingKeyId2signedKeyIds;

    /**
     * Creates an instance of {@code PgpKeyRegistryImpl} with the given public and secret key ring collection files.
     *
     * @param pubringFile
     *            the file containing the public keys - usually named {@code pubring.gpg} (located in {@code ~/.gnupg/}
     *            ). Must not be <code>null</code>. The file does not need to exist, though.
     * @param secringFile
     *            the file containing the secret keys - usually named {@code secring.gpg} (located in {@code ~/.gnupg/}
     *            ). Must not be <code>null</code>. The file does not need to exist, though.
     */
    public PgpKeyRegistryImpl(File pubringFile, File secringFile)
    {
        this.pubringFile = assertNotNull("pubringFile", pubringFile);
        this.secringFile = assertNotNull("secringFile", secringFile);
    }

    @Override
    public File getPubringFile()
    {
        return pubringFile;
    }

    @Override
    public File getSecringFile()
    {
        return secringFile;
    }

    @Override
    public PgpKey getPgpKeyOrFail(final PgpKeyId pgpKeyId) throws IllegalArgumentException
    {
        final PgpKey pgpKey = getPgpKey(pgpKeyId);
        if (pgpKey == null)
            throw new IllegalArgumentException("No PGP key found for this keyId: " + pgpKeyId);

        return pgpKey;
    }

    @Override
    public synchronized PgpKey getPgpKey(final PgpKeyId pgpKeyId) throws IllegalArgumentException
    {
        assertNotNull("pgpKeyId", pgpKeyId);
        loadIfNeeded();
        final PgpKey pgpKey = pgpKeyId2pgpKey.get(pgpKeyId);
        return pgpKey;
    }

    @Override
    public PgpKey getPgpKeyOrFail(final PgpKeyFingerprint pgpKeyFingerprint) throws IllegalArgumentException
    {
        final PgpKey pgpKey = getPgpKey(pgpKeyFingerprint);
        if (pgpKey == null)
            throw new IllegalArgumentException("No PGP key found for this fingerprint: " + pgpKeyFingerprint);

        return pgpKey;
    }

    @Override
    public synchronized PgpKey getPgpKey(final PgpKeyFingerprint pgpKeyFingerprint) throws IllegalArgumentException
    {
        assertNotNull("pgpKeyFingerprint", pgpKeyFingerprint);
        loadIfNeeded();
        final PgpKey pgpKey = pgpKeyFingerprint2pgpKey.get(pgpKeyFingerprint);
        return pgpKey;
    }

    @Override
    public synchronized Collection<PgpKey> getMasterKeys()
    {
        loadIfNeeded();
        return Collections.unmodifiableCollection(pgpKeyId2masterKey.values());
    }

    @Override
    public void markStale()
    {
        pubringFileLastModified = Long.MIN_VALUE;
        secringFileLastModified = Long.MIN_VALUE;
    }

    /**
     * Loads the key ring files, if they were not yet read or if this registry is stale.
     */
    protected synchronized void loadIfNeeded()
    {
        if (pgpKeyId2pgpKey == null
                || getPubringFile().lastModified() != pubringFileLastModified
                || getSecringFile().lastModified() != secringFileLastModified)
        {
            logger.debug("loadIfNeeded: invoking load().");
            load();
        }
        else
            logger.trace("loadIfNeeded: *not* invoking load().");
    }

    /**
     * Loads the key ring files.
     */
    protected synchronized void load()
    {
        pgpKeyFingerprint2pgpKey = null;
        final Map<PgpKeyFingerprint, PgpKey> pgpKeyFingerprint2pgpKey = new HashMap<>();
        final Map<PgpKeyId, PgpKey> pgpKeyId2pgpKey = new HashMap<>();
        final Map<PgpKeyId, PgpKey> pgpKeyId2masterKey = new HashMap<>();

        final long pubringFileLastModified;
        final long secringFileLastModified;
        try
        {
            final File secringFile = getSecringFile();
            logger.debug("load: secringFile='{}'", secringFile);
            secringFileLastModified = secringFile.lastModified();
            if (secringFile.isFile())
            {
                final PGPSecretKeyRingCollection pgpSecretKeyRingCollection;
                try (InputStream in = new BufferedInputStream(new FileInputStream(secringFile));)
                {
                    pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in),
                            new BcKeyFingerprintCalculator());
                }
                for (final Iterator<?> it1 = pgpSecretKeyRingCollection.getKeyRings(); it1.hasNext();)
                {
                    final PGPSecretKeyRing keyRing = (PGPSecretKeyRing) it1.next();
                    PgpKey masterKey = null;
                    for (final Iterator<?> it2 = keyRing.getPublicKeys(); it2.hasNext();)
                    {
                        final PGPPublicKey publicKey = (PGPPublicKey) it2.next();
                        masterKey = enlistPublicKey(pgpKeyFingerprint2pgpKey, pgpKeyId2pgpKey,
                                pgpKeyId2masterKey, masterKey, keyRing, publicKey);
                    }

                    for (final Iterator<?> it3 = keyRing.getSecretKeys(); it3.hasNext();)
                    {
                        final PGPSecretKey secretKey = (PGPSecretKey) it3.next();
                        final PgpKeyId pgpKeyId = new PgpKeyId(secretKey.getKeyID());
                        final PgpKey pgpKey = pgpKeyId2pgpKey.get(pgpKeyId);
                        if (pgpKey == null)
                            throw new IllegalStateException(
                                    "Secret key does not have corresponding public key in secret key ring! pgpKeyId="
                                            + pgpKeyId);

                        pgpKey.setSecretKey(secretKey);
                        logger.debug("load: read secretKey with pgpKeyId={}", pgpKeyId);
                    }
                }
            }

            final File pubringFile = getPubringFile();
            logger.debug("load: pubringFile='{}'", pubringFile);
            pubringFileLastModified = pubringFile.lastModified();
            if (pubringFile.isFile())
            {
                final PGPPublicKeyRingCollection pgpPublicKeyRingCollection;
                try (InputStream in = new BufferedInputStream(new FileInputStream(pubringFile));)
                {
                    pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in),
                            new BcKeyFingerprintCalculator());
                }

                for (final Iterator<?> it1 = pgpPublicKeyRingCollection.getKeyRings(); it1.hasNext();)
                {
                    final PGPPublicKeyRing keyRing = (PGPPublicKeyRing) it1.next();
                    PgpKey masterKey = null;
                    for (final Iterator<?> it2 = keyRing.getPublicKeys(); it2.hasNext();)
                    {
                        final PGPPublicKey publicKey = (PGPPublicKey) it2.next();
                        masterKey = enlistPublicKey(pgpKeyFingerprint2pgpKey, pgpKeyId2pgpKey,
                                pgpKeyId2masterKey, masterKey, keyRing, publicKey);
                    }
                }
            }
        } catch (IOException | PGPException x)
        {
            throw new RuntimeException(x);
        }

        for (final PgpKey pgpKey : pgpKeyId2pgpKey.values())
        {
            if (pgpKey.getPublicKey() == null)
                throw new IllegalStateException("pgpKey.publicKey == null :: keyId = " + pgpKey.getPgpKeyId());

            if (pgpKey.getPublicKeyRing() == null)
                throw new IllegalStateException("pgpKey.publicKeyRing == null :: keyId = " + pgpKey.getPgpKeyId());
        }

        this.secringFileLastModified = secringFileLastModified;
        this.pubringFileLastModified = pubringFileLastModified;
        this.pgpKeyFingerprint2pgpKey = pgpKeyFingerprint2pgpKey;
        this.pgpKeyId2pgpKey = pgpKeyId2pgpKey;
        this.pgpKeyId2masterKey = pgpKeyId2masterKey;

        assignSubKeys();
    }

    private void assignSubKeys()
    {
        for (final PgpKey masterKey : pgpKeyId2masterKey.values())
        {
            final Set<PgpKeyId> subKeyIds = masterKey.getSubKeyIds();
            final List<PgpKey> subKeys = new ArrayList<PgpKey>(subKeyIds.size());
            for (final PgpKeyId subKeyId : subKeyIds)
            {
                final PgpKey subKey = getPgpKeyOrFail(subKeyId);
                subKeys.add(subKey);
            }
            masterKey.setSubKeys(Collections.unmodifiableList(subKeys));
            masterKey.setSubKeyIds(Collections.unmodifiableSet(subKeyIds));
        }
    }

    private PgpKey enlistPublicKey(final Map<PgpKeyFingerprint, PgpKey> pgpKeyFingerprint2pgpKey,
            final Map<PgpKeyId, PgpKey> pgpKeyId2PgpKey,
            final Map<PgpKeyId, PgpKey> pgpKeyId2masterKey,
            PgpKey masterKey, final PGPKeyRing keyRing, final PGPPublicKey publicKey)
    {
        final PgpKeyId pgpKeyId = new PgpKeyId(publicKey.getKeyID());
        final PgpKeyFingerprint pgpKeyFingerprint = new PgpKeyFingerprint(publicKey.getFingerprint());

        PgpKey pgpKey = pgpKeyFingerprint2pgpKey.get(pgpKeyFingerprint);
        if (pgpKey == null)
        {
            pgpKey = new PgpKey(pgpKeyId, pgpKeyFingerprint);
            pgpKeyFingerprint2pgpKey.put(pgpKeyFingerprint, pgpKey);
            PgpKey old = pgpKeyId2PgpKey.put(pgpKeyId, pgpKey);
            if (old != null)
                throw new IllegalStateException(
                        String.format(
                                "PGP-key-ID collision! Two keys with different fingerprints have the same key-ID! keyId=%s fingerprint1=%s fingerprint2=%s",
                                pgpKeyId, old.getPgpKeyFingerprint(), pgpKey.getPgpKeyFingerprint()));
        }

        if (keyRing instanceof PGPSecretKeyRing)
            pgpKey.setSecretKeyRing((PGPSecretKeyRing) keyRing);
        else if (keyRing instanceof PGPPublicKeyRing)
            pgpKey.setPublicKeyRing((PGPPublicKeyRing) keyRing);
        else
            throw new IllegalArgumentException(
                    "keyRing is neither an instance of PGPSecretKeyRing nor PGPPublicKeyRing!");

        pgpKey.setPublicKey(publicKey);

        if (publicKey.isMasterKey())
        {
            masterKey = pgpKey;
            pgpKeyId2masterKey.put(pgpKey.getPgpKeyId(), pgpKey);
        }
        else
        {
            if (masterKey == null)
                throw new IllegalStateException("First key is a non-master key!");

            pgpKey.setMasterKey(masterKey);
            masterKey.getSubKeyIds().add(pgpKey.getPgpKeyId());
        }
        return masterKey;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.openpgp.wot.key.PgpKeyRegistry#getPgpKeyFingerprintsSignedBy(org.bouncycastle.openpgp.wot.key.PgpKeyFingerprint)
     */
    @Override
    public synchronized Set<PgpKeyFingerprint> getPgpKeyFingerprintsSignedBy(
            final PgpKeyFingerprint signingPgpKeyFingerprint)
    {
        assertNotNull("signingPgpKeyFingerprint", signingPgpKeyFingerprint);
        final PgpKey signingPgpKey = getPgpKey(signingPgpKeyFingerprint);
        if (signingPgpKey == null)
            return Collections.emptySet();

        final Set<PgpKeyId> pgpKeyIds = getSigningKeyId2signedKeyIds().get(signingPgpKey.getPgpKeyId());
        if (pgpKeyIds == null)
            return Collections.emptySet();

        final Set<PgpKeyFingerprint> result = new HashSet<>(pgpKeyIds.size());
        for (final PgpKeyId pgpKeyId : pgpKeyIds)
        {
            final PgpKey pgpKey = getPgpKeyOrFail(pgpKeyId);
            result.add(pgpKey.getPgpKeyFingerprint());
        }
        return Collections.unmodifiableSet(result);
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.openpgp.wot.key.PgpKeyRegistry#getPgpKeyIdsSignedBy(org.bouncycastle.openpgp.wot.key.PgpKeyId)
     */
    @Override
    public Set<PgpKeyId> getPgpKeyIdsSignedBy(final PgpKeyId signingPgpKeyId)
    {
        final Set<PgpKeyId> pgpKeyIds = getSigningKeyId2signedKeyIds().get(signingPgpKeyId);
        if (pgpKeyIds == null)
            return Collections.emptySet();

        return Collections.unmodifiableSet(pgpKeyIds);
    }

    protected synchronized Map<PgpKeyId, Set<PgpKeyId>> getSigningKeyId2signedKeyIds()
    {
        loadIfNeeded();
        if (signingKeyId2signedKeyIds == null)
        {
            final Map<PgpKeyId, Set<PgpKeyId>> m = new HashMap<>();
            for (final PgpKey pgpKey : pgpKeyId2pgpKey.values())
            {
                final PGPPublicKey publicKey = pgpKey.getPublicKey();
                for (final PgpUserId pgpUserId : pgpKey.getPgpUserIds())
                {
                    if (pgpUserId.getUserId() != null)
                    {
                        for (@SuppressWarnings("unchecked") final Iterator<?> it = nullToEmpty(publicKey.getSignaturesForID(pgpUserId.getUserId())); it.hasNext();)
                        {
                            final PGPSignature pgpSignature = (PGPSignature) it.next();
                            if (isCertification(pgpSignature))
                                enlistInSigningKey2signedKeyIds(m, pgpKey, pgpSignature);
                        }
                    } else if (pgpUserId.getUserAttribute() != null)
                    {
                        for (@SuppressWarnings("unchecked") final Iterator<?> it = nullToEmpty(publicKey.getSignaturesForUserAttribute(pgpUserId.getUserAttribute())); it.hasNext();)
                        {
                            final PGPSignature pgpSignature = (PGPSignature) it.next();
                            if (isCertification(pgpSignature))
                                enlistInSigningKey2signedKeyIds(m, pgpKey, pgpSignature);
                        }
                    } else
                        throw new IllegalStateException("WTF?!");
                }

                // It seems, there are both: certifications for individual
                // user-ids and certifications for the
                // entire key. I therefore first take the individual ones
                // (above) into account then and then
                // the ones for the entire key (below).
                // Normally, the signatures bound to the key are never
                // 'certifications', but it rarely happens.
                // Don't know, if these are malformed or deprecated (very old)
                // keys, but I should take them into account.
                for (@SuppressWarnings("unchecked") final Iterator<?> it = nullToEmpty(publicKey.getKeySignatures()); it.hasNext();)
                {
                    final PGPSignature pgpSignature = (PGPSignature) it.next();
                    if (isCertification(pgpSignature))
                        enlistInSigningKey2signedKeyIds(m, pgpKey, pgpSignature);
                }
            }
            signingKeyId2signedKeyIds = m;
        }
        return signingKeyId2signedKeyIds;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.openpgp.wot.key.PgpKeyRegistry#getSignatures(org.bouncycastle.openpgp.wot.key.PgpUserId)
     */
    @Override
    public synchronized List<PGPSignature> getSignatures(final PgpUserId pgpUserId)
    {
        assertNotNull("pgpUserId", pgpUserId);
        final PGPPublicKey publicKey = pgpUserId.getPgpKey().getPublicKey();

        final IdentityHashMap<PGPSignature, PGPSignature> pgpSignatures = new IdentityHashMap<>();

        final List<PGPSignature> result = new ArrayList<>();
        if (pgpUserId.getUserId() != null)
        {
            for (@SuppressWarnings("unchecked") final Iterator<?> it = nullToEmpty(publicKey.getSignaturesForID(pgpUserId.getUserId())); it.hasNext();)
            {
                final PGPSignature pgpSignature = (PGPSignature) it.next();
                if (!pgpSignatures.containsKey(pgpSignature) && isCertification(pgpSignature))
                {
                    pgpSignatures.put(pgpSignature, pgpSignature);
                    result.add(pgpSignature);
                }
            }
        }
        else if (pgpUserId.getUserAttribute() != null)
        {
            for (@SuppressWarnings("unchecked") final Iterator<?> it = nullToEmpty(publicKey.getSignaturesForUserAttribute(pgpUserId.getUserAttribute())); it.hasNext();)
            {
                final PGPSignature pgpSignature = (PGPSignature) it.next();
                if (!pgpSignatures.containsKey(pgpSignature) && isCertification(pgpSignature))
                {
                    pgpSignatures.put(pgpSignature, pgpSignature);
                    result.add(pgpSignature);
                }
            }
        }
        else
            throw new IllegalStateException("WTF?!");

        // There are also key-signatures which are not for a certain indivdual user-id/-attribute, but for the entire key.
        // See the comment in getSigningKeyId2signedKeyIds() above for more details.
        for (@SuppressWarnings("unchecked") final Iterator<?> it = nullToEmpty(publicKey.getKeySignatures()); it.hasNext();)
        {
            final PGPSignature pgpSignature = (PGPSignature) it.next();
            if (!pgpSignatures.containsKey(pgpSignature) && isCertification(pgpSignature))
            {
                pgpSignatures.put(pgpSignature, pgpSignature);
                result.add(pgpSignature);
            }
        }

        return result;
    }

    protected static <E> Iterator<E> nullToEmpty(final Iterator<E> iterator)
    {
        if (iterator == null)
            return Collections.<E> emptyList().iterator();
        else
            return iterator;
    }

    private void enlistInSigningKey2signedKeyIds(final Map<PgpKeyId, Set<PgpKeyId>> signingKeyId2signedKeyIds,
            final PgpKey pgpKey, final PGPSignature pgpSignature)
    {
        final PgpKeyId signingPgpKeyId = new PgpKeyId(pgpSignature.getKeyID());
        Set<PgpKeyId> signedKeyIds = signingKeyId2signedKeyIds.get(signingPgpKeyId);
        if (signedKeyIds == null)
        {
            signedKeyIds = new HashSet<>();
            signingKeyId2signedKeyIds.put(signingPgpKeyId, signedKeyIds);
        }
        signedKeyIds.add(pgpKey.getPgpKeyId());
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.openpgp.wot.key.PgpKeyRegistry#isCertification(org.bouncycastle.openpgp.PGPSignature)
     */
    @Override
    public boolean isCertification(final PGPSignature pgpSignature)
    {
        assertNotNull("pgpSignature", pgpSignature);
        return isCertification(pgpSignature.getSignatureType());
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.openpgp.wot.key.PgpKeyRegistry#isCertification(int)
     */
    @Override
    public boolean isCertification(int pgpSignatureType)
    {
        return PGPSignature.DEFAULT_CERTIFICATION == pgpSignatureType
                || PGPSignature.NO_CERTIFICATION == pgpSignatureType
                || PGPSignature.CASUAL_CERTIFICATION == pgpSignatureType
                || PGPSignature.POSITIVE_CERTIFICATION == pgpSignatureType;
    }
}
