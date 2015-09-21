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
 * Registry providing fast access to the keys of a public and a secret key ring collection.
 * <p>
 * An {@code PgpKeyRegistry} reads the {@code pubring.gpg} and {@code secring.gpg} (normally located in
 * {@code ~/.gnupg/}) and organizes them in {@link PgpKey} instances. It then provides fast lookup by key-id or
 * fingerprint via {@link #getPgpKey(PgpKeyId)} or {@link #getPgpKey(PgpKeyFingerprint)}.
 * <p>
 * The {@code PgpKeyRegistry} tracks the timestamps of the key ring collection files. If one of the files changes, i.e.
 * the timestamp changes, the files are re-loaded. But beware: The file system's timestamps usually have a pretty bad
 * resolution (of 1 or even 2 seconds). Therefore, it may happen that a modification goes undetected, if multiple
 * changes occur within the resolution.
 *
 * @author Marco หงุ่ยตระกูล-Schulze - marco at codewizards dot co
 */
public class PgpKeyRegistry
{
    private static final Logger logger = LoggerFactory.getLogger(PgpKeyRegistry.class);

    private final File pubringFile;
    private final File secringFile;

    private long pubringFileLastModified = Long.MIN_VALUE;
    private long secringFileLastModified = Long.MIN_VALUE;

    private Map<PgpKeyFingerprint, PgpKey> pgpKeyFingerprint2pgpKey; // all keys
    private Map<PgpKeyId, PgpKey> pgpKeyId2pgpKey; // all keys
    private Map<PgpKeyId, PgpKey> pgpKeyId2masterKey; // only master-keys

    private Map<PgpKeyId, Set<PgpKeyId>> signingKeyId2signedKeyIds;

    /**
     * Creates an instance of {@code PgpKeyRegistry} with the given public and secret key ring collection files.
     *
     * @param pubringFile
     *            the file containing the public keys - usually named {@code pubring.gpg} (located in {@code ~/.gnupg/}
     *            ). Must not be <code>null</code>. The file does not need to exist, though.
     * @param secringFile
     *            the file containing the secret keys - usually named {@code secring.gpg} (located in {@code ~/.gnupg/}
     *            ). Must not be <code>null</code>. The file does not need to exist, though.
     */
    public PgpKeyRegistry(File pubringFile, File secringFile)
    {
        this.pubringFile = assertNotNull("pubringFile", pubringFile);
        this.secringFile = assertNotNull("secringFile", secringFile);
    }

    /**
     * Gets the file containing the public keys - usually named {@code pubring.gpg} (located in {@code ~/.gnupg/}).
     *
     * @return the file containing the public keys. Never <code>null</code>.
     */
    public File getPubringFile()
    {
        return pubringFile;
    }

    /**
     * Gets the file containing the secret keys - usually named {@code secring.gpg} (located in {@code ~/.gnupg/}).
     *
     * @return the file containing the secret keys. Never <code>null</code>.
     */
    public File getSecringFile()
    {
        return secringFile;
    }

    /**
     * Gets the key with the given ID. If no such key exists, an {@link IllegalArgumentException} is thrown.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyId
     *            the key's ID. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyId}. Never <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyId} is <code>null</code> or there is no key known with this ID.
     */
    public PgpKey getPgpKeyOrFail(final PgpKeyId pgpKeyId) throws IllegalArgumentException
    {
        final PgpKey pgpKey = getPgpKey(pgpKeyId);
        if (pgpKey == null)
            throw new IllegalArgumentException("No PGP key found for this keyId: " + pgpKeyId);

        return pgpKey;
    }

    /**
     * Gets the key with the given ID. If no such key exists, <code>null</code> is returned.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyId
     *            the key's ID. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyId}. May be <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyId} is <code>null</code>.
     */
    public synchronized PgpKey getPgpKey(final PgpKeyId pgpKeyId) throws IllegalArgumentException
    {
        assertNotNull("pgpKeyId", pgpKeyId);
        loadIfNeeded();
        final PgpKey pgpKey = pgpKeyId2pgpKey.get(pgpKeyId);
        return pgpKey;
    }

    /**
     * Gets the key with the given fingerprint. If no such key exists, an {@link IllegalArgumentException} is thrown.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyFingerprint
     *            the key's fingerprint. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyFingerprint}. Never <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyFingerprint} is <code>null</code> or there is no key known with this
     *             fingerprint.
     */
    public PgpKey getPgpKeyOrFail(final PgpKeyFingerprint pgpKeyFingerprint) throws IllegalArgumentException
    {
        final PgpKey pgpKey = getPgpKey(pgpKeyFingerprint);
        if (pgpKey == null)
            throw new IllegalArgumentException("No PGP key found for this fingerprint: " + pgpKeyFingerprint);

        return pgpKey;
    }

    /**
     * Gets the key with the given fingerprint. If no such key exists, <code>null</code> is returned.
     * <p>
     * It makes no difference to this method whether the key is a master-key or a sub-key.
     *
     * @param pgpKeyFingerprint
     *            the key's fingerprint. Must not be <code>null</code>.
     * @return the key identified by the given {@code pgpKeyFingerprint}. May be <code>null</code>.
     * @throws IllegalArgumentException
     *             if the given {@code pgpKeyFingerprint} is <code>null</code>.
     */
    public synchronized PgpKey getPgpKey(final PgpKeyFingerprint pgpKeyFingerprint) throws IllegalArgumentException
    {
        assertNotNull("pgpKeyFingerprint", pgpKeyFingerprint);
        loadIfNeeded();
        final PgpKey pgpKey = pgpKeyFingerprint2pgpKey.get(pgpKeyFingerprint);
        return pgpKey;
    }

    /**
     * Gets all master-keys. Their sub-keys are accessible via {@link PgpKey#getSubKeys()}.
     *
     * @return all master-keys. Never <code>null</code>.
     */
    public synchronized Collection<PgpKey> getMasterKeys()
    {
        loadIfNeeded();
        return Collections.unmodifiableCollection(pgpKeyId2masterKey.values());
    }

    /**
     * Marks this registry stale - causing it to reload at the next read access.
     * <p>
     * If a modification of a key ring file happens, this modification is usually detected automatically, rendering this
     * registry stale implicitly. However, a change is not reliably detected, because the file system's timestamp
     * resolution is usually 1 second or even worse. Multiple changes within this resolution might thus go undetected.
     * In order to make sure that a key ring file modification reliably causes this registry to reload, this method can
     * be invoked.
     */
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

    /**
     * Gets all those keys' fingerprints whose keys were signed (certified) by the key identified by the given
     * fingerprint.
     * <p>
     * Usually, the fingerprint specified should identify a master-key and usually only master-key-fingerprints are
     * returned by this method.
     *
     * @param signingPgpKeyFingerprint
     *            the fingerprint of the key having signed all those keys that we're interested in. Must not be
     *            <code>null</code>.
     * @return the fingerprints of all those keys which have been signed (certified) by the key identified by
     *         {@code signingPgpKeyFingerprint}. Never <code>null</code>, but maybe empty.
     */
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

    /**
     * Gets all those keys' IDs whose keys were signed (certified) by the key identified by the given ID.
     * <p>
     * Usually, the ID specified should identify a master-key and usually only master-key-IDs are returned by this
     * method.
     *
     * @param signingPgpKeyId
     *            the ID of the key having signed all those keys that we're interested in. Must not be <code>null</code>
     *            .
     * @return the IDs of all those keys which have been signed (certified) by the key identified by
     *         {@code signingPgpKeyId}. Never <code>null</code>, but maybe empty.
     */
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

    /**
     * Gets the signatures certifying the authenticity of the given user-ID.
     *
     * @param pgpUserId
     *            the user-ID whose certifications should be returned. Must not be <code>null</code>.
     * @return the certifications authenticating the given {@code pgpUserId}. Never <code>null</code>. Because every
     *         user-ID is normally at least signed by the owning key, it is normally never empty, too.
     */
    @SuppressWarnings("unchecked")
    public synchronized List<PGPSignature> getSignatures(final PgpUserId pgpUserId)
    {
        assertNotNull("pgpUserId", pgpUserId);
        final PGPPublicKey publicKey = pgpUserId.getPgpKey().getPublicKey();

        final IdentityHashMap<PGPSignature, PGPSignature> pgpSignatures = new IdentityHashMap<>();

        final List<PGPSignature> result = new ArrayList<>();
        if (pgpUserId.getUserId() != null)
        {
            for (final Iterator<?> it = nullToEmpty(publicKey.getSignaturesForID(pgpUserId.getUserId())); it.hasNext();)
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
            for (final Iterator<?> it = nullToEmpty(publicKey.getSignaturesForUserAttribute(pgpUserId
                    .getUserAttribute())); it.hasNext();)
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
        for (final Iterator<?> it = nullToEmpty(publicKey.getKeySignatures()); it.hasNext();)
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

    /**
     * Determines whether the given signature is a certification.
     * <p>
     * A certification is a signature indicating that a certain key or user-identity is authentic.
     *
     * @param pgpSignature
     *            the signature to be checked. Must not be <code>null</code>.
     * @return <code>true</code>, if the signature is a certification; <code>false</code>, if it is of a different type.
     * @see #isCertification(int)
     */
    public boolean isCertification(final PGPSignature pgpSignature)
    {
        assertNotNull("pgpSignature", pgpSignature);
        return isCertification(pgpSignature.getSignatureType());
    }

    /**
     * Determines whether the given signature-type indicates a certification.
     * <p>
     * A certification is a signature indicating that a certain key or user-identity is authentic.
     *
     * @param pgpSignatureType
     *            the type of the signature - like {@link PGPSignature#DEFAULT_CERTIFICATION} or other constants (used
     *            by the property {@link PGPSignature#getSignatureType()}, for example).
     * @return <code>true</code>, if the given signature-type means certification; <code>false</code> otherwise.
     * @see #isCertification(PGPSignature)
     */
    public boolean isCertification(int pgpSignatureType)
    {
        return PGPSignature.DEFAULT_CERTIFICATION == pgpSignatureType
                || PGPSignature.NO_CERTIFICATION == pgpSignatureType
                || PGPSignature.CASUAL_CERTIFICATION == pgpSignatureType
                || PGPSignature.POSITIVE_CERTIFICATION == pgpSignatureType;
    }
}
