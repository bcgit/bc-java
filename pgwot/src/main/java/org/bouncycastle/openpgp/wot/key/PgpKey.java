package org.bouncycastle.openpgp.wot.key;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;

/**
 * OpenPGP key or key pair (if both public and secret key are present).
 *
 * @author Marco หงุ่ยตระกูล-Schulze - marco at codewizards dot co
 */
public class PgpKey
{
    private final PgpKeyId pgpKeyId;

    private final PgpKeyFingerprint pgpKeyFingerprint;

    private PGPPublicKeyRing publicKeyRing;

    private PGPSecretKeyRing secretKeyRing;

    private PGPPublicKey publicKey;

    private PGPSecretKey secretKey;

    private PgpKey masterKey;

    // A sub-key may be added twice, because we enlist from both the secret *and* public key ring
    // collection. Therefore, we now use a LinkedHashSet (instead of an ArrayList).
    private Set<PgpKeyId> subKeyIds;

    private List<PgpKey> subKeys;

    private List<PgpUserId> pgpUserIds;

    public PgpKey(final PgpKeyId pgpKeyId, final PgpKeyFingerprint pgpKeyFingerprint)
    {
        this.pgpKeyId = assertNotNull("pgpKeyId", pgpKeyId);
        this.pgpKeyFingerprint = assertNotNull("pgpKeyFingerprint", pgpKeyFingerprint);
    }

    public PgpKeyId getPgpKeyId()
    {
        return pgpKeyId;
    }

    public PgpKeyFingerprint getPgpKeyFingerprint()
    {
        return pgpKeyFingerprint;
    }

    public PGPPublicKeyRing getPublicKeyRing()
    {
        return publicKeyRing;
    }

    protected void setPublicKeyRing(PGPPublicKeyRing publicKeyRing)
    {
        this.publicKeyRing = publicKeyRing;
    }

    public PGPSecretKeyRing getSecretKeyRing()
    {
        return secretKeyRing;
    }

    protected void setSecretKeyRing(PGPSecretKeyRing secretKeyRing)
    {
        this.secretKeyRing = secretKeyRing;
    }

    public PGPPublicKey getPublicKey()
    {
        return publicKey;
    }

    protected void setPublicKey(final PGPPublicKey publicKey)
    {
        this.publicKey = publicKey;
    }

    public PGPSecretKey getSecretKey()
    {
        return secretKey;
    }

    protected void setSecretKey(final PGPSecretKey secretKey)
    {
        this.secretKey = secretKey;
    }

    public List<PgpUserId> getPgpUserIds()
    {
        if (pgpUserIds == null)
        {
            final List<PgpUserId> l = new ArrayList<>();

            for (final Iterator<?> it = publicKey.getUserIDs(); it.hasNext();)
            {
                final String userId = (String) it.next();
                l.add(new PgpUserId(this, userId));
            }

            for (final Iterator<?> it = publicKey.getUserAttributes(); it.hasNext();)
            {
                final PGPUserAttributeSubpacketVector userAttribute = (PGPUserAttributeSubpacketVector) it.next();
                l.add(new PgpUserId(this, userAttribute));
            }
            pgpUserIds = Collections.unmodifiableList(l);
        }
        return pgpUserIds;
    }

    /**
     * Gets the master-key for this key.
     *
     * @return the master-key for this key. Always <code>null</code>, if this is a master-key. Never <code>null</code>,
     *         if this is a sub-key.
     * @see #getSubKeyIds()
     * @see #getSubKeys()
     */
    public PgpKey getMasterKey()
    {
        return masterKey;
    }

    protected void setMasterKey(PgpKey masterKey)
    {
        this.masterKey = masterKey;
    }

    public Set<PgpKeyId> getSubKeyIds()
    {
        if (subKeyIds == null && masterKey == null) // only a master-key can have sub-keys! hence we keep it null, if
                                                    // this is not a master-key!
            subKeyIds = new LinkedHashSet<>();

        return subKeyIds;
    }

    protected void setSubKeyIds(Set<PgpKeyId> subKeyIds)
    {
        this.subKeyIds = subKeyIds;
    }

    /**
     * Gets the sub-keys.
     *
     * @return the sub-keys. Never <code>null</code>, if this is a master-key. Always <code>null</code>, if this is a
     *         sub-key.
     * @see #getMasterKey()
     * @see #getSubKeyIds()
     */
    public List<PgpKey> getSubKeys()
    {
        return subKeys;
    }

    protected void setSubKeys(List<PgpKey> subKeys)
    {
        this.subKeys = subKeys;
    }

    @Override
    public String toString()
    {
        final Iterator<?> userIdIt = publicKey.getUserIDs();
        final String primaryUserId;
        if (userIdIt == null || !userIdIt.hasNext())
            primaryUserId = null;
        else
            primaryUserId = (String) userIdIt.next();

        return String.format("%s[pgpKeyId=%s masterKey=%s primaryUserId=%s]", this.getClass().getSimpleName(),
                pgpKeyId, masterKey, primaryUserId);
    }
}
