package org.bouncycastle.openpgp.wot.key;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;

/**
 * User-identity or user-attribute of an OpenPGP key.
 */
public class PgpUserId
{
    private final PgpKey pgpKey;
    private final String userId;
    private final PGPUserAttributeSubpacketVector userAttribute;
    private volatile PgpUserIdNameHash nameHash;

    public PgpUserId(final PgpKey pgpKey, final String userId)
    {
        this.pgpKey = assertNotNull("pgpKey", pgpKey);
        this.userId = assertNotNull("userId", userId);
        this.userAttribute = null;
    }

    public PgpUserId(final PgpKey pgpKey, final PGPUserAttributeSubpacketVector userAttribute)
    {
        this.pgpKey = assertNotNull("pgpKey", pgpKey);
        this.userId = null;
        this.userAttribute = assertNotNull("userAttribute", userAttribute);
    }

    public PgpKey getPgpKey()
    {
        return pgpKey;
    }

    public String getUserId()
    {
        return userId;
    }

    public PGPUserAttributeSubpacketVector getUserAttribute()
    {
        return userAttribute;
    }

    // namehash_from_uid (PKT_user_id *uid) from keyid.c
    public PgpUserIdNameHash getNameHash()
    {
        if (nameHash == null)
        {
            if (userId != null)
                nameHash = PgpUserIdNameHash.createFromUserId(userId);
            else
                nameHash = PgpUserIdNameHash.createFromUserAttribute(userAttribute);
        }
        return nameHash;
    }

    @Override
    public String toString()
    {
        return String.format("%s[pgpKeyId=%s userId=%s userAttribute=%s]",
                this.getClass().getSimpleName(), getPgpKey().getPgpKeyId(), userId, userAttribute);
    }
}
