package org.bouncycastle.cms;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

interface CMSAuthEnvelopedGenerator
{
    public static final String AES128_CCM = NISTObjectIdentifiers.id_aes128_CCM.getId();
    public static final String AES192_CCM = NISTObjectIdentifiers.id_aes192_CCM.getId();
    public static final String AES256_CCM = NISTObjectIdentifiers.id_aes256_CCM.getId();
    public static final String AES128_GCM = NISTObjectIdentifiers.id_aes128_GCM.getId();
    public static final String AES192_GCM = NISTObjectIdentifiers.id_aes192_GCM.getId();
    public static final String AES256_GCM = NISTObjectIdentifiers.id_aes256_GCM.getId();
}
