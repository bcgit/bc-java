package org.bouncycastle.jcajce.provider.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.util.SecretKeyUtil;

public class SecretKeyUtilTest
    extends TestCase
{
    public void testgetKeySize()
    {
        assertEquals(192, SecretKeyUtil.getKeySize(PKCSObjectIdentifiers.des_EDE3_CBC));

        assertEquals(128, SecretKeyUtil.getKeySize(NISTObjectIdentifiers.id_aes128_CBC));
        assertEquals(192, SecretKeyUtil.getKeySize(NISTObjectIdentifiers.id_aes192_CBC));
        assertEquals(256, SecretKeyUtil.getKeySize(NISTObjectIdentifiers.id_aes256_CBC));

        assertEquals(128, SecretKeyUtil.getKeySize(NTTObjectIdentifiers.id_camellia128_cbc));
        assertEquals(192, SecretKeyUtil.getKeySize(NTTObjectIdentifiers.id_camellia192_cbc));
        assertEquals(256, SecretKeyUtil.getKeySize(NTTObjectIdentifiers.id_camellia256_cbc));
    }
}
