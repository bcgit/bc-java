package org.bouncycastle.jcajce.provider.util.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.util.SecretKeyUtil;

public class SecretKeyUtilTest extends TestCase {

    public void testgetKeySize() {
        assertEquals(192, SecretKeyUtil.getKeySize(PKCSObjectIdentifiers.des_EDE3_CBC));
    }
}