package org.bouncycastle.jcajce.provider.test;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class ECKeyAgreementDomainValidationTest extends TestCase {
    protected void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected void tearDown() {
        Security.removeProvider("BC");
    }

    /**
     * Same curve should succeed.
     */
    public void testSameCurveAgreement()
            throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");

        kpg.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();

        KeyAgreement ka1 = KeyAgreement.getInstance("ECDH", "BC");
        KeyAgreement ka2 = KeyAgreement.getInstance("ECDH", "BC");

        ka1.init(kp1.getPrivate());
        ka1.doPhase(kp2.getPublic(), true);

        ka2.init(kp2.getPrivate());
        ka2.doPhase(kp1.getPublic(), true);

        byte[] s1 = ka1.generateSecret();
        byte[] s2 = ka2.generateSecret();

        assertTrue(java.util.Arrays.equals(s1, s2));
    }

    /**
     * Different curves should fail due to domain parameter mismatch.
     */
    public void testDifferentCurveAgreement()
            throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");

        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp256 = kpg.generateKeyPair();

        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair kp384 = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");

        try {
            ka.init(kp256.getPrivate());
            ka.doPhase(kp384.getPublic(), true);

            fail("Expected InvalidKeyException for mismatched EC domain parameters");
        } catch (java.security.InvalidKeyException e) {
            // expected
        }
    }
}