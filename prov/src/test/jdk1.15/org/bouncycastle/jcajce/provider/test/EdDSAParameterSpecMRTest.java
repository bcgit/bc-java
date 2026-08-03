package org.bouncycastle.jcajce.provider.test;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Exercise the standard JDK 15+ java.security.spec.EdDSAParameterSpec bridging and the
 * third-party key fallback against the multi-release jar - behaviour that historically lived
 * in the (since removed) jdk1.15 overlay copies of SignatureSpi / AlgorithmParametersSpi and
 * drifted from the base tree.
 */
public class EdDSAParameterSpecMRTest
    extends TestCase
{
    private static final String BC = "BC";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public void testSignatureAcceptsJdkParameterSpec()
        throws Exception
    {
        byte[] msg = Hex.decode("deadbeef");
        byte[] ctx = Hex.decode("f00f");

        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", BC).generateKeyPair();

        Signature signer = Signature.getInstance("Ed25519", BC);
        signer.setParameter(new java.security.spec.EdDSAParameterSpec(false, ctx));
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        // a verifier configured through the BC spec must accept the same instance selectors.
        Signature verifier = Signature.getInstance("Ed25519", BC);
        verifier.setParameter(new org.bouncycastle.jcajce.spec.EdDSAParameterSpec("Ed25519", false, ctx));
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);

        assertTrue("JDK spec signature not verified by BC spec verifier", verifier.verify(sig));

        // and the parameters must round trip out through the JDK spec class as well.
        AlgorithmParameters algParams = signer.getParameters();
        java.security.spec.EdDSAParameterSpec jdkSpec =
            algParams.getParameterSpec(java.security.spec.EdDSAParameterSpec.class);

        assertFalse(jdkSpec.isPrehash());
        assertTrue(jdkSpec.getContext().isPresent());
        assertTrue(Arrays.areEqual(ctx, jdkSpec.getContext().get()));
    }

    public void testAlgorithmParametersInitWithJdkSpec()
        throws Exception
    {
        byte[] ctx = Hex.decode("0badf00d");

        AlgorithmParameters algParams = AlgorithmParameters.getInstance("Ed448", BC);
        algParams.init(new java.security.spec.EdDSAParameterSpec(true, ctx));

        org.bouncycastle.jcajce.spec.EdDSAParameterSpec bcSpec =
            algParams.getParameterSpec(org.bouncycastle.jcajce.spec.EdDSAParameterSpec.class);

        assertEquals("Ed448", bcSpec.getCurveName());
        assertTrue(bcSpec.isPrehash());
        assertTrue(Arrays.areEqual(ctx, bcSpec.getContext()));

        java.security.spec.EdDSAParameterSpec jdkSpec =
            algParams.getParameterSpec(java.security.spec.EdDSAParameterSpec.class);

        assertTrue(jdkSpec.isPrehash());
        assertTrue(jdkSpec.getContext().isPresent());
        assertTrue(Arrays.areEqual(ctx, jdkSpec.getContext().get()));
    }

    public void testForeignProviderKeyFallback()
        throws Exception
    {
        byte[] msg = Hex.decode("deadbeef");

        KeyPair kp = KeyPairGenerator.getInstance("Ed25519", BC).generateKeyPair();

        // a key from another provider exposes nothing but its encoding - the signature must
        // fall back to decoding it, as it does on JDK 8.
        Signature signer = Signature.getInstance("Ed25519", BC);
        signer.initSign(new ForeignPrivateKey(kp.getPrivate()));
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("Ed25519", BC);
        verifier.initVerify(new ForeignPublicKey(kp.getPublic()));
        verifier.update(msg);

        assertTrue("foreign key signature not verified", verifier.verify(sig));
    }

    private static class ForeignPrivateKey
        implements PrivateKey
    {
        private final PrivateKey delegate;

        ForeignPrivateKey(PrivateKey delegate)
        {
            this.delegate = delegate;
        }

        public String getAlgorithm()
        {
            return delegate.getAlgorithm();
        }

        public String getFormat()
        {
            return delegate.getFormat();
        }

        public byte[] getEncoded()
        {
            return delegate.getEncoded();
        }
    }

    private static class ForeignPublicKey
        implements PublicKey
    {
        private final PublicKey delegate;

        ForeignPublicKey(PublicKey delegate)
        {
            this.delegate = delegate;
        }

        public String getAlgorithm()
        {
            return delegate.getAlgorithm();
        }

        public String getFormat()
        {
            return delegate.getFormat();
        }

        public byte[] getEncoded()
        {
            return delegate.getEncoded();
        }
    }
}
