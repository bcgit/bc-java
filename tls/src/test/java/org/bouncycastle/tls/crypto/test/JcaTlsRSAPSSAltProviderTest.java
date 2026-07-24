package org.bouncycastle.tls.crypto.test;

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRSAPSSSigner;
import org.bouncycastle.util.Strings;

/**
 * Regression test for RSA-PSS CertificateVerify generation when the private key is held by an
 * alternate provider that registers only the generic "RSASSA-PSS" signature name and takes the
 * digest from a PSSParameterSpec - the shape of SunMSCAPI (Windows smart card keys) since JDK 13.
 */
public class JcaTlsRSAPSSAltProviderTest
    extends TestCase
{
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    public void testRSAPSSSignatureWithGenericPSSOnlyAltProvider()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", BC);
        kpGen.initialize(2048, new SecureRandom());
        KeyPair kp = kpGen.generateKeyPair();

        JcaTlsCrypto crypto = new JcaTlsCryptoProvider()
            .setProvider(BC)
            .setAlternateProvider(new GenericPSSOnlyProvider())
            .create(new SecureRandom());

        implTestSignatureScheme(crypto, kp, SignatureScheme.rsa_pss_rsae_sha256, "SHA256withRSAandMGF1");
        implTestSignatureScheme(crypto, kp, SignatureScheme.rsa_pss_rsae_sha384, "SHA384withRSAandMGF1");
        implTestSignatureScheme(crypto, kp, SignatureScheme.rsa_pss_rsae_sha512, "SHA512withRSAandMGF1");
    }

    private void implTestSignatureScheme(JcaTlsCrypto crypto, KeyPair kp, int signatureScheme, String verifyAlgorithm)
        throws Exception
    {
        PrivateKey opaqueKey = new OpaquePrivateKey(kp.getPrivate());

        JcaTlsRSAPSSSigner signer = new JcaTlsRSAPSSSigner(crypto, opaqueKey, signatureScheme);

        TlsStreamSigner streamSigner = signer.getStreamSigner(
            SignatureScheme.getSignatureAndHashAlgorithm(signatureScheme));

        byte[] message = Strings.toByteArray("RSA-PSS via generic-name-only alternate provider");

        OutputStream sOut = streamSigner.getOutputStream();
        sOut.write(message, 0, message.length);
        sOut.close();

        byte[] signature = streamSigner.getSignature();

        Signature verifier = Signature.getInstance(verifyAlgorithm, BC);
        verifier.initVerify(kp.getPublic());
        verifier.update(message, 0, message.length);

        assertTrue(SignatureScheme.getText(signatureScheme), verifier.verify(signature));
    }

    /**
     * Mimics SunMSCAPI: the only registered signature is the generic "RSASSA-PSS", the digest must
     * be supplied via setParameter, and only the provider's own (opaque) key type is accepted.
     */
    public static class GenericPSSOnlyProvider
        extends Provider
    {
        GenericPSSOnlyProvider()
        {
            super("GenericPSSOnly", 1.0, "signs with the generic RSASSA-PSS algorithm name only");

            put("Signature.RSASSA-PSS", GenericPSSSignatureSpi.class.getName());
        }
    }

    static class OpaquePrivateKey
        implements PrivateKey
    {
        final PrivateKey inner;

        OpaquePrivateKey(PrivateKey inner)
        {
            this.inner = inner;
        }

        public String getAlgorithm()
        {
            return inner.getAlgorithm();
        }

        public String getFormat()
        {
            return null;
        }

        public byte[] getEncoded()
        {
            return null;
        }
    }

    public static class GenericPSSSignatureSpi
        extends SignatureSpi
    {
        private final Signature delegate;
        private boolean parameterSet = false;

        public GenericPSSSignatureSpi()
            throws Exception
        {
            this.delegate = Signature.getInstance("RSASSA-PSS", BC);
        }

        protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException
        {
            if (!(privateKey instanceof OpaquePrivateKey))
            {
                throw new InvalidKeyException("key type not supported by this provider");
            }

            delegate.initSign(((OpaquePrivateKey)privateKey).inner);
        }

        protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException
        {
            if (!(privateKey instanceof OpaquePrivateKey))
            {
                throw new InvalidKeyException("key type not supported by this provider");
            }

            delegate.initSign(((OpaquePrivateKey)privateKey).inner, random);
        }

        protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException
        {
            delegate.initVerify(publicKey);
        }

        protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException
        {
            delegate.setParameter(params);
            parameterSet = true;
        }

        protected void engineUpdate(byte b)
            throws SignatureException
        {
            checkParameterSet();
            delegate.update(b);
        }

        protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException
        {
            checkParameterSet();
            delegate.update(b, off, len);
        }

        protected byte[] engineSign()
            throws SignatureException
        {
            checkParameterSet();
            return delegate.sign();
        }

        protected boolean engineVerify(byte[] sigBytes)
            throws SignatureException
        {
            checkParameterSet();
            return delegate.verify(sigBytes);
        }

        protected void engineSetParameter(String param, Object value)
        {
            throw new UnsupportedOperationException("engineSetParameter unsupported");
        }

        protected Object engineGetParameter(String param)
        {
            throw new UnsupportedOperationException("engineGetParameter unsupported");
        }

        private void checkParameterSet()
            throws SignatureException
        {
            // like SunMSCAPI, the generic algorithm has no default digest
            if (!parameterSet)
            {
                throw new SignatureException("parameters required for RSASSA-PSS signature");
            }
        }
    }
}
