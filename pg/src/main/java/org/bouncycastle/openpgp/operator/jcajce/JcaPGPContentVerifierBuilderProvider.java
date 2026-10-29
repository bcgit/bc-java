package org.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.bcpg.MLDSACompositePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SLHDSAPublicBCPGKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;

public class JcaPGPContentVerifierBuilderProvider
    implements PGPContentVerifierBuilderProvider
{
    private OperatorHelper helper = OperatorUtils.createDefaultHelper();
    private JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

    public JcaPGPContentVerifierBuilderProvider()
    {
    }

    public JcaPGPContentVerifierBuilderProvider setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);
        keyConverter.setProvider(provider);
        digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaPGPContentVerifierBuilderProvider setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);
        keyConverter.setProvider(providerName);
        digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm)
        throws PGPException
    {
        return new JcaPGPContentVerifierBuilder(keyAlgorithm, hashAlgorithm);
    }

    private class JcaPGPContentVerifierBuilder
        implements PGPContentVerifierBuilder
    {
        private int hashAlgorithm;
        private int keyAlgorithm;

        public JcaPGPContentVerifierBuilder(int keyAlgorithm, int hashAlgorithm)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }

        public PGPContentVerifier build(final PGPPublicKey publicKey)
            throws PGPException
        {
            if (PublicKeyUtils.isPQCAlgorithm(keyAlgorithm))
            {
                return buildPQCVerifier(publicKey);
            }

            final PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
            final PublicKey jcaKey = keyConverter.getPublicKey(publicKey);

            final Signature signature;
            if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY && jcaKey.getAlgorithm().equals("Ed448"))
            {
                signature = helper.createSignature(PublicKeyAlgorithmTags.Ed448, hashAlgorithm);
            }
            else
            {
                signature = helper.createSignature(keyAlgorithm, hashAlgorithm);
            }

            try
            {
                signature.initVerify(jcaKey);
            }
            catch (InvalidKeyException e)
            {
                throw new PGPException("invalid key.", e);
            }

            return new PGPContentVerifier()
            {
                private final boolean isEdDsa = keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY || keyAlgorithm == PublicKeyAlgorithmTags.Ed448 || keyAlgorithm == PublicKeyAlgorithmTags.Ed25519;

                public int getHashAlgorithm()
                {
                    return hashAlgorithm;
                }

                public int getKeyAlgorithm()
                {
                    return keyAlgorithm;
                }

                public long getKeyID()
                {
                    return publicKey.getKeyID();
                }

                public boolean verify(byte[] expected)
                {
                    try
                    {
                        // an RSA PGP signature is stored as an MPI, this can occasionally result in a short
                        // signature if there is a leading zero.
                        if (jcaKey instanceof RSAPublicKey)
                        {
                            int modLength = (((RSAPublicKey)jcaKey).getModulus().bitLength() + 7) / 8;
                            if (expected.length < modLength)
                            {
                                byte[] tmp = new byte[modLength];

                                System.arraycopy(expected, 0, tmp, tmp.length - expected.length, expected.length);

                                return signature.verify(tmp);
                            }
                        }
                        if (isEdDsa)
                        {
                            signature.update(digestCalculator.getDigest());

                            return signature.verify(expected);
                        }
                        return signature.verify(expected);
                    }
                    catch (SignatureException e)
                    {
                        throw new PGPRuntimeOperationException("unable to verify signature: " + e.getMessage(), e);
                    }
                }

                public OutputStream getOutputStream()
                {
                    if (isEdDsa)
                    {
                        return digestCalculator.getOutputStream();
                    }
                    return OutputStreamFactory.createStream(signature);
                }
            };
        }

        /**
         * RFC 9980 sec. 5.2.3 and 6.1.3: the message digest (RFC 9580 sec. 5.2.4) is verified with each
         * component signature, and a composite signature is valid only if both the EdDSA and the ML-DSA
         * signature verify. A digest of fewer than 256 bits MUST be rejected (sec. 5.3.1, 6.2.1).
         */
        private PGPContentVerifier buildPQCVerifier(final PGPPublicKey publicKey)
            throws PGPException
        {
            final PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
            OperatorUtils.checkPQCSignatureDigest(keyAlgorithm, hashAlgorithm, digestCalculator);
            final PublicKey jcaKey = keyConverter.getPublicKey(publicKey);

            final Signature[] signatures;
            final int[] signatureLengths;
            try
            {
                if (PublicKeyUtils.isMLDSACompositeAlgorithm(keyAlgorithm))
                {
                    if (!(jcaKey instanceof CompositePublicKey) || ((CompositePublicKey)jcaKey).getPublicKeys().size() != 2)
                    {
                        throw new PGPException("public key algorithm " + keyAlgorithm + " requires a CompositePublicKey of two component keys");
                    }
                    CompositePublicKey comp = (CompositePublicKey)jcaKey;
                    signatures = new Signature[]{
                        helper.createSignature(keyAlgorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519 ? "Ed25519" : "Ed448"),
                        helper.createSignature("ML-DSA")
                    };
                    signatures[0].initVerify(comp.getPublicKeys().get(0));
                    signatures[1].initVerify(comp.getPublicKeys().get(1));
                    signatureLengths = new int[]{
                        MLDSACompositePublicBCPGKey.getEdDSASignatureLength(keyAlgorithm),
                        MLDSACompositePublicBCPGKey.getMLDSASignatureLength(keyAlgorithm)
                    };
                }
                else
                {
                    signatures = new Signature[]{ helper.createSignature("SLH-DSA") };
                    signatures[0].initVerify(jcaKey);
                    signatureLengths = new int[]{ SLHDSAPublicBCPGKey.getSignatureLength(keyAlgorithm) };
                }
            }
            catch (InvalidKeyException e)
            {
                throw new PGPException("invalid key.", e);
            }

            return new PGPContentVerifier()
            {
                public int getHashAlgorithm()
                {
                    return hashAlgorithm;
                }

                public int getKeyAlgorithm()
                {
                    return keyAlgorithm;
                }

                public long getKeyID()
                {
                    return publicKey.getKeyID();
                }

                public boolean verify(byte[] expected)
                {
                    byte[] dataDigest = digestCalculator.getDigest();
                    int total = 0;
                    for (int i = 0; i != signatureLengths.length; i++)
                    {
                        total += signatureLengths[i];
                    }
                    if (expected.length != total)
                    {
                        return false;
                    }
                    try
                    {
                        boolean valid = true;
                        int off = 0;
                        for (int i = 0; i != signatures.length; i++)
                        {
                            signatures[i].update(dataDigest);
                            // every component MUST verify (RFC 9980 sec. 5.2.3)
                            valid &= signatures[i].verify(Arrays.copyOfRange(expected, off, off + signatureLengths[i]));
                            off += signatureLengths[i];
                        }
                        return valid;
                    }
                    catch (SignatureException e)
                    {
                        throw new PGPRuntimeOperationException("unable to verify signature: " + e.getMessage(), e);
                    }
                }

                public OutputStream getOutputStream()
                {
                    return digestCalculator.getOutputStream();
                }
            };
        }
    }
}
