package org.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.bcpg.MLDSACompositePublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.SLHDSAPublicBCPGKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeOutputStream;

public class JcaPGPContentSignerBuilder
    implements PGPContentSignerBuilder
{
    private OperatorHelper helper = OperatorUtils.createDefaultHelper();
    private JcaPGPDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
    private int hashAlgorithm;
    private SecureRandom random;
    private int keyAlgorithm;

    public JcaPGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm)
    {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public JcaPGPContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public JcaPGPContentSignerBuilder setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);
        keyConverter.setProvider(provider);
        digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaPGPContentSignerBuilder setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);
        keyConverter.setProvider(providerName);
        digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public JcaPGPContentSignerBuilder setDigestProvider(Provider provider)
    {
        digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaPGPContentSignerBuilder setDigestProvider(String providerName)
    {
        digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public PGPContentSigner build(final int signatureType, PGPPrivateKey privateKey)
        throws PGPException
    {
        if (privateKey instanceof JcaPGPPrivateKey)
        {
            return build(signatureType, privateKey.getKeyID(), ((JcaPGPPrivateKey)privateKey).getPrivateKey());
        }
        else
        {
            return build(signatureType, privateKey.getKeyID(), keyConverter.getPrivateKey(privateKey));
        }
    }

    public PGPContentSigner build(final int signatureType, final long keyID, final PrivateKey privateKey)
        throws PGPException
    {
        if (PublicKeyUtils.isPQCAlgorithm(keyAlgorithm))
        {
            return buildPQCSigner(signatureType, keyID, privateKey);
        }

        final PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
        final PGPDigestCalculator edDigestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
        final Signature signature;

        if (keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY && privateKey.getAlgorithm().equals("Ed448"))
        {
            signature = helper.createSignature("Ed448");
        }
        else
        {
            signature = helper.createSignature(keyAlgorithm, hashAlgorithm);
        }


        try
        {
            if (random != null)
            {
                signature.initSign(privateKey, random);
            }
            else
            {
                signature.initSign(privateKey);
            }
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("invalid key.", e);
        }

        return new PGPContentSigner()
        {
            private final boolean isEdDsa = keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY || keyAlgorithm == PublicKeyAlgorithmTags.Ed448 || keyAlgorithm == PublicKeyAlgorithmTags.Ed25519;

            public int getType()
            {
                return signatureType;
            }

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
                return keyID;
            }

            public OutputStream getOutputStream()
            {
                if (isEdDsa)
                {
                    return new TeeOutputStream(edDigestCalculator.getOutputStream(), digestCalculator.getOutputStream());
                }
                return new TeeOutputStream(OutputStreamFactory.createStream(signature), digestCalculator.getOutputStream());
            }

            public byte[] getSignature()
            {
                try
                {
                    if (isEdDsa)
                    {
                        signature.update(edDigestCalculator.getDigest());
                    }
                    return signature.sign();
                }
                catch (SignatureException e)
                {
                    throw new PGPRuntimeOperationException("Unable to create signature: " + e.getMessage(), e);
                }
            }

            public byte[] getDigest()
            {
                return digestCalculator.getDigest();
            }
        };
    }

    /**
     * RFC 9980 sec. 5.2.2 and 6.1.2: the message digest (RFC 9580 sec. 5.2.4) is signed with the component
     * signature algorithms - PureEdDSA (RFC 8032, empty context) and the hedged pure ML-DSA (FIPS 204, empty
     * context) for the composites, the hedged pure slh_sign (FIPS 205, empty context) for SLH-DSA - and the
     * composite signature is the EdDSA signature followed by the ML-DSA signature. The digest MUST be at
     * least 256 bits (sec. 5.3.1, 6.2.1).
     */
    private PGPContentSigner buildPQCSigner(final int signatureType, final long keyID, PrivateKey privateKey)
        throws PGPException
    {
        final PGPDigestCalculator digestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
        final PGPDigestCalculator dataDigestCalculator = digestCalculatorProviderBuilder.build().get(hashAlgorithm);
        OperatorUtils.checkPQCSignatureDigest(keyAlgorithm, hashAlgorithm, digestCalculator);

        final Signature[] signatures;
        final int[] signatureLengths;
        try
        {
            // RFC 9980 sec. 5.1.2 / 6.1.2: the hedged variants
            SecureRandom hedge = random != null ? random : CryptoServicesRegistrar.getSecureRandom();
            if (PublicKeyUtils.isMLDSACompositeAlgorithm(keyAlgorithm))
            {
                if (!(privateKey instanceof CompositePrivateKey) || ((CompositePrivateKey)privateKey).getPrivateKeys().size() != 2)
                {
                    throw new PGPException("public key algorithm " + keyAlgorithm + " requires a CompositePrivateKey of two component keys");
                }
                CompositePrivateKey comp = (CompositePrivateKey)privateKey;
                signatures = new Signature[]{
                    helper.createSignature(keyAlgorithm == PublicKeyAlgorithmTags.MLDSA65_Ed25519 ? "Ed25519" : "Ed448"),
                    helper.createSignature("ML-DSA")
                };
                signatures[0].initSign(comp.getPrivateKeys().get(0), hedge);
                signatures[1].initSign(comp.getPrivateKeys().get(1), hedge);
                signatureLengths = new int[]{
                    MLDSACompositePublicBCPGKey.getEdDSASignatureLength(keyAlgorithm),
                    MLDSACompositePublicBCPGKey.getMLDSASignatureLength(keyAlgorithm)
                };
            }
            else
            {
                signatures = new Signature[]{ helper.createSignature("SLH-DSA") };
                signatures[0].initSign(privateKey, hedge);
                signatureLengths = new int[]{ SLHDSAPublicBCPGKey.getSignatureLength(keyAlgorithm) };
            }
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("invalid key.", e);
        }

        return new PGPContentSigner()
        {
            public int getType()
            {
                return signatureType;
            }

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
                return keyID;
            }

            public OutputStream getOutputStream()
            {
                return new TeeOutputStream(dataDigestCalculator.getOutputStream(), digestCalculator.getOutputStream());
            }

            public byte[] getSignature()
            {
                try
                {
                    byte[] dataDigest = dataDigestCalculator.getDigest();
                    byte[] result = new byte[0];
                    for (int i = 0; i != signatures.length; i++)
                    {
                        signatures[i].update(dataDigest);
                        byte[] sig = signatures[i].sign();
                        if (sig.length != signatureLengths[i])
                        {
                            throw new IllegalStateException("unexpected component signature length: " + sig.length);
                        }
                        result = Arrays.concatenate(result, sig);
                    }
                    return result;
                }
                catch (SignatureException e)
                {
                    throw new PGPRuntimeOperationException("Unable to create signature: " + e.getMessage(), e);
                }
            }

            public byte[] getDigest()
            {
                return digestCalculator.getDigest();
            }
        };
    }
}
