package org.bouncycastle.crypto.signers;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.slhdsa.SLHDSAEngine;
import org.bouncycastle.pqc.crypto.DigestUtils;

/**
 * SLH-DSA signer.
 */
public class HashSLHDSASigner
    implements Signer
{
    private byte[] msgPrefix;
    private byte[] optRand;
    private SLHDSAPublicKeyParameters pubKey;
    private SLHDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private Digest digest;

    private byte[] pkSeed, pkRoot, skSeed, skPrf;

    public HashSLHDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        ParametersWithContext withContext = null;
        if (param instanceof ParametersWithContext)
        {
            withContext = (ParametersWithContext)param;
            param = ((ParametersWithContext)param).getParameters();

            if (withContext.getContextLength() > 255)
            {
                throw new IllegalArgumentException("context too long");
            }
        }

        SLHDSAParameters parameters;
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                privKey = ((SLHDSAPrivateKeyParameters)((ParametersWithRandom)param).getParameters());
                random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (SLHDSAPrivateKeyParameters)param;
                random = null;
            }

            parameters = privKey.getParameters();

            skSeed = privKey.getSeed();
            skPrf = privKey.getPrf();
            pkSeed = privKey.getPublicSeed();
            pkRoot = privKey.getRoot();

            // generate randomizer
            optRand = new byte[parameters.getN()];
        }
        else
        {
            pubKey = (SLHDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

            skSeed = null;
            skPrf = null;
            pkSeed = pubKey.getSeed();
            pkRoot = pubKey.getRoot();

            parameters = pubKey.getParameters();
        }

        initDigest(parameters, withContext);
    }

    private void initDigest(SLHDSAParameters parameters, ParametersWithContext withContext)
    {
        digest = createDigest(parameters);

        ASN1ObjectIdentifier digestOID = DigestUtils.getDigestOid(digest.getAlgorithmName());

        // TODO[asn1] Encode this into the message prefix directly?
        byte[] digestOIDEncoding;
        try
        {
            digestOIDEncoding = digestOID.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("oid encoding failed: " + e.getMessage());
        }

        int ctxLength = withContext == null ? 0 : withContext.getContextLength();

        msgPrefix = new byte[2 + ctxLength + digestOIDEncoding.length];
        msgPrefix[0] = 1;
        msgPrefix[1] = (byte)ctxLength;
        if (withContext != null)
        {
            withContext.copyContextTo(msgPrefix, 2, ctxLength);
        }
        System.arraycopy(digestOIDEncoding, 0, msgPrefix, 2 + ctxLength, digestOIDEncoding.length);
    }

    public void update(byte b)
    {
        digest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    public byte[] generateSignature() throws CryptoException, DataLengthException
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        if (random != null)
        {
            random.nextBytes(optRand);
        }
        else
        {
            System.arraycopy(privKey.getPublicSeed(), 0, optRand, 0, optRand.length);
        }

        return SLHDSAEngine.internalGenerateSignature(privKey.getParameters(), skSeed, skPrf, pkSeed, pkRoot, msgPrefix, hash, optRand);
    }

    public boolean verifySignature(byte[] signature)
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return SLHDSAEngine.internalVerifySignature(pubKey.getParameters(), pkSeed, pkRoot, msgPrefix, hash, signature);
    }

    public void reset()
    {
        digest.reset();
    }

    protected byte[] internalGenerateSignature(byte[] message, byte[] optRand)
    {
        return SLHDSAEngine.internalGenerateSignature(privKey.getParameters(), skSeed, skPrf, pkSeed, pkRoot, null, message, optRand);
    }

    protected boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        return SLHDSAEngine.internalVerifySignature(pubKey.getParameters(), pkSeed, pkRoot, null, message, signature);
    }

    private static Digest createDigest(SLHDSAParameters parameters)
    {
        switch (parameters.getType())
        {
        case SLHDSAParameters.TYPE_PURE:
            String name = parameters.getName();
            if (name.startsWith("sha2"))
            {
                if (SLHDSAParameters.sha2_128f == parameters
                    || SLHDSAParameters.sha2_128s == parameters)
                {
                    return SHA256Digest.newInstance();
                }
                else
                {
                    return new SHA512Digest();
                }
            }
            else
            {
                if (SLHDSAParameters.shake_128f == parameters
                    || SLHDSAParameters.shake_128s == parameters)
                {
                    return new SHAKEDigest(128);
                }
                else
                {
                    return new SHAKEDigest(256);
                }
            }
        case SLHDSAParameters.TYPE_SHA2_256:
            return SHA256Digest.newInstance();
        case SLHDSAParameters.TYPE_SHA2_512:
            return new SHA512Digest();
        case SLHDSAParameters.TYPE_SHAKE128:
            return new SHAKEDigest(128);
        case SLHDSAParameters.TYPE_SHAKE256:
            return new SHAKEDigest(256);
        default:
            throw new IllegalArgumentException("unknown parameters type");
        }
    }
}

