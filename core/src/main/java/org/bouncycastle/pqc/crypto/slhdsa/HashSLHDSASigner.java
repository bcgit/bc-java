package org.bouncycastle.pqc.crypto.slhdsa;

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
import org.bouncycastle.pqc.crypto.DigestUtils;
import org.bouncycastle.util.Arrays;

/**
 * SLH-DA signer.
 */
public class HashSLHDSASigner
    implements Signer
{
    private byte[] msgPrefix;
    private SLHDSAPublicKeyParameters pubKey;
    private SLHDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private Digest digest;

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
        }
        else
        {
            pubKey = (SLHDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

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
        // TODO Redundant with the engine created in internalGenerateSignature
        SLHDSAEngine engine = privKey.getParameters().getEngine();

        engine.init(privKey.pk.seed);

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        // generate randomizer
        byte[] optRand = new byte[engine.N];
        if (random != null)
        {
            random.nextBytes(optRand);
        }
        else
        {
            System.arraycopy(privKey.pk.seed, 0, optRand, 0, optRand.length);
        }

        return internalGenerateSignature(privKey, msgPrefix, hash, optRand);
    }

    public boolean verifySignature(byte[] signature)
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return internalVerifySignature(pubKey, msgPrefix, hash, signature);
    }

    public void reset()
    {
        digest.reset();
    }

    protected byte[] internalGenerateSignature(byte[] message, byte[] optRand)
    {
        return internalGenerateSignature(privKey, null, message, optRand);
    }

    private static byte[] internalGenerateSignature(SLHDSAPrivateKeyParameters privKey, byte[] msgPrefix, byte[] msg,
        byte[] optRand)
    {
        // TODO Check init via privKey != null

        SLHDSAEngine engine = privKey.getParameters().getEngine();
        engine.init(privKey.pk.seed);

        Fors fors = new Fors(engine);
        byte[] R = engine.PRF_msg(privKey.sk.prf, optRand, msgPrefix, msg);

        IndexedDigest idxDigest = engine.H_msg(R, privKey.pk.seed, privKey.pk.root, msgPrefix, msg);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;
        // FORS sign
        ADRS adrs = new ADRS();
        adrs.setTypeAndClear(ADRS.FORS_TREE);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        SIG_FORS[] sig_fors = fors.sign(mHash, privKey.sk.seed, privKey.pk.seed, adrs);
        // get FORS public key - spec shows M?
        adrs = new ADRS();
        adrs.setTypeAndClear(ADRS.FORS_TREE);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        byte[] PK_FORS = fors.pkFromSig(sig_fors, mHash, privKey.pk.seed, adrs);

        // sign FORS public key with HT
        ADRS treeAdrs = new ADRS();
        treeAdrs.setTypeAndClear(ADRS.TREE);

        HT ht = new HT(engine, privKey.getSeed(), privKey.getPublicSeed());
        byte[] SIG_HT = ht.sign(PK_FORS, idx_tree, idx_leaf);

        byte[][] sigComponents = new byte[sig_fors.length + 2][];
        sigComponents[0] = R;

        for (int i = 0; i != sig_fors.length; i++)
        {
            sigComponents[1 + i] = Arrays.concatenate(sig_fors[i].sk, Arrays.concatenate(sig_fors[i].authPath));
        }
        sigComponents[sigComponents.length - 1] = SIG_HT;

        return Arrays.concatenate(sigComponents);
    }

    protected boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        return internalVerifySignature(pubKey, null, message, signature);
    }

    private static boolean internalVerifySignature(SLHDSAPublicKeyParameters pubKey, byte[] msgPrefix, byte[] msg,
        byte[] signature)
    {
        // TODO Check init via pubKey != null

        //# Input: Message M, signature SIG, public key PK
        //# Output: Boolean

        // init
        SLHDSAEngine engine = pubKey.getParameters().getEngine();

        engine.init(pubKey.getSeed());

        ADRS adrs = new ADRS();

        if (((1 + engine.K * (1 + engine.A) + engine.H + engine.D *engine.WOTS_LEN)* engine.N) != signature.length)
        {
            return false;
        }

        SIG sig = new SIG(engine.N, engine.K, engine.A, engine.D, engine.H_PRIME, engine.WOTS_LEN, signature);

        byte[] R = sig.getR();
        SIG_FORS[] sig_fors = sig.getSIG_FORS();
        SIG_XMSS[] SIG_HT = sig.getSIG_HT();

        // compute message digest and index
        IndexedDigest idxDigest = engine.H_msg(R, pubKey.getSeed(), pubKey.getRoot(), msgPrefix, msg);
        byte[] mHash = idxDigest.digest;
        long idx_tree = idxDigest.idx_tree;
        int idx_leaf = idxDigest.idx_leaf;

        // compute FORS public key
        adrs.setTypeAndClear(ADRS.FORS_TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        byte[] PK_FORS = new Fors(engine).pkFromSig(sig_fors, mHash, pubKey.getSeed(), adrs);
        // verify HT signature
        adrs.setTypeAndClear(ADRS.TREE);
        adrs.setLayerAddress(0);
        adrs.setTreeAddress(idx_tree);
        adrs.setKeyPairAddress(idx_leaf);
        HT ht = new HT(engine, null, pubKey.getSeed());
        return ht.verify(PK_FORS, SIG_HT, pubKey.getSeed(), idx_tree, idx_leaf, pubKey.getRoot());
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

