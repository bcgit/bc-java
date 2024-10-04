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
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private SLHDSAPrivateKeyParameters privKey;
    private SLHDSAPublicKeyParameters pubKey;
    private byte[] ctx;
    private SecureRandom random;
    private Digest digest;
    private byte[] digestOidEncoding;

    public HashSLHDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (param instanceof ParametersWithContext)
        {
            ctx = ((ParametersWithContext)param).getContext();
            param = ((ParametersWithContext)param).getParameters();

            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("context too long");
            }
        }
        else
        {
            ctx = EMPTY_CONTEXT;
        }

        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                privKey = ((SLHDSAPrivateKeyParameters)((ParametersWithRandom)param).getParameters());
                this.random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (SLHDSAPrivateKeyParameters)param;
            }

            initDigest(privKey);
        }
        else
        {
            pubKey = (SLHDSAPublicKeyParameters)param;
            
            initDigest(pubKey);
        }

        reset();
    }

    private void initDigest(SLHDSAKeyParameters key)
    {
        digest = createDigest(key);

        ASN1ObjectIdentifier oid = DigestUtils.getDigestOid(digest.getAlgorithmName());
        try
        {
            digestOidEncoding = oid.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("oid encoding failed: " + e.getMessage());
        }
    }

    @Override
    public void update(byte b)
    {
        digest.update(b);
    }

    @Override
    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    @Override
    public byte[] generateSignature() throws CryptoException, DataLengthException
    {
        SLHDSAEngine engine = privKey.getParameters().getEngine();

        engine.init(privKey.pk.seed);

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        byte[] ds_message = new byte[1 + 1 + ctx.length + digestOidEncoding.length + hash.length];
        ds_message[0] = 1;
        ds_message[1] = (byte)ctx.length;
        System.arraycopy(ctx, 0, ds_message, 2, ctx.length);
        System.arraycopy(digestOidEncoding, 0, ds_message, 2 + ctx.length, digestOidEncoding.length);
        System.arraycopy(hash, 0, ds_message, 2 + ctx.length + digestOidEncoding.length, hash.length);

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
        return internalGenerateSignature(ds_message, optRand);
    }

    @Override
    public boolean verifySignature(byte[] signature)
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        byte[] ds_message = new byte[1 + 1 + ctx.length + digestOidEncoding.length + hash.length];
        ds_message[0] = 1;
        ds_message[1] = (byte)ctx.length;
        System.arraycopy(ctx, 0, ds_message, 2, ctx.length);
        System.arraycopy(digestOidEncoding, 0, ds_message, 2 + ctx.length, digestOidEncoding.length);
        System.arraycopy(hash, 0, ds_message, 2 + ctx.length + digestOidEncoding.length, hash.length);

        return internalVerifySignature(ds_message, signature);
    }

    @Override
    public void reset()
    {
        digest.reset();
    }

    public byte[] internalGenerateSignature(byte[] message, byte[] optRand)
    {
        SLHDSAEngine engine = privKey.getParameters().getEngine();
        engine.init(privKey.pk.seed);

        Fors fors = new Fors(engine);
        byte[] R = engine.PRF_msg(privKey.sk.prf, optRand, message);

        IndexedDigest idxDigest = engine.H_msg(R, privKey.pk.seed, privKey.pk.root, message);
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

    public boolean internalVerifySignature(byte[] message, byte[] signature)
    {
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
        IndexedDigest idxDigest = engine.H_msg(R, pubKey.getSeed(), pubKey.getRoot(), message);
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

    private static Digest createDigest(SLHDSAKeyParameters key)
    {
        int type = key.getParameters().getType();

        switch (type)
        {
        case SLHDSAParameters.TYPE_PURE:
            String name = key.getParameters().getName();
            if (name.startsWith("sha2"))
            {
                if (SLHDSAParameters.sha2_128f == key.parameters
                    || SLHDSAParameters.sha2_128s == key.parameters)
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
                if (SLHDSAParameters.shake_128f == key.parameters
                    || SLHDSAParameters.shake_128s == key.parameters)
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

