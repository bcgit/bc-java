package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

public class XMSSMTKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private XMSSMTKeyGenerationParameters param;
    private XMSSMTKeyPairGenerator engine = new XMSSMTKeyPairGenerator();
    private ASN1ObjectIdentifier treeDigest;

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public XMSSMTKeyPairGeneratorSpi()
    {
        super("XMSSMT");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        // what the JCA specifies here; it extends IllegalArgumentException, so catches still match
        throw new InvalidParameterException("use AlgorithmParameterSpec");
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof XMSSMTParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a XMSSMTParameterSpec");
        }

        XMSSMTParameterSpec xmssParams = (XMSSMTParameterSpec)params;

        if (xmssParams.getTreeDigest().equals(XMSSParameterSpec.SHA256))
        {
            treeDigest = NISTObjectIdentifiers.id_sha256;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHA256Digest()), random);
        }
        else if (xmssParams.getTreeDigest().equals(XMSSParameterSpec.SHA512))
        {
            treeDigest = NISTObjectIdentifiers.id_sha512;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHA512Digest()), random);
        }
        else if (xmssParams.getTreeDigest().equals(XMSSParameterSpec.SHAKE128))
        {
            treeDigest = NISTObjectIdentifiers.id_shake128;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHAKEDigest(128)), random);
        }
        else if (xmssParams.getTreeDigest().equals(XMSSParameterSpec.SHAKE256))
        {
            treeDigest = NISTObjectIdentifiers.id_shake256;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), new SHAKEDigest(256)), random);
        }
        else if (xmssParams.getTreeDigest().equals(XMSSParameterSpec.SHA256_192))
        {
            treeDigest = NISTObjectIdentifiers.id_sha256;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), NISTObjectIdentifiers.id_sha256, 24), random);
        }
        else if (xmssParams.getTreeDigest().equals(XMSSParameterSpec.SHAKE256_256))
        {
            treeDigest = NISTObjectIdentifiers.id_shake256_len;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), NISTObjectIdentifiers.id_shake256_len, 32), random);
        }
        else if (xmssParams.getTreeDigest().equals(XMSSParameterSpec.SHAKE256_192))
        {
            treeDigest = NISTObjectIdentifiers.id_shake256_len;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), NISTObjectIdentifiers.id_shake256_len, 24), random);
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown tree digest: " + xmssParams.getTreeDigest());
        }

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            // XMSSMT-SHA2_20/2_512 (RFC 8391 sec. 5.4) - the layer count has to divide the total
            // height, so the (10, 20) this used to default to was not a constructible parameter
            // set at all. The tree digest has to be set here too, or the key returned has none.
            treeDigest = NISTObjectIdentifiers.id_sha512;
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(20, 2, new SHA512Digest()), random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        XMSSMTPublicKeyParameters pub = (XMSSMTPublicKeyParameters)pair.getPublic();
        XMSSMTPrivateKeyParameters priv = (XMSSMTPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCXMSSMTPublicKey(treeDigest, pub), new BCXMSSMTPrivateKey(treeDigest, priv));
    }
}
