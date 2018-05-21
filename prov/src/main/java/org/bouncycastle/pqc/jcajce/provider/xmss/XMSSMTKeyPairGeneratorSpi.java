package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.security.InvalidAlgorithmParameterException;
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
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
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

        engine.init(param);
        initialised = true;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            param = new XMSSMTKeyGenerationParameters(new XMSSMTParameters(10, 20, new SHA512Digest()), random);

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        XMSSMTPublicKeyParameters pub = (XMSSMTPublicKeyParameters)pair.getPublic();
        XMSSMTPrivateKeyParameters priv = (XMSSMTPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCXMSSMTPublicKey(treeDigest, pub), new BCXMSSMTPrivateKey(treeDigest, priv));
    }
}
