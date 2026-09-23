package org.bouncycastle.jcajce.provider.asymmetric.xmss;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.XMSSMTKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSMTKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSMTPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSMTPublicKeyParameters;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.XMSSMTParameterSpec;

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

        // as XMSSKeyPairGeneratorSpi: one table in DigestUtil, and the parameter set class built
        // from it is the only thing that differed between the two copies
        DigestUtil.TreeDigest digest = DigestUtil.getTreeDigest(xmssParams.getTreeDigest());

        // as XMSSKeyPairGeneratorSpi: built before either field is written, and the parameter
        // set's unchecked refusals - a total height outside [2, MAX_HEIGHT], a layer count that
        // does not divide it, a single-leaf subtree - reported as the
        // InvalidAlgorithmParameterException this method declares.
        XMSSMTKeyGenerationParameters generationParams;

        try
        {
            generationParams = new XMSSMTKeyGenerationParameters(
                new XMSSMTParameters(xmssParams.getHeight(), xmssParams.getLayers(), digest.getOID(),
                    digest.getN()), random);
        }
        catch (IllegalArgumentException e)
        {
            throw SecurityExceptions.invalidAlgorithmParameterException(e.getMessage(), e);
        }

        treeDigest = digest.getOID();
        param = generationParams;

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
            // Built before either field is written, as initialize() builds it: the parameter set
            // here is a constant and cannot be refused, so this changes nothing today, and that is
            // exactly what makes the order worth having - the two initialisation paths hold the
            // same invariant by construction rather than one of them holding it by arithmetic a
            // later edit could change, which is what the (10, 20) above was.
            XMSSMTKeyGenerationParameters generationParams = new XMSSMTKeyGenerationParameters(
                new XMSSMTParameters(20, 2, new SHA512Digest()), random);

            treeDigest = NISTObjectIdentifiers.id_sha512;
            param = generationParams;

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        XMSSMTPublicKeyParameters pub = (XMSSMTPublicKeyParameters)pair.getPublic();
        XMSSMTPrivateKeyParameters priv = (XMSSMTPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCXMSSMTPublicKey(treeDigest, pub), new BCXMSSMTPrivateKey(treeDigest, priv));
    }
}
