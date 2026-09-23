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
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.params.XMSSPrivateKeyParameters;
import org.bouncycastle.crypto.params.XMSSPublicKeyParameters;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.XMSSParameterSpec;

public class XMSSKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private XMSSKeyGenerationParameters param;
    private ASN1ObjectIdentifier treeDigest;
    private XMSSKeyPairGenerator engine = new XMSSKeyPairGenerator();

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public XMSSKeyPairGeneratorSpi()
    {
        super("XMSS");
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
        if (!(params instanceof XMSSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("parameter object not a XMSSParameterSpec");
        }

        XMSSParameterSpec xmssParams = (XMSSParameterSpec)params;

        // the name to OID and n table is DigestUtil's, shared with XMSSMTKeyPairGeneratorSpi,
        // which had a copy of these seven branches differing only in the parameter set class built
        // below
        DigestUtil.TreeDigest digest = DigestUtil.getTreeDigest(xmssParams.getTreeDigest());

        // built before either field is written. XMSSParameters refuses a height outside
        // [2, MAX_HEIGHT] with an unchecked IllegalArgumentException, and an assignment ahead of
        // that left this generator naming the tree digest of the parameter set it had just failed
        // to build while the engine went on holding the one an earlier initialize succeeded with -
        // so the next generateKeyPair(), legal because of that earlier call, labelled its key with
        // a digest nothing had generated it under. The refusal is reported as the
        // InvalidAlgorithmParameterException this method declares, which is what getTreeDigest one
        // line above already throws for a tree digest name it does not know.
        XMSSKeyGenerationParameters generationParams;

        try
        {
            generationParams = new XMSSKeyGenerationParameters(
                new XMSSParameters(xmssParams.getHeight(), digest.getOID(), digest.getN()), random);
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
            // the tree digest has to be set here as well, otherwise the key returned carries none
            // and its equals()/hashCode()/getTreeDigest() fail on it. Built before either field is
            // written, as initialize() builds it: the parameter set here is a constant and cannot
            // be refused, so this changes nothing today, and that is exactly what makes the order
            // worth having - the two initialisation paths hold the same invariant by construction
            // rather than one of them holding it by arithmetic a later edit could change.
            XMSSKeyGenerationParameters generationParams = new XMSSKeyGenerationParameters(
                new XMSSParameters(10, new SHA512Digest()), random);

            treeDigest = NISTObjectIdentifiers.id_sha512;
            param = generationParams;

            engine.init(param);
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        XMSSPublicKeyParameters pub = (XMSSPublicKeyParameters)pair.getPublic();
        XMSSPrivateKeyParameters priv = (XMSSPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCXMSSPublicKey(treeDigest, pub), new BCXMSSPrivateKey(treeDigest, priv));
    }
}
