package org.bouncycastle.openpgp.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

/**
 * Regression test for github #1230. JcaPGPKeyConverter.getPublicKey was throwing
 * InvalidParameterSpecException ("Not a supported curve") on JDK 11+ when the
 * underlying provider was Sun's because the converter was passing the X9.62
 * OID-encoded form to AlgorithmParameters, which Sun's CurveDB doesn't recognise.
 * The fix routes through the curve name first and falls back to the OID encoding
 * only if the provider doesn't know the name.
 */
public class JcaECDSAKeyConverterTest
    extends AbstractPacketTest
{
    public String getName()
    {
        return "JcaECDSAKeyConverter";
    }

    public void performTest()
        throws Exception
    {
        roundTripWithBcProvider();
        roundTripWithSunProvider();
    }

    private void roundTripWithBcProvider()
        throws Exception
    {
        Provider bc = new BouncyCastleProvider();
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(bc);
        }

        KeyPair kp = generateP256KeyPair(bc);
        PGPKeyPair pgpKp = new JcaPGPKeyPair(
            PublicKeyAlgorithmTags.ECDSA, kp, new Date());

        PublicKey converted = new JcaPGPKeyConverter().setProvider(bc).getPublicKey(pgpKp.getPublicKey());

        signAndVerify(kp.getPrivate(), converted, bc);
    }

    private void roundTripWithSunProvider()
        throws Exception
    {
        Provider bc = new BouncyCastleProvider();
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(bc);
        }

        Provider sunEc = Security.getProvider("SunEC");
        if (sunEc == null)
        {
            // Some JDK distributions don't ship SunEC; nothing to verify.
            return;
        }

        // Generate the key with BC so the keypair is independent of the
        // provider being exercised in the converter.
        KeyPair kp = generateP256KeyPair(bc);
        PGPKeyPair pgpKp = new JcaPGPKeyPair(
            PublicKeyAlgorithmTags.ECDSA, kp, new Date());

        PublicKey converted = new JcaPGPKeyConverter().setProvider(sunEc).getPublicKey(pgpKp.getPublicKey());
        isTrue("converted key was null", converted != null);
        isTrue("expected ECDSA / EC algorithm",
            "EC".equals(converted.getAlgorithm()) || "ECDSA".equals(converted.getAlgorithm()));

        // Sign with the BC private key and verify with the SunEC-converted public key.
        signAndVerify(kp.getPrivate(), converted, sunEc);
    }

    private KeyPair generateP256KeyPair(Provider provider)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
        kpg.initialize(new ECNamedCurveGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private void signAndVerify(java.security.PrivateKey priv, PublicKey pub, Provider verifyProvider)
        throws Exception
    {
        byte[] msg = "the quick brown fox".getBytes();

        Signature sig = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        sig.initSign(priv);
        sig.update(msg);
        byte[] sigBytes = sig.sign();

        Signature ver = Signature.getInstance("SHA256withECDSA", verifyProvider);
        ver.initVerify(pub);
        ver.update(msg);
        isTrue("signature verification failed under " + verifyProvider.getName(), ver.verify(sigBytes));
    }

    public static void main(String[] args)
    {
        runTest(new JcaECDSAKeyConverterTest());
    }
}
