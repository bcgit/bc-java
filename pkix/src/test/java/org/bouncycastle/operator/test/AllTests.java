package org.bouncycastle.operator.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.util.encoders.Hex;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String TEST_DATA_HOME = "bc.test.data.home";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testAlgorithmNameFinder()
        throws Exception
    {
        AlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();

        assertTrue(nameFinder.hasAlgorithmName(OIWObjectIdentifiers.elGamalAlgorithm));
        assertFalse(nameFinder.hasAlgorithmName(Extension.authorityKeyIdentifier));

        assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers.elGamalAlgorithm), "ELGAMAL");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.rsaEncryption), "RSA");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.id_RSAES_OAEP), "RSAOAEP");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.md5), "MD5");
        assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers.idSHA1), "SHA1");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha224), "SHA224");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha256), "SHA256");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha384), "SHA384");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha512), "SHA512");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha512WithRSAEncryption), "SHA512WITHRSA");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.id_RSASSA_PSS), "RSAPSS");
        assertEquals(nameFinder.getAlgorithmName(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160), "RIPEMD160WITHRSA");
        assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, DERNull.INSTANCE)), "ELGAMAL");
        assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)), "RSA");

        assertEquals(nameFinder.getAlgorithmName(Extension.authorityKeyIdentifier), Extension.authorityKeyIdentifier.getId());
    }

    public void testOaepWrap()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(2048);

        KeyPair kp = kGen.generateKeyPair();

        checkAlgorithmId(kp, "SHA-1", OIWObjectIdentifiers.idSHA1);
        checkAlgorithmId(kp, "SHA-224", NISTObjectIdentifiers.id_sha224);
        checkAlgorithmId(kp, "SHA-256", NISTObjectIdentifiers.id_sha256);
        checkAlgorithmId(kp, "SHA-384", NISTObjectIdentifiers.id_sha384);
        checkAlgorithmId(kp, "SHA-512", NISTObjectIdentifiers.id_sha512);
        checkAlgorithmId(kp, "SHA-512/224", NISTObjectIdentifiers.id_sha512_224);
        checkAlgorithmId(kp, "SHA-512/256", NISTObjectIdentifiers.id_sha512_256);
        checkAlgorithmId(kp, "SHA-512(224)", NISTObjectIdentifiers.id_sha512_224);
        checkAlgorithmId(kp, "SHA-512(256)", NISTObjectIdentifiers.id_sha512_256);
    }

    private void checkAlgorithmId(KeyPair kp, String digest, ASN1ObjectIdentifier digestOid)
    {
        JceAsymmetricKeyWrapper wrapper = new JceAsymmetricKeyWrapper(
            new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), new PSource.PSpecified(Hex.decode("beef"))),
            kp.getPublic()).setProvider(BC);

        Assert.assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, wrapper.getAlgorithmIdentifier().getAlgorithm());
        RSAESOAEPparams oaepParams = RSAESOAEPparams.getInstance(wrapper.getAlgorithmIdentifier().getParameters());
        Assert.assertEquals(digestOid, oaepParams.getHashAlgorithm().getAlgorithm());
        Assert.assertEquals(PKCSObjectIdentifiers.id_mgf1, oaepParams.getMaskGenAlgorithm().getAlgorithm());
        Assert.assertEquals(new AlgorithmIdentifier(digestOid, DERNull.INSTANCE), oaepParams.getMaskGenAlgorithm().getParameters());
        Assert.assertEquals(PKCSObjectIdentifiers.id_pSpecified, oaepParams.getPSourceAlgorithm().getAlgorithm());
        Assert.assertEquals(new DEROctetString(Hex.decode("beef")), oaepParams.getPSourceAlgorithm().getParameters());
    }
}