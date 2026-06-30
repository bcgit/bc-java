package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Coverage for the OID &lt;-&gt; digest-name tables in
 * {@link org.bouncycastle.jcajce.util.MessageDigestUtils}. The ripemd256
 * assertion is the regression for a copy/paste error in the OID table, which
 * mapped TeleTrusTObjectIdentifiers.ripemd256 to "RIPEMD-128" (introduced 2015,
 * commit d43872b127). Because getDigestName feeds digest creation in
 * OperatorHelper, the wrong name caused a RIPEMD-256-signed cert/CMS/OCSP to be
 * hashed with RIPEMD-128 or to fail with NoSuchAlgorithmException.
 */
public class MessageDigestUtilsTest
    extends SimpleTest
{
    public String getName()
    {
        return "MessageDigestUtils";
    }

    public void performTest()
        throws Exception
    {
        // OID -> display-name direction (MessageDigestUtils.getDigestName).
        isTrue("md5", "MD5".equals(MessageDigestUtils.getDigestName(PKCSObjectIdentifiers.md5)));
        isTrue("sha1", "SHA-1".equals(MessageDigestUtils.getDigestName(OIWObjectIdentifiers.idSHA1)));
        isTrue("sha256", "SHA-256".equals(MessageDigestUtils.getDigestName(NISTObjectIdentifiers.id_sha256)));
        isTrue("sha512", "SHA-512".equals(MessageDigestUtils.getDigestName(NISTObjectIdentifiers.id_sha512)));
        isTrue("sha3-256", "SHA3-256".equals(MessageDigestUtils.getDigestName(NISTObjectIdentifiers.id_sha3_256)));
        isTrue("ripemd128", "RIPEMD-128".equals(MessageDigestUtils.getDigestName(TeleTrusTObjectIdentifiers.ripemd128)));
        isTrue("ripemd160", "RIPEMD-160".equals(MessageDigestUtils.getDigestName(TeleTrusTObjectIdentifiers.ripemd160)));
        // Regression: ripemd256 must map to "RIPEMD-256", not "RIPEMD-128".
        isTrue("ripemd256", "RIPEMD-256".equals(MessageDigestUtils.getDigestName(TeleTrusTObjectIdentifiers.ripemd256)));

        // An unknown OID returns its dotted-decimal string unchanged.
        ASN1ObjectIdentifier bogus = new ASN1ObjectIdentifier("1.2.3.4.5.6.7.9");
        isTrue("unknown oid string", "1.2.3.4.5.6.7.9".equals(MessageDigestUtils.getDigestName(bogus)));

        // name -> AlgorithmIdentifier direction (getDigestAlgID), both the
        // hyphenated and bare aliases, plus the round-trip through getDigestName.
        isTrue("algid sha-256", NISTObjectIdentifiers.id_sha256.equals(
            MessageDigestUtils.getDigestAlgID("SHA-256").getAlgorithm()));
        isTrue("algid sha256", NISTObjectIdentifiers.id_sha256.equals(
            MessageDigestUtils.getDigestAlgID("SHA256").getAlgorithm()));
        AlgorithmIdentifier sha1Id = MessageDigestUtils.getDigestAlgID("SHA-1");
        isTrue("algid sha-1", OIWObjectIdentifiers.idSHA1.equals(sha1Id.getAlgorithm()));
        isTrue("algid round-trip", NISTObjectIdentifiers.id_sha256.equals(
            MessageDigestUtils.getDigestAlgID(
                MessageDigestUtils.getDigestName(NISTObjectIdentifiers.id_sha256)).getAlgorithm()));

        // An unknown digest name throws (not a null return).
        try
        {
            MessageDigestUtils.getDigestAlgID("not-a-digest");
            fail("expected IllegalArgumentException for unknown digest name");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new MessageDigestUtilsTest());
    }
}
