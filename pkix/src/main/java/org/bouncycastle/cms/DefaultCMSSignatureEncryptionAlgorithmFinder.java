package org.bouncycastle.cms;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class DefaultCMSSignatureEncryptionAlgorithmFinder
    implements CMSSignatureEncryptionAlgorithmFinder
{
    private static final Set RSA_PKCS1d5 = new HashSet();
    private static final Map GOST_ENC = new HashMap();

    static
    {
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.md2WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.md4WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.md5WithRSAEncryption);
        RSA_PKCS1d5.add(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.md4WithRSAEncryption);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.md4WithRSA);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.md5WithRSA);
        RSA_PKCS1d5.add(OIWObjectIdentifiers.sha1WithRSA);
        RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);

        GOST_ENC.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001,
            new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, DERNull.INSTANCE));
        GOST_ENC.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, DERNull.INSTANCE));
        GOST_ENC.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, DERNull.INSTANCE));
    }

    public AlgorithmIdentifier findEncryptionAlgorithm(AlgorithmIdentifier signatureAlgorithm)
    {
               // RFC3370 section 3.2 with RFC 5754 update
        if (RSA_PKCS1d5.contains(signatureAlgorithm.getAlgorithm()))
        {
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        }
        // GOST signature encryption algorithms
        if (GOST_ENC.containsKey(signatureAlgorithm.getAlgorithm()))
        {
            return (AlgorithmIdentifier)GOST_ENC.get(signatureAlgorithm.getAlgorithm());
        }
        return signatureAlgorithm;
    }
}
