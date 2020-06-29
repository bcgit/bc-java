package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.util.Arrays;

public class RSAUtil
{
    private static final byte[] RSAPSSParams_256_A, RSAPSSParams_384_A, RSAPSSParams_512_A;
    private static final byte[] RSAPSSParams_256_B, RSAPSSParams_384_B, RSAPSSParams_512_B;

    static
    {
        /*
         * RFC 4055
         */

        AlgorithmIdentifier sha256Identifier_A = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        AlgorithmIdentifier sha384Identifier_A = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        AlgorithmIdentifier sha512Identifier_A = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        AlgorithmIdentifier sha256Identifier_B = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier sha384Identifier_B = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
        AlgorithmIdentifier sha512Identifier_B = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);

        AlgorithmIdentifier mgf1SHA256Identifier_A = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256Identifier_A);
        AlgorithmIdentifier mgf1SHA384Identifier_A = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha384Identifier_A);
        AlgorithmIdentifier mgf1SHA512Identifier_A = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha512Identifier_A);
        AlgorithmIdentifier mgf1SHA256Identifier_B = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256Identifier_B);
        AlgorithmIdentifier mgf1SHA384Identifier_B = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha384Identifier_B);
        AlgorithmIdentifier mgf1SHA512Identifier_B = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha512Identifier_B);

        ASN1Integer sha256Size = new ASN1Integer(HashAlgorithm.getOutputSize(HashAlgorithm.sha256));
        ASN1Integer sha384Size = new ASN1Integer(HashAlgorithm.getOutputSize(HashAlgorithm.sha384));
        ASN1Integer sha512Size = new ASN1Integer(HashAlgorithm.getOutputSize(HashAlgorithm.sha512));

        ASN1Integer trailerField = new ASN1Integer(1);

        try
        {
            RSAPSSParams_256_A = new RSASSAPSSparams(sha256Identifier_A, mgf1SHA256Identifier_A, sha256Size, trailerField)
                .getEncoded(ASN1Encoding.DER);
            RSAPSSParams_384_A = new RSASSAPSSparams(sha384Identifier_A, mgf1SHA384Identifier_A, sha384Size, trailerField)
                .getEncoded(ASN1Encoding.DER);
            RSAPSSParams_512_A = new RSASSAPSSparams(sha512Identifier_A, mgf1SHA512Identifier_A, sha512Size, trailerField)
                .getEncoded(ASN1Encoding.DER);
            RSAPSSParams_256_B = new RSASSAPSSparams(sha256Identifier_B, mgf1SHA256Identifier_B, sha256Size, trailerField)
                .getEncoded(ASN1Encoding.DER);
            RSAPSSParams_384_B = new RSASSAPSSparams(sha384Identifier_B, mgf1SHA384Identifier_B, sha384Size, trailerField)
                .getEncoded(ASN1Encoding.DER);
            RSAPSSParams_512_B = new RSASSAPSSparams(sha512Identifier_B, mgf1SHA512Identifier_B, sha512Size, trailerField)
                .getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.getMessage());
        }
    }

    public static boolean supportsPKCS1(AlgorithmIdentifier pubKeyAlgID)
    {
        ASN1ObjectIdentifier oid = pubKeyAlgID.getAlgorithm();
        return PKCSObjectIdentifiers.rsaEncryption.equals(oid)
            || X509ObjectIdentifiers.id_ea_rsa.equals(oid);
    }

    public static boolean supportsPSS_PSS(short signatureAlgorithm, AlgorithmIdentifier pubKeyAlgID)
    {
        ASN1ObjectIdentifier oid = pubKeyAlgID.getAlgorithm();
        if (!PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid))
        {
            return false;
        }

        /*
         * TODO ASN.1 NULL shouldn't really be allowed here; it's a workaround for e.g. Oracle JDK
         * 1.8.0_241, where the X.509 certificate implementation adds the NULL when re-encoding the
         * original parameters. It appears it was fixed at some later date (OpenJDK 12.0.2 does not
         * have the issue), but not sure exactly when.
         */
        ASN1Encodable pssParams = pubKeyAlgID.getParameters();
        if (null == pssParams || pssParams instanceof ASN1Null)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return true;
            default:
                return false;
            }
        }

        byte[] encoded;
        try
        {
            encoded = pssParams.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        }
        catch (Exception e)
        {
            return false;
        }

        byte[] expected_A, expected_B;
        switch (signatureAlgorithm)
        {
        case SignatureAlgorithm.rsa_pss_pss_sha256:
            expected_A = RSAPSSParams_256_A;
            expected_B = RSAPSSParams_256_B;
            break;
        case SignatureAlgorithm.rsa_pss_pss_sha384:
            expected_A = RSAPSSParams_384_A;
            expected_B = RSAPSSParams_384_B;
            break;
        case SignatureAlgorithm.rsa_pss_pss_sha512:
            expected_A = RSAPSSParams_512_A;
            expected_B = RSAPSSParams_512_B;
            break;
        default:
            return false;
        }

        return Arrays.areEqual(expected_A, encoded)
            || Arrays.areEqual(expected_B, encoded);
    }

    public static boolean supportsPSS_RSAE(AlgorithmIdentifier pubKeyAlgID)
    {
        ASN1ObjectIdentifier oid = pubKeyAlgID.getAlgorithm();
        return PKCSObjectIdentifiers.rsaEncryption.equals(oid);
    }
}
