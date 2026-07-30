package org.bouncycastle.jce.provider.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.asn1.gm.SM9Signature;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9SigPrivateKeyParameters;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression pin for the SM9 DER encodings (the GM/T 0080-2020 structures,
 * nationally adopted as GB/T 41389-2022): the generators, representative master
 * and user keys, the signature structure, the stream-mode ciphertext structure,
 * and the KEM key-package structure.
 * <p>
 * The <i>values</i> encoded here are the official GM/T 0044.5-2016 worked-example
 * values, but the expected DER blobs in crypto/sm9/sm9_der_encodings.txt were
 * produced by this implementation - they are not transcribed from a standard
 * document. This test therefore guards the encodings against accidental change;
 * it is not a conformance check against an external authority. The algorithm
 * outputs themselves are covered by the official KATs (SM9SignerTest,
 * SM9KEMTest, SM9KeyExchangeTest and SM9CipherTest).
 */
public class SM9EncodingTest
    extends SimpleTest
{
    public String getName()
    {
        return "SM9Encoding";
    }

    private Map loadVectors(String fileName)
        throws Exception
    {
        Map m = new HashMap();
        BufferedReader br = new BufferedReader(
            new InputStreamReader(TestResourceFinder.findTestResource("crypto/sm9", fileName)));
        try
        {
            String line;
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq > 0)
                {
                    m.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
                }
            }
        }
        finally
        {
            br.close();
        }
        return m;
    }

    private byte[] hex(Map v, String key)
    {
        return Hex.decode((String)v.get(key));
    }

    public void performTest()
        throws Exception
    {
        Map enc = loadVectors("sm9_der_encodings.txt");
        Map sig = loadVectors("sm9_signature.txt");
        Map kex = loadVectors("sm9_keyexchange.txt");
        Map kem = loadVectors("sm9_kem.txt");
        Map cipher = loadVectors("sm9_encryption.txt");

        isEncoding("SM9 DER P1", bitString(SM9Curve.P1.getEncoded(false)), enc, "P1_DER");
        isEncoding("SM9 DER P2", bitString(SM9Curve.P2.getEncoded()), enc, "P2_DER");

        SM9SigMasterPrivateKeyParameters signMaster =
            new SM9SigMasterPrivateKeyParameters(new BigInteger((String)sig.get("ks"), 16));
        SM9SigPrivateKeyParameters signUser = signMaster.generateUserKey(hex(sig, "IDA"));
        isEncoding("SM9 DER ks", integer((String)sig.get("ks")), enc, "ks_DER");
        isEncoding("SM9 DER Ppub-s", bitString(signMaster.getPublicKeyParameters().getEncoded()),
            enc, "Ppubs_DER");
        isEncoding("SM9 DER dsA", bitString(signUser.getEncoded()), enc, "dsA_DER");

        byte hid = (byte)Integer.parseInt((String)kex.get("hid"), 16);
        SM9EncMasterPrivateKeyParameters encMaster =
            new SM9EncMasterPrivateKeyParameters(new BigInteger((String)kex.get("ke"), 16));
        SM9EncPrivateKeyParameters encUser = encMaster.generateExchangeKey(hex(kex, "IDA"), hid);
        isEncoding("SM9 DER ke", integer((String)kex.get("ke")), enc, "ke_DER");
        isEncoding("SM9 DER Ppub-e", bitString(encMaster.getPublicKeyParameters().getEncoded()),
            enc, "Ppube_DER");
        isEncoding("SM9 DER deA", bitString(encUser.getEncoded()), enc, "deA_DER");

        byte[] s = Arrays.concatenate(new byte[]{0x04}, hex(sig, "Sx"), hex(sig, "Sy"));
        byte[] signatureEncoding = new SM9Signature(hex(sig, "h"), s).getEncoded();
        isEncoding("SM9 DER SM9Signature", signatureEncoding, enc, "signature_DER");
        SM9Signature parsedSignature = SM9Signature.getInstance(hex(enc, "signature_DER"));
        isTrue("SM9 DER SM9Signature h", Arrays.areEqual(parsedSignature.getH(), hex(sig, "h")));
        isTrue("SM9 DER SM9Signature S", Arrays.areEqual(parsedSignature.getS(), s));

        byte[] c1 = Arrays.concatenate(new byte[]{0x04}, hex(cipher, "C1_x"), hex(cipher, "C1_y"));
        byte[] cipherEncoding = new SM9Cipher(SM9Cipher.EN_TYPE_STREAM, c1,
            hex(cipher, "modeA_C3"), hex(cipher, "modeA_C2")).getEncoded();
        isEncoding("SM9 DER SM9Cipher", cipherEncoding, enc, "cipher_DER");
        SM9Cipher parsedCipher = SM9Cipher.getInstance(hex(enc, "cipher_DER"));
        isTrue("SM9 DER SM9Cipher type", parsedCipher.getEnType() == SM9Cipher.EN_TYPE_STREAM);
        isTrue("SM9 DER SM9Cipher C1", Arrays.areEqual(parsedCipher.getC1(), c1));
        isTrue("SM9 DER SM9Cipher C3",
            Arrays.areEqual(parsedCipher.getC3(), hex(cipher, "modeA_C3")));
        isTrue("SM9 DER SM9Cipher C2",
            Arrays.areEqual(parsedCipher.getC2(), hex(cipher, "modeA_C2")));

        ASN1EncodableVector keyPackage = new ASN1EncodableVector(2);
        keyPackage.add(new DEROctetString(hex(kem, "K")));
        keyPackage.add(new DERBitString(
            Arrays.concatenate(new byte[]{0x04}, hex(kem, "C_x"), hex(kem, "C_y"))));
        isEncoding("SM9 DER SM9KeyPackage", new DERSequence(keyPackage).getEncoded(),
            enc, "keypackage_DER");
    }

    private void isEncoding(String message, byte[] actual, Map vectors, String expected)
    {
        isTrue(message, Arrays.areEqual(actual, hex(vectors, expected)));
    }

    private static byte[] bitString(byte[] value)
        throws Exception
    {
        return new DERBitString(value).getEncoded();
    }

    private static byte[] integer(String value)
        throws Exception
    {
        return new ASN1Integer(new BigInteger(value, 16)).getEncoded();
    }

    public static void main(String[] args)
    {
        runTest(new SM9EncodingTest());
    }
}
