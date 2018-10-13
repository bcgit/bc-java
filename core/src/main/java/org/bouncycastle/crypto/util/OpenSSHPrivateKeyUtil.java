package org.bouncycastle.crypto.util;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Strings;


public class OpenSSHPrivateKeyUtil
{

    private static final byte[] AUTH_MAGIC = Strings.toByteArray("openssh-key-v1\0"); // C string so null terminated


    /**
     * Parse a private key.
     * <p>
     * This method accepts the body of the openssh private key.
     * The easiest way to extract the body is to use PemReader, for example:
     * <p>
     * byte[] blob = new PemReader([reader]).readPemObject().getContent();
     * CipherParameters params = parsePrivateKeyBlob(blob);
     *
     * @param blob The key.
     * @return A cipher parameters instance.
     */
    public static CipherParameters parsePrivateKeyBlob(byte[] blob)

    {
        CipherParameters result = null;

        try
        {
            ASN1Sequence sequence = ASN1Sequence.getInstance(blob);


            if (sequence.size() == 6)
            {
                if (allIntegers(sequence) && ((ASN1Integer)sequence.getObjectAt(0)).getPositiveValue().equals(BigInteger.ZERO))
                {
                    // length of 6 and all Integers -- DSA
                    result = new DSAPrivateKeyParameters(
                        ((ASN1Integer)sequence.getObjectAt(5)).getPositiveValue(),
                        new DSAParameters(
                            ((ASN1Integer)sequence.getObjectAt(1)).getPositiveValue(),
                            ((ASN1Integer)sequence.getObjectAt(2)).getPositiveValue(),
                            ((ASN1Integer)sequence.getObjectAt(3)).getPositiveValue())
                    );
                }


            }
            else if (sequence.size() == 9)
            {
                if (allIntegers(sequence) && ((ASN1Integer)sequence.getObjectAt(0)).getPositiveValue().equals(BigInteger.ZERO))
                {
                    // length of 8 and all Integers -- RSA


                    RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(sequence);

                    result = new RSAPrivateCrtKeyParameters(
                        rsaPrivateKey.getModulus(),
                        rsaPrivateKey.getPublicExponent(),
                        rsaPrivateKey.getPrivateExponent(),
                        rsaPrivateKey.getPrime1(),
                        rsaPrivateKey.getPrime2(),
                        rsaPrivateKey.getExponent1(),
                        rsaPrivateKey.getExponent2(),
                        rsaPrivateKey.getCoefficient());

                }

            }
            else if (sequence.size() == 4)
            {
                if (sequence.getObjectAt(3) instanceof DERTaggedObject && sequence.getObjectAt(2) instanceof DERTaggedObject)
                {
                    ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(sequence);
                    ASN1ObjectIdentifier curveOID = (ASN1ObjectIdentifier)ecPrivateKey.getParameters();
                    X9ECParameters x9Params = ECNamedCurveTable.getByOID(curveOID);
                    result = new ECPrivateKeyParameters(
                        ecPrivateKey.getKey(),
                        new ECNamedDomainParameters(
                            curveOID,
                            x9Params.getCurve(),
                            x9Params.getG(),
                            x9Params.getN(),
                            x9Params.getH(),
                            x9Params.getSeed()));
                }
            }
        }
        catch (Throwable t)
        {

            SSHBuffer kIn = new SSHBuffer(AUTH_MAGIC, blob);

            // Cipher name.
            String cipherName = new String(kIn.readString());

            if (!"none".equals(cipherName))
            {
                throw new IllegalStateException("encrypted keys not supported");
            }


            // KDF name
            kIn.readString();

            // KDF
            byte[] kdf = kIn.readString();


            long publicKeyCount = kIn.readU32();

            List<CipherParameters> publicKeys = new ArrayList<CipherParameters>();

            for (int l = 0; l != publicKeyCount; l++)
            {
                // Burn off public keys.
                OpenSSHPublicKeyUtil.parsePublicKey(kIn.readString());
            }

            SSHBuffer pkIn = new SSHBuffer(kIn.readPaddedString());
            int check1 = pkIn.readU32();
            int check2 = pkIn.readU32();


            if (check1 != check2)
            {
                throw new IllegalStateException("private key check values are not the same");
            }


            String keyType = pkIn.cString();

            if ("ssh-ed25519".equals(keyType))
            {
                //
                // Skip public key
                //
                pkIn.readString();
                byte[] edPrivateKey = pkIn.readString();

                result = new Ed25519PrivateKeyParameters(edPrivateKey, 0);

            }
            else
            {
                throw new IllegalStateException("can not parse private key of type " + keyType);
            }


        }

        if (result == null)
        {
            throw new IllegalArgumentException("unable to parse key");
        }


        return result;

    }


    private static boolean allIntegers(ASN1Sequence sequence)
    {
        for (int t = 0; t < sequence.size(); t++)
        {
            if (!(sequence.getObjectAt(t) instanceof ASN1Integer))
            {
                return false;

            }
        }
        return true;
    }


}
