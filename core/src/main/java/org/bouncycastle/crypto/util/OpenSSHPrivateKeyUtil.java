package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;


/**
 * A collection of utility methods for parsing OpenSSH private keys.
 */
public class OpenSSHPrivateKeyUtil
{
    private OpenSSHPrivateKeyUtil()
    {

    }

    /**
     * Magic value for propriety OpenSSH private key.
     **/
    static final byte[] AUTH_MAGIC = Strings.toByteArray("openssh-key-v1\0"); // C string so null terminated

    /**
     * Encode a cipher parameters into an OpenSSH private key.
     * This does not add headers like ----BEGIN RSA PRIVATE KEY----
     *
     * @param params the cipher parameters.
     * @return a byte array
     */
    public static byte[] encodePrivateKey(AsymmetricKeyParameter params)
        throws IOException
    {
        if (params == null)
        {
            throw new IllegalArgumentException("param is null");
        }

        if (params instanceof RSAPrivateCrtKeyParameters)
        {
            PrivateKeyInfo pInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(params);

            return pInfo.parsePrivateKey().toASN1Primitive().getEncoded();
        }
        else if (params instanceof ECPrivateKeyParameters)
        {
            PrivateKeyInfo pInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(params);

            return pInfo.parsePrivateKey().toASN1Primitive().getEncoded();
        }
        else if (params instanceof DSAPrivateKeyParameters)
        {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new ASN1Integer(0));
            vec.add(new ASN1Integer(((DSAPrivateKeyParameters)params).getParameters().getP()));
            vec.add(new ASN1Integer(((DSAPrivateKeyParameters)params).getParameters().getQ()));
            vec.add(new ASN1Integer(((DSAPrivateKeyParameters)params).getParameters().getG()));

            // public key = g.modPow(x, p);

            BigInteger pubKey = ((DSAPrivateKeyParameters)params).getParameters().getG().modPow(
                ((DSAPrivateKeyParameters)params).getX(),
                ((DSAPrivateKeyParameters)params).getParameters().getP());
            vec.add(new ASN1Integer(pubKey));

            vec.add(new ASN1Integer(((DSAPrivateKeyParameters)params).getX()));
            try
            {
                return new DERSequence(vec).getEncoded();
            }
            catch (Exception ex)
            {
                throw new IllegalStateException("unable to encode DSAPrivateKeyParameters " + ex.getMessage(), ex);
            }
        }
        else if (params instanceof Ed25519PrivateKeyParameters)
        {
            SSHBuilder builder = new SSHBuilder();

            builder.write(AUTH_MAGIC);
            builder.writeString("none");
            builder.writeString("none");
            builder.u32(0); // Zero length of the KDF

            builder.u32(1);

            Ed25519PublicKeyParameters publicKeyParameters = ((Ed25519PrivateKeyParameters)params).generatePublicKey();

            byte[] pkEncoded = OpenSSHPublicKeyUtil.encodePublicKey(publicKeyParameters);
            builder.rawArray(pkEncoded);

            SSHBuilder pkBuild = new SSHBuilder();

            pkBuild.u32(0x00ff00ff);
            pkBuild.u32(0x00ff00ff);

            pkBuild.writeString("ssh-ed25519");

            byte[] pubKeyEncoded = ((Ed25519PrivateKeyParameters)params).generatePublicKey().getEncoded();

            pkBuild.rawArray(pubKeyEncoded); // Public key written as length defined item.

            // The private key in SSH is 64 bytes long and is the concatenation of the private and the public keys
            pkBuild.rawArray(Arrays.concatenate(((Ed25519PrivateKeyParameters)params).getEncoded(), pubKeyEncoded));
            pkBuild.u32(0); // No comment.
            builder.rawArray(pkBuild.getBytes());

            return builder.getBytes();
        }

        throw new IllegalArgumentException("unable to convert " + params.getClass().getName() + " to openssh private key");

    }

    /**
     * Parse a private key.
     * <p>
     * This method accepts the body of the OpenSSH private key.
     * The easiest way to extract the body is to use PemReader, for example:
     * <p>
     * byte[] blob = new PemReader([reader]).readPemObject().getContent();
     * CipherParameters params = parsePrivateKeyBlob(blob);
     *
     * @param blob The key.
     * @return A cipher parameters instance.
     */
    public static AsymmetricKeyParameter parsePrivateKeyBlob(byte[] blob)
    {
        AsymmetricKeyParameter result = null;

        if  (blob[0] == 0x30)
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
        else
        {
            SSHBuffer kIn = new SSHBuffer(AUTH_MAGIC, blob);
            // Cipher name.
            String cipherName = Strings.fromByteArray(kIn.readString());

            if (!"none".equals(cipherName))
            {
                throw new IllegalStateException("encrypted keys not supported");
            }

            // KDF name
            kIn.readString();

            // KDF options
            kIn.readString();

            long publicKeyCount = kIn.readU32();

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

            String keyType = Strings.fromByteArray(pkIn.readString());

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

    /**
     * allIntegers returns true if the sequence holds only ASN1Integer types.
     **/
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
