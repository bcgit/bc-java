package org.bouncycastle.openpgp;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;

/**
 * PGP utilities.
 */
public class PGPUtil
    implements HashAlgorithmTags
{
    private static String defProvider = "BC";

    private static Map<String, Integer> nameToHashId = new HashMap<String, Integer>()
    {
        {
            put("sha1", Integers.valueOf(HashAlgorithmTags.SHA1));
            put("sha224", Integers.valueOf(HashAlgorithmTags.SHA224));
            put("sha256", Integers.valueOf(HashAlgorithmTags.SHA256));
            put("sha384", Integers.valueOf(HashAlgorithmTags.SHA384));
            put("sha512", Integers.valueOf(HashAlgorithmTags.SHA512));
            put("sha3-224", Integers.valueOf(HashAlgorithmTags.SHA3_224));
            put("sha3-256", Integers.valueOf(HashAlgorithmTags.SHA3_256));
            put("sha3-384", Integers.valueOf(HashAlgorithmTags.SHA3_384));
            put("sha3-512", Integers.valueOf(HashAlgorithmTags.SHA3_512));
            put("ripemd160", Integers.valueOf(HashAlgorithmTags.RIPEMD160));
            put("rmd160", Integers.valueOf(HashAlgorithmTags.RIPEMD160));
            put("md2", Integers.valueOf(HashAlgorithmTags.MD2));
            put("md4", Integers.valueOf(HashAlgorithmTags.MD4));
            put("tiger", Integers.valueOf(HashAlgorithmTags.TIGER_192));
            put("haval", Integers.valueOf(HashAlgorithmTags.HAVAL_5_160));
            put("sm3", Integers.valueOf(HashAlgorithmTags.SM3));
            put("md5", Integers.valueOf(HashAlgorithmTags.MD5));
        }
    };

    private static Map<ASN1ObjectIdentifier, String> oidToName = new HashMap<ASN1ObjectIdentifier, String>()
    {
        {
            put(CryptlibObjectIdentifiers.curvey25519, "Curve25519");
            put(EdECObjectIdentifiers.id_X25519, "Curve25519");
            put(EdECObjectIdentifiers.id_Ed25519, "Ed25519");
            put(SECObjectIdentifiers.secp256r1, "NIST P-256");
            put(SECObjectIdentifiers.secp384r1, "NIST P-384");
            put(SECObjectIdentifiers.secp521r1, "NIST P-521");
        }
    };

    /**
     * Return an appropriate name for the hash algorithm represented by the passed
     * in hash algorithm ID number.
     *
     * @param hashAlgorithm the algorithm ID for a hash algorithm.
     * @return a String representation of the hash name.
     */
    public static String getDigestName(
        int hashAlgorithm)
        throws PGPException
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithmTags.SHA1:
            return "SHA1";
        case HashAlgorithmTags.MD2:
            return "MD2";
        case HashAlgorithmTags.MD5:
            return "MD5";
        case HashAlgorithmTags.RIPEMD160:
            return "RIPEMD160";
        case HashAlgorithmTags.SHA256:
            return "SHA256";
        case HashAlgorithmTags.SHA384:
            return "SHA384";
        case HashAlgorithmTags.SHA512:
            return "SHA512";
        case HashAlgorithmTags.SHA224:
            return "SHA224";
        case HashAlgorithmTags.SHA3_256:
        case HashAlgorithmTags.SHA3_256_OLD:
            return "SHA256";
        case HashAlgorithmTags.SHA3_384:
            return "SHA384";
        case HashAlgorithmTags.SHA3_512:
        case HashAlgorithmTags.SHA3_512_OLD:
            return "SHA512";
        case HashAlgorithmTags.SHA3_224:
            return "SHA224";
        case HashAlgorithmTags.TIGER_192:
            return "TIGER";
        default:
            throw new PGPException("unknown hash algorithm tag in getDigestName: " + hashAlgorithm);
        }
    }

    public static int getDigestIDForName(String name)
    {
        name = Strings.toLowerCase(name);
        if (nameToHashId.containsKey(name))
        {
            return ((Integer)nameToHashId.get(name)).intValue();
        }
        throw new IllegalArgumentException("unable to map " + name + " to a hash id");
    }

    /**
     * Return the EC curve name for the passed in OID.
     *
     * @param oid the EC curve object identifier in the PGP key
     * @return  a string representation of the OID.
     */
    public static String getCurveName(
        ASN1ObjectIdentifier oid)
    {
        String name = (String)oidToName.get(oid);

        if (name != null)
        {
            return name;
        }

        // fall back
        return ECNamedCurveTable.getName(oid);
    }

    /**
     * Return an appropriate name for the signature algorithm represented by the passed
     * in public key and hash algorithm ID numbers.
     *
     * @param keyAlgorithm  the algorithm ID for the public key algorithm used in the signature.
     * @param hashAlgorithm the algorithm ID for the hash algorithm used.
     * @return a String representation of the signature name.
     */
    public static String getSignatureName(
        int keyAlgorithm,
        int hashAlgorithm)
        throws PGPException
    {
        String encAlg;

        switch (keyAlgorithm)
        {
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
            encAlg = "RSA";
            break;
        case PublicKeyAlgorithmTags.DSA:
            encAlg = "DSA";
            break;
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT: // in some malformed cases.
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            encAlg = "ElGamal";
            break;
        default:
            throw new PGPException("unknown algorithm tag in signature:" + keyAlgorithm);
        }

        return getDigestName(hashAlgorithm) + "with" + encAlg;
    }

    /**
     * Return an appropriate name for the symmetric algorithm represented by the passed
     * in symmetric algorithm ID number.
     *
     * @param algorithm the algorithm ID for a symmetric cipher.
     * @return a String representation of the cipher name.
     */
    public static String getSymmetricCipherName(
        int algorithm)
    {
        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.NULL:
            return null;
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            return "DESEDE";
        case SymmetricKeyAlgorithmTags.IDEA:
            return "IDEA";
        case SymmetricKeyAlgorithmTags.CAST5:
            return "CAST5";
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            return "Blowfish";
        case SymmetricKeyAlgorithmTags.SAFER:
            return "SAFER";
        case SymmetricKeyAlgorithmTags.DES:
            return "DES";
        case SymmetricKeyAlgorithmTags.AES_128:
            return "AES";
        case SymmetricKeyAlgorithmTags.AES_192:
            return "AES";
        case SymmetricKeyAlgorithmTags.AES_256:
            return "AES";
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            return "Camellia";
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            return "Camellia";
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            return "Camellia";
        case SymmetricKeyAlgorithmTags.TWOFISH:
            return "Twofish";
        default:
            throw new IllegalArgumentException("unknown symmetric algorithm: " + algorithm);
        }
    }


    /**
     * Return the JCA/JCE provider that will be used by factory classes in situations where a
     * provider must be determined on the fly.
     *
     * @return the name of the default provider.
     * @deprecated unused
     */
    public static String getDefaultProvider()
    {
        // TODO: no longer used.
        return defProvider;
    }

    /**
     * Set the provider to be used by the package when it is necessary to find one on the fly.
     *
     * @param provider the name of the JCA/JCE provider to use by default.
     * @deprecated unused
     */
    public static void setDefaultProvider(
        String provider)
    {
        defProvider = provider;
    }

    static MPInteger[] dsaSigToMpi(
        byte[] encoding)
        throws PGPException
    {
        ASN1Integer i1, i2;

        try
        {
            ASN1Sequence s = ASN1Sequence.getInstance(encoding);

            i1 = ASN1Integer.getInstance(s.getObjectAt(0));
            i2 = ASN1Integer.getInstance(s.getObjectAt(1));
        }
        catch (RuntimeException e)
        {
            throw new PGPException("exception decoding signature", e);
        }

        return new MPInteger[]{
            new MPInteger(i1.getValue()),
            new MPInteger(i2.getValue())
        };
    }

    /**
     * Return true if the byte[] blob probably represents key ring data.
     *
     * @return true if data likely represents a key ring stream.
     */
    public static boolean isKeyRing(byte[] blob)
        throws IOException
    {
        BCPGInputStream bIn = new BCPGInputStream(new ByteArrayInputStream(blob));

        int tag = bIn.nextPacketTag();

        return tag == PacketTags.PUBLIC_KEY || tag == PacketTags.PUBLIC_SUBKEY
            || tag == PacketTags.SECRET_KEY || tag == PacketTags.SECRET_SUBKEY;
    }

    /**
     * Return true if the byte[] blob probably represents key box data.
     *
     * @return true if data likely represents a key box stream.
     */
    public static boolean isKeyBox(byte[] data)
        throws IOException
    {
        if (data.length < 12)
        {
            return false;
        }

        InputStream bIn = new ByteArrayInputStream(data);

        // skip size and headers
        for (int i = 0; i != 8; i++)
        {
            bIn.read();
        }

        return bIn.read() == 'K' && bIn.read() == 'B' && bIn.read() == 'X' && bIn.read() == 'f';
    }

    /**
     * Generates a random key for a {@link SymmetricKeyAlgorithmTags symmetric encryption algorithm}
     * .
     *
     * @param algorithm the symmetric key algorithm identifier.
     * @param random    a source of random data.
     * @return a key of the length required by the specified encryption algorithm.
     * @throws PGPException if the encryption algorithm is unknown.
     */
    public static byte[] makeRandomKey(
        int algorithm,
        SecureRandom random)
        throws PGPException
    {
        int keySize = 0;

        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            keySize = 192;
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.SAFER:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.DES:
            keySize = 64;
            break;
        case SymmetricKeyAlgorithmTags.AES_128:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.AES_192:
            keySize = 192;
            break;
        case SymmetricKeyAlgorithmTags.AES_256:
            keySize = 256;
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            keySize = 128;
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            keySize = 192;
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            keySize = 256;
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            keySize = 256;
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        byte[] keyBytes = new byte[(keySize + 7) / 8];

        random.nextBytes(keyBytes);

        return keyBytes;
    }

    /**
     * Write out the contents of the provided file as a literal data packet.
     *
     * @param out      the stream to write the literal data to.
     * @param fileType the {@link PGPLiteralData} type to use for the file data.
     * @param file     the file to write the contents of.
     * @throws IOException if an error occurs reading the file or writing to the output stream.
     */
    public static void writeFileToLiteralData(
        OutputStream out,
        char fileType,
        File file)
        throws IOException
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, file);
        pipeFileContents(file, pOut, 32768);
    }

    /**
     * Write out the contents of the provided file as a literal data packet in partial packet
     * format.
     *
     * @param out      the stream to write the literal data to.
     * @param fileType the {@link PGPLiteralData} type to use for the file data.
     * @param file     the file to write the contents of.
     * @param buffer   buffer to be used to chunk the file into partial packets.
     * @throws IOException if an error occurs reading the file or writing to the output stream.
     * @see PGPLiteralDataGenerator#open(OutputStream, char, String, Date, byte[])
     */
    public static void writeFileToLiteralData(
        OutputStream out,
        char fileType,
        File file,
        byte[] buffer)
        throws IOException
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, file.getName(), new Date(file.lastModified()), buffer);
        pipeFileContents(file, pOut, buffer.length);
    }

    static void pipeFileContents(File file, OutputStream pOut, int bufferSize)
        throws IOException
    {
        byte[] buf = new byte[bufferSize];

        FileInputStream in = new FileInputStream(file);
        try
        {
            int len;
            while ((len = in.read(buf)) > 0)
            {
                pOut.write(buf, 0, len);
            }

            pOut.close();
        }
        finally
        {
            Arrays.fill(buf, (byte)0);
            try
            {
                in.close();
            }
            catch (IOException ignored)
            {
                // ignore...
            }
        }
    }

    private static final int READ_AHEAD = 60;

    private static boolean isPossiblyBase64(
        int ch)
    {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
            || (ch == '\r') || (ch == '\n');
    }

    /**
     * Obtains a stream that can be used to read PGP data from the provided stream.
     * <p>
     * If the initial bytes of the underlying stream are binary PGP encodings, then the stream will
     * be returned directly, otherwise an {@link ArmoredInputStream} is used to wrap the provided
     * stream and remove ASCII-Armored encoding.
     * </p>
     *
     * @param in the stream to be checked and possibly wrapped.
     * @return a stream that will return PGP binary encoded data.
     * @throws IOException if an error occurs reading the stream, or initialising the
     * {@link ArmoredInputStream}.
     */
    public static InputStream getDecoderStream(
        InputStream in)
        throws IOException
    {
        if (!in.markSupported())
        {
            in = new BufferedInputStreamExt(in);
        }

        in.mark(READ_AHEAD);

        int ch = in.read();


        if ((ch & 0x80) != 0)
        {
            in.reset();

            return in;
        }
        else
        {
            if (!isPossiblyBase64(ch))
            {
                in.reset();

                return new ArmoredInputStream(in);
            }

            byte[] buf = new byte[READ_AHEAD];
            int count = 1;
            int index = 1;

            buf[0] = (byte)ch;
            while (count != READ_AHEAD && (ch = in.read()) >= 0)
            {
                if (!isPossiblyBase64(ch))
                {
                    in.reset();

                    return new ArmoredInputStream(in);
                }

                if (ch != '\n' && ch != '\r')
                {
                    buf[index++] = (byte)ch;
                }

                count++;
            }

            in.reset();

            //
            // nothing but new lines, little else, assume regular armoring
            //
            if (count < 4)
            {
                return new ArmoredInputStream(in);
            }

            //
            // test our non-blank data
            //
            byte[] firstBlock = new byte[8];

            System.arraycopy(buf, 0, firstBlock, 0, firstBlock.length);

            try
            {
                byte[] decoded = Base64.decode(firstBlock);

                //
                // it's a base64 PGP block.
                //
                if ((decoded[0] & 0x80) != 0)
                {
                    return new ArmoredInputStream(in, false);
                }

                return new ArmoredInputStream(in);
            }
            catch (DecoderException e)
            {
                throw new IOException(e.getMessage());
            }
        }
    }

    static class BufferedInputStreamExt
        extends BufferedInputStream
    {
        BufferedInputStreamExt(InputStream input)
        {
            super(input);
        }

        public synchronized int available()
            throws IOException
        {
            int result = super.available();
            if (result < 0)
            {
                result = Integer.MAX_VALUE;
            }
            return result;
        }
    }
}
