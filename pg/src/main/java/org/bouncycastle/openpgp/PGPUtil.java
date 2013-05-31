package org.bouncycastle.openpgp;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.util.encoders.Base64;

/**
 * Basic utility class
 */
public class PGPUtil
    implements HashAlgorithmTags
{
    private    static String    defProvider = "BC";

    /**
     * Return the provider that will be used by factory classes in situations
     * where a provider must be determined on the fly.
     * 
     * @return String
     */
    public static String getDefaultProvider()
    {
        return defProvider;
    }
    
    /**
     * Set the provider to be used by the package when it is necessary to 
     * find one on the fly.
     * 
     * @param provider
     */
    public static void setDefaultProvider(
        String    provider)
    {
        defProvider = provider;
    }
    
    static MPInteger[] dsaSigToMpi(
        byte[] encoding) 
        throws PGPException
    {
        ASN1InputStream aIn = new ASN1InputStream(encoding);

        DERInteger i1;
        DERInteger i2;

        try
        {
            ASN1Sequence s = (ASN1Sequence)aIn.readObject();

            i1 = (DERInteger)s.getObjectAt(0);
            i2 = (DERInteger)s.getObjectAt(1);
        }
        catch (IOException e)
        {
            throw new PGPException("exception encoding signature", e);
        }

        MPInteger[] values = new MPInteger[2];
        
        values[0] = new MPInteger(i1.getValue());
        values[1] = new MPInteger(i2.getValue());
        
        return values;
    }
    
    static String getDigestName(
        int        hashAlgorithm)
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
        default:
            throw new PGPException("unknown hash algorithm tag in getDigestName: " + hashAlgorithm);
        }
    }
    
    static String getSignatureName(
        int        keyAlgorithm,
        int        hashAlgorithm)
        throws PGPException
    {
        String     encAlg;
                
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

    public static byte[] makeRandomKey(
        int             algorithm,
        SecureRandom    random) 
        throws PGPException
    {
        int        keySize = 0;
        
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
        case SymmetricKeyAlgorithmTags.TWOFISH:
            keySize = 256;
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }
        
        byte[]    keyBytes = new byte[(keySize + 7) / 8];
        
        random.nextBytes(keyBytes);
        
        return keyBytes;
    }

    /**
     * write out the passed in file as a literal data packet.
     * 
     * @param out
     * @param fileType the LiteralData type for the file.
     * @param file
     * 
     * @throws IOException
     */
    public static void writeFileToLiteralData(
        OutputStream    out,
        char            fileType,
        File            file)
        throws IOException
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, file.getName(), file.length(), new Date(file.lastModified()));
        pipeFileContents(file, pOut, 4096);
    }
    
    /**
     * write out the passed in file as a literal data packet in partial packet format.
     * 
     * @param out
     * @param fileType the LiteralData type for the file.
     * @param file
     * @param buffer buffer to be used to chunk the file into partial packets.
     * 
     * @throws IOException
     */
    public static void writeFileToLiteralData(
        OutputStream    out,
        char            fileType,
        File            file,
        byte[]          buffer)
        throws IOException
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, file.getName(), new Date(file.lastModified()), buffer);
        pipeFileContents(file, pOut, buffer.length);
    }

    private static void pipeFileContents(File file, OutputStream pOut, int bufSize) throws IOException
    {
        FileInputStream in = new FileInputStream(file);
        byte[] buf = new byte[bufSize];

        int len;
        while ((len = in.read(buf)) > 0)
        {
            pOut.write(buf, 0, len);
        }

        pOut.close();
        in.close();
    }

    private static final int READ_AHEAD = 60;
    
    private static boolean isPossiblyBase64(
        int    ch)
    {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') 
                || (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
                || (ch == '\r') || (ch == '\n');
    }
    
    /**
     * Return either an ArmoredInputStream or a BCPGInputStream based on
     * whether the initial characters of the stream are binary PGP encodings or not.
     * 
     * @param in the stream to be wrapped
     * @return a BCPGInputStream
     * @throws IOException
     */
    public static InputStream getDecoderStream(
        InputStream    in) 
        throws IOException
    {
        if (!in.markSupported())
        {
            in = new BufferedInputStreamExt(in);
        }
        
        in.mark(READ_AHEAD);
        
        int    ch = in.read();
        

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
            
            byte[]  buf = new byte[READ_AHEAD];
            int     count = 1;
            int     index = 1;
            
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
            byte[]    firstBlock = new byte[8];
            
            System.arraycopy(buf, 0, firstBlock, 0, firstBlock.length);

            byte[]    decoded = Base64.decode(firstBlock);
            
            //
            // it's a base64 PGP block.
            //
            if ((decoded[0] & 0x80) != 0)
            {
                return new ArmoredInputStream(in, false);
            }
            
            return new ArmoredInputStream(in);
        }
    }

    static Provider getProvider(String providerName)
        throws NoSuchProviderException
    {
        Provider prov = Security.getProvider(providerName);

        if (prov == null)
        {
            throw new NoSuchProviderException("provider " + providerName + " not found.");
        }

        return prov;
    }
    
    static class BufferedInputStreamExt extends BufferedInputStream
    {
        BufferedInputStreamExt(InputStream input)
        {
            super(input);
        }

        public synchronized int available() throws IOException
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
