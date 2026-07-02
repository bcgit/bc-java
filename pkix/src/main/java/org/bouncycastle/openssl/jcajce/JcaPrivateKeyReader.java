package org.bouncycastle.openssl.jcajce;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.PrivateKey;
import java.security.Provider;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.Streams;

/**
 * Reads a private key in any of the common OpenSSL on-disk forms and converts it
 * to a JCA {@link PrivateKey}, transparently decrypting the password-protected variants.
 * <p>
 * The following encodings are recognised, on the PEM side by the type {@link PEMParser}
 * hands back and on the DER side by the structure of the outermost SEQUENCE:
 * <ul>
 * <li>traditional (PKCS#1) RSA keys - {@code -----BEGIN RSA PRIVATE KEY-----} and their DER body;</li>
 * <li>PKCS#8 {@link PrivateKeyInfo} - {@code -----BEGIN PRIVATE KEY-----} and DER;</li>
 * <li>password-protected traditional keys ({@code -----BEGIN ... PRIVATE KEY-----} with a
 * {@code Proc-Type/DEK-Info} header), decrypted with the supplied password;</li>
 * <li>encrypted PKCS#8 ({@code -----BEGIN ENCRYPTED PRIVATE KEY-----} and DER
 * {@code EncryptedPrivateKeyInfo}), decrypted with the supplied password.</li>
 * </ul>
 * <p>
 * This is the JCA-aware read-side companion to {@link JcaPKIXIdentityBuilder} and lives in the
 * {@code .jcajce} package because it produces a {@link java.security.PrivateKey}. It is a
 * convenience over {@link PEMParser} / {@link JcaPEMKeyConverter} only - the standards-compliant
 * writers ({@link JcaPKCS8Generator}, {@link JcePEMEncryptorBuilder},
 * {@link JceOpenSSLPKCS8EncryptorBuilder}) remain the way to emit keys.
 */
public class JcaPrivateKeyReader
{
    private JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
    private final char[] password;

    /**
     * Base constructor for reading unencrypted keys. Supplying an encrypted key to a reader
     * built this way results in a {@link PEMException}.
     */
    public JcaPrivateKeyReader()
    {
        this(null);
    }

    /**
     * Construct a reader carrying the password used to decrypt password-protected keys. The
     * password is ignored when the key turns out to be unencrypted.
     *
     * @param password the password to decrypt with, or null if no encrypted key is expected.
     */
    public JcaPrivateKeyReader(char[] password)
    {
        this.password = password;
    }

    public JcaPrivateKeyReader setProvider(Provider provider)
    {
        this.keyConverter = keyConverter.setProvider(provider);

        return this;
    }

    public JcaPrivateKeyReader setProvider(String providerName)
    {
        this.keyConverter = keyConverter.setProvider(providerName);

        return this;
    }

    /**
     * Read a private key from a PEM or DER file, auto-detecting the encoding.
     *
     * @param keyFile the file containing the key.
     * @return the recovered private key.
     * @throws IOException on a read, parse, or decryption failure.
     */
    public PrivateKey readKey(File keyFile)
        throws IOException
    {
        if (!keyFile.canRead())
        {
            if (keyFile.exists())
            {
                throw new IOException("Unable to open file " + keyFile.getPath() + " for reading.");
            }
            throw new FileNotFoundException("Unable to open " + keyFile.getPath() + ": it does not exist.");
        }

        FileInputStream fIn = new FileInputStream(keyFile);
        try
        {
            return readKey(Streams.readAll(fIn));
        }
        finally
        {
            fIn.close();
        }
    }

    /**
     * Read a private key from a stream of PEM or DER bytes, auto-detecting the encoding. The
     * stream is fully drained but not closed.
     *
     * @param keyStream the stream containing the key.
     * @return the recovered private key.
     * @throws IOException on a read, parse, or decryption failure.
     */
    public PrivateKey readKey(InputStream keyStream)
        throws IOException
    {
        return readKey(Streams.readAll(keyStream));
    }

    /**
     * Read a private key from a buffer of PEM or DER bytes, auto-detecting the encoding.
     *
     * @param encoding the key bytes.
     * @return the recovered private key.
     * @throws IOException on a parse or decryption failure.
     */
    public PrivateKey readKey(byte[] encoding)
        throws IOException
    {
        if (encoding.length == 0)
        {
            throw new PEMException("no key data found");
        }

        // A DER private key is always an ASN.1 SEQUENCE (0x30); anything else is treated as PEM,
        // so PEMParser can report the structural type and no element-counting heuristic is needed.
        if ((encoding[0] & 0xff) == 0x30)
        {
            return readDER(encoding);
        }

        return readKey(new InputStreamReader(new ByteArrayInputStream(encoding)));
    }

    /**
     * Read a private key from a PEM reader. The reader is consumed but not closed.
     *
     * @param reader a reader positioned at a PEM private key object.
     * @return the recovered private key.
     * @throws IOException on a parse or decryption failure.
     */
    public PrivateKey readKey(Reader reader)
        throws IOException
    {
        Object obj = new PEMParser(reader).readObject();
        if (obj == null)
        {
            throw new PEMException("no PEM object found");
        }

        if (obj instanceof PEMKeyPair)
        {
            return keyConverter.getPrivateKey(((PEMKeyPair)obj).getPrivateKeyInfo());
        }
        if (obj instanceof PrivateKeyInfo)
        {
            return keyConverter.getPrivateKey((PrivateKeyInfo)obj);
        }
        if (obj instanceof PEMEncryptedKeyPair)
        {
            PEMKeyPair keyPair = ((PEMEncryptedKeyPair)obj).decryptKeyPair(
                new JcePEMDecryptorProviderBuilder().build(requirePassword()));

            return keyConverter.getPrivateKey(keyPair.getPrivateKeyInfo());
        }
        if (obj instanceof PKCS8EncryptedPrivateKeyInfo)
        {
            return decryptPKCS8((PKCS8EncryptedPrivateKeyInfo)obj);
        }

        throw new PEMException("unrecognised private key object: " + obj.getClass().getName());
    }

    private PrivateKey readDER(byte[] der)
        throws IOException
    {
        ASN1Primitive primitive;

        ASN1InputStream aIn = new ASN1InputStream(der);
        try
        {
            primitive = aIn.readObject();
            if (aIn.readObject() != null)
            {
                throw new PEMException("extra data after private key");
            }
        }
        finally
        {
            aIn.close();
        }

        if (!(primitive instanceof ASN1Sequence))
        {
            throw new PEMException("DER private key is not a SEQUENCE");
        }

        ASN1Sequence seq = (ASN1Sequence)primitive;
        if (seq.size() < 2)
        {
            throw new PEMException("DER private key SEQUENCE too short");
        }

        // The shape guards above only constrain the outer SEQUENCE; the inner getInstance /
        // EncryptedPrivateKeyInfo decode can still throw an unchecked exception (e.g.
        // IllegalArgumentException, NoSuchElementException) on malformed inner content, so
        // wrap them to honour the throws IOException contract of the public readKey methods.
        try
        {
            ASN1Encodable first = seq.getObjectAt(0);
            if (first instanceof ASN1Integer)
            {
                // PrivateKeyInfo is { version, AlgorithmIdentifier SEQUENCE, ... };
                // an RSAPrivateKey (PKCS#1) is { version, modulus INTEGER, ... }.
                if (seq.getObjectAt(1) instanceof ASN1Sequence)
                {
                    return keyConverter.getPrivateKey(PrivateKeyInfo.getInstance(seq));
                }

                return keyConverter.getPrivateKey(wrapPKCS1(RSAPrivateKey.getInstance(seq)));
            }

            // EncryptedPrivateKeyInfo is { AlgorithmIdentifier SEQUENCE, encryptedData OCTET STRING }.
            return decryptPKCS8(new PKCS8EncryptedPrivateKeyInfo(der));
        }
        catch (IOException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PEMException("problem parsing private key: " + e.toString(), e);
        }
    }

    private PrivateKey decryptPKCS8(PKCS8EncryptedPrivateKeyInfo encInfo)
        throws IOException
    {
        try
        {
            InputDecryptorProvider decryptorProvider =
                new JceOpenSSLPKCS8DecryptorProviderBuilder().build(requirePassword());

            return keyConverter.getPrivateKey(encInfo.decryptPrivateKeyInfo(decryptorProvider));
        }
        catch (OperatorCreationException e)
        {
            throw new PEMException("unable to create PKCS#8 decryptor: " + e.getMessage(), e);
        }
        catch (PKCSException e)
        {
            throw new PEMException("unable to decrypt private key: " + e.getMessage(), e);
        }
    }

    /**
     * Wrap a bare PKCS#1 {@link RSAPrivateKey} as a PKCS#8 {@link PrivateKeyInfo} with the
     * rsaEncryption algorithm identifier, so the standard converter can consume it.
     */
    private static PrivateKeyInfo wrapPKCS1(RSAPrivateKey rsaPrivateKey)
        throws IOException
    {
        return new PrivateKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
            rsaPrivateKey);
    }

    private char[] requirePassword()
        throws PEMException
    {
        if (password == null)
        {
            throw new PEMException("encrypted private key but no password supplied");
        }

        return password;
    }
}
