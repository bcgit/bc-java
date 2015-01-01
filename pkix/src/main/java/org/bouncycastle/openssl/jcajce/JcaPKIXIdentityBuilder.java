package org.bouncycastle.openssl.jcajce;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkix.jcajce.JcaPKIXIdentity;

/**
 * Builder for a private/public identity object representing a "user"
 */
public class JcaPKIXIdentityBuilder
{
    private JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
    private JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();

    public JcaPKIXIdentityBuilder()
    {

    }

    public JcaPKIXIdentityBuilder setProvider(Provider provider)
    {
        this.keyConverter = keyConverter.setProvider(provider);
        this.certConverter = certConverter.setProvider(provider);

        return this;
    }

    public JcaPKIXIdentityBuilder setProvider(String providerName)
    {
        this.keyConverter = keyConverter.setProvider(providerName);
        this.certConverter = certConverter.setProvider(providerName);

        return this;
    }

    /**
     * Build an identity from the passed in key and certificate file in PEM format.
     *
     * @param keyFile  the PEM file containing the key
     * @param certificateFile the PEM file containing the certificate
     * @return an identity object.
     * @throws IOException on a general parsing error.
     * @throws CertificateException on a certificate parsing error.
     */
    public JcaPKIXIdentity build(File keyFile, File certificateFile)
        throws IOException, CertificateException
    {
        checkFile(keyFile);
        checkFile(certificateFile);

        FileInputStream keyStream = new FileInputStream(keyFile);
        FileInputStream certificateStream = new FileInputStream(certificateFile);

        JcaPKIXIdentity rv =  build(keyStream, certificateStream);

        keyStream.close();
        certificateStream.close();

        return rv;
    }

    /**
     * Build an identity from the passed in key and certificate stream in PEM format.
     *
     * @param keyStream  the PEM stream containing the key
     * @param certificateStream the PEM stream containing the certificate
     * @return an identity object.
     * @throws IOException on a general parsing error.
     * @throws CertificateException on a certificate parsing error.
     */
    public JcaPKIXIdentity build(InputStream keyStream, InputStream certificateStream)
        throws IOException, CertificateException
    {
        PEMParser keyParser = new PEMParser(new InputStreamReader(keyStream));

        PrivateKey privKey;

        Object keyObj = keyParser.readObject();
        if (keyObj instanceof PEMKeyPair)
        {
            PEMKeyPair kp = (PEMKeyPair)keyObj;

            privKey = keyConverter.getPrivateKey(kp.getPrivateKeyInfo());
        }
        else if (keyObj instanceof PrivateKeyInfo)
        {
            privKey = keyConverter.getPrivateKey((PrivateKeyInfo)keyObj);
        }
        else
        {
            throw new IOException("unrecognised private key file"); // TODO: handle encrypted private keys
        }

        PEMParser certParser = new PEMParser(new InputStreamReader(certificateStream));

        List certs = new ArrayList();
        Object certObj;
        while ((certObj = certParser.readObject()) != null)
        {
            certs.add(certConverter.getCertificate((X509CertificateHolder)certObj));
        }

        return new JcaPKIXIdentity(privKey, (X509Certificate[])certs.toArray(new X509Certificate[certs.size()]));
    }

    private void checkFile(File file)
        throws IOException
    {
        if (file.canRead())
        {
            if (file.exists())
            {
                throw new IOException("Unable to open file " + file.getPath() + " for reading.");
            }
            throw new FileNotFoundException("Unable to open " + file.getPath() + ": it does not exist.");
        }
    }
}
