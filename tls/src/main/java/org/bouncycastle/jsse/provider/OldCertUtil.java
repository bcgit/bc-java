package org.bouncycastle.jsse.provider;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.SSLPeerUnverifiedException;

class OldCertUtil
{
    public static javax.security.cert.X509Certificate[] getPeerCertificateChain(boolean isFips, X509Certificate[] peerCertificates) throws SSLPeerUnverifiedException
    {
        /*
         * "Note: this method exists for compatibility with previous releases. New applications
         * should use getPeerCertificates() instead."
         */
        javax.security.cert.X509Certificate[] chain = new javax.security.cert.X509Certificate[peerCertificates.length];

        try
        {
            for (int i = 0; i < peerCertificates.length; ++i)
            {
                if (isFips)
                {
                    chain[i] = new X509CertificateWrapper(peerCertificates[i]);
                }
                else
                {
                    chain[i] = javax.security.cert.X509Certificate.getInstance(peerCertificates[i].getEncoded());
                }
            }
        }
        catch (Exception e)
        {
            throw new SSLPeerUnverifiedException(e.getMessage());
        }

        return chain;
    }

    @SuppressWarnings("deprecation")
    private static class X509CertificateWrapper extends javax.security.cert.X509Certificate
    {
        private final X509Certificate c;

        private X509CertificateWrapper(X509Certificate c)
        {
            this.c = c;
        }

        @Override
        public void checkValidity()
            throws javax.security.cert.CertificateExpiredException, javax.security.cert.CertificateNotYetValidException
        {
            try
            {
                c.checkValidity();
            }
            catch (CertificateExpiredException e)
            {
                throw new javax.security.cert.CertificateExpiredException(e.getMessage());
            }
            catch (CertificateNotYetValidException e)
            {
                throw new javax.security.cert.CertificateNotYetValidException(e.getMessage());
            }
        }

        @Override
        public void checkValidity(Date date)
            throws javax.security.cert.CertificateExpiredException, javax.security.cert.CertificateNotYetValidException
        {
            try
            {
                c.checkValidity(date);
            }
            catch (CertificateExpiredException e)
            {
                throw new javax.security.cert.CertificateExpiredException(e.getMessage());
            }
            catch (CertificateNotYetValidException e)
            {
                throw new javax.security.cert.CertificateNotYetValidException(e.getMessage());
            }
        }

        @Override
        public int getVersion()
        {
            return c.getVersion() - 1;
        }

        @Override
        public BigInteger getSerialNumber()
        {
            return c.getSerialNumber();
        }

        @Override
        public Principal getIssuerDN()
        {
            return c.getIssuerX500Principal();
        }

        @Override
        public Principal getSubjectDN()
        {
            return c.getSubjectX500Principal();
        }

        @Override
        public Date getNotBefore()
        {
            return c.getNotBefore();
        }

        @Override
        public Date getNotAfter()
        {
            return c.getNotAfter();
        }

        @Override
        public String getSigAlgName()
        {
            return c.getSigAlgName();
        }

        @Override
        public String getSigAlgOID()
        {
            return c.getSigAlgOID();
        }

        @Override
        public byte[] getSigAlgParams()
        {
            return c.getSigAlgParams();
        }

        @Override
        public byte[] getEncoded() throws javax.security.cert.CertificateEncodingException
        {
            try
            {
                return c.getEncoded();
            }
            catch (CertificateEncodingException e)
            {
                throw new javax.security.cert.CertificateEncodingException(e.getMessage());
            }
        }

        @Override
        public void verify(PublicKey key) throws javax.security.cert.CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException
        {
            try
            {
                c.verify(key);
            }
            catch (CertificateEncodingException e)
            {
                throw new javax.security.cert.CertificateEncodingException(e.getMessage());
            }
            catch (CertificateExpiredException e)
            {
                throw new javax.security.cert.CertificateExpiredException(e.getMessage());
            }
            catch (CertificateNotYetValidException e)
            {
                throw new javax.security.cert.CertificateNotYetValidException(e.getMessage());
            }
            catch (CertificateParsingException e)
            {
                throw new javax.security.cert.CertificateParsingException(e.getMessage());
            }
            catch (CertificateException e)
            {
                throw new javax.security.cert.CertificateException(e.getMessage());
            }
        }

        @Override
        public void verify(PublicKey key, String sigProvider) throws javax.security.cert.CertificateException,
            NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
        {
            try
            {
                c.verify(key, sigProvider);
            }
            catch (CertificateEncodingException e)
            {
                throw new javax.security.cert.CertificateEncodingException(e.getMessage());
            }
            catch (CertificateExpiredException e)
            {
                throw new javax.security.cert.CertificateExpiredException(e.getMessage());
            }
            catch (CertificateNotYetValidException e)
            {
                throw new javax.security.cert.CertificateNotYetValidException(e.getMessage());
            }
            catch (CertificateParsingException e)
            {
                throw new javax.security.cert.CertificateParsingException(e.getMessage());
            }
            catch (CertificateException e)
            {
                throw new javax.security.cert.CertificateException(e.getMessage());
            }
        }

        @Override
        public String toString()
        {
            return c.toString();
        }

        @Override
        public PublicKey getPublicKey()
        {
            return c.getPublicKey();
        }
    }
}
