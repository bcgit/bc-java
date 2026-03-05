package org.bouncycastle.jsse.provider;
import java.lang.ref.SoftReference;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIHostName;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.tls.KeyExchangeAlgorithm;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Properties;

class ProvPKCS12
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.keystore" + ".pkcs12.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {
            String defType = Properties.getPropertyValue("org.bouncycastle.pkcs12.default");

            if (defType != null)
            {
                provider.addAlgorithm("Alg.Alias.KeyStore.PKCS12", defType);
                provider.addAlgorithm("Alg.Alias.KeyStore.BCPKCS12", defType);
                provider.addAlgorithm("Alg.Alias.KeyStore.PKCS12-DEF", defType.substring(0, 5) + "-DEF" + defType.substring(6));
            }
            else
            {
                provider.addAlgorithm("KeyStore.PKCS12", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
                provider.addAlgorithm("KeyStore.BCPKCS12", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
                provider.addAlgorithm("KeyStore.PKCS12-DEF", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore");
            }

            provider.addAlgorithm("KeyStore.PKCS12-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
            provider.addAlgorithm("KeyStore.PKCS12-3DES-3DES", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore3DES");
            provider.addAlgorithm("KeyStore.PKCS12-AES256-AES128", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256");
            provider.addAlgorithm("KeyStore.PKCS12-AES256-AES128-GCM", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256GCM");

            provider.addAlgorithm("KeyStore.PKCS12-DEF-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore");
            provider.addAlgorithm("KeyStore.PKCS12-DEF-3DES-3DES", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore3DES");
            provider.addAlgorithm("KeyStore.PKCS12-DEF-AES256-AES128", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256");
            provider.addAlgorithm("KeyStore.PKCS12-DEF-AES256-AES128-GCM", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStoreAES256GCM");
        }
    }
}
