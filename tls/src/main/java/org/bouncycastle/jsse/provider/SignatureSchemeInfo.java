package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;

class SignatureSchemeInfo
{
    static final int historical_rsa_md5 = 0x0101;
    static final int historical_rsa_sha224 = 0x0301;

    static final int historical_dsa_sha1 = 0x0202;
    static final int historical_dsa_sha224 = 0x0302;
    static final int historical_dsa_sha256 = 0x0402;

    static final int historical_ecdsa_sha224 = 0x0303;

    static String[] getJcaSignatureAlgorithms(Collection<SignatureSchemeInfo> infos)
    {
        if (null == infos)
        {
            return new String[0];
        }

        ArrayList<String> result = new ArrayList<String>();
        for (SignatureSchemeInfo info : infos)
        {
            result.add(info.getJcaSignatureAlgorithm());
        }
        return result.toArray(new String[0]);
    }

    private final int signatureScheme;
    private final String name;
    private final String jcaSignatureAlgorithm;
    private final String keyAlgorithm;

    SignatureSchemeInfo(int signatureScheme, String name, String jcaSignatureAlgorithm, String keyAlgorithm)
    {
        this.signatureScheme = signatureScheme;
        this.name = name;
        this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
    }

    int getSignatureScheme()
    {
        return signatureScheme;
    }

    String getName()
    {
        return name;
    }

    String getJcaSignatureAlgorithm()
    {
        return jcaSignatureAlgorithm;
    }

    String getKeyAlgorithm()
    {
        return keyAlgorithm;
    }

    boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, name, null)
            && algorithmConstraints.permits(primitives, keyAlgorithm, null)
            // TODO SunJSSE passes AlgorithmParameters here (for PSS algorithms)
            && algorithmConstraints.permits(primitives, jcaSignatureAlgorithm, null);
            // TODO[tls13] Some schemes have a specific NamedGroup, check permission if TLS 1.3+
    }
}
