package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsUtils;

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

    static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(int signatureScheme)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException();
        }

        short hashAlgorithm = (short)((signatureScheme >>> 8) & 0xFF);
        short signatureAlgorithm = (short)(signatureScheme & 0xFF);

        return SignatureAndHashAlgorithm.getInstance(hashAlgorithm, signatureAlgorithm);
    }

    static int getSignatureScheme(SignatureAndHashAlgorithm sigAndHashAlg)
    {
        if (null == sigAndHashAlg)
        {
            throw new NullPointerException();
        }

        short hashAlgorithm = sigAndHashAlg.getHash(), signatureAlgorithm = sigAndHashAlg.getSignature();

        return ((hashAlgorithm & 0xFF) << 8) | (signatureAlgorithm & 0xFF);
    }

    private final int signatureScheme;
    private final String name;
    private final String jcaSignatureAlgorithm;
    private final String keyAlgorithm;
    private final AlgorithmParameters algorithmParameters;
    private final boolean enabled;

    SignatureSchemeInfo(int signatureScheme, String name, String jcaSignatureAlgorithm, String keyAlgorithm,
        AlgorithmParameters algorithmParameters, boolean enabled)
    {
        if (!TlsUtils.isValidUint16(signatureScheme))
        {
            throw new IllegalArgumentException();
        }

        this.signatureScheme = signatureScheme;
        this.name = name;
        this.jcaSignatureAlgorithm = jcaSignatureAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.algorithmParameters = algorithmParameters;
        this.enabled = enabled;
    }

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        return getSignatureAndHashAlgorithm(signatureScheme);
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

    boolean isEnabled()
    {
        return enabled;
    }

    boolean isPermittedBy(BCAlgorithmConstraints algorithmConstraints)
    {
        Set<BCCryptoPrimitive> primitives = JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;

        return algorithmConstraints.permits(primitives, name, null)
            && algorithmConstraints.permits(primitives, keyAlgorithm, null)
            && algorithmConstraints.permits(primitives, jcaSignatureAlgorithm, algorithmParameters);
            // TODO[tls13] Some schemes have a specific NamedGroup, check permission if TLS 1.3+
    }

    @Override
    public String toString()
    {
        return name + "(0x" + Integer.toHexString(signatureScheme) + ")";
    }
}
