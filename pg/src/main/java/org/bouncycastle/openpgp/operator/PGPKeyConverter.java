package org.bouncycastle.openpgp.operator;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPKdfParameters;
import org.bouncycastle.util.BigIntegers;

public abstract class PGPKeyConverter
{
    protected PGPKeyConverter()
    {
        
    }

    /**
     * Reference: <a href="https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/13/">RFC Draft-ietf-openpgp-crypto-refresh-13</a>
     * <p>
     * This class provides information about the recommended algorithms to use
     * depending on the key version and curve type in OpenPGP keys.
     *
     * <p>
     * For OpenPGP keys using the specified curves, the following algorithms are recommended:
     * <table border="1" cellpadding="5">
     *   <caption>Recommended Algorithms for OpenPGP Keys</caption>
     *   <tr>
     *     <th>Curve</th>
     *     <th>Hash Algorithm</th>
     *     <th>Symmetric Algorithm</th>
     *   </tr>
     *   <tr>
     *     <td>NIST P-256</td>
     *     <td>SHA2-256</td>
     *     <td>AES-128</td>
     *   </tr>
     *   <tr>
     *     <td>NIST P-384</td>
     *     <td>SHA2-384</td>
     *     <td>AES-192</td>
     *   </tr>
     *   <tr>
     *     <td>NIST P-521</td>
     *     <td>SHA2-512</td>
     *     <td>AES-256</td>
     *   </tr>
     *   <tr>
     *     <td>brainpoolP256r1</td>
     *     <td>SHA2-256</td>
     *     <td>AES-128</td>
     *   </tr>
     *   <tr>
     *     <td>brainpoolP384r1</td>
     *     <td>SHA2-384</td>
     *     <td>AES-192</td>
     *   </tr>
     *   <tr>
     *     <td>brainpoolP512r1</td>
     *     <td>SHA2-512</td>
     *     <td>AES-256</td>
     *   </tr>
     *   <tr>
     *     <td>Curve25519Legacy</td>
     *     <td>SHA2-256</td>
     *     <td>AES-128</td>
     *   </tr>
     *   <tr>
     *     <td>Curve448</td>
     *     <td>SHA2-512</td>
     *     <td>AES-256</td>
     *   </tr>
     * </table>
     */
    protected PGPKdfParameters implGetKdfParameters(ASN1ObjectIdentifier curveID, PGPAlgorithmParameters algorithmParameters)
    {
        if (null == algorithmParameters)
        {
            if (curveID.equals(SECObjectIdentifiers.secp256r1) || curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1)
                || curveID.equals(CryptlibObjectIdentifiers.curvey25519) || curveID.equals(EdECObjectIdentifiers.id_X25519))
            {
                return new PGPKdfParameters(HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128);
            }
            else if (curveID.equals(SECObjectIdentifiers.secp384r1) || curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
            {
                return new PGPKdfParameters(HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_192);
            }
            else if (curveID.equals(SECObjectIdentifiers.secp521r1) || curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP512r1)
                || curveID.equals(EdECObjectIdentifiers.id_X448))
            {
                return new PGPKdfParameters(HashAlgorithmTags.SHA512, SymmetricKeyAlgorithmTags.AES_256);
            }
            else
            {
                throw new IllegalArgumentException("unknown curve");
            }
        }
        return (PGPKdfParameters)algorithmParameters;
    }

    protected PrivateKeyInfo getPrivateKeyInfo(ASN1ObjectIdentifier algorithm, int keySize, byte[] key)
        throws IOException
    {
        return (new PrivateKeyInfo(new AlgorithmIdentifier(algorithm),
            new DEROctetString(BigIntegers.asUnsignedByteArray(keySize, new BigInteger(1, key)))));
    }

    protected PrivateKeyInfo getPrivateKeyInfo(ASN1ObjectIdentifier algorithm, byte[] key)
        throws IOException
    {
        return (new PrivateKeyInfo(new AlgorithmIdentifier(algorithm), new DEROctetString(key)));
    }
}
