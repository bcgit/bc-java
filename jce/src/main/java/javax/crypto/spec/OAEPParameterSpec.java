package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * This class specifies the set of parameters used with OAEP Padding, as defined
 * in the PKCS #1 standard. Its ASN.1 definition in PKCS#1 standard is described
 * below:
 * 
 * </pre>
 * 
 * RSAES-OAEP-params ::= SEQUENCE { hashAlgorithm [0] OAEP-PSSDigestAlgorithms
 * DEFAULT sha1, maskGenAlgorithm [1] PKCS1MGFAlgorithms DEFAULT mgf1SHA1,
 * pSourceAlgorithm [2] PKCS1PSourceAlgorithms DEFAULT pSpecifiedEmpty }
 * 
 * </pre>
 * 
 * where
 * 
 * <pre>
 * 
 * OAEP-PSSDigestAlgorithms ALGORITHM-IDENTIFIER ::= { { OID id-sha1 PARAMETERS
 * NULL }| { OID id-sha256 PARAMETERS NULL }| { OID id-sha384 PARAMETERS NULL } | {
 * OID id-sha512 PARAMETERS NULL }, ... -- Allows for future expansion -- }
 * PKCS1MGFAlgorithms ALGORITHM-IDENTIFIER ::= { { OID id-mgf1 PARAMETERS
 * OAEP-PSSDigestAlgorithms }, ... -- Allows for future expansion -- }
 * PKCS1PSourceAlgorithms ALGORITHM-IDENTIFIER ::= { { OID id-pSpecified
 * PARAMETERS OCTET STRING }, ... -- Allows for future expansion -- }
 * 
 * </pre>
 * 
 * @see PSource
 */
public class OAEPParameterSpec
    implements AlgorithmParameterSpec
{
    private String mdName;
    private String mgfName;
    private AlgorithmParameterSpec mgfSpec;
    private PSource pSrc;

    /**
     * Constructs a parameter set for OAEP padding as defined in the PKCS #1
     * standard using the specified message digest algorithm mdName, mask
     * generation function algorithm mgfName, parameters for the mask generation
     * function mgfSpec, and source of the encoding input P pSrc.
     * 
     * @param mdName the algorithm name for the message digest.
     * @param mgfName the algorithm name for the mask generation function.
     * @param mgfSpec the parameters for the mask generation function. If null is
     *            specified, null will be returned by getMGFParameters().
     * @param pSrc the source of the encoding input P.
     * @throws NullPointerException  if mdName, mgfName, or pSrc is null.
     */
    public OAEPParameterSpec(String mdName, String mgfName,
            AlgorithmParameterSpec mgfSpec, PSource pSrc)
    {
        this.mdName = mdName;
        this.mgfName = mgfName;
        this.mgfSpec = mgfSpec;
        this.pSrc = pSrc;
    }

    /**
     * Returns the message digest algorithm name.
     * 
     * @return the message digest algorithm name.
     */
    public String getDigestAlgorithm()
    {
        return mdName;
    }

    /**
     * Returns the mask generation function algorithm name.
     * 
     * @return the mask generation function algorithm name.
     */
    public String getMGFAlgorithm()
    {
        return mgfName;
    }

    /**
     * Returns the parameters for the mask generation function.
     * 
     * @return the parameters for the mask generation function.
     */
    public AlgorithmParameterSpec getMGFParameters()
    {
        return mgfSpec;
    }

    /**
     * Returns the source of encoding input P.
     * 
     * @return the source of encoding input P.
     */
    public PSource getPSource()
    {
        return pSrc;
    }
}
