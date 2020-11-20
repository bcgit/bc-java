package javax.crypto.spec;

/**
 * This class specifies the source for encoding input P in OAEP Padding, as
 * defined in the {@link https://www.ietf.org/rfc/rfc3447.txt PKCS #1} standard.
 * 
 * <pre>
 *  
 *  PKCS1PSourceAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *  { OID id-pSpecified PARAMETERS OCTET STRING },
 *  ...  -- Allows for future expansion --
 *  }
 * </pre>
 */
public class PSource
{
    /**
     * This class is used to explicitly specify the value for encoding input P
     * in OAEP Padding.
     * 
     */
    public final static class PSpecified
        extends PSource
    {
        private byte[] p;

        /**
         * The encoding input P whose value equals byte[0].
         */
        public static final PSpecified DEFAULT = new PSpecified(new byte[0]);

        /**
         * Constructs the source explicitly with the specified value p as the
         * encoding input P.
         * 
         * @param p the value of the encoding input. The contents of the array
         *            are copied to protect against subsequent modification.
         * @throws NullPointerException if p is null.
         */
        public PSpecified(byte[] p)
        {
            super("PSpecified");
            if (p == null)
            {
                throw new NullPointerException("The encoding input is null");
            }
            this.p = copyOf(p);
        }

        /**
         * Returns the value of encoding input P.
         * 
         * @return the value of encoding input P. A new array is returned each
         *         time this method is called.
         */
        public byte[] getValue()
        {
            return copyOf(p);
        }

        private byte[] copyOf(byte[] b)
        {
            byte[] tmp = new byte[b.length];

            System.arraycopy(b, 0, tmp, 0, b.length);

            return tmp;
        }
    }

    private String pSrcName;

    /**
     * Constructs a source of the encoding input P for OAEP padding as defined
     * in the PKCS #1 standard using the specified PSource algorithm.
     * 
     * @param pSrcName the algorithm for the source of the encoding input P.
     * @throws NullPointerException if pSrcName is null.
     */
    protected PSource(String pSrcName)
    {
        if (pSrcName == null)
        {
            throw new NullPointerException("pSrcName is null");
        }
        this.pSrcName = pSrcName;
    }

    /**
     * Returns the PSource algorithm name.
     * 
     * @return the PSource algorithm name.
     */
    public String getAlgorithm()
    {
        return pSrcName;
    }
}
