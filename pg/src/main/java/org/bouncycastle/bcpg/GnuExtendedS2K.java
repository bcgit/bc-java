package org.bouncycastle.bcpg;

/**
 * Add a constructor fort GNU-extended S2K
 * <p>
 * This extension is documented on GnuPG documentation DETAILS file,
 * section "GNU extensions to the S2K algorithm". Its support is
 * already present in S2K class but lack for a constructor.
 */
public class GnuExtendedS2K
    extends S2K
{
    public GnuExtendedS2K(int mode)
    {
        super(0x0);
        this.type = GNU_DUMMY_S2K;
        this.protectionMode = mode;
    }
}
