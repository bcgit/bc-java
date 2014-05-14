package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.util.Arrays;

public final class KDFCounterParameters
    implements DerivationParameters
{

    private final byte[] ki;
    private final byte[] fixedInputData_beforeCtr;
    private final byte[] fixedInputData_afterCtr;
    private final int r;

    /**
     * This KDF has been defined by the publicly available NIST SP 800-108 specification.
     * NIST SP800-108 allows for alternative orderings of the input fields, meaning that the input can be formated in multiple ways.
     * There are 3 supported formats:  - Below [i]_2 is a counter of r-bits length concatenated to the fixedInputData.
     * 1: K(i) := PRF( KI, [i]_2 || Label || 0x00 || Context || [L]_2 ) with the counter at the very beginning of the fixedInputData (The default implementation has this format)
     * 2: K(i) := PRF( KI, Label || 0x00 || Context || [L]_2 || [i]_2 ) with the counter at the very end of the fixedInputData
     * 3a: K(i) := PRF( KI, Label || 0x00 || [i]_2 || Context || [L]_2 ) OR:
     * 3b: K(i) := PRF( KI, Label || 0x00 || [i]_2 || [L]_2 || Context ) OR:
     * 3c: K(i) := PRF( KI, Label || [i]_2 || 0x00 || Context || [L]_2 ) etc... with the counter somewhere in the 'middle' of the fixedInputData.
     * 
     * This function must be called with the following KDFCounterParameters():
     *  - KI
     *  - The part of the fixedInputData that comes BEFORE the counter OR null
     *  - the part of the fixedInputData that comes AFTER the counter OR null
     *  - the length of the counter in bits (not bytes)
     *  
     * Resulting function calls assuming an 8 bit counter.
     * 1.  KDFCounterParameters(ki, 	null, 									"Label || 0x00 || Context || [L]_2]",	8);
     * 2.  KDFCounterParameters(ki, 	"Label || 0x00 || Context || [L]_2]", 	null,									8);
     * 3a. KDFCounterParameters(ki, 	"Label || 0x00",						"Context || [L]_2]",					8);
     * 3b. KDFCounterParameters(ki, 	"Label || 0x00",						"[L]_2] || Context",					8);
     * 3c. KDFCounterParameters(ki, 	"Label", 								"0x00 || Context || [L]_2]",			8);
     */
    
    public KDFCounterParameters(byte[] ki, byte[] fixedInputData, int r)
    {
    	//Retained for backwards compatibility
    	this(ki, null, fixedInputData, r);
    }
    	
    public KDFCounterParameters(byte[] ki, byte[] fixedInputData_beforeCtr, byte[] fixedInputData_afterCtr, int r)
    {
        if (ki == null)
        {
            throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
        }
        this.ki = Arrays.clone(ki);

        if (fixedInputData_beforeCtr == null)
        {
            this.fixedInputData_beforeCtr = new byte[0];
        }
        else
        {
            this.fixedInputData_beforeCtr = Arrays.clone(fixedInputData_beforeCtr);
        }
        
        if (fixedInputData_afterCtr == null)
        {
            this.fixedInputData_afterCtr = new byte[0];
        }
        else
        {
            this.fixedInputData_afterCtr = Arrays.clone(fixedInputData_afterCtr);
        }

        if (r != 8 && r != 16 && r != 24 && r != 32)
        {
            throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
        }
        this.r = r;
    }
    
    public byte[] getKI()
    {
        return ki;
    }

    public byte[] getFixedInputData()
    {
    	//Retained for backwards compatibility
        return Arrays.clone(fixedInputData_afterCtr);
    }

    public byte[] getFixedInputData_beforeCtr()
    {
        return Arrays.clone(fixedInputData_beforeCtr);
    }
    
    public byte[] getFixedInputData_afterCtr()
    {
        return Arrays.clone(fixedInputData_afterCtr);
    }    
    public int getR()
    {
        return r;
    }
}
