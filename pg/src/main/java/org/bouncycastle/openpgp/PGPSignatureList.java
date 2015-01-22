package org.bouncycastle.openpgp;

import java.util.Iterator;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Iterable;

/**
 * A list of PGP signatures - normally in the signature block after literal data.
 */
public class PGPSignatureList
    implements Iterable<PGPSignature>
{
    PGPSignature[]    sigs;
    
    public PGPSignatureList(
        PGPSignature[]    sigs)
    {
        this.sigs = new PGPSignature[sigs.length];
        
        System.arraycopy(sigs, 0, this.sigs, 0, sigs.length);
    }
    
    public PGPSignatureList(
        PGPSignature    sig)
    {
        this.sigs = new PGPSignature[1];
        this.sigs[0] = sig;
    }
    
    public PGPSignature get(
        int    index)
    {
        return sigs[index];
    }
    
    public int size()
    {
        return sigs.length;
    }
    
    public boolean isEmpty()
    {
        return (sigs.length == 0);
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator<PGPSignature> iterator()
    {
        return new Arrays.Iterator(sigs);
    }
}
