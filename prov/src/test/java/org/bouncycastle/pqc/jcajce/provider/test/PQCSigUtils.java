package org.bouncycastle.pqc.jcajce.provider.test;

import org.bouncycastle.util.Arrays;

public class PQCSigUtils
{
    static class SigWrapper
    {
        private final byte[] sig;

        SigWrapper(byte[] sig)
        {
            this.sig = sig;
        }

        public boolean equals(Object o)
        {
            if (o instanceof SigWrapper)
            {
                SigWrapper other = (SigWrapper)o;

                return Arrays.areEqual(other.sig, this.sig);
            }

            return false;
        }

        public int hashCode()
        {
            return Arrays.hashCode(this.sig);
        }
    }
}
