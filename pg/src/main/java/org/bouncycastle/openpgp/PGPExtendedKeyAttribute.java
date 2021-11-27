package org.bouncycastle.openpgp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.gpg.SExpression;

public class PGPExtendedKeyAttribute
{
    private final List<Object> values;

    public List<Object> getValues()
    {
        return values;
    }

    private PGPExtendedKeyAttribute(List<Object> values)
    {
        this.values = values;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {

        ArrayList<Object> values = new ArrayList<Object>();

        public Builder addAttribute(Object value)
        {
            if (value instanceof String || value instanceof SExpression.QuotedString)
            {
                this.values.add(value.toString());
            }
            else if (value instanceof byte[])
            {
                this.values.add(value);
            }
            else if (value instanceof SExpression)
            {
                Builder b = new Builder();
                for (Iterator it = ((SExpression)value).getValues().iterator(); it.hasNext();)
                {
                    b.addAttribute(it.next());
                }
                this.values.add(b.build());
            }
            else
            {
                throw new IllegalArgumentException("expected either string or SExpression object.");
            }

            return this;
        }

        public PGPExtendedKeyAttribute build()
        {
            return new PGPExtendedKeyAttribute(Collections.unmodifiableList(values));
        }

    }


}
