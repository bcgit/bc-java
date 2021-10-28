package org.bouncycastle.openpgp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.gpg.SExpression;

public class PGPExtendedKeyAttribute
{
    public final List<Object> values;

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
                for (Object item : ((SExpression)value).getValues())
                {
                    b.addAttribute(item);
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
