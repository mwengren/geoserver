/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;

import org.geoserver.security.password.RandomPasswordProvider;
import org.geotools.data.Query;
import org.opengis.filter.Filter;

/**
 * Common security utility methods. 
 * 
 * @author mcr
 *
 */
public class SecurityUtils {

    /**
     * Spring Secruity 3.x drops the common base security exception
     * class SpringSecurityException, now the test is based on the package
     * name
     * 
     * @param t, the exception to check
     * @return true if the exception is caused by Spring Security
     */
    public static boolean  isSecurityException(Throwable t) {
        return t != null && t.getClass().getPackage().getName()
            .startsWith("org.springframework.security");
    }
    
    /**
     * Converts a char array to a byte array.
     * <p>
     * This method is unsafe since the charset is not specified, one of 
     * {@link #toBytes(char[], String)} or  {@link #toBytes(char[], Charset)} should be used 
     * instead. When not specified {@link Charset#defaultCharset()} is used.
     * </p>
     */
    public static byte[] toBytes(char[] ch) {
        return toBytes(ch, Charset.defaultCharset());
    }

    /**
     * Converts a char array to a byte array.
     */
    public static byte[] toBytes(char[] ch, String charset) {
        return toBytes(ch, Charset.forName(charset));
    }

    /**
     * Converts a char array to a byte array.
     */
    public static byte[] toBytes(char[] ch, Charset charset) {
        return charset.encode(CharBuffer.wrap(ch)).array();
    }

    /**
     * Converts byte array to char array.
     * <p>
     * This method is unsafe since the charset is not specified, one of 
     * {@link #toChars(byte[], String)} or  {@link #toChars(byte[], Charset)} should be used 
     * instead. When not specified {@link Charset#defaultCharset()} is used.
     * </p>
     */
    public static char[] toChars(byte[] b) {
        return toChars(b, Charset.defaultCharset());
    }

    /**
     * Converts byte array to char array.
     */
    public static char[] toChars(byte[] b, String charset) {
        return toChars(b, Charset.forName(charset));
    }

    /**
     * Converts byte array to char array.
     */
    public static char[] toChars(byte[] b, Charset charset) {
        return charset.decode(ByteBuffer.wrap(b)).array();
    }

    /**
     * Scrambles a char array overwriting all characters with random characters, used for 
     * scrambling plain text passwords after usage to avoid keeping them around in memory.
     */
    public static void scramble(char[] ch) {
        RandomPasswordProvider rpp = new RandomPasswordProvider();
        rpp.getRandomPassword(ch);
    }

    /**
     * Scrambles a byte array overwriting all characters with random characters, used for 
     * scrambling plain text passwords after usage to avoid keeping them around in memory.
     */
    public static void scramble(byte[] ch) {
        RandomPasswordProvider rpp = new RandomPasswordProvider();
        rpp.getRandomPassword(ch);
    }
    /**
     * Builds the write query based on the access limits class
     * 
     * @return
     */
    public static Query getWriteQuery(WrapperPolicy policy) {
        if(policy.getAccessLevel() != AccessLevel.READ_WRITE) {
            return new Query(null, Filter.EXCLUDE);
        } else if (policy.getLimits() == null) {
            return Query.ALL;
        } else if (policy.getLimits() instanceof VectorAccessLimits) {
            VectorAccessLimits val = (VectorAccessLimits) policy.getLimits();
            return val.getWriteQuery();
        } else {
            throw new IllegalArgumentException("SecureFeatureStore has been fed "
                    + "with unexpected AccessLimits class " + policy.getLimits().getClass());
        }
    }
}
