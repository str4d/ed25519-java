package net.i2p.crypto.eddsa;

/**
 * @author str4d
 *
 */
public class Utils {
    /**
     * Constant-time byte comparison.
     */
    public static int equal(int b, int c) {
        int result = 0;
        for (int i = 0; i < 8; i++) {
            result |= (b >> i & 1) ^ (c >> i & 1);
        }
        return result == 0 ? 1 : 0;
    }

    /**
     * Constant-time determine if byte is negative.
     * @param b the byte to check.
     * @return 1 if the byte is negative, 0 otherwise.
     */
    public static int negative(int b) {
        return (b >> 8) & 1;
    }

    /**
     * Convert a to radix 16.
     * @param a = a[0]+256*a[1]+...+256^31 a[31]
     * @return
     */
    public static byte[] toRadix16(byte[] a) {
        byte[] e = new byte[64];
        int i;
        // Radix 16 notation
        for (i = 0; i < 32; i++) {
            e[2*i+0] = (byte) ((a[i] >> 0) & 15);
            e[2*i+1] = (byte) ((a[i] >> 4) & 15);
        }
        /* each e[i] is between 0 and 15 */
        /* e[63] is between 0 and 7 */
        int carry = 0;
        for (i = 0; i < 63; i++) {
            e[i] += carry;
            carry = e[i] + 8;
            carry >>= 4;
        e[i] -= carry << 4;
        }
        e[63] += carry;
        /* each e[i] is between -8 and 8 */
        return e;
    }

    /**
     * I don't really know what this method does.
     * @param a
     * @return
     */
    public static byte[] slide(byte[] a) {
        byte[] r = new byte[256];
        int i;
        int b;
        int k;

        for (i = 0;i < 256;++i) {
            r[i] = (byte) (1 & (a[i >> 3] >> (i & 7)));
        }

        for (i = 0;i < 256;++i) {
            if (r[i] != 0) {
                for (b = 1; b <= 6 && i + b < 256; ++b) {
                    if (r[i + b] != 0) {
                        if (r[i] + (r[i + b] << b) <= 15) {
                            r[i] += r[i + b] << b; r[i + b] = 0;
                        } else if (r[i] - (r[i + b] << b) >= -15) {
                            r[i] -= r[i + b] << b;
                            for (k = i + b; k < 256; ++k) {
                                if (r[k] == 0) {
                                    r[k] = 1;
                                    break;
                                }
                                r[k] = 0;
                            }
                        } else
                            break;
                    }
                }
            }
        }

        return r;
    }

    /**
     * Get the i'th bit of a byte array.
     * @param h the byte array.
     * @param i the bit index.
     * @return the value of the i'th bit in h.
     */
    public static int bit(byte[] h, int i) {
        return h[i/8] >> (i%8) & 1;
    }

    /**
     * Converts bytes to a hex string.
     * @param raw the byte[] to be converted.
     * @return the hex representation as a string.
     */
    public static String getHex(byte[] raw) {
        if ( raw == null ) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(Character.forDigit((b & 0xF0) >> 4, 16))
            .append(Character.forDigit((b & 0x0F), 16));
        }
        return hex.toString();
    }

    /**
     * Converts a hex string to bytes.
     * @param s the hex string to be converted.
     * @return the byte[]
     */
    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
