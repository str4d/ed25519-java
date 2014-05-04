package net.i2p.crypto.eddsa;

/**
 * @author str4d
 *
 */
public class Utils {
    /**
     * Constant-time byte comparison.
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(int b, int c) {
        return b == c ? 1 : 0;
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
     * Get the i'th bit of a byte array.
     * @param h the byte array.
     * @param i the bit index.
     * @return 0 or 1, the value of the i'th bit in h
     */
    public static int bit(byte[] h, int i) {
        return (h[i/8] >> (i%8)) & 1;
    }
}
