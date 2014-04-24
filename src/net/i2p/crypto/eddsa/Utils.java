package net.i2p.crypto.eddsa;

/**
 * @author str4d
 *
 */
public class Utils {
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
