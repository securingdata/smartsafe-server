package fr.securingdata.smartsafe.server;

import javacard.framework.*;
import javacard.security.*;

/**
 * Signature algorithm ALG_AES_CMAC_128 generates a 16-byte Cipher-based MAC (CMAC) 
 * using AES with blocksize 128 in CBC mode with ISO9797_M2 padding scheme.
 */
public class AESCMac128 extends Signature {

	// Algorithm constant (Matches the Javacard 3.x value)
	public static final byte ALG_AES_CMAC_128 = (byte) 49;

	private Signature cspAESMAC;

	private static final short ZERO             = (short) 0;
	private static final short LENGTH_BLOCK_AES = (short) 16;

	// Constant XOR value according to AES-CMAC-128 for subkey generation
	final byte CONST_RB  = (byte) 0x87;
	final byte CONST_PAD = (byte) 0x80;

	private byte[] buffer;
	private static final short LENGTH_BUFFER = (short) 48;

	// Holds L, K1 and K2 during processing
	private static final short OFFSET_SUBKEY = (short) 0;
	private static final short LENGTH_SUBKEY = (short) LENGTH_BLOCK_AES;

	// Holds the intermediate values as well as the final CMAC
	private static final short OFFSET_CMAC = (short)(OFFSET_SUBKEY + LENGTH_SUBKEY);
	
	public AESCMac128() {		
		cspAESMAC = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
		buffer = JCSystem.makeTransientByteArray(LENGTH_BUFFER, JCSystem.CLEAR_ON_DESELECT);
	}
	
	public byte getAlgorithm() {
		return ALG_AES_CMAC_128;
	}
	
	public short getLength() {
		return LENGTH_BLOCK_AES;
	}
	
	public void init(Key theKey, byte theMode)  {
		init(theKey, theMode, null, ZERO, ZERO);
	}

	public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen)  {
		// Reset our entire buffer
		Util.arrayFillNonAtomic(buffer, ZERO, LENGTH_BUFFER, (byte)0x00);

		/*
		 * SUBKEY GENERATION
		 */
		 
		// Step 1.  L := AES-128(K, const_Zero);  
		// In step 1, AES-128 with key K is applied to an all-zero input block.
		// NOTE: The IV is always zero for this step as it is not the actual CMAC calculation
		cspAESMAC.init(theKey, Signature.MODE_SIGN);
		cspAESMAC.sign(buffer, OFFSET_SUBKEY, LENGTH_BLOCK_AES, buffer, OFFSET_SUBKEY);		
		
		// buffer[OFFSET_SUBKEY] now contains the value of L, this is the only portion of the Subkey generation
		// we perform here, as the rest is in the sign() or verify() method when we know the length of the
		// final block.
		
		// Now we initialise cspAES with theKey and our IV (if supplied), for the actual CMAC operation
		if (bArray != null) {
			cspAESMAC.init(theKey, theMode, bArray, bOff, bLen);
		} else {
			cspAESMAC.init(theKey, theMode);			
		}		
	}
	
	public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset)  {

		/*
		 * First, call update() until we have <= LENGTH_BLOCK_AES bytes to process (which may be zero times)
		 * This ensures we are dealing only with the last block and also handles the case where
		 * inLength == 0.
		 */
		while (inLength > LENGTH_BLOCK_AES) {
			// Encipher the next block, storing it in the CMAC output
			cspAESMAC.update(inBuff, inOffset, LENGTH_BLOCK_AES);

			// Move to the next block
			inLength -= LENGTH_BLOCK_AES;
			inOffset += LENGTH_BLOCK_AES;
						
		}
		
		// We now know that we are dealing with the last block
		processFinalBlock(inBuff, inOffset, inLength);

		// We now know that buffer[OFFSET_CMAC] contains the final block to process

		// Perform the final CBC encipherment on the last block, writing it back to the same location
		cspAESMAC.sign(buffer, OFFSET_CMAC, LENGTH_BLOCK_AES, buffer, OFFSET_CMAC);
		
		// buffer[OFFSET_CMAC] now contains the CMAC (untrimmed)
		
		// Write the trimmed CMAC value to the outBuffer
		Util.arrayCopyNonAtomic(buffer, OFFSET_CMAC, sigBuff, sigOffset, LENGTH_BLOCK_AES);

		// Reset our internal buffer
		Util.arrayFillNonAtomic(buffer, ZERO, LENGTH_BUFFER, (byte)0x00);
		
		// Return the length of the CMAC
		return LENGTH_BLOCK_AES;
	}

	public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength) {
		if (sigLength <= 0 || sigLength > LENGTH_BLOCK_AES) return false;

		/*
		 * First, call update() until we have <= LENGTH_BLOCK_AES bytes to process (which may be zero times)
		 * This ensures we are dealing only with the last block and also handles the case where
		 * inLength == 0.
		 */
		while (inLength > LENGTH_BLOCK_AES) {
			// Encipher the next block, storing it in the CMAC output
			cspAESMAC.update(inBuff, inOffset, LENGTH_BLOCK_AES);

			// Move to the next block
			inLength -= LENGTH_BLOCK_AES;
			inOffset += LENGTH_BLOCK_AES;
						
		}
		
		// We now know that we are dealing with the last block
		processFinalBlock(inBuff, inOffset, inLength);

		// We now know that buffer[OFFSET_CMAC] contains the final block to process

		// Perform the final CBC encipherment on the last block, writing it back to the same location
		boolean result = cspAESMAC.verify(buffer, OFFSET_CMAC, LENGTH_BLOCK_AES, sigBuff, sigOffset, sigLength);
		Util.arrayFillNonAtomic(buffer, ZERO, LENGTH_BUFFER, (byte)0x00);

		return result;
	}

	public void update(byte[] inBuff, short inOffset, short inLength) {
		// This is an intermediate operation, so the length must be a multiple of the block size and non-zero
		if (inLength == 0 || (inLength % LENGTH_BLOCK_AES != 0)) {
			CryptoException.throwIt(CryptoException.ILLEGAL_USE);
		}
		
		// We now know that this is a multiple of the block length;
		while (inLength != 0) {
			// Encipher the next block, storing it in the CMAC output
			cspAESMAC.update(inBuff, inOffset, LENGTH_BLOCK_AES);

			// Move to the next block
			inLength -= LENGTH_BLOCK_AES;
			inOffset += LENGTH_BLOCK_AES;
		}
	}
                        	
	/**
	 * This method performs the steps associated with the final message block, including
	 * the generation of subkeys, message length checking, padding and final subkey XOR'ing
	 */
	private void processFinalBlock(byte[] inBuff, short inOffset, short inLength) {

		// In step 2, the number of blocks, n, is calculated.  
		// The number of blocks is the smallest integer value greater than or equal to the quotient 
		// determined by dividing the length parameter by the block length, 16 octets.		
		// NOTE: Not necessary as we know we're in the final block
		
		// In step 3, the length of the input message is checked.  
		// If the input length is 0 (null), the number of blocks to be processed shall be 1, and 
		// 	the flag shall be marked as not-complete-block (false).	
		// Otherwise, if the last block length is 128 bits, the flag is marked as complete-block 
		// 	(true); else mark the flag as not-complete-block (false).
		if (inLength == LENGTH_BLOCK_AES) {			
			// We process this as a complete block

			// In step 4, M_last is calculated by exclusive-OR'ing M_n and one of the previously calculated subkeys.  
			// If the last block is a complete block (true), then M_last is the exclusive-OR of M_n and K1.

			// Generate K1
			generateSubkey(buffer, OFFSET_SUBKEY);
			
			for (short i = 0; i < LENGTH_BLOCK_AES; i++) {
				buffer[(short)(OFFSET_CMAC + i)] = (byte)(inBuff[(short)(inOffset + i)] ^ buffer[(short)(OFFSET_SUBKEY + i)]);
			}			
			// buffer[OFFSET_CMAC] now contains the XOR of M_last and K1
		} else {
			// We process this as a not-complete-block
			// In step 4, M_last is calculated by exclusive-OR'ing M_n and one of the previously calculated subkeys.  
			// If the last block is a complete block (true), then M_last is the exclusive-OR of M_n and K1.
			// Otherwise, M_last is the exclusive-OR of padding(M_n) and K2.

			// Handle the special case (from step 3) where the input length is zero
			if (inLength == 0) {
				// Fill the CMAC buffer with zeroes
				Util.arrayFillNonAtomic(buffer, OFFSET_CMAC, LENGTH_BLOCK_AES, (byte)0x00);
				
				// Set the first byte to the padding constant
				buffer[OFFSET_CMAC] = CONST_PAD;				
			} else {
				
				// Copy the input buffer to our CMAC buffer
				Util.arrayCopyNonAtomic(inBuff, inOffset, buffer, OFFSET_CMAC, inLength);
				
				// Set the next byte to the padding constant and increment the length to cover it
				buffer[(short)(OFFSET_CMAC + inLength++)] = CONST_PAD;
				
				while (inLength != LENGTH_BLOCK_AES) {
					// Set the next byte to the zero and increment the length to cover it
					buffer[(short)(OFFSET_CMAC + inLength++)] = 0x00;
				}
			}

			// Generate K2 (just execute the Subkey routine twice)
			generateSubkey(buffer, OFFSET_SUBKEY);
			generateSubkey(buffer, OFFSET_SUBKEY);			
			for (short i = 0; i < LENGTH_BLOCK_AES; i++) {
				buffer[(short)(OFFSET_CMAC + i)] ^= buffer[(short)(OFFSET_SUBKEY + i)];
			}			
			// buffer[OFFSET_CMAC] now contains the XOR of padding(M_last) and K2
		}		
	}
	
	private void rollLeft(byte[] buffer, short offset, short length) {		
		// The carry byte is used to store the carry bit for both the current and previous bytes
		byte carry = 0;
		short end = (short)(offset + length - 1);

		// Traverse backwards through the array
		for (short i = end; i >= offset; i--) {
			// Store the carry bit for this byte
			carry |= (buffer[i] & 0x80);
			
			// Shift this byte by 1
			buffer[i] <<= 1;
			
			// Restore the previous byte's carry bit
			buffer[i] |= (carry & 0x01);
			
			// Unsigned-right-shift this byte's carry bit down to first position
			// NOTE: Due to int promotion of this signed type, we have to mask off
			// 		 to the first byte of the promoted carry value.
			carry = (byte)((carry & 0xFF) >>> 7);
		}
		
		// Apply the final carry bit (it will only ever be 0x01 or 0x00)
		// buffer[end] |= carry;
	}
	
	// This method will generate subkey K1 and return it to the same byte array
	// Calling it twice will generate K2
	private void generateSubkey(byte[] l, short offset) {				
		// Step 1 has already been performed in the init() routine
	
		// In step 2, K1 is derived through the following operation:
		
		// If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
		if ((l[offset] & 0x80) == 0x00) {
			rollLeft(buffer, offset, LENGTH_BLOCK_AES);
		}			
		// Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.		
		else {
			rollLeft(l, offset, LENGTH_BLOCK_AES);
			l[(short)(offset + LENGTH_BLOCK_AES - 1)] ^= CONST_RB;				
		}

		// In step 3, K2 is derived through the following operation:							
		// If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
		// Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

		// NOTE: This is just the same operation as for K1, but twice. So call it twice!
	}

	//305 methods in order to compile also in 305
	public byte getCipherAlgorithm() {
		return 0;
	}
	public byte getMessageDigestAlgorithm() {
		return 0;
	}
	public byte getPaddingAlgorithm() {
		return 0;
	}
	public void setInitialDigest(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4, short arg5) throws CryptoException {}
	public short signPreComputedHash(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4) throws CryptoException {
		return 0;
	}
	public boolean verifyPreComputedHash(byte[] arg0, short arg1, short arg2, byte[] arg3, short arg4, short arg5) throws CryptoException {
		return false;
	}
}