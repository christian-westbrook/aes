//=================================================================================================
//Program      : AES
//Class        : AESMethods1
//Package      : default
//Programmer   : Christian Westbrook
//Date Created : 9/22/2018
//Last Updated : 9/26/2018
//Abstract     : This class implements five layers of the Advanced Encryption Standard, namely
//				 the KeyAddition, ByteSubstitution, ShiftRows, MixColumns, and KeySchedule layers.
//=================================================================================================

public class AESMethods2
{	

	//====================================================================
	// Method	: keyAddition()
	// Abstract : Adds the round subkey to the data path
	//
	// Input	: Data path (String of 16 characters)
	//			  Round subkey (String of 16 characters)
	// Process	: Add the round subkey to the input data using addition in
	//			  the Galois field GF(2). This is logically equivalent to
	//			  a bitwise XOR operation. To accomplish this, the input
	//            text string and bit string are converted to bytes. The
	//            bytes then undergo an XOR operation, the result of which
	//            is converted back to a string for output.
	// Output	: New data
	//====================================================================
	public static String keyAddition(String text, String key)
	{
		// Confirm that both the input data path and round subkey are of valid block size (16 bytes, 128 bits)
		if(text.length() != 16 || key.length() != 16)
		{
			System.out.println("[Error] Invalid block size input to keyAddition(). Halting execution.");
			System.exit(1);
		}
		
		// Convert textual data to numerical data that can be operated on mathematically
		byte[] textBytes = text.getBytes();
		byte[] keyBytes = key.getBytes();
		
		// Add the key bits to the data bits in the Galois field GF(2), and then convert
		// the new numerical data back to textual data
		char[] newChars = new char[16];
		
		for(int i = 0; i < 16; i++)
			newChars[i] = (char) (textBytes[i] ^ keyBytes[i]);
		
		// Return the new data
		return new String(newChars);
	}
	
	//====================================================================
	// Method	: byteSubstitution()
	// Abstract : Linear substitution of bytes based on a predefined
	//			  substitution box
	//
	// Input	: Data path (String of 16 characters)
	// Process	: Convert the input text string to a series of hex strings.
	//            Use the predefined substitution box to perform a byte
	//            substitution object on the hex strings, and then convert
	//            the new hex strings back to a string of ASCII characters
	//            for output.
	// Output	: New data
	//====================================================================
	public static String byteSubstitution(String text)
	{
		// Confirm that the input data path is of valid block size.
		if(text.length() != 16)
		{
			System.out.println("[Error] Invalid block size input to byteSubstitution(). Halting execution.");
			System.exit(1);
		}
		
		// Convert textual data to numerical data that can be operated on mathematically
		byte[] textBytes = text.getBytes();
		
		// S-box conversion table
		String[][] sBox =  {{"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
							{"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
							{"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
							{"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
							{"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
							{"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
							{"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
							{"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
							{"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
							{"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
							{"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
							{"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
							{"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
							{"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
							{"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
							{"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}};
		
		// Convert each byte to a hex string, use the s-box to perform byte substitution,
		// and then convert each hex string to an ASCII character
		char[] newChars = new char[16];
		
		for(int i = 0; i < 16; i++)
		{
			String hexString = String.format("%02X ", textBytes[i]);
			
			int a = Character.digit(hexString.charAt(0), 16);
			int b = Character.digit(hexString.charAt(1), 16);
			
			String newHexString = sBox[a][b];
			
			int c = Character.digit(newHexString.charAt(0), 16);
			int d = Character.digit(newHexString.charAt(1), 16);
			int e = (c * 16) + d;
			
			newChars[i] = (char) e;
		}
		
		// Return the new data
		return new String(newChars);
	}
	
	//====================================================================
	// Method	: shiftRows()
	// Abstract : Shift each row of the data path matrix by a predefined
	//            number of indices.
	//
	// Input	: Data path (String of 16 characters)
	// Process	: Map each character in the input string to the correct
	//            position in a new character array corresponding to the
	//            predefined shift. Return the new string of data as
	//            output.
	// Output	: New data
	//====================================================================
	public static String shiftRows(String text)
	{
		// Confirm that the input data path is of valid block size.
		if(text.length() != 16)
		{
			System.out.println("[Error] Invalid block size input to shiftRows(). Halting execution.");
			System.exit(1);
		}
		
		// Create a character array to store the shifted data
		char[] newChars = new char[16];
		
		// Shift data from the input string into the new character array
		newChars[0] = text.charAt(0);
		newChars[1] = text.charAt(5);
		newChars[2] = text.charAt(10);
		newChars[3] = text.charAt(15);
		newChars[4] = text.charAt(4);
		newChars[5] = text.charAt(9);
		newChars[6] = text.charAt(14);
		newChars[7] = text.charAt(3);
		newChars[8] = text.charAt(8);
		newChars[9] = text.charAt(13);
		newChars[10] = text.charAt(2);
		newChars[11] = text.charAt(7);
		newChars[12] = text.charAt(12);
		newChars[13] = text.charAt(1);
		newChars[14] = text.charAt(6);
		newChars[15] = text.charAt(11);
		
		// Return the new data
		return new String(newChars);
	}
	
	//====================================================================
	// Method	: mixColumns()
	// Abstract : 
	//
	// Input	: Data path (String of 16 characters)
	// Process	: 
	// Output	: New data
	//====================================================================
	public String mixColumns(String text)
	{
		return null;
	}
	
	//====================================================================
	// Method	: keySchedule()
	// Abstract : 
	//
	// Input	: 
	// Process	: 
	// Output	: 
	//====================================================================
	public String keySchedule(String key, int round)
	{
		return null;
	}
	
	public static void main(String[] args)
	{
		// Unit test for keyAddition()
		String text = "0000000000000000"; 			// '0' = 48 base 10 = 00110000 base 2
		String key  = "aaaaaaaaaaaaaaaa"; 			// 'a' = 97 base 10 = 01100001 base 2
													// ----------------------------------- GF(2) Addition
													// 'Q' = 81 base 10 = 01010001 base 2
							
		System.out.println("Unit Test: keyAddition()");
		System.out.println(keyAddition(text, key) + "\n");
		
		// Unit test for byteSubstitution
		text = "PPPPPPPPPPPPPPPP";					// 'P' = 80 base 10 = 50 base 16
													// ------------------------------- ByteSubstitution
													// 'S' = 83 base 10 = 53 base 16
													
		System.out.println("Unit Test: byteSubstitution()");
		System.out.println(byteSubstitution(text) + "\n");
		
		// Unit test for shiftRows()
		text = "ABCDEFGHIJKLMNOP";					// ABCDEFGHIJKLMNOP
													// -------------------------------- ShiftRows
													// AFKPEJODINCHMBGL
													
		System.out.println("Unit Test: shiftRows()");
		System.out.println(shiftRows(text));
		
		
	}
}