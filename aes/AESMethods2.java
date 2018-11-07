package aes;

/**
 *	This class implements five layers of the Advanced Encryption Standard,
 *	namely the KeyAddition, ByteSubstitution, ShiftRows, MixColumns, and
 * 	KeySchedule layers.
 *
 *	@author		Christian Westbrook
 *	@version	1.0
 */

public class AESMethods2
{

	/**
	 *	Adds the round subkey to the input data path using addition in the
	 *	Galois field GF(2).
	 *
	 * 	@param	text		Input data path (String of 16 characters)
	 *	@param 	key			Round subkey (String of 16 characters)
	 *	@return				New data path
	 */
	public static String keyAddition(String text, String key)
	{
		// Confirm that both the input data path and round subkey are of valid block size (16 bytes, 128 bits)
		validateDataPath(text, "keyAddition(text)");
		validateDataPath(key, "keyAddition(key)");

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

	/**
	 *	Performs a linear substitution of bytes based on a predefined
	 *	substitution box.
	 *
	 *	@param	text		Input data path (String of 16 characters)
	 *	@return 			New data path
	 */
	public static String byteSubstitution(String text)
	{
		// Confirm that the input data path is of valid block size.
		validateDataPath(text, "byteSubstitution()");

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

	/**
	 *	Shifts each row of the input data path matrix by a predefined number
	 *	of indices.
	 *
	 *	@param	text		Input data path (String of 16 characters)
	 *	@return				New data path
	 */
	public static String shiftRows(String text)
	{
		// Confirm that the input data path is of valid block size.
		validateDataPath(text, "shiftRows()");

		// Create a character array to store the shifted data
		char[] newChars = new char[16];

		// Shift data from the input string into the new character array
		newChars[0]  = text.charAt(0);
		newChars[1]  = text.charAt(5);
		newChars[2]  = text.charAt(10);
		newChars[3]  = text.charAt(15);
		newChars[4]  = text.charAt(4);
		newChars[5]  = text.charAt(9);
		newChars[6]  = text.charAt(14);
		newChars[7]  = text.charAt(3);
		newChars[8]  = text.charAt(8);
		newChars[9]  = text.charAt(13);
		newChars[10] = text.charAt(2);
		newChars[11] = text.charAt(7);
		newChars[12] = text.charAt(12);
		newChars[13] = text.charAt(1);
		newChars[14] = text.charAt(6);
		newChars[15] = text.charAt(11);

		// Return the new data
		return new String(newChars);
	}

	/**
	 *	Performs a linear transformation that mixes each column of
	 *	the data matrix.
	 *
	 *	@param	text		Input data path (String of 16 characters)
	 *	@return				New data path
	 */
	public static String mixColumns(String text)
	{
		// TEST CODE
		System.out.println("Input data path     : " + text);
		// END TEST CODE

		// Confirm that the input data path is of valid block size.
		validateDataPath(text, "mixColumns()");

		// TEST CODE
		System.out.println("Block size          : " + text.length());
		// END TEST CODE

		// Convert textual data to numerical data that can be operated on mathematically
		byte[] textBytes = text.getBytes();

		// TEST CODE
		System.out.print("Byte representation : ");
		for(int i = 0; i < textBytes.length; i++)
			System.out.print(textBytes[i] + " ");
		System.out.println();
		// END TEST CODE

		// Divide the input data into four columns for matrix multiplication
		byte[] first  = {textBytes[0], textBytes[1], textBytes[2], textBytes[3]};
		byte[] second = {textBytes[4], textBytes[5], textBytes[6], textBytes[7]};
		byte[] third  = {textBytes[8], textBytes[9], textBytes[10], textBytes[11]};
		byte[] fourth = {textBytes[12], textBytes[13], textBytes[14], textBytes[15]};

		// TEST CODE
		System.out.println("First Column        : " + first[0] + " " + first[1] + " " + first[2] + " " + first[3]);
		System.out.println("Second Column       : " + second[0] + " " + second[1] + " " + second[2] + " " + second[3]);
		System.out.println("Third Column        : " + third[0] + " " + third[1] + " " + third[2] + " " + third[3]);
		System.out.println("Fourth Column       : " + fourth[0] + " " + fourth[1] + " " + fourth[2] + " " + fourth[3]);
		// END TEST CODE

		// Combine the columns into a 2D byte array
		byte[][] cols = {first, second, third, fourth};

		// Create new data by multiplying each column with a constant matrix

		byte[][] newCols = new byte[4][4];  // New path matrix

		byte[][] matrix = {{2, 3, 1, 1},	// Constant matrix
						   {1, 2, 3, 1},
						   {1, 1, 2, 3},
		                   {3, 1, 1, 2}};

		for(int i = 0; i < 4; i++)			// Loop through each column to be mixed
		{
			// TEST CODE
			System.out.println("\nMixing row " + i);
			// END TEST CODE

			byte[] inCol    = new byte[4];	// Input column
			byte[] outCol  	= new byte[4]; 	// Output column

			// Load input column
			for(int j = 0; j < 4; j++)
			{
				inCol[j] = cols[i][j];
			}

			// TEST CODE
			System.out.println("Input column        : " + inCol[0] + " " + inCol[1] + " " + inCol[2] + " " + inCol[3]);
			// END TEST CODE

			// Mix columns
			outCol[i] = (byte) (extFieldMultiply(matrix[i][0], inCol[0]) ^ extFieldMultiply(matrix[i][1], inCol[1]) ^ extFieldMultiply(matrix[i][2], inCol[2]) ^ extFieldMultiply(matrix[i][3], inCol[3]));

			// Assign output column to output byte matrix
			newCols[i] =  outCol;
		}

		char[] newChars = new char[16];

		// Convert output byte matrix to output String data path
		int index = 0;
		for(int i = 0; i < 4; i++)
		{
			for(int j = 0; j < 4; j++)
			{
				newChars[index] = (char) newCols[i][j];
				index++;
			}
		}

		return new String(newChars);
	}

	/**
	 *	Abstract
	 *
	 *	@param	key		Encryption key
	 *	@param	round	The current round of AES being performed
	 * 	@return			Null
	 */
	public String keySchedule(String key, int round)
	{
		return null;
	}

	/**
	 *	Validates the block size of the data path
	 *
	 *	@param	text	Text for validation
	 *	@param	method	The name of the method calling this method
	 */
	public static void validateDataPath(String text, String method)
	{
		// Confirm that the input data path is of valid block size.
		if(text.length() != 16)
		{
			System.out.println("[Error] Invalid block size input to " + method + ". Halting execution.");
			System.exit(1);
		}
	}

	/**
	 *	Multiplies two input elements of the extension field (2^8) represented as bit vectors
	 *
	 *	@param	poly1	A polynomial in the extension field (2^8) represented as a bit vector
	 *	@param	poly2	A polynomial in the extension field (2^8) represented as a bit vector
	 *	@return			The result of polynomial multiplication represented as a bit vector
	 */
	public static byte extFieldMultiply(byte poly1, byte poly2)
	{

		// TEST CODE
		System.out.println("\nMultiply " + poly1 + " by " + poly2);
		// END TEST CODE

		// Represent the coefficients of the polynomials as integers

		// Convert the input bytes to String objects
		String poly1Str = String.format("%8s", Integer.toBinaryString(poly1 & 0xFF)).replace(' ', '0');
		String poly2Str = String.format("%8s", Integer.toBinaryString(poly2 & 0xFF)).replace(' ', '0');

		// TEST CODE
		System.out.printf("Binary rep. of %4d : " + poly1Str + "\n", poly1);
		System.out.printf("Binary rep. of %4d : " + poly2Str + "\n", poly2);
		// END TEST CODE

		// Convert each character to an integer representation of polynomial term coefficients
		int[] p1Coefficients = new int[8];
		int[] p2Coefficients = new int[8];

		for(int i = 0; i < 8; i++)
		{
			p1Coefficients[i] = Character.getNumericValue(poly1Str.charAt(i));
			p2Coefficients[i] = Character.getNumericValue(poly2Str.charAt(i));
		}

		// TEST CODE
		System.out.printf("Coeff. rep. of %4d : ", poly1);
		for(int i = 0; i < 8; i++)
			System.out.print(p1Coefficients[i] + " ");
		System.out.println();

		System.out.printf("Coeff. rep. of %4d : ", poly2);
		for(int i = 0; i < 8; i++)
			System.out.print(p2Coefficients[i] + " ");
		System.out.println();

		System.out.printf("Poly rep. of %4d   : ", poly1);
		printPolyByCoeff(p1Coefficients);
		System.out.println();

		System.out.printf("Poly rep. of %4d   : ", poly2);
		printPolyByCoeff(p2Coefficients);
		System.out.println();
		// END TEST CODE

		// Create an array to store the result of polynomial multiplication
		int[] cPrimeCoefficients = new int[16];

		// Multiply every term of poly1 with every term of poly2

		// TEST CODE
		System.out.println("Multiply terms");
		// END TEST CODE

		for(int i = 0; i < 8; i++)	// For every term of poly1
		{
			for(int j = 0; j < 8; j++) // For every term of poly2
			{
				// Check to see if both terms exist

				if(p1Coefficients[i] == 1 && p2Coefficients[j] == 1)
				{
					// Multiply terms

					// Determine the order of each term
					int poly1Order = -1;
					int poly2Order = -1;

					// Determine the order of the first term
					switch (i)
					{
						case 0:  poly1Order = 7; break;
						case 1:  poly1Order = 6; break;
						case 2:  poly1Order = 5; break;
						case 3:  poly1Order = 4; break;
						case 4:  poly1Order = 3; break;
						case 5:  poly1Order = 2; break;
						case 6:  poly1Order = 1; break;
						case 7:  poly1Order = 0; break;
						default: System.out.println("[Error] Invalid polynomial coefficient in extFieldMultiply()."); System.exit(1); break;
					}

					// Determine the order of the second term
					switch (j)
					{
						case 0:  poly2Order = 7; break;
						case 1:  poly2Order = 6; break;
						case 2:  poly2Order = 5; break;
						case 3:  poly2Order = 4; break;
						case 4:  poly2Order = 3; break;
						case 5:  poly2Order = 2; break;
						case 6:  poly2Order = 1; break;
						case 7:  poly2Order = 0; break;
						default: System.out.println("[Error] Invalid polynomial coefficient in extFieldMultiply()."); System.exit(1); break;
					}

					// Computer the order of the new term
					int newOrder = -1;

					if(poly1Order != 0 && poly2Order != 0)
						newOrder = poly1Order + poly2Order;
					else if(poly1Order == 0 && poly2Order != 0)
						newOrder = poly2Order;
					else if(poly1Order != 0 && poly2Order == 0)
						newOrder = poly1Order;
					else
						newOrder = 0;

					// Store the new term in the cPrime array
					cPrimeCoefficients[newOrder]++;
				}
			}
		}

		// Reduce cPrime coefficients within the extension field GF(2)
		for(int i = 0; i < 16; i++)
		{
			cPrimeCoefficients[i] = cPrimeCoefficients[i] % 2;
		}


		// Compute C(x) as C'(x) divided by P(x) repreatedly until C(x) fits in
		// the original extension field GF(2^8)
		int[] pCoefficients = {1, 0, 0, 0, 1, 1, 0, 1, 1};	// P(x)
		int[] c				= cPrimeCoefficients;			// Stores the final reduced polynomial

		boolean fits = false;								// Checks if the polynomial fits in the
															// original extension field

		while(!fits)
		{
			// Check to see if the polynomial C(x) fits in the original extension field
			if(c[15] == 0 && c[14] == 0 && c[13] == 0 && c[12] == 0 && c[11] == 0
			&& c[10] == 0 && c[9] == 0 && c[8] == 0)
			{
				fits = true;
			}
			else
			{
				// Reduce C(x) by P(x)

				// Multiply P(x) so as to reduce the highest order term in C(x)
				int shift = 7;
				int index = 15;

				while(c[index] != 1)
				{
					shift--;
					index--;
				}

				int[] shiftedP = new int[pCoefficients.length + shift];

				int j = 8;
				for(int i = shiftedP.length - 1; i >= (shiftedP.length - 1) - pCoefficients.length; i--)
				{
					shiftedP[i] = pCoefficients[j];
					j--;
				}

				// Reduce C(x) by P(x)

				for(int i = 0; i < 16; i++)
				{
					c[i] = (c[i] + shiftedP[i]) % 2;
				}
			}
		}

		// Convert coefficient array to byte
		byte output = 0;

		for(int i = 0; i < c.length; i++)
		{
			if(c[i] == 1)
			{
				if(i == 0)
					output++;
				else
					output = (byte) (output + (i * 2));
			}
		}

		return output;
	}

	/**
	 *	Prints a polynomial from an input integer array of coefficients.
	 *
	 *	@param	@coefficients		An integer array of coefficients.
	 */
	public static void printPolyByCoeff(int[] coefficients)
	{
		for(int i = 0; i < coefficients.length; i++)
		{
			if(coefficients[i] == 1)
			{
				System.out.print(" + X^" + i);
			}
		}
	}

	public static void main(String[] args)
	{
		// Unit test for keyAddition()
		System.out.println("Unit Test: keyAddition()");

		String text = "0000000000000000"; // '0' = 48 base 10 = 00110000 base 2
		String key  = "aaaaaaaaaaaaaaaa"; // 'a' = 97 base 10 = 01100001 base 2
										  // ------------------- GF(2) Addition
										  // 'Q' = 81 base 10 = 01010001 base 2

		System.out.println(keyAddition(text, key) + "\n");

		// Unit test for byteSubstitution
		System.out.println("Unit Test: byteSubstitution()");
		text = "PPPPPPPPPPPPPPPP";		// 'P' = 80 base 10 = 50 base 16
										// ------------------- byteSubstitution
										// 'S' = 83 base 10 = 53 base 16

		System.out.println(byteSubstitution(text) + "\n");

		// Unit test for shiftRows()
		System.out.println("Unit Test: shiftRows()");

		text = "ABCDEFGHIJKLMNOP";		// ABCDEFGHIJKLMNOP
										// -------------------------- ShiftRows
										// AFKPEJODINCHMBGL

		System.out.println(shiftRows(text) + "\n");

		// Unit test for mixColumns()	//
		System.out.println("Unit Test: mixColumns()");

		System.out.print("\nUnit Test Case      : ");
		char[] chars = new char[16];
		for(int i = 0; i < 16; i++)
		{
			chars[i] = 25;
			System.out.print(chars[i]);
		}
		System.out.println();

		String output = mixColumns(new String(chars));

		System.out.print("\nOutput as bytes     : ");

		for(int i = 0; i < 16; i++)
		{
			System.out.print((byte) output.charAt(i));
		}
		System.out.println();
	}
}
