/*
 ============================================================================
 Name        : BinToB64App.java
 Author      : Tofig Kareemov
 Version     :
 Copyright   : Your copyright notice
 Description : Base64 Encryptor in Java Application
 ============================================================================
 */
package com.androphic.base64.encryptor;

//# For encoding
//javac BinToB64App.java
//java BinToB64App -e input_file
//
//# For decoding
//javac BinToB64App.java
//java BinToB64App -d input_file.c64

import java.io.*;

public class BinToC64App {

	private static final int BUFFER_SIZE = 4096 * 3; // Must be File Cluster size * 3 for speed and no inter-padding

	private static void encodeBase64(File inputFile, File outputFile, String sKey) {
		try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile));
				BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
			C64 oEnc = new C64();
			byte[] Input = new byte[BUFFER_SIZE];
			byte[] Output = new byte[BUFFER_SIZE * 3 / 2];
			int bytesRead;
			oEnc.setEncryption(sKey, C64.S_ALPHABET_QWERTY);
			while ((bytesRead = bis.read(Input)) != -1) {
				int iEncodedBytes = 0;
				iEncodedBytes = oEnc.encrypt(Input, bytesRead, Output, C64.I_LINE_MIME, true);
				bos.write(Output, 0, iEncodedBytes);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void decodeBase64(File inputFile, File outputFile, String sKey) {
		try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
			C64 oEnc = new C64();
			BufferedReader reader;
			byte[] Output = new byte[BUFFER_SIZE];
			reader = new BufferedReader(new FileReader(inputFile));
			oEnc.setEncryption(sKey, C64.S_ALPHABET_QWERTY);
			String line = reader.readLine();
			while (line != null) {
				int iLen = line.length();
				if (iLen <= C64.I_LINE_MIME) {
					int iEncodedBytes = oEnc.decrypt(line.getBytes(), iLen, Output);
					bos.write(Output, 0, iEncodedBytes);
				}
				line = reader.readLine();
			}
			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		if (args.length < 2) {
			System.err.println("Usage: java -jar b2c64.jar <-e/-d> <input_file> <crypt_key_text>");
			System.exit(1);
		}
		String flag = args[0];
		String inputFileName = args[1];
		String sKey = null;
		if (args.length >= 3) {
			sKey = args[2];
		}
		String outputFileName;
		if ("-e".equals(flag)) {
			outputFileName = inputFileName + ".c64";
		} else if ("-d".equals(flag)) {
			if (!inputFileName.endsWith(".c64")) {
				System.err.println("Error: Decoding requires a '.c64' file.");
				System.exit(1);
			}
			outputFileName = inputFileName.substring(0, inputFileName.length() - 4);
		} else {
			System.err.println("Invalid flag. Use <-e/-d>.");
			System.exit(1);
			return;
		}
		File inputFile = new File(inputFileName);
		if (!inputFile.exists()) {
			System.err.println("Input file \"" + inputFileName + "\" doesn't exist.");
			System.exit(1);
			return;
		}
		File outputFile = new File(outputFileName);
		System.out.println("Output file: " + outputFileName);
		try {
			if ("-e".equals(flag)) {
				encodeBase64(inputFile, outputFile, sKey);
			} else if ("-d".equals(flag)) {
				decodeBase64(inputFile, outputFile, sKey);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Done.");
	}
}
