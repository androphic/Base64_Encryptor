package com.androphic.base64.encryptor;

//# For encoding
//javac BinToB64App.java
//java BinToB64App -e input_file
//
//# For decoding
//javac BinToB64App.java
//java BinToB64App -d input_file.b64

import java.io.*;
import java.util.Base64;

public class BinToB64App {

	private static final int BUFFER_SIZE = 4096;

	private static void encodeBase64(File inputFile, File outputFile) {
		try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile));
				BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
			Base64.Encoder encoder = Base64.getEncoder();

			byte[] buffer = new byte[BUFFER_SIZE];
			int bytesRead;

			while ((bytesRead = bis.read(buffer)) != -1) {
//                byte[] encodedBytes = encoder.encode(buffer, 0, bytesRead);
//                bos.write(encodedBytes);
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void decodeBase64(File inputFile, File outputFile) {
		try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile));
				BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {

			Base64.Decoder decoder = Base64.getDecoder();
			byte[] buffer = new byte[BUFFER_SIZE];
			int bytesRead;

			while ((bytesRead = bis.read(buffer)) != -1) {
//                byte[] decodedBytes = decoder.decode(buffer, 0, bytesRead);
//                bos.write(decodedBytes);
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		if (args.length != 2) {
			System.err.println("Usage: java BinaryToBase64 <-e/-d> <input_file>");
			System.exit(1);
		}

		String flag = args[0];
		String inputFileName = args[1];
		String outputFileName;

		if ("-e".equals(flag)) {
			outputFileName = inputFileName + ".b64";
		} else if ("-d".equals(flag)) {
			if (!inputFileName.endsWith(".b64")) {
				System.err.println("Error: Decoding requires a '.b64' file.");
				System.exit(1);
			}
			outputFileName = inputFileName.substring(0, inputFileName.length() - 4);
		} else {
			System.err.println("Invalid flag. Use <-e/-d>.");
			System.exit(1);
			return;
		}

		File inputFile = new File(inputFileName);
		File outputFile = new File(outputFileName);

		try {
			if ("-e".equals(flag)) {
				encodeBase64(inputFile, outputFile);
			} else if ("-d".equals(flag)) {
				decodeBase64(inputFile, outputFile);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
