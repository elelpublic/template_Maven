package com.infodesire.totppoc;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.awt.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.List;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

/**
 * Proof of concept for TOTP
 *
 * See: https://github.com/samdjstevens/java-totp
 *
 */
public class App {


  private static Options options = new Options();


  public static void main( String[] args ) throws ParseException, IOException, QrGenerationException {

    print( "TOTPPOC" );
    print( "Time-based One Time Password - Proof of Concept" );
    print( "" );

    options.addOption( "l", true, "length of secret (default 32)" );
    options.addOption( "a", true, "Name of app issuing secret (default App)" );
    options.addOption( "s", true, "The secret to be used to verify" );
    options.addOption( "c", true, "The secret to be used to verify" );
    options.addOption( "i", false, "Interactive mode" );

    CommandLineParser parser = new DefaultParser();
    CommandLine commandLine = parser.parse(options, args);

    if( commandLine.hasOption( "i" ) ) {
      repl();
    }

    List<String> argslist = commandLine.getArgList();

    if( argslist.isEmpty() ) {
      usage( "No command given. Entering interactive mode." );
      repl();
    }

    String command = argslist.get( 0 );

    if( command.equals( "secret" ) ) {
      String keyLength = commandLine.getOptionValue( "l" );
      String appName = commandLine.getOptionValue( "a" );
      secret( keyLength, appName );
    }
    else if( command.equals( "verify" ) ) {
      String secret = commandLine.getOptionValue( "s" );
      String code = commandLine.getOptionValue( "c" );
      verify( secret, code );
    }

  }

  private static void repl() throws IOException, QrGenerationException {
    BufferedReader in = new BufferedReader( new InputStreamReader( System.in ) );
    String command = null;
    do {
      print( "" );
      print( "Enter command: secret, verify, quit" );
      command = in.readLine();
      if( command.equals( "secret" ) ) {
        print( "Enter key length (Enter for 32):" );
        String keyLength = in.readLine();
        print( "Enter app name (Enter for \"App\"):" );
        String appName = in.readLine();
        secret( keyLength, appName );
      }
      else if( command.equals( "verify" ) ) {
        print( "Enter secret: " );
        String secret = in.readLine();
        print( "Enter code: " );
        String code = in.readLine();
        verify( secret, code );
      }
    }
    while( !command.equals( "quit" ) );
  }

  private static void secret( String keyLength, String appName ) throws QrGenerationException, IOException {

    SecretGenerator secretGenerator = keyLength == null || keyLength.trim().length() == 0
      ? new DefaultSecretGenerator()
      : new DefaultSecretGenerator( Integer.parseInt( keyLength ) );

    String secret = secretGenerator.generate();

    if( appName == null || appName.trim().length() == 0 ) {
      appName = "App";
    }

    print( "Add this secret to your authenticator app: " );
    print( secret );

    QrData data = new QrData.Builder()
      .label("example@example.com")
      .secret(secret)
      .issuer(appName)
      .algorithm( HashingAlgorithm.SHA1) // More on this below
      .digits(6)
      .period(30)
      .build();

    QrGenerator generator = new ZxingPngQrGenerator();
    byte[] imageData = generator.generate(data);

    File imageFile = new File( "target/qr.png" );
    File htmlFile = new File( "target/qr.html" );

    Files.write( imageFile.toPath(), imageData);
    print( "Or scan the QR code in this file using your authenticator app: " );
    print( imageFile.getAbsolutePath() );

    print( "" );
    print( "The app name is: " + appName );

    String dataUri = getDataUriForImage(imageData, "img/png" );
    PrintWriter html = new PrintWriter( htmlFile );
    html.println( "<html><body>" );
    html.println( "Use this method to present qr code instead of saving file to disk for security reasons.<br>" );
    html.println( "<img src=\"" + dataUri + "\" />" );
    html.println( "<br>Or enter this secret code into your authenticator: " + secret );
    html.println( "</body></html>" );
    html.close();

    Desktop.getDesktop().open( imageFile );
    Desktop.getDesktop().open( htmlFile );

  }


  private static void verify( String secret, String code ) {

    if( secret == null ) {
      usage( "Secret missing" );
      return;
    }

    if( code == null ) {
      usage( "Code missing" );
      return;
    }

    TimeProvider timeProvider = new SystemTimeProvider();
    CodeGenerator codeGenerator = new DefaultCodeGenerator();
    CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

// secret = the shared secret for the user
// code = the code submitted by the user
    boolean successful = verifier.isValidCode(secret, code);

    print( "Verify: " + ( successful ? "OK" : "failed" ) );

  }

  private static void usage( String message ) {

    HelpFormatter formatter = new HelpFormatter();
    print( message );
    formatter.printHelp("totppoc [options] command", options);
    print( "" );
    print( "commands:" );
    print( "secret \t generates secret to import into authenticator app" );
    print( "verify \t verify a code" );

  }

  private static void print( String line ) {
    System.out.println( line );
  }


}

