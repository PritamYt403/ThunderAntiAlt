package com.pritamx.thunderantialt.license;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**

* Sends a license key to the Cloudflare Worker validation API.
  */
  public final class LicenseValidator {
  
  private static final URI API_URI = URI.create(
  "https://thunderantialt-license.h7198083.workers.dev/api/validate"
  );
  
  private final HttpClient client = HttpClient.newBuilder()
  .connectTimeout(Duration.ofSeconds(8))
  .build();
  
  public LicenseStatus validate(String key) {
  if (key == null || key.isBlank()) {
  return LicenseStatus.INVALID;
  }
  
   String escapedKey = key
         .replace("\\", "\\\\")
         .replace("\"", "\\\"");

 String json = "{\"key\":\"" + escapedKey + "\"}";

 HttpRequest request = HttpRequest.newBuilder()
         .uri(API_URI)
         .timeout(Duration.ofSeconds(12))
         .header("Content-Type", "application/json")
         .POST(HttpRequest.BodyPublishers.ofString(json))
         .build();

 try {
     HttpResponse<String> response = client.send(
             request,
             HttpResponse.BodyHandlers.ofString()
     );

     if (response.statusCode() != 200) {
         return LicenseStatus.UNAVAILABLE;
     }

     String body = response.body();

     if (Pattern.compile("\"valid\"\\s*:\\s*true")
             .matcher(body).find()) {
         return LicenseStatus.ACTIVE;
     }

     Matcher matcher = Pattern.compile(
             "\"status\"\\s*:\\s*\"([^\"]+)\""
     ).matcher(body);

     if (!matcher.find()) {
         return LicenseStatus.UNAVAILABLE;
     }

     return switch (matcher.group(1).toLowerCase()) {
         case "expired" -> LicenseStatus.EXPIRED;
         case "revoked" -> LicenseStatus.REVOKED;
         case "invalid" -> LicenseStatus.INVALID;
         default -> LicenseStatus.UNAVAILABLE;
     };

 } catch (IOException e) {
     return LicenseStatus.UNAVAILABLE;
 } catch (InterruptedException e) {
     Thread.currentThread().interrupt();
     return LicenseStatus.UNAVAILABLE;
 }
  
  }
     }
