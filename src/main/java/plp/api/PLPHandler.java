package plp.api;

import lib.Log;
import io.javalin.config.JavalinConfig;
import io.javalin.http.Context;
import org.json.JSONObject;
import plp.config.AppConfig;
import plp.crypto.ClientCertIssuer;
import plp.service.JwtService;
import plp.service.RestX;

import java.security.PublicKey;
import java.util.*;

/**
 * Port of api/validate.php (blueprint), reachable as
 * /api/mqtt/v1/validate/clientcert and /api/mqtt/v1/validate/clientcertmd.
 */
public class PLPHandler
{
  private final ClientCertIssuer certIssuer;

  public PLPHandler(ClientCertIssuer certIssuer)
  {
    this.certIssuer = certIssuer;
  }

  public void registerRoutes(JavalinConfig config)
  {
    // Eine Route für alle Validierungstypen — der konkrete Typ wird in resolve()
    // aus dem Pfad aufgelöst (analog zu api/validate.php). Neue Typen brauchen
    // daher keine neue Route und keinen neuen Eintrag am Reverse Proxy.
    config.routes.post("/api/mqtt/v1/validate/*", this::resolve);
    config.routes.get("/api/mqtt/v1/validate/*", this::resolve);
  }

  private void resolve(Context ctx) throws Exception
  {
    List<String> segments = Arrays.stream(ctx.path().split("/"))
      .filter(s -> !s.isEmpty())
      .toList();

    int idx = segments.indexOf("validate");
    String type = (idx >= 0 && segments.size() > idx + 1) ? segments.get(idx + 1) : "";

    switch (type)
    {
      case "clientcert"   -> handle(ctx, this::clientCert);

      case "clientcertmd" -> handle(ctx, this::clientCertIos);
      case "clientcertios" -> handle(ctx, this::clientCertIos); // clientCertMd

      case "clientcertand" -> handle(ctx, this::clientCertAnd);

      case "test"         -> handle(ctx, this::test);
      default             -> ctx.status(500);
    }
  }

  private interface Operation
  {
    PLPResponse run(Context ctx, PLPRequest req) throws Exception;
  }

  private void handle(Context ctx, Operation operation) throws Exception
  {
    ctx.contentType("application/json");

    PLPRequest req = PLPRequest.from(ctx);
    Log.i("[validate] request:\n" + req.dump());

    PLPResponse response = operation.run(ctx, req);

    String responseBody = req.asXml() ? response.toXml() : response.toJson();
    Log.i("[validate] response:\n" + (req.asXml() ? Log.xml(responseBody) : Log.json(responseBody)));
    ctx.result(responseBody);
  }


  private PLPResponse test(Context ctx, PLPRequest req) throws Exception
  {
    return new PLPResponse()
      .set("test", "SUCCESS".equals(ctx.header("X-Client-Verify"))
        ? "test-test with Client Cert"
        : "test-test not Client Cert");
  }

  private boolean verifyPairingData(String devID, String qrc)
  {
    try {
      String coreHost = AppConfig.plCoreUrl();
      String coreJwt = AppConfig.plCoreJwt();

      var jwt = new JwtService(coreJwt);
      PublicKey publKey = AppConfig.plCorePublicKey();
      jwt.setPublicKey(publKey);
      boolean bValid = jwt.isValid();
      if(bValid) {
        RestX restX = new RestX(coreHost + "/api/plp/v1/validate/licverify/");

        JSONObject jsonBody = new JSONObject();
        jsonBody.put("devId", devID);
        jsonBody.put("qrc", qrc);

        RestX.Response r = restX.post(jsonBody.toString(), Map.of("Authorization", "Bearer " + coreJwt));
        if (r.status() == 200) {
          JSONObject jsonObj = new JSONObject(r.body());
          String valid = jsonObj.optString("valid", "0");
          if (Integer.valueOf(valid) == 1) {
            return true;
          }
        }
      }
    } catch (Exception e) {
      Log.e("Exception in verifyPairingData: "+ e.getMessage());
    }
    return false;
  }

  /**
   * Port of fnx_clientcert(): issues a client certificate for win/android
   * (from the device's own public key) or a PKCS12 for apple.
   */
  private PLPResponse clientCert(Context ctx, PLPRequest req) throws Exception
  {
    if (!req.has(PLPRequest.DEV_ID) || !req.has(PLPRequest.QRC) || !req.has(PLPRequest.OS)
      || !req.has(PLPRequest.TLS) || !req.has(PLPRequest.PORT))
    {
      return PLPResponse.invalid();
    }

    String ccrt = "0";
    if (!verifyPairingData(req.get(PLPRequest.DEV_ID), req.get(PLPRequest.QRC)))
    {
      return PLPResponse.invalid(ccrt);
    }

    String os = req.get(PLPRequest.OS);
    if (os.equals("win") || os.equals("android"))
    {
      byte[] publicKeyPem = Base64.getDecoder().decode(req.get(PLPRequest.PUBPEMB64));
      ClientCertIssuer.CertResult cert = certIssuer.issueFromPublicKey(publicKeyPem, req.get(PLPRequest.PORT), req.get(PLPRequest.DEFAULT_MODE));
      if (cert != null && !cert.certB64().isEmpty())
      {
        return new PLPResponse()
          .set("serialnr", cert.serialNr())
          .set("certb64", cert.certB64())
          .set("valid", "1")
          .set("ccrt", ccrt);
      }
    }
    else if (os.equals("apple"))
    {
      String pwd = newPassword();
      String pkcs12Hex = certIssuer.issuePkcs12(pwd, req.get(PLPRequest.PORT), req.get(PLPRequest.DEFAULT_MODE));
      if (pkcs12Hex != null && !pkcs12Hex.isEmpty())
      {
        return new PLPResponse()
          .set("crt", pkcs12Hex)
          .set("pwd", pwd)
          .set("valid", "1")
          .set("ccrt", ccrt);
      }
    }

    return PLPResponse.invalid();
  }

  /**
   * Port of fnx_clientcertmd(): issues a PKCS12 for ios with a dynamic
   * extended-key-usage OID.
   */
  private PLPResponse clientCertIos(Context ctx, PLPRequest req) throws Exception
  {
    if (!req.has(PLPRequest.DEV_ID) || !req.has(PLPRequest.QRC) || !req.has(PLPRequest.OS)
      || !req.has(PLPRequest.TLS) || !req.has(PLPRequest.PORT))
    {
      return PLPResponse.invalid();
    }

    String ccrt = "0";
    if (!verifyPairingData(req.get(PLPRequest.DEV_ID), req.get(PLPRequest.QRC)))
    {
      return PLPResponse.invalid(ccrt);
    }

    if (req.get(PLPRequest.OS).equals("ios"))
    {
      String oidExt = req.has(PLPRequest.OID_EXT) ? req.get(PLPRequest.OID_EXT) : "0";
      String ekuOid = "1.3.6.1.4.1.59269.100.1." + oidExt;

      String pwd = newPassword();
      String pkcs12Hex = certIssuer.issuePkcs12WithEku(pwd, req.get(PLPRequest.PORT), req.get(PLPRequest.DEFAULT_MODE), ekuOid);
      if (pkcs12Hex != null && !pkcs12Hex.isEmpty())
      {
        return new PLPResponse()
          .set("crt", pkcs12Hex)
          .set("pwd", pwd)
          .set("valid", "1")
          .set("ccrt", ccrt);
      }
    }

    return PLPResponse.invalid();
  }

  private PLPResponse clientCertAnd(Context ctx, PLPRequest req) throws Exception
  {
    if (!req.has(PLPRequest.DEV_ID) || !req.has(PLPRequest.QRC) || !req.has(PLPRequest.OS)
      || !req.has(PLPRequest.TLS) || !req.has(PLPRequest.PORT))
    {
      return PLPResponse.invalid();
    }

    String ccrt = "0";
    if (!verifyPairingData(req.get(PLPRequest.DEV_ID), req.get(PLPRequest.QRC)))
    {
      return PLPResponse.invalid(ccrt);
    }

    String os = req.get(PLPRequest.OS);
    if (os.equals("win") || os.equals("android"))
    {
      byte[] publicKeyPem = Base64.getDecoder().decode(req.get(PLPRequest.PUBPEMB64));
      ClientCertIssuer.CertResult cert = certIssuer.issueFromPublicKey(publicKeyPem, req.get(PLPRequest.PORT), req.get(PLPRequest.DEFAULT_MODE));
      if (cert != null && !cert.certB64().isEmpty())
      {
        return new PLPResponse()
          .set("serialnr", cert.serialNr())
          .set("certb64", cert.certB64())
          .set("valid", "1")
          .set("ccrt", ccrt);
      }
    }
    else if (os.equals("apple"))
    {
      String pwd = newPassword();
      String pkcs12Hex = certIssuer.issuePkcs12(pwd, req.get(PLPRequest.PORT), req.get(PLPRequest.DEFAULT_MODE));
      if (pkcs12Hex != null && !pkcs12Hex.isEmpty())
      {
        return new PLPResponse()
          .set("crt", pkcs12Hex)
          .set("pwd", pwd)
          .set("valid", "1")
          .set("ccrt", ccrt);
      }
    }

    return PLPResponse.invalid();
  }

  private static String newPassword()
  {
    return UUID.randomUUID().toString().toUpperCase();
  }
}
