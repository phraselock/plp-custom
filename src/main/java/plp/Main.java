package plp;

import io.javalin.Javalin;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import plp.config.AppConfig;
import plp.crypto.ClientCert;
import plp.crypto.IClientCertIssuer;
import plp.api.PLPHandler;

/*
  ./gradlew shadowJar
 */

public class Main {

  public static void main(String[] args)
  {
    var threadPool = new QueuedThreadPool(
      AppConfig.jettyMaxThreads(),  // max
      AppConfig.jettyMinThreads(),  // min
      60_000                        // idle timeout ms
    );
    threadPool.setName("jetty-plp-custom");

    var app = Javalin.create(config -> {
      config.jetty.threadPool = threadPool;
      config.jetty.port = AppConfig.port();

      config.routes.before(ctx -> {
        if (!AppConfig.allowedIps().contains(ctx.ip())) {
          ctx.status(444).result("-");
          ctx.skipRemainingHandlers();
        }
      });

      config.routes.get("/", ctx -> ctx.result("plp-custom is running"));

      IClientCertIssuer certIssuer = new ClientCert(AppConfig.caDirectory());
      new PLPHandler(certIssuer).registerRoutes(config);
    });

    app.start();
  }
}
