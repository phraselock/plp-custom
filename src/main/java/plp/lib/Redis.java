package plp.lib;

import com.ipoxo.plcore.lib.Log;
import redis.clients.jedis.Jedis;

import java.util.Set;

public class Redis
{
  public static void writePairingTokenData(String peer, String config)
  {
    try (Jedis jedis = new Jedis("localhost", 6379))
    {
      // Anlegen
      jedis.sadd(peer, config);
      jedis.expire(peer, 20);  // TTL in Sekunden
    }
    catch (Exception e)
    {
      Log.e("[Redis] writePeerConfig: " + e.getMessage());
    }
  }

  public static Set<String> readPairingTokenData(String peer)
  {
    try (Jedis jedis = new Jedis("localhost", 6379))
    {
      // Lesen
      Set<String> children = jedis.smembers(peer);
      return children;
    }
    catch (Exception e)
    {
      Log.e("[Redis] readPeerConfig: " + e.getMessage());
    }
    return null;
  }

}
