package regression;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;
class SmokeTest {
 @Test void jsonRoundTrip() throws Exception {
  var mapper = new ObjectMapper();
  var node = mapper.readTree("{\"name\":\"mantis\",\"items\":[1,2,3]}");
  assertEquals(node, mapper.readTree(mapper.writeValueAsString(node)));
  assertEquals(3, node.get("items").size());
 }
}