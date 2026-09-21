package regression;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import static org.junit.jupiter.api.Assertions.*;
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SmokeTest {
 @Autowired TestRestTemplate http;
 @Test void servletHttpBehavior() { assertEquals("mantis:GET", http.getForObject("/hello", String.class)); }
 @Test void beanValidationRejectsEmptyInput() {
  var headers = new HttpHeaders(); headers.setContentType(MediaType.APPLICATION_JSON);
  assertEquals(400, http.postForEntity("/echo", new HttpEntity<>("{\"name\":\"\"}", headers), String.class).getStatusCodeValue());
 }
 @Test void validInputAccepted() {
  var headers = new HttpHeaders(); headers.setContentType(MediaType.APPLICATION_JSON);
  var response = http.postForEntity("/echo", new HttpEntity<>("{\"name\":\"mantis\"}", headers), String.class);
  assertEquals(200, response.getStatusCodeValue()); assertEquals("mantis", response.getBody());
 }
 @Test void frameworkAlignment() { assertEquals(System.getProperty("expectedFramework"), org.springframework.core.SpringVersion.getVersion()); }
}