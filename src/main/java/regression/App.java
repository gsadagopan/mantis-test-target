package regression;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
@SpringBootApplication
@RestController
public class App {
 public static void main(String[] args) { SpringApplication.run(App.class, args); }
 @GetMapping("/hello") public String hello(HttpServletRequest request) { return "mantis:" + request.getMethod(); }
 @PostMapping("/echo") public String echo(@Valid @RequestBody Message input) { return input.name; }
 public static class Message { @NotBlank public String name; }
}
