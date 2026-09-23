package regression;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
@SpringBootApplication
@RestController
public class App {
 public static void main(String[] args) { SpringApplication.run(App.class, args); }
 @GetMapping("/hello") public String hello(HttpServletRequest request) { return "mantis:" + request.getMethod(); }
 @PostMapping("/echo") public String echo(@Valid @RequestBody Message input) { return input.name; }
 public static class Message { @NotBlank public String name; }
}
