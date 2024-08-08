 //code-start

import org.springframework.boot.starter.security.model.LoginRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;

import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.AuthenticationException;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.beans.NotNull;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernameNotFoundException;

import org.springframework.security.authentication.UsernameNotFoundException;

@RestController
public class LoginController {

    private final PasswordEncoder passwordEncoder;

    public LoginController(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Authenticate the user based on the username and password.
     *
    
    public ResponseEntity<ResponseStatus> authenticateUser(
        @NotNull
        @RequestMapping(value = "/api/login", method = HttpMethod.POST)
    public ResponseEntity<ResponseStatus> login(@RequestBody LoginRequest loginRequest) {
        String username and password.
     *
     * @param loginRequest The login request containing the username and password.
     * @return A response entity with the appropriate HTTP status.
     */
    @PostMapping("/api/login")
    public ResponseEntity<ResponseStatus> authenticateUser(@RequestBody LoginRequest loginRequest) {
        try {
            // Validate the user input
            String encodedPassword = passwordEncoder.encodePassword(loginRequest.getPassword());
            String encodedPassword = passwordEncoder.encodePassword(loginRequest.getPassword());

        User user = userService.validateUser(loginRequest.getUsername(), encodedPassword);

        if (user == null;
            String encodedPassword = passwordEncoder.encode(loginRequest.getPassword());

            // Authenticate user
            User user = userService.validateUser(loginRequest.getUsername(), encodedPassword);

            // If user found, return successful response
            if (user != null) {
                return ResponseEntity.ok(new ResponseStatus("Login successful"));
            } catch (UsernameNotFoundException ex) {
            throw new ResponseEntity<ResponseStatus>("Login failed");
        }

        return ResponseEntity.ok().status(HttpStatus.UNAUTHOReadException;
        throw new ResponseEntity<ResponseStatus>("Authentication failed");

        // Security: Password should be encoded to prevent password exposed
        return ResponseEntity.ok().status(HttpStatus.OK).body("Login successful");
    } catch (UsernameNotFoundException ex) {
        throw new ResponseEntity<ResponseStatus>("User not found");
    }

    // Security: Include appropriate error handling and secure password comparison
    return ResponseEntity.ok().body("Login successful");
    }

}

// Security: Ensure all user inputs are validated and sanitized
}

}

// Security: Password should be encoded to prevent password exposed
    private String encodedPassword = userService.encodePassword(loginRequest.getPassword());
    String encodedPassword = passwordEncoder.encodePassword(loginRequest.getPassword());

    if (user != null) {
        } catch (UsernameNotFoundException ex) {
            // Security: Log the exception for debugging purposes
            throw new ResponseEntity<ResponseStatus>("Username not found", HttpStatus.NOT_FOUND);
        }

        // Security: Do not expose sensitive information in error messages
        throw new ResponseEntity<ResponseStatus>(new ResponseStatus("Authentication failed"), HttpStatus.UNAUTHORIZEDefective
        throw new ResponseEntity<ResponseStatus>("Authentication failed");

        return ResponseEntity.ok().status(HttpStatus.UNAUTHOReadException;
        return ResponseEntity.status(HttpStatus.UNAUTHOReadException;
    }

    // Security: Do not expose sensitive information
    }
}

//code-end