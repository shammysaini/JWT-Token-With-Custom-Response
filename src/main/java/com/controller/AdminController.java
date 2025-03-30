package com.controller;

import com.dto.*;
import com.security.AuthService;
import com.security.JwtUtils;
import com.security.UserDetailsImpl;
import com.service.BloggerService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/admin")
@Slf4j
public class AdminController {

    private final BloggerService bloggerService;
    private final AuthService authService;
    private final JwtUtils jwtUtils;
    private static final Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

    public AdminController(BloggerService bloggerService, AuthService authService, JwtUtils jwtUtils) {
        this.bloggerService = bloggerService;
        this.authService = authService;
        this.jwtUtils = jwtUtils;

    }

    @PostMapping("/signup")
    public ResponseEntity<CommonResponse<SignupResponse>> signup(@Valid @RequestBody SignupRequest signupRequest) {
        CommonResponse<SignupResponse> response = bloggerService.saveRecord(signupRequest);

        if (response.getMessage().equalsIgnoreCase("record.success")) {
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/signing")
    public ResponseEntity<CommonResponse<JwtResponse>>authenticateUser(@RequestBody LoginRequest loginRequest ) {
        log.info("Attempting to log in user: {}", loginRequest.getUserEmail());
        CommonResponse<JwtResponse> commonResponse;
        try {
            Authentication authentication = authService.authenticate(loginRequest.getUserEmail(), loginRequest.getPassword());
            String jwt = jwtUtils.generateToken(authentication, loginRequest.getUserEmail());
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                    .toList();
            commonResponse = new CommonResponse<>(true, "Login Successfully",
                    HttpStatus.OK.value(), new JwtResponse(jwt, userDetails.id(), userDetails.getUsername(), roles));
            log.info("User {} logged in successfully", userDetails.getUsername());
            return ResponseEntity.ok(commonResponse);
        }
            catch (Exception exception) {
                    log.error("Login failed for user {}: {}", loginRequest.getUserEmail(), exception.getMessage());
                    commonResponse = new CommonResponse<>(
                            false, "Invalid credentials", HttpStatus.UNAUTHORIZED.value(), null
                    );
            }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(commonResponse);

    }
    @GetMapping("/check")
    public ResponseEntity<CommonResponse<TempResponse>> show(){
        TempResponse tempResponse = new TempResponse();
        tempResponse.setName("champion");
        CommonResponse<TempResponse> response = new CommonResponse<>();
        response.setResult(true);
        response.setMessage("fetch Record successfully");
        response.setStatus(HttpStatus.OK.value());
        response.setData(tempResponse);
        return new ResponseEntity<>(response, HttpStatus.OK);

    }
    @PostMapping("/logout")
    public ResponseEntity<CommonResponse<String>> logoutUser(@RequestHeader("Authorization") String token) {
        CommonResponse<String> commonResponse;
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(new CommonResponse<>(false, "Invalid token", HttpStatus.BAD_REQUEST.value(), null));
        }
            token = token.substring(7).trim(); // Trim extra spaces
            log.info("Token after trimming: {}", token);

            if (jwtUtils.isTokenExpired(token)) {
                commonResponse = new CommonResponse<>(false, "Token is already expired",
                        HttpStatus.BAD_REQUEST.value(),null);
                return ResponseEntity.badRequest().body(commonResponse);
            }

            if (!jwtUtils.validateToken(token)) {
                tokenBlacklist.add(token);
                commonResponse = new CommonResponse<>(false, "Invalid Token",
                        HttpStatus.BAD_REQUEST.value(),null);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(commonResponse);
            }
        tokenBlacklist.add(token);

        commonResponse = new CommonResponse<>(true, "User logged out successfully", HttpStatus.OK.value(), null);
        return ResponseEntity.ok(commonResponse);
        }

}


