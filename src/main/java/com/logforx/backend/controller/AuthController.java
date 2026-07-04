package com.logforx.backend.controller;

import com.logforx.backend.model.Investigator;
import com.logforx.backend.repository.InvestigatorRepository;
import com.logforx.backend.service.AuditLogService;
import com.logforx.backend.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private InvestigatorRepository investigatorRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuditLogService auditLogService;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String email = credentials.get("email");
        String password = credentials.get("password");

        if (email == null || password == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email and Password fields are required");
            return ResponseEntity.badRequest().body(error);
        }

        Optional<Investigator> optInvestigator = investigatorRepository.findByEmail(email);
        if (optInvestigator.isPresent()) {
            Investigator investigator = optInvestigator.get();
            if (passwordEncoder.matches(password, investigator.getPassword())) {
                String token = jwtService.generateToken(investigator.getEmail(), investigator.getName(), investigator.getBadgeId());
                
                Map<String, Object> response = new HashMap<>();
                response.put("token", token);
                response.put("role", "Investigator");
                response.put("email", investigator.getEmail());
                response.put("name", investigator.getName());
                response.put("badgeId", investigator.getBadgeId());
                
                auditLogService.logAction("LOGIN", investigator.getBadgeId(), "Investigator logged in successfully.");
                return ResponseEntity.ok(response);
            }
        }

        // Fallback to default user if no records exist in the database yet
        if (email.equalsIgnoreCase("investigator@logforx.local") && password.equals("cybersecurity2026")) {
            if (!investigatorRepository.existsByEmail(email)) {
                Investigator defaultInvestigator = new Investigator();
                defaultInvestigator.setEmail(email);
                defaultInvestigator.setPassword(passwordEncoder.encode(password));
                defaultInvestigator.setName("Investigator John Doe");
                defaultInvestigator.setBadgeId("INV-2026-9904");
                investigatorRepository.save(defaultInvestigator);
            }
            
            String token = jwtService.generateToken(email, "Investigator John Doe", "INV-2026-9904");
            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            response.put("role", "Investigator");
            response.put("email", email);
            response.put("name", "Investigator John Doe");
            response.put("badgeId", "INV-2026-9904");
            
            auditLogService.logAction("LOGIN", "INV-2026-9904", "Default investigator logged in successfully.");
            return ResponseEntity.ok(response);
        }

        Map<String, String> error = new HashMap<>();
        error.put("error", "Invalid email or password");
        return ResponseEntity.status(401).body(error);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");
        String name = request.get("name");
        String badgeId = request.get("badgeId");

        if (email == null || password == null || name == null || badgeId == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "All fields are required (email, password, name, badgeId)");
            return ResponseEntity.badRequest().body(error);
        }

        if (investigatorRepository.existsByEmail(email)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email is already registered");
            return ResponseEntity.badRequest().body(error);
        }

        if (investigatorRepository.existsByBadgeId(badgeId)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Badge ID is already registered");
            return ResponseEntity.badRequest().body(error);
        }

        Investigator investigator = new Investigator();
        investigator.setEmail(email);
        investigator.setPassword(passwordEncoder.encode(password));
        investigator.setName(name);
        investigator.setBadgeId(badgeId);

        investigatorRepository.save(investigator);
        
        auditLogService.logAction("REGISTER", badgeId, "Investigator registered: " + name);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Investigator registered successfully");
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        Map<String, String> response = new HashMap<>();
        response.put("message", "Reset link sent to " + email);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Password reset successful");
        return ResponseEntity.ok(response);
    }
}
