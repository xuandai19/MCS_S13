package com.example.productservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    /**
     * POST /api/products
     * Chỉ cho phép role ADMIN (header X-User-Role do Gateway gắn sau khi verify JWT).
     * USER sẽ nhận 403 Forbidden.
     */
    @PostMapping
    public ResponseEntity<?> createProduct(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestHeader(value = "X-User-Id", required = false) String username,
            @RequestBody(required = false) Map<String, Object> body) {

        if (role == null || role.isBlank()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Missing role header. Request must go through Gateway."));
        }

        if (!"ADMIN".equalsIgnoreCase(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of(
                            "error", "Access denied. ADMIN role required.",
                            "yourRole", role,
                            "username", username != null ? username : "unknown"
                    ));
        }

        return ResponseEntity.ok(Map.of(
                "message", "Product created successfully",
                "createdBy", username,
                "role", role,
                "product", body != null ? body : Map.of("name", "Sample Product")
        ));
    }

    @GetMapping
    public ResponseEntity<?> listProducts(
            @RequestHeader(value = "X-User-Role", required = false) String role,
            @RequestHeader(value = "X-User-Id", required = false) String username) {

        return ResponseEntity.ok(Map.of(
                "message", "Product list (any authenticated user)",
                "username", username != null ? username : "anonymous",
                "role", role != null ? role : "none"
        ));
    }
}
