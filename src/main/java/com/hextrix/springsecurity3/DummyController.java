package com.hextrix.springsecurity3;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DummyController {
    @PostMapping("/login")
    public void login () {
    }

    @GetMapping("/admin-only")
    public String adminOnly() {
        return "Admin only";
    }

    @GetMapping("/any-endpoint")
    public String anyEndpoint () {
        return "Any endpoint";
    }
}
