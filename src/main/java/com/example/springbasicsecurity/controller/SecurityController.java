package com.example.springbasicsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/auth")
public class SecurityController {


    @GetMapping("/getMsg")
    public String greeting() {
        return "spring security example";
    }
}
