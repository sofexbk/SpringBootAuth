package com.springsecurity.springsecurity.auth;

import com.springsecurity.springsecurity.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    private String token;
    private String firstname;
    private String lastname;
    private String email;
    private Role role;
    private UUID userId;
}
