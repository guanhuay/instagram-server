package com.instagram.controllers;

import com.instagram.commons.exceptions.RoleNotFoundException;
import com.instagram.models.ERole;
import com.instagram.models.Role;
import com.instagram.models.User;
import com.instagram.payload.request.ResetPasswordRequest;
import com.instagram.payload.request.SignInRequest;
import com.instagram.payload.request.SignUpRequest;
import com.instagram.payload.response.JwtResponse;
import com.instagram.payload.response.MessageResponse;
import com.instagram.repository.RoleRepository;
import com.instagram.repository.UserRepository;
import com.instagram.security.jwt.JwtUtils;
import com.instagram.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @PutMapping("/reset_password")
    public ResponseEntity<?> updateUserPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        if(!userRepository.existsByUserName(resetPasswordRequest.getUserName())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username does not exist"));
        }

        // Update user password
        User user = userRepository.findByUserName(resetPasswordRequest.getUserName());
        String newEncodedPassword = passwordEncoder.encode(resetPasswordRequest.getNewPassword());
        user.setPassword(newEncodedPassword);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User password updated successfully"));
    }

    @PostMapping("/sign_in")
    public ResponseEntity<?> signInUser(@Valid @RequestBody SignInRequest signInRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getUserName(), signInRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
    }

    @PostMapping("/sign_up")
    public ResponseEntity<?> signUpUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userRepository.existsByUserName(signUpRequest.getUserName())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUserName(), signUpRequest.getEmail(), passwordEncoder.encode(signUpRequest.getPassword()));
        Set<String> userRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if(userRoles == null) {
            Role userRole = roleRepository.findByRoleName(ERole.ROLE_USER).orElseThrow(() -> new RoleNotFoundException(ERole.ROLE_USER.name()));
            roles.add(userRole);
        } else {
            userRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByRoleName(ERole.ROLE_ADMIN).orElseThrow(() -> new RoleNotFoundException(ERole.ROLE_ADMIN.name()));
                        roles.add(adminRole);
                        break;

                    case "mod":
                        Role modRole = roleRepository.findByRoleName(ERole.ROLE_MODERATOR).orElseThrow(() -> new RoleNotFoundException(ERole.ROLE_ADMIN.name()));
                        roles.add(modRole);
                        break;

                    default:
                        Role userRole = roleRepository.findByRoleName(ERole.ROLE_USER).orElseThrow(() -> new RoleNotFoundException(ERole.ROLE_ADMIN.name()));
                        roles.add(userRole);
                        break;
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
