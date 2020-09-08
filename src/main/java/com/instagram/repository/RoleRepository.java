package com.instagram.repository;

import com.instagram.models.ERole;
import com.instagram.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByRoleName(ERole eRole);
}
