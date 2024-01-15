package ru.aurorahost.server.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.aurorahost.server.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findUserByUsername(String username);
    User findUserByEmail(String email);
}
