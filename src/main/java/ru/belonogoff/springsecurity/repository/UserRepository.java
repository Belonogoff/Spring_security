package ru.belonogoff.springsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.belonogoff.springsecurity.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

}
