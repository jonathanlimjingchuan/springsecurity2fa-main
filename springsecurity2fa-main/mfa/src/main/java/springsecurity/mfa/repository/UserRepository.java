package springsecurity.mfa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import springsecurity.mfa.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}