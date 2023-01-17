package com.spring.security.controller;

import com.spring.security.model.User;
import com.spring.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder encoder;

    @GetMapping("/users")
    public ResponseEntity<List<User>> Users() {
        System.out.println("Verificando os usuários!");
        return ResponseEntity.ok(userRepository.findAll(Sort.by(Sort.Direction.ASC, "id")));
    }

    @PostMapping("/saveorupdate")
    public ResponseEntity<User> save(@RequestBody User user) {
        System.out.println("Criando/Atualizando login: " + user.getLogin());
        Optional<User> userOptional = userRepository.findByLogin(user.getLogin());
        user.setPassword(encoder.encode(user.getPassword()));
        if (userOptional.isEmpty()) {
            userOptional = Optional.of(user);
        } else {
            userOptional.get().setPassword(user.getPassword());
        }
        return ResponseEntity.ok(userRepository.save(userOptional.get()));
    }

    @GetMapping("/validatePassword")
    public ResponseEntity<Boolean> validatePassword(@RequestParam String login, @RequestParam String password) {
        Optional<User> user =  userRepository.findByLogin(login);

        if (user.isEmpty()){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(false);
        }
        boolean validate = encoder.matches(password, user.get().getPassword());

        return ResponseEntity.status(HttpStatus.OK).body(validate);
    }
}
