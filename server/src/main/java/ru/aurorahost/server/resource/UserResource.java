package ru.aurorahost.server.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.aurorahost.server.domain.User;

@RestController
@RequestMapping(value = "/user")
public class UserResource {

    @GetMapping
    public User showUser() {
        return User.builder()
                .email("kri@uit.no")
                .firstName("Kristian")
                .lastName("Iversen")
                .build();
    }
}
