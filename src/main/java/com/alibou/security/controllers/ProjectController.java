package com.alibou.security.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alibou.security.models.Project;
import com.alibou.security.payload.GenericResponse;
import com.alibou.security.payload.response.LoginDto;
import com.alibou.security.payload.response.ProjectDto;
import com.alibou.security.payload.response.ResponseMessage;
import com.alibou.security.services.ProjectService;
import com.alibou.security.user.User;
import com.alibou.security.utils.Authentication;

import lombok.RequiredArgsConstructor;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/projects")
public class ProjectController {

    @Autowired
    private final ProjectService service;

    @PostMapping
    public ResponseEntity<?> save(
            @RequestBody Project data) {
        service.save(data);
        return ResponseEntity.accepted().build();
    }

    @GetMapping
    public ResponseEntity<GenericResponse<List<ProjectDto>>> findAllBooks() {
        User user = Authentication.getUser();
        System.out.println(user.getId());
        return ResponseEntity.ok(GenericResponse.success(service.findAll(),
                new ResponseMessage("PROJECT_RECIEVED_SUCCESS", "Projects recieved successfully"), 200, "Ok"));
    }
}
