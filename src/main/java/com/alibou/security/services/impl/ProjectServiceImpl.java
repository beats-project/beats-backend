package com.alibou.security.services.impl;

import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.alibou.security.models.Project;
import com.alibou.security.repository.ProjectRepository;
import com.alibou.security.services.ProjectService;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ProjectServiceImpl implements ProjectService {

    @Autowired
    private final ProjectRepository repo;

    public void save(Project project) {
        System.out.println("Save Called");
    }

    public List<Project> findAll() {
        return repo.findAll();
    }

}
