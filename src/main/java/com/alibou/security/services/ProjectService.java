package com.alibou.security.services;

import java.util.List;

import com.alibou.security.models.Project;

public interface ProjectService {
    public void save(Project project);

    public List<Project> findAll();
}
