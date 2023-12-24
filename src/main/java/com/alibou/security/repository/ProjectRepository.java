package com.alibou.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.alibou.security.models.Project;

public interface ProjectRepository extends JpaRepository<Project, Integer> {
}
