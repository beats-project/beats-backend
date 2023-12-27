package com.alibou.security.payload.response;

import java.time.LocalDateTime;
import java.util.List;

import com.alibou.security.models.Task;
import com.alibou.security.user.User;
import com.fasterxml.jackson.annotation.JsonManagedReference;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProjectDto {
    private Long id;

    private String name;
    private String description;
    private LocalDateTime dueDate;

    @JsonManagedReference
    private List<Task> tasks;

    private boolean deleted;
}
