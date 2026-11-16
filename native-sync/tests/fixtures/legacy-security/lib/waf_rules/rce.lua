-- CRS 核心 命令/代码执行 规则组
return {
    { id = "932100", target = "args", pattern = [[(?i)\$\{jndi:]],      score = 5, action = "block" },
    { id = "932110", target = "args", pattern = [[(?i)\bsystem\s*\(]],  score = 5, action = "block" },
    { id = "932120", target = "args", pattern = [[(?i)\bexec\s*\(]],    score = 5, action = "block" },
    { id = "932130", target = "args", pattern = [[(?i)\bpassthru\s*\(]],score = 5, action = "block" },
    { id = "932140", target = "args", pattern = [[(?i)\bshell_exec\s*\(]], score = 5, action = "block" },
    { id = "932150", target = "args", pattern = [[(?i)\bcmd\.exe\b]],   score = 5, action = "block" },
    { id = "932160", target = "args", pattern = [[(?i)/bin/(?:ba)?sh\b]], score = 5, action = "block" },
}
