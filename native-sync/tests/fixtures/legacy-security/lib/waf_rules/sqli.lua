-- CRS 核心 SQL 注入规则组 (等价迁移, 精简版)
return {
    { id = "942100", target = "args",  pattern = [[(?i)\bunion\b[\s\S]{0,20}\bselect\b]], score = 5, action = "block" },
    { id = "942110", target = "args",  pattern = [[(?i)\bselect\b[\s\S]{0,40}\bfrom\b]],   score = 5, action = "block" },
    { id = "942120", target = "args",  pattern = [[(?i)\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+]], score = 5, action = "block" },
    { id = "942130", target = "args",  pattern = [[(?i)\bsleep\s*\(\s*\d+]],               score = 5, action = "block" },
    { id = "942140", target = "args",  pattern = [[(?i)\bbenchmark\s*\(]],                 score = 5, action = "block" },
    { id = "942150", target = "args",  pattern = [[(?i)\binformation_schema\b]],           score = 5, action = "block" },
    { id = "942160", target = "args",  pattern = [[(?i)\bxp_cmdshell\b]],                  score = 5, action = "block" },
    { id = "942170", target = "args",  pattern = [[(?i)\bwaitfor\s+delay\b]],              score = 5, action = "block" },
}
