-- 扫描器/工具指纹规则组
return {
    { id = "913100", target = "ua", pattern = [[(?i)\bsqlmap\b]],     score = 5, action = "block" },
    { id = "913110", target = "ua", pattern = [[(?i)\bnikto\b]],      score = 5, action = "block" },
    { id = "913120", target = "ua", pattern = [[(?i)\bnmap\b]],       score = 5, action = "block" },
    { id = "913130", target = "ua", pattern = [[(?i)\bmasscan\b]],    score = 5, action = "block" },
    { id = "913140", target = "ua", pattern = [[(?i)\bacunetix\b]],   score = 5, action = "block" },
    { id = "913150", target = "ua", pattern = [[(?i)\bdirbuster\b]],  score = 5, action = "block" },
    { id = "913160", target = "ua", pattern = [[(?i)\bzgrab\b]],      score = 5, action = "block" },
}
