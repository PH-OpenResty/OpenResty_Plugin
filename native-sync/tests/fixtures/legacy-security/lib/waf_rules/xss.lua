-- CRS 核心 XSS 规则组
return {
    { id = "941100", target = "args", pattern = [[(?i)<script[^>]*>]],            score = 5, action = "block" },
    { id = "941110", target = "args", pattern = [[(?i)javascript\s*:]],           score = 5, action = "block" },
    { id = "941120", target = "args", pattern = [[(?i)\bonerror\s*=]],            score = 5, action = "block" },
    { id = "941130", target = "args", pattern = [[(?i)\bonload\s*=]],             score = 5, action = "block" },
    { id = "941140", target = "args", pattern = [[(?i)<iframe]],                  score = 5, action = "block" },
    { id = "941150", target = "args", pattern = [[(?i)\bdocument\.cookie\b]],     score = 5, action = "block" },
    { id = "941160", target = "uri",  pattern = [[(?i)\beval\s*\(]],              score = 5, action = "block" },
}
