-- CRS 核心 路径穿越/本地文件包含 规则组
return {
    { id = "930100", target = "uri",  pattern = [[(?:\.\./|\.\.\\)]],             score = 5, action = "block" },
    { id = "930110", target = "args", pattern = [[(?i)/etc/passwd]],              score = 5, action = "block" },
    { id = "930120", target = "args", pattern = [[(?i)/proc/self/environ]],       score = 5, action = "block" },
    { id = "930130", target = "args", pattern = [[(?i)php://(?:filter|input)]],   score = 5, action = "block" },
    { id = "930140", target = "args", pattern = [[(?i)expect://]],                score = 5, action = "block" },
    { id = "930150", target = "args", pattern = [[(?i)data:text/html]],           score = 5, action = "block" },
}
