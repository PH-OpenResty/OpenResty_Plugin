-- 协议异常/畸形请求 规则组
return {
    { id = "920100", target = "uri",  pattern = [[%00]],                       score = 5, action = "block" },
    { id = "920110", target = "uri",  pattern = [[(?i)%ff]],                   score = 5, action = "block" },
    { id = "920120", target = "uri",  pattern = [[(?i)(?:\.git/|\.svn/|\.env$)]], score = 6, action = "block" },
    { id = "920130", target = "uri",  pattern = [[(?i)(?:/wp-admin/|/phpmyadmin/)]], score = 5, action = "block" },
}
