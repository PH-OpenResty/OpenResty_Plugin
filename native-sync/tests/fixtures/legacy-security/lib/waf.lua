-- WAF 引擎: 分组加载 CRS 核心规则, 异常评分, 命中即拦截
local _M = {}
local groups_cache = {}
local compiled = {}

local function load_group(name)
    if groups_cache[name] ~= nil then return groups_cache[name] end
    local ok, mod = pcall(require, "lib.waf_rules." .. name)
    groups_cache[name] = (ok and type(mod) == "table") and mod or false
    return groups_cache[name]
end

-- ngx.re 没有 compile 接口, 直接传 pattern 字符串 (内部有 regex 缓存)
local function re_of(rule)
    return rule.pattern
end

local function dec(s)
    if not s then return "" end
    local ok, v = pcall(ngx.unescape_uri, s)
    return ok and v or s
end

local function targets()
    return {
        uri   = dec(ngx.var.request_uri),
        args  = dec(ngx.var.args),
        ua    = ngx.var.http_user_agent or "",
        referer = ngx.var.http_referer or "",
        cookie  = ngx.var.http_cookie or "",
        body  = ngx.var.request_body or "",
    }
end

function _M.inspect(site)
    local cfg = site.waf
    if not cfg or cfg.enabled == false then return false end
    local t = targets()
    local score, threshold = 0, cfg.threshold or 5

    for _, g in ipairs(cfg.groups or {}) do
        local rules = load_group(g)
        if rules then
            for _, r in ipairs(rules) do
                local re = re_of(r)
                if re then
                    local subject = t[r.target or "uri"]
                    if subject and subject ~= "" then
                        local from, _, err = ngx.re.find(subject, re, "jo")
                        if err then
                            ngx.log(ngx.ERR, "waf regex error ", r.id, ": ", err)
                        elseif from then
                            score = score + (r.score or 5)
                            if r.action == "block" or score >= threshold then
                                return true, r.id, score
                            end
                        end
                    end
                end
            end
        end
    end
    return false, nil, score
end

return _M
