-- 站点级限流: 请求速率 + 并发连接数
local limit_req = require "resty.limit.req"

local _M = {}
local req_limiters = {}

local function get_req(site)
    local cfg = site.rate_limit or {}
    local rate, burst = cfg.req_per_sec or 50, cfg.burst or 100
    -- 速率参数进入缓存键: 站点配置变更后立刻生效, 不会复用旧限流器
    local k = site.name .. "|" .. tostring(rate) .. "|" .. tostring(burst)
    local l = req_limiters[k]
    if not l then
        l = limit_req.new("ratelimit_dict", rate, burst)
        req_limiters[k] = l
    end
    return l
end

function _M.check(site, host)
    local cfg = site.rate_limit
    if not cfg or cfg.enabled == false then return true end

    local key = host .. ":" .. (ngx.var.remote_addr or "0.0.0.0")

    local l = get_req(site)
    local delay, err = l:incoming(key, true)
    if not delay then
        if err == "rejected" then return false, "rate" end
        ngx.log(ngx.ERR, "ratelimit error: ", err)
        return true
    end
    if delay > 0 then ngx.sleep(delay) end

    return true
end

function _M.leave() end

return _M
