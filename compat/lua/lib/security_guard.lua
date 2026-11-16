-- Native Config/Edge owns the request's site, revision, routing and TLS.
-- Only the retained WAF and rate-limit engines execute in Lua.
local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"
local waf = require "lib.waf"
local ratelimit = require "lib.ratelimit"
local policies = assert(lrucache.new(512))
local _M = {}

local function policy()
    local id, revision = ngx.var.scdn_edge_site, ngx.var.scdn_edge_revision
    if not id or not revision then return nil end
    local key = revision .. ":" .. id
    local site = policies:get(key)
    if site then return site end
    site = cjson.decode(ngx.var.scdn_edge_security or "")
    if not site or site.name ~= id then return nil end
    -- Existing engines can suppress missing groups; fail closed at the bridge.
    if site.waf.enabled then
        for _, group in ipairs(site.waf.groups) do
            local ok, rules = pcall(require, "lib.waf_rules." .. group)
            if not ok or type(rules) ~= "table" then return nil end
        end
    end
    policies:set(key, site)
    return site
end

function _M.run()
    if ngx.var.scdn_edge_security_checked == "1" then return end
    local site = policy()
    if not site then return ngx.exit(503) end
    ngx.ctx.site = site
    local ok, reason = ratelimit.check(site, ngx.var.host)
    if not ok then
        ngx.log(ngx.WARN, "ratelimit ", reason, " site=", site.name)
        return ngx.exit(429)
    end
    local blocked, rule, score = waf.inspect(site)
    if blocked then
        ngx.log(ngx.WARN, "waf block site=", site.name, " rule=", rule, " score=", score)
        return ngx.exit(403)
    end
    ngx.var.scdn_edge_security_checked = "1"
end

return _M
