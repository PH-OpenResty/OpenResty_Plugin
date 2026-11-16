-- One-time conversion of administrator-trusted legacy site files. Run with
-- LuaJIT and redirect stdout to a private candidate file; never eval user input.
local output, ids, hosts = {"sites {"}, {}, {}
local function quote(s)
    assert(type(s) == "string" and not s:find("[%z\1-\31\127]"), "invalid text")
    return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"'
end
local function number(n, low, high)
    assert(type(n) == "number" and n == math.floor(n) and n >= low and n <= high, "invalid numeric policy")
    return tostring(n)
end
local function identifier(s)
    assert(type(s) == "string" and #s <= 96 and s:match("^[A-Za-z0-9][A-Za-z0-9_-]*$"), "invalid identifier")
    return s
end
local function origin(s)
    if not s:match("^https?://") then s = "http://" .. s end
    return quote(s)
end
local function layer(s)
    assert(s == "l1" or s == "l2" or s == "off" or s == "auto", "invalid cache policy")
    return s
end
local allowed = {name=true,enabled=true,server_names=true,root=true,upstream=true,cache=true,
    ssl=true,waf=true,rate_limit=true,locations=true,tier=true,origin_host=true}
local function known_fields(value, fields)
    if not value then return end
    assert(type(value) == "table", "expected policy table")
    for k in pairs(value) do assert(fields[k], "unsupported policy field: " .. tostring(k)) end
end
assert(#arg > 0, "provide trusted legacy site files")
for _, path in ipairs(arg) do
    local site = assert(loadfile(path))()
    assert(type(site) == "table", "invalid site")
    for k in pairs(site) do assert(allowed[k], "unsupported site field: " .. tostring(k)) end
    known_fields(site.cache,{layer=true})
    known_fields(site.ssl,{cert=true,key=true})
    known_fields(site.waf,{enabled=true,threshold=true,groups=true})
    known_fields(site.rate_limit,{enabled=true,req_per_sec=true,burst=true})
    known_fields(site.tier,{hits=true,window_ms=true})
    local id = identifier(site.name)
    assert(not ids[id], "duplicate site"); ids[id] = true
    output[#output+1] = "site " .. quote(id) .. " {"
    output[#output+1] = "enabled " .. (site.enabled == false and "off" or "on") .. ";"
    for _, host in ipairs(site.server_names or {}) do
        host = host:lower(); assert(not hosts[host], "duplicate Host"); hosts[host] = true
        output[#output+1] = "host " .. quote(host) .. ";"
    end
    if site.root and site.root ~= "" then output[#output+1] = "root " .. quote(site.root) .. ";" end
    if site.upstream and site.upstream ~= "" then output[#output+1] = "upstream " .. origin(site.upstream) .. ";" end
    if site.origin_host and site.origin_host ~= "" then output[#output+1] = "origin_host " .. quote(site.origin_host) .. ";" end
    local cache = layer(site.cache and site.cache.layer or "l2")
    output[#output+1] = "cache " .. cache .. ";"
    if site.tier then
        output[#output+1] = "tier " .. number(site.tier.hits,1,1000000) .. " " .. number(site.tier.window_ms,100,86400000) .. ";"
    end
    local tls = site.ssl or {}
    if tls.cert and tls.cert ~= "" then
        output[#output+1] = "certificate " .. quote(tls.cert) .. ";"
        output[#output+1] = "certificate_key " .. quote(tls.key) .. ";"
    else assert(not tls.key or tls.key == "", "missing certificate") end
    local waf = site.waf or {enabled=false}
    output[#output+1] = "waf " .. (waf.enabled == false and "off" or "on") .. ";"
    output[#output+1] = "waf_threshold " .. number(waf.threshold or 5,1,1000000) .. ";"
    for _, group in ipairs(waf.groups or {}) do output[#output+1] = "waf_group " .. quote(identifier(group)) .. ";" end
    local rate = site.rate_limit or {enabled=false}
    output[#output+1] = rate.enabled == false and "rate_limit off;" or
        "rate_limit " .. number(rate.req_per_sec or 50,1,1000000) .. " " .. number(rate.burst or 100,0,1000000) .. ";"
    for _, route in ipairs(site.locations or {}) do
        known_fields(route,{prefix=true,upstream=true,cache=true,origin_host=true})
        local upstream = route.upstream or site.upstream
        assert(upstream and upstream ~= "", "prefix needs upstream")
        output[#output+1] = "prefix " .. quote(route.prefix) .. " { upstream " .. origin(upstream)
            .. "; cache " .. layer(route.cache or cache) .. ";"
            .. (route.origin_host and " origin_host " .. quote(route.origin_host) .. ";" or "") .. " }"
    end
    output[#output+1] = "}"
end
output[#output+1] = "}"
io.write(table.concat(output,"\n"),"\n")
