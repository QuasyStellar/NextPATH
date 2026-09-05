-- Fallback to secondary upstream DNS on bad/empty answer from primary upstream
local ffi = require('ffi')
local kres = require('kres')
ffi.cdef("void kr_server_selection_init(struct kr_query *qry);")

local M = {
	layer = {},
	action = policy.FORWARD({
		'1.1.1.1',
		'9.9.9.10@9953',
		'149.112.112.10@9953',
		'208.67.222.222@443',
		'76.76.2.0',
		'8.8.8.8'
	})
}

local fallback = {}

local function do_fallback(state, req, qry)
	local key = tostring(req)
	if fallback[key] then
		return false
	end
	fallback[key] = true

	local qname = kres.dname2str(qry.sname)
	local qtype = kres.tostring.type[qry.stype]

	event.after(0, function()
		cache.clear(qname, true)
	end)

	if qry.cname_parent == nil then
		req.answ_selected.len = 0
	end
	req.auth_selected.len = 0
	req.add_selected.len = 0

	qry.flags.NO_NS_FOUND = false
	qry.flags.TCP = false

	req.selection_context.forwarding_targets.len = 0
	req.count_fail_row = 0

	M.action(state, req)
	ffi.C.kr_server_selection_init(qry)

	return true
end

function M.layer.consume(state, req, pkt)
	local qry = req:current()
	if not qry or qry.flags.CACHED or not qry.flags.FORWARD then
		return state
	end

	if pkt:rcode() == kres.rcode.NOERROR
		and not (qry.stype == kres.type.A and pkt:ancount() == 0) then
		return state
	end

	if do_fallback(state, req, qry) then
		return kres.FAIL
	end
	return state
end

function M.layer.reset(state, req)
	local qry = req:current()
	if not qry or qry.flags.CACHED or not qry.flags.FORWARD
		or req.count_fail_row == 0 then
		return state
	end

	do_fallback(state, req, qry)
	return state
end

function M.layer.finish(state, req)
	local key = tostring(req)
	fallback[key] = nil
	return state
end

return M
