import json, re, sys, pathlib

root = pathlib.Path(__file__).resolve().parent.parent
errs = []
def bad(m): errs.append(m)
def is_int(v): return isinstance(v, int) and not isinstance(v, bool)

CAPS = {"prepare","credential-cache","response-conditions","credential-refresh","safe-redirects","scoped-delete","conditional-json-fields","auth-modes"}
FIELD_KEYS = {"key","label","type","hint","required","default","options","role","input"}
PROGRAM_KEYS = {"schemaVersion","id","name","version","description","author","homepage","mark","color","permissions","config","upload","delete","prepare","requires","authModes"}
REQ_KEYS = {"method","url","headers","query","errors","body","response","followRedirects","timeoutSeconds","maxRedirects","refreshCredentials"}
BODY_KEYS = {"type","fileField","fields","conditionalFields"}
KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,39}$")

def unknown(obj, allowed, where):
    for k in obj:
        if k not in allowed: bad(f"{where}: 未知字段 {k}")

def valid_path(p):
    return isinstance(p,str) and len(p)<=120 and (p=="$" or re.fullmatch(r"(?:\$\.)?(?:[A-Za-z_][A-Za-z0-9_-]*|\[\d+\])(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[\d+\])*", p))

def check_field(f, where, keys):
    unknown(f, FIELD_KEYS, where)
    k = f.get("key","")
    if not KEY_RE.fullmatch(k) or k in keys or k == "authMode": bad(f"{where}: 字段键无效/重复 {k}")
    keys.add(k)
    t = f.get("type","text")
    if t not in {"text","secret","toggle","select"}: bad(f"{where}: 类型无效 {t}")
    if not isinstance(f.get("label"),str) or not f["label"] or len(f["label"])>50: bad(f"{where}: label 无效")
    if "required" in f and not isinstance(f["required"],bool): bad(f"{where}: required 非布尔")
    r = f.get("role")
    if r is not None and not re.fullmatch(r"[a-z][a-z0-9-]{0,23}", str(r)): bad(f"{where}: role 无效 {r}")
    if t=="select" and not f.get("options"): bad(f"{where}: select 缺 options")

def check_exports(resp, where):
    ex = resp.get("exports", {})
    if not isinstance(ex, dict): bad(f"{where}: exports 非对象"); return set()
    out=set()
    for name, spec in ex.items():
        if not KEY_RE.fullmatch(name): bad(f"{where}: 导出名无效 {name}")
        p = spec.get("path")
        src = spec.get("source","json")
        if src=="json" and not valid_path(p): bad(f"{where}: 导出路径无效 {p}")
        if src=="header" and not re.fullmatch(r"[A-Za-z0-9-]+", str(p)): bad(f"{where}: 导出 header 无效 {p}")
        out.add(name)
    return out

def check_response(resp, where, upload):
    if resp is None:
        if upload: bad(f"{where}: 上传缺少 response")
        return set()
    allowed = {"successStatuses","success","errorMessage","errorCode","url","thumbnail","deleteKey","deleteUrl","exports"}
    unknown(resp, allowed, where)
    ss = resp.get("successStatuses", [200,201] if upload else [])
    for s in ss:
        if not is_int(s) or not (200 <= s <= 299): bad(f"{where}: successStatuses 非 2xx {s}")
    for k in ("url","thumbnail","deleteKey","deleteUrl"):
        if k in resp and not valid_path(resp[k]): bad(f"{where}: response.{k} 路径无效 {resp[k]}")
    if upload and "url" not in resp: bad(f"{where}: 上传 response 缺少 url")
    for k in ("errorMessage","errorCode"):
        if k in resp and not valid_path(resp[k]): bad(f"{where}: {k} 路径无效")
    succ = resp.get("success")
    if succ is not None:
        if "path" not in succ or not valid_path(succ["path"]): bad(f"{where}: success.path 无效")
        ops = [k for k in ("equals","exists","containsAny") if k in succ]
        if len(ops)!=1: bad(f"{where}: success 操作必须且只能有一个")
        if "containsAny" in succ:
            v = succ["containsAny"]
            if not isinstance(v,list) or not (1<=len(v)<=8) or any(not isinstance(x,str) or not (2<=len(x)<=80) for x in v):
                bad(f"{where}: containsAny 无效")
    return check_exports(resp, where) if not upload else set()

TMPL = re.compile(r"\$\{([^}]+)\}")
FUNCS = ("base64","sha256","hmacSha256","basicAuth","normalizeBaseUrl","assetText","urlEncode")

def check_templates(node, keys, available, operation, where, schema=2):
    if isinstance(node, dict):
        for v in node.values(): check_templates(v, keys, available, operation, where, schema)
    elif isinstance(node, list):
        for v in node: check_templates(v, keys, available, operation, where, schema)
    elif isinstance(node,str):
        for m in TMPL.finditer(node):
            ref = m.group(1).strip()
            fm = re.fullmatch(r"(\w+)\((.*)\)", ref)
            if fm and fm.group(1) in FUNCS:
                subs = [s.strip() for s in fm.group(2).split(",")]
            else:
                subs = [ref]
            for s in subs:
                ok = (s=="uuid" or s in {"time.millis","time.unix"}
                      or (s.startswith("config.") and s[7:] in keys and not (schema==2 and operation=="delete"))
                      or (len(s.split("."))==3 and s.split(".")[0]=="steps" and s.split(".")[2] in available.get(s.split(".")[1], set()) and operation!="delete")
                      or (s.startswith("file.") and operation=="upload" and s in {"file.name","file.mime","file.bytes","file.base64"})
                      or (s.startswith("upload.") and operation=="delete" and s in {"upload.url","upload.deleteKey","upload.deleteUrl"}))
                if not ok: bad(f"{where}: 模板变量无效 {s}")

def check_request(req, where, operation, keys, available, schema=2):
    unknown(req, REQ_KEYS, where)
    upload = operation=="upload"
    prepare = operation=="prepare"
    method = str(req.get("method", "GET" if prepare else "POST")).upper()
    allowed = {"GET","HEAD","POST"} if prepare else ({"POST","PUT","PATCH"} if upload else {"POST","DELETE","GET"})
    if method not in allowed: bad(f"{where}: method 不受支持 {method}")
    url = req.get("url")
    if not isinstance(url,str) or not url: bad(f"{where}: url 无效")
    headers = req.get("headers") or {}
    if len(headers)>64: bad(f"{where}: headers 过多")
    banned = {"host","content-length","proxy-authorization","proxy-connection","connection","transfer-encoding","upgrade"}
    for h in headers:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", h): bad(f"{where}: header 名无效 {h}")
        if h.lower() in banned: bad(f"{where}: 禁止的 header {h}")
    to = req.get("timeoutSeconds",60)
    if not is_int(to) or not 5<=to<=300: bad(f"{where}: timeoutSeconds 无效")
    if "followRedirects" in req and not isinstance(req["followRedirects"],bool): bad(f"{where}: followRedirects 非布尔")
    body = req.get("body")
    if body is None:
        if upload: bad(f"{where}: 上传缺少 body")
        body = {"type":"none"}
    else:
        unknown(body, BODY_KEYS, where+".body")
        t = body.get("type","multipart")
        if t not in {"multipart","json","form","binary","none"}: bad(f"{where}: body.type 无效 {t}")
        if not upload and t in {"multipart","binary"}: bad(f"{where}: 前置/删除不能发送文件")
        if "conditionalFields" in body:
            if t!="json": bad(f"{where}: conditionalFields 仅支持 json")
            if not prepare: bad(f"{where}: conditionalFields 仅用于前置")
            for cf in body["conditionalFields"]:
                unknown(cf, {"key","value","when"}, where+".conditionalFields")
                when = cf.get("when",{})
                if ("contains" in when) == ("notContains" in when): bad(f"{where}: when 需要 contains/notContains 二选一")
                if when.get("config") not in keys: bad(f"{where}: when.config 未声明 {when.get('config')}")
    if method in {"GET","HEAD"} and body.get("type","multipart")!="none": bad(f"{where}: GET/HEAD 不能带 body")
    if upload:
        check_response(req.get("response"), where, True)
    else:
        out = check_exports(req.get("response") or {}, where)
        if prepare and not out: bad(f"{where}: 前置必须导出变量")
    ref = req.get("refreshCredentials")
    if ref is not None:
        if prepare: bad(f"{where}: 前置不能声明 refreshCredentials")
        for s in ref.get("steps",[]):
            if s not in available: bad(f"{where}: refresh 引用未知步骤 {s}")
        for s in ref.get("statuses",[401]):
            if s not in {200,201,400,401,403,409,410,422}: bad(f"{where}: refresh status 不支持 {s}")
    check_templates({k:v for k,v in req.items()}, keys, available, operation, where, schema)
    return body

meta = json.loads((root/"plugin.json").read_text(encoding="utf-8"))
for k, lim in (("id",80),("name",60),("version",30),("description",160),("author",80)):
    v = meta.get(k)
    if not isinstance(v,str) or not v or len(v)>lim: bad(f"plugin.json: {k} 无效")
if meta.get("packageVersion")!=1: bad("plugin.json: packageVersion 必须为 1")
if meta.get("runtime") not in {"http-v1","http-v2"}: bad("plugin.json: runtime 无效")
if not re.fullmatch(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+", meta.get("id","")): bad("plugin.json: id 不是反向域名")
if not re.fullmatch(r"\d+\.\d+\.\d+([-+].*)?", meta.get("version","")): bad("plugin.json: version 非 SemVer")
mark = meta.get("mark","P")
if isinstance(mark,str) and not 1<=len(mark)<=3: bad("plugin.json: mark 长度")
if not re.fullmatch(r"#[0-9A-Fa-f]{6}", meta.get("color","#6377E8")): bad("plugin.json: color 格式")
entry = meta.get("entry","")
if not entry.endswith(".json") or not (root/entry).is_file(): bad("plugin.json: entry 无效")
icon = meta.get("icon")
if icon and not (root/icon).is_file(): bad(f"plugin.json: icon 不存在 {icon}")

prog = json.loads((root/entry).read_text(encoding="utf-8"))
unknown(prog, PROGRAM_KEYS, "程序")
if prog.get("schemaVersion")!=2: bad("程序: schemaVersion 必须为 2")
if meta.get("runtime")!="http-v2": bad("程序: runtime 与 schemaVersion 不匹配")
req_caps = prog.get("requires",[])
for c in req_caps:
    if c not in CAPS: bad(f"程序: 未知能力 {c}")
perm = prog.get("permissions",{})
unknown(perm, {"network","readSelectedFile","allowInsecureHttp","deleteUploadedFile"}, "permissions")
hosts = perm.get("network",[])
if not (1<=len(hosts)<=16): bad("permissions.network 数量")
for h in hosts:
    if not isinstance(h,str) or not re.fullmatch(r"(?:[a-z0-9-]+\.)*[a-z0-9-]+", h): bad(f"permissions.network 主机无效 {h}")
if perm.get("readSelectedFile") is not True: bad("readSelectedFile 必须为 true")

keys = set()
for f in prog.get("config",[]): check_field(f, "config", keys)

modes = prog.get("authModes",[])
if modes:
    if "auth-modes" not in req_caps: bad("缺少 auth-modes 能力")
    if not 1<=len(modes)<=8: bad("authModes 数量")
    ids = [m.get("id") for m in modes]
    if len(set(ids))!=len(ids): bad("authModes.id 重复")
    mode_keys = set()
    for m in modes:
        unknown(m, {"id","label","config","prepare","upload","delete"}, "authModes")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", str(m.get("id",""))): bad(f"authModes.id 无效 {m.get('id')}")
        if not isinstance(m.get("label"),str) or not m["label"] or len(m["label"])>40: bad("authModes.label 无效")
        if len(m.get("config",[]))>20: bad("authModes.config 过多")
        for f in m.get("config",[]):
            shared = set(keys)|set(mode_keys)
            added = set()
            check_field(f, f"authModes[{m.get('id')}].config", added)
            for k in added:
                if k in shared: bad(f"authModes[{m.get('id')}]: 字段键 {k} 与公共/其它方式冲突")
            mode_keys |= added
    for m in modes:
        mk = set(keys) | {f["key"] for f in m.get("config",[])}
        available = {}
        prep = m.get("prepare",[])
        if len(prep)>4: bad("authModes.prepare 过多")
        for step in prep:
            sid = step.get("id")
            if not isinstance(sid,str) or not KEY_RE.fullmatch(sid): bad(f"prepare.id 无效 {sid}")
            if sid in available: bad(f"prepare.id 重复 {sid}")
            reqobj = {k:v for k,v in step.items() if k not in {"id","cache"}}
            unknown(step, {"id","cache"}|REQ_KEYS, f"prepare[{sid}]")
            check_request(reqobj, f"prepare[{sid}]", "prepare", mk, available)
            cache = step.get("cache")
            if cache:
                if "credential-cache" not in req_caps: bad("缺少 credential-cache 能力")
                unknown(cache, {"scope","ttlFrom","ttlSeconds","refreshBeforeSeconds","maxTtlSeconds"}, f"cache[{sid}]")
                if "ttlFrom" in cache and "ttlSeconds" in cache: bad("cache: ttlFrom 与 ttlSeconds 二选一")
                ttl = cache.get("ttlSeconds")
                if ttl is not None and (not is_int(ttl) or not 1<=ttl<=86400): bad("cache.ttlSeconds 越界")
                rb = cache.get("refreshBeforeSeconds",30)
                if not is_int(rb) or not 0<=rb<=300: bad("cache.refreshBeforeSeconds 越界")
            available[sid] = check_exports(step.get("response") or {}, f"prepare[{sid}]")
        check_request(m.get("upload") or {}, f"authModes[{m.get('id')}].upload", "upload", mk, available)
        if "delete" in m: bad("未使用 delete 请求")
        for step in prep:
            for cf in (step.get("body") or {}).get("conditionalFields",[]):
                if "conditional-json-fields" not in req_caps: bad("缺少 conditional-json-fields 能力")
                target = cf["when"]["config"]
                fld = next((f for f in m.get("config",[])+prog.get("config",[]) if f["key"]==target), None)
                if fld is None or fld.get("type","text")!="text": bad(f"条件字段引用了非文本配置 {target}")
        up = m.get("upload") or {}
        ref = up.get("refreshCredentials")
        if ref:
            if "credential-refresh" not in req_caps: bad("缺少 credential-refresh 能力")
            for sid in ref.get("steps",[]):
                step = next((s for s in prep if s.get("id")==sid), None)
                if step is None or not step.get("cache"): bad(f"refresh 引用无缓存步骤 {sid}")
else:
    check_request(prog.get("upload") or {}, "upload", "upload", keys, {})

raw = json.dumps(prog, ensure_ascii=False)
for m in re.finditer(r"https?://([^/\"\\]+)", raw):
    host = m.group(1).split(":")[0].lower()
    if host not in [h.lower() for h in hosts]: bad(f"URL 主机未授权 {host}")

if errs:
    print("FAIL")
    for e in errs: print(" -", e)
    sys.exit(1)
print("PASS: plugin.json / uploader.json 通过本地结构校验")