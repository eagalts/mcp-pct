#!/usr/bin/env python3
"""
ptgen — сборка .pkt из YAML и обратно, без ручной работы в Packet Tracer.

  ptgen.py build   topology.yaml  template.pkt  out.pkt
  ptgen.py export  input.pkt  out.yaml
  ptgen.py models  template.pkt          # какие модели есть в шаблоне
  ptgen.py addmodel template.pkt donor.pkt MODEL [MODEL...] out.pkt
                                         # перенести модели из любого .pkt (со сбросом настроек)

Шаблон — любой .pkt, где есть хотя бы по одному устройству каждой нужной
модели. Генератор клонирует эти устройства (со всеми модулями и портами),
проставляет имена, координаты, MAC, IP, конфиги и создаёт линки.

Формат YAML:
  devices:
    - name: R1
      model: "1941"
      x: 400            # координаты можно не задавать — будет авто-раскладка
      y: 100
      config: |         # строки IOS, применяются поверх конфига шаблона
        interface GigabitEthernet0/0
         ip address 10.0.0.1 255.255.255.0
         no shutdown
    - name: PC1
      model: PC-PT
      ip: 10.0.0.10/24
      gateway: 10.0.0.1
  links:
    - [R1, Gi0/0, SW1, Gi0/1]      # имена портов можно сокращать
"""
import copy
import ipaddress
import random
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict, deque

import yaml

import ptcodec

# ------------------------------------------------------------------ порты ---

ABBR = [("gigabitethernet", "GigabitEthernet"), ("fastethernet", "FastEthernet"),
        ("ethernet", "Ethernet"), ("serial", "Serial"),
        ("gi", "GigabitEthernet"), ("g", "GigabitEthernet"),
        ("fa", "FastEthernet"), ("f", "FastEthernet"),
        ("se", "Serial"), ("s", "Serial"), ("eth", "Ethernet"), ("e", "Ethernet")]


def norm_port(p):
    p = str(p).strip().replace(" ", "")
    m = re.match(r"([A-Za-z]+)([\d/.]*)$", p)
    if not m:
        return p
    pre, num = m.group(1).lower(), m.group(2)
    for a, full in ABBR:
        if pre == a:
            return full + num
    return p


# Известные имена портов по моделям (для проверки YAML). Неизвестные модели
# не проверяются — PT сам отбросит неверный линк.
PORTS = {
    "2960-24TT": [f"FastEthernet0/{i}" for i in range(1, 25)] +
                 ["GigabitEthernet0/1", "GigabitEthernet0/2"],
    "1941": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
    "2911": ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"],
    "4331": ["GigabitEthernet0/0/0", "GigabitEthernet0/0/1", "GigabitEthernet0/0/2"],
    "PC-PT": ["FastEthernet0"],
    "Server-PT": ["FastEthernet0"],
    "Laptop-PT": ["FastEthernet0"],
}
PTYPE = {"eCopperFastEthernet": "FastEthernet", "eCopperGigabitEthernet": "GigabitEthernet",
         "eCopperEthernet": "Ethernet", "eSerial": "Serial",
         "eFiberFastEthernet": "FastEthernet", "eFiberGigabitEthernet": "GigabitEthernet",
         "eCopperTenGigabitEthernet": "TenGigabitEthernet", "eFiberTenGigabitEthernet": "TenGigabitEthernet"}


def port_map(dev):
    """Имена интерфейсов -> элементы PORT, по дереву модулей (как их именует IOS)."""
    dtype = (dev.findtext("ENGINE/TYPE") or "").strip().lower()
    root = dev.find("ENGINE/MODULE")
    out = {}
    if root is None:
        return out
    is_switch = dtype in ("switch", "multilayerswitch")
    host = dtype in ("pc", "server", "laptop", "printer", "cloud")
    for si, slot in enumerate(root.findall("SLOT")):
        mod = slot.find("MODULE")
        if mod is None:
            continue
        stype = slot.findtext("TYPE")
        ports = [p for p in mod.findall("PORT") if p.findtext("TYPE") in PTYPE]
        counters = defaultdict(int)
        for p in ports:
            t = PTYPE[p.findtext("TYPE")]
            n = counters[t]
            counters[t] += 1
            if host:
                name = f"{t}{si}" if si else f"{t}0"
            else:
                name = f"{t}{si}/{n + 1 if is_switch else n}"
            out.setdefault(name, p)
        # карты WIC/HWIC в подслотах встроенного модуля: Serial0/<подслот>/<n>
        for sj, sub in enumerate(mod.findall("SLOT")):
            sm = sub.find("MODULE")
            if sm is None:
                continue
            counters = defaultdict(int)
            for p in sm.findall("PORT"):
                if p.findtext("TYPE") not in PTYPE:
                    continue
                t = PTYPE[p.findtext("TYPE")]
                out[f"{t}{si}/{sj}/{counters[t]}"] = p
                counters[t] += 1
    return out


def sync_ports(dev):
    """Перенести ip address / shutdown из running-config в поля портов (PT хранит и там, и там)."""
    rc = dev.find("ENGINE/RUNNINGCONFIG")
    if rc is None:
        return
    pm = port_map(dev)
    for h, sub in _sections([l.text or "" for l in rc]):
        if not h.startswith("interface "):
            continue
        p = pm.get(h.split(None, 1)[1].strip())
        if p is None:
            continue
        ip, mask = "", ""
        for s in sub:
            w = s.split()
            if w[:2] == ["ip", "address"] and len(w) >= 4 and w[2] != "dhcp":
                ip, mask = w[2], w[3]
        if p.find("IP") is not None:
            set_text(p, "IP", ip)
            set_text(p, "SUBNET", mask)
        set_text(p, "POWER", "false" if any(s.strip() == "shutdown" for s in sub) else "true")


# Тип по MDI/MDIX: одинаковые -> кроссовер, разные -> прямой кабель
MDIX_TYPES = {"switch", "hub", "multilayerswitch"}


# --------------------------------------------------------------- утилиты ---

def rand_mem():
    return str(random.randint(1_000_000_000_000, 2_999_999_999_999))


def rand_ref():
    return "save-ref-id:%d" % random.getrandbits(63)


def mac_to_ll(mac):
    h = mac.replace(".", "")
    b = bytearray.fromhex(h)
    b[0] ^= 0x02
    e = b[:3] + b"\xff\xfe" + b[3:]
    g = [e[i:i + 2].hex().upper().lstrip("0") or "0" for i in range(0, 8, 2)]
    return "FE80::" + ":".join(g)


def set_text(el, path, value):
    x = el.find(path)
    if x is not None:
        x.text = value
    return x


class Template:
    def __init__(self, xml_bytes):
        self.root = ET.fromstring(xml_bytes)
        self.net = self.root.find("NETWORK")
        self.devs = self.net.find("DEVICES")
        self.links = self.net.find("LINKS")
        self.pw = self.root.find("PHYSICALWORKSPACE")
        self.parent = {c: p for p in self.root.iter() for c in p}
        self.nodes = {}
        for n in self.pw.iter("NODE"):
            u = n.findtext("UUID_STR")
            if u:
                self.nodes[u] = n
        self.proto = {}
        for d in self.devs:
            model = d.find("ENGINE/TYPE").get("model")
            self.proto.setdefault(model, d)
        self.link_proto = self.links[0] if len(self.links) else None

    def dev_type(self, d):
        return (d.findtext("ENGINE/TYPE") or "").strip().lower()

    def phys_uuid(self, d):
        p = d.findtext("WORKSPACE/PHYSICAL") or ""
        return p.split(",")[-1] if p else None


# ---------------------------------------------------------------- сборка ---

def _sections(lines):
    """show run -> список (заголовок, [подстроки]); строки без отступа — заголовки."""
    out = []
    for l in lines:
        if l.startswith(" ") and out and out[-1][0] not in ("!", ""):
            out[-1][1].append(l)
        else:
            out.append([l, []])
    return out


def _subkey(l):
    s = l.strip()
    if s in ("shutdown", "no shutdown"):
        return "shutdown"
    w = s.split()
    if w[:1] == ["no"]:
        w = w[1:]
    if w[:2] in (["ip", "address"], ["switchport", "mode"], ["switchport", "access"],
                 ["switchport", "trunk"], ["ipv6", "address"]):
        return " ".join(w[:3] if w[1] in ("access", "trunk") else w[:2])
    return s


def merge_config(lines, user_cfg):
    """Слить пользовательский конфиг с конфигом шаблона по секциям."""
    base = _sections(lines)
    user = _sections([l.rstrip() for l in user_cfg.splitlines() if l.strip()])
    index = {h: s for h, s in base if h not in ("!", "")}
    insert_at = next((i for i, (h, _) in enumerate(base)
                      if h.startswith("line ") or h.strip() == "end"), len(base))
    new = []
    for h, sub in user:
        if h in index:
            tsub = index[h]
            for u in sub:
                k = _subkey(u)
                tsub[:] = [t for t in tsub if _subkey(t) != k]
                if u.strip() != "no shutdown":
                    tsub.append(" " + u.strip())
        elif h.startswith("hostname "):
            continue
        else:
            new += [[h, [" " + s.strip() for s in sub if s.strip() != "no shutdown"]], ["!", []]]
            index[h] = new[-2][1]
    base[insert_at:insert_at] = new
    return [x for h, sub in base for x in [h] + sub]


def apply_config(eng, name, user_cfg):
    rc = eng.find("RUNNINGCONFIG")
    if rc is None:
        return
    lines = [l.text or "" for l in rc]
    if not lines:
        return
    lines = ["hostname " + name if l.startswith("hostname ") else l for l in lines]
    if user_cfg:
        lines = merge_config(lines, user_cfg)
    for c in list(rc):
        rc.remove(c)
    for l in lines:
        ET.SubElement(rc, "LINE").text = l


def clone_device(T, spec, x, y):
    model = str(spec["model"])
    if model not in T.proto:
        raise SystemExit("модели %r нет в шаблоне. Есть: %s" % (model, ", ".join(T.proto)))
    proto = T.proto[model]
    d = copy.deepcopy(proto)
    eng = d.find("ENGINE")
    name = spec["name"]
    set_text(eng, "NAME", name)
    set_text(eng, "SYS_NAME", name)
    ref = rand_ref()
    set_text(eng, "SAVE_REF_ID", ref)
    sn = eng.find("SERIALNUMBER")
    if sn is not None and sn.text:
        sn.text = sn.text[:3] + "".join(random.choice("0123456789ABCDEFGHJKLMNPQRSTUVWXYZ")
                                        for _ in range(len(sn.text) - 3))
    lg = d.find("WORKSPACE/LOGICAL")
    set_text(lg, "X", str(x))
    set_text(lg, "Y", str(y))
    set_text(lg, "MEM_ADDR", rand_mem())
    dev_addr = rand_mem()
    set_text(lg, "DEV_ADDR", dev_addr)

    # уникальные MAC на всех портах
    for port in d.iter("PORT"):
        mac_el = port.find("MACADDRESS")
        if mac_el is None or not mac_el.text:
            continue
        pre = mac_el.text.replace(".", "")[:6]
        mac = pre + "%06X" % random.getrandbits(24)
        mac = ".".join(mac[i:i + 4] for i in range(0, 12, 4))
        mac_el.text = mac
        set_text(port, "BIA", mac)
        ll = mac_to_ll(mac)
        set_text(port, "IPV6_LINK_LOCAL", ll)
        set_text(port, "IPV6_DEFAULT_LINK_LOCAL", ll)

    # IP для оконечных устройств (PC/Server/Laptop): поля первого порта
    if "ip" in spec:
        iface = ipaddress.ip_interface(spec["ip"])
        port = next((p for p in d.iter("PORT") if p.find("IP") is not None), None)
        if port is None:
            raise SystemExit("%s: у модели %s нет IP-полей на порту — задайте IP через config"
                             % (name, model))
        set_text(port, "IP", str(iface.ip))
        set_text(port, "SUBNET", str(iface.network.netmask))
        set_text(port, "PORT_DHCP_ENABLE", "false")
        if spec.get("gateway"):
            set_text(port, "PORT_GATEWAY", str(spec["gateway"]))
        if spec.get("dns"):
            set_text(port, "PORT_DNS", str(spec["dns"]))
    elif spec.get("dhcp"):
        port = next((p for p in d.iter("PORT") if p.find("IP") is not None), None)
        if port is not None:
            set_text(port, "PORT_DHCP_ENABLE", "true")

    apply_config(eng, name, spec.get("config"))
    sync_ports(d)
    if spec.get("config") and spec.get("save", True):
        rc, sc = eng.find("RUNNINGCONFIG"), eng.find("STARTUPCONFIG")
        if rc is not None and sc is not None:
            for c in list(sc):
                sc.remove(c)
            for l in rc:
                ET.SubElement(sc, "LINE").text = l.text

    # узел физического рабочего пространства
    old_uuid = T.phys_uuid(proto)
    if old_uuid and old_uuid in T.nodes:
        node = copy.deepcopy(T.nodes[old_uuid])
        new_uuid = "{%s}" % uuid.uuid4()
        set_text(node, "UUID_STR", new_uuid)
        set_text(node, "NAME", name)
        T.parent[T.nodes[old_uuid]].append(node)
        path = d.findtext("WORKSPACE/PHYSICAL")
        set_text(d, "WORKSPACE/PHYSICAL", path.rsplit(",", 1)[0] + "," + new_uuid)
    return d, ref, dev_addr


def auto_layout(specs, links):
    """Слоёная раскладка: BFS от роутеров (если нет координат)."""
    names = [s["name"] for s in specs]
    adj = defaultdict(list)
    for a, _, b, _ in links:
        adj[a].append(b)
        adj[b].append(a)
    kind = {s["name"]: str(s["model"]) for s in specs}

    def rank(n):
        m = kind[n].upper()
        if m.startswith(("PC", "SERVER", "LAPTOP", "PRINTER")):
            return 2
        if m.startswith(("2960", "3560", "3650", "SWITCH")):
            return 1
        return 0
    level = {}
    roots = sorted(names, key=rank)
    for r in roots:
        if r in level:
            continue
        level[r] = rank(r)
        q = deque([r])
        while q:
            u = q.popleft()
            for v in adj[u]:
                if v not in level:
                    level[v] = max(level[u] + 1, rank(v))
                    q.append(v)
    rows = defaultdict(list)
    for n in names:
        rows[level[n]].append(n)
    pos = {}
    for lv, row in rows.items():
        per = 12
        for i, n in enumerate(row):
            sub, col = divmod(i, per)
            w = min(len(row), per)
            pos[n] = (round(100 + (col + 0.5) * (1400 / w), 1), 100 + lv * 220 + sub * 90)
    return pos


def parse_links(raw):
    out = []
    for l in raw or []:
        if isinstance(l, dict):
            l = [l["a"], l["a_port"], l["b"], l["b_port"]]
        if len(l) != 4:
            raise SystemExit("линк должен быть [dev, port, dev, port]: %r" % (l,))
        out.append((str(l[0]), norm_port(l[1]), str(l[2]), norm_port(l[3])))
    return out


def validate(specs, links, T=None):
    errs = []
    names = {}
    for s in specs:
        if s["name"] in names:
            errs.append("дублируется имя устройства %s" % s["name"])
        names[s["name"]] = str(s["model"])
    used = {}
    for a, pa, b, pb in links:
        for dev, port in ((a, pa), (b, pb)):
            if dev not in names:
                errs.append("линк ссылается на неизвестное устройство %s" % dev)
                continue
            known = (list(port_map(T.proto[names[dev]])) if T is not None and names[dev] in T.proto
                     else PORTS.get(names[dev]))
            if known and port not in known:
                errs.append("%s (%s): нет порта %s" % (dev, names[dev], port))
            if (dev, port) in used:
                errs.append("%s %s занят дважды" % (dev, port))
            used[(dev, port)] = 1
    if errs:
        raise SystemExit("Ошибки в YAML:\n  " + "\n  ".join(errs))


def build(topo, tpl_bytes):
    T = Template(ptcodec.decrypt(tpl_bytes))
    specs = topo.get("devices") or []
    links = parse_links(topo.get("links"))
    validate(specs, links, T)
    auto = auto_layout(specs, links)

    old_devs = [d for d in T.devs if d.find("ENGINE/TYPE").get("model") != "Power Distribution Device"]
    old_uuids = [T.phys_uuid(d) for d in old_devs]
    if T.link_proto is None and links:
        raise SystemExit("в шаблоне нет ни одного линка — добавьте хотя бы один кабель")
    link_proto = copy.deepcopy(T.link_proto) if T.link_proto is not None else None

    info = {}
    new_devs = []
    for s in specs:
        x, y = s.get("x"), s.get("y")
        if x is None or y is None:
            x, y = auto[s["name"]]
        d, ref, addr = clone_device(T, s, x, y)
        info[s["name"]] = (ref, addr, T.dev_type(d))
        new_devs.append(d)

    # убрать исходные устройства/линки шаблона
    for d in old_devs:
        T.devs.remove(d)
    for u in old_uuids:
        if u in T.nodes:
            n = T.nodes[u]
            T.parent[n].remove(n)
    for l in list(T.links):
        T.links.remove(l)
    for d in new_devs:
        T.devs.append(d)

    for a, pa, b, pb in links:
        l = copy.deepcopy(link_proto)
        c = l.find("CABLE")
        set_text(c, "FROM", info[a][0])
        set_text(c, "TO", info[b][0])
        ports = c.findall("PORT")
        ports[0].text, ports[1].text = pa, pb
        set_text(c, "FROM_DEVICE_MEM_ADDR", info[a][1])
        set_text(c, "TO_DEVICE_MEM_ADDR", info[b][1])
        set_text(c, "FROM_PORT_MEM_ADDR", rand_mem())
        set_text(c, "TO_PORT_MEM_ADDR", rand_mem())
        same = (info[a][2] in MDIX_TYPES) == (info[b][2] in MDIX_TYPES)
        set_text(c, "TYPE", "eCrossOver" if same else "eStraightThrough")
        T.links.append(l)

    xml = ET.tostring(T.root, encoding="utf-8")
    return ptcodec.encrypt(xml), len(specs), len(links)


# ------------------------------------------------- добавление моделей в шаблон ---

KEEP_GLOBAL = re.compile(r"^(version |no service |service |hostname |spanning-tree |license udi|ip cef|"
                         r"no ipv6 cef|ip classless|ip flow-export|no profinet|line |end$|!$)")
DEFAULT_VLANS = {"1", "1002", "1003", "1004", "1005"}
PORT_KEEP = {"MACADDRESS", "BIA", "IPV6_LINK_LOCAL", "IPV6_DEFAULT_LINK_LOCAL"}


def factory_reset(d):
    """Сбросить настроенное устройство к заводскому виду (конфиг, VLAN, порты, сервисы)."""
    eng = d.find("ENGINE")
    rc = eng.find("RUNNINGCONFIG")
    if rc is not None and len(rc):
        out = []
        for h, sub in _sections([l.text or "" for l in rc]):
            if h.startswith("interface "):
                iface = h.split(None, 1)[1]
                if re.match(r"(Vlan(?!1$)|Port-channel|Loopback|Tunnel)", iface) or "." in iface:
                    continue
                out.append(h)
                if iface == "Vlan1":
                    out += [" no ip address", " shutdown"]
                elif iface.startswith("Vlan") is False and (eng.findtext("TYPE") or "").lower() == "router":
                    out += [" no ip address", " duplex auto", " speed auto", " shutdown"]
            elif h.startswith("line "):
                out += [h] + [s for s in sub if s.strip() in ("login",)]
            elif KEEP_GLOBAL.match(h):
                out += [h if not h.startswith("hostname ") else "hostname " + (h.split()[1] if len(h.split()) > 1 else "Device")]
        for c in list(rc):
            rc.remove(c)
        for l in out:
            ET.SubElement(rc, "LINE").text = l
    sc = eng.find("STARTUPCONFIG")
    if sc is not None:
        for c in list(sc):
            sc.remove(c)
    # VLAN: и список, и vlan.dat во флеше
    for vl in d.iter("VLANS"):
        for v in list(vl.findall("VLAN")):
            if v.get("number") not in DEFAULT_VLANS:
                vl.remove(v)
    for fc in d.iter("FILE_CONTENT"):
        cnt = fc.find("VLAN_COUNT")
        if cnt is not None:
            cnt.text = str(len(fc.findall("VLANS/VLAN")))
    # порты: значения как у последнего порта того же типа (обычно ненастроенного)
    pm = port_map(d)
    ref = {}
    for name, p in pm.items():
        ref[p.findtext("TYPE")] = p
    for name, p in pm.items():
        r = ref[p.findtext("TYPE")]
        if r is p:
            continue
        for c in p:
            if c.tag in PORT_KEEP or len(c):
                continue
            rv = r.find(c.tag)
            if rv is not None and not len(rv):
                c.text = rv.text
    # хосты/серверы: адреса и DHCP-сервер
    for p in pm.values():
        for tag in ("IP", "SUBNET", "PORT_GATEWAY", "PORT_DNS"):
            set_text(p, tag, "")
    for dh in d.iter("DHCP_SERVER"):
        set_text(dh, "ENABLED", "0")


def add_models(tpl_bytes, donor_bytes, models):
    T = Template(ptcodec.decrypt(tpl_bytes))
    D = Template(ptcodec.decrypt(donor_bytes))
    host_proto = next((d for d in T.devs if T.phys_uuid(d) in T.nodes and
                       (d.findtext("ENGINE/TYPE") or "").lower() in ("pc", "server", "laptop")), None)
    if host_proto is None:
        raise SystemExit("в шаблоне нужен хотя бы один PC — к его столу крепятся новые устройства")
    host_node = T.nodes[T.phys_uuid(host_proto)]
    added = []
    for m in models:
        if m in T.proto:
            continue
        if m not in D.proto:
            raise SystemExit("в файле-доноре нет модели %s. Есть: %s" % (m, ", ".join(D.proto)))
        d = copy.deepcopy(D.proto[m])
        factory_reset(d)
        eng = d.find("ENGINE")
        set_text(eng, "SAVE_REF_ID", rand_ref())
        lg = d.find("WORKSPACE/LOGICAL")
        set_text(lg, "X", str(100 + 120 * len(added)))
        set_text(lg, "Y", "40")
        set_text(lg, "MEM_ADDR", rand_mem())
        set_text(lg, "DEV_ADDR", rand_mem())
        set_text(lg, "DEVCLUSTERID", host_proto.findtext("WORKSPACE/LOGICAL/DEVCLUSTERID"))
        node = copy.deepcopy(host_node)
        nu = "{%s}" % uuid.uuid4()
        set_text(node, "UUID_STR", nu)
        set_text(node, "NAME", eng.findtext("NAME"))
        T.parent[host_node].append(node)
        path = host_proto.findtext("WORKSPACE/PHYSICAL")
        set_text(d, "WORKSPACE/PHYSICAL", path.rsplit(",", 1)[0] + "," + nu)
        T.devs.append(d)
        T.proto[m] = d
        added.append(m)
    return ptcodec.encrypt(ET.tostring(T.root, encoding="utf-8")), added


# --------------------------------------------------------------- экспорт ---

BOILER = re.compile(r"^(!|version |no service |service |spanning-tree mode|"
                    r"spanning-tree extend|license udi|ip cef|no ipv6 cef|end$|line |"
                    r"boot-start|boot-end|ip classless|ip flow-export)")
SUB_DEFAULT = re.compile(r"^\s*(no ip address|duplex auto|speed auto|login)$")


def export(pkt_bytes):
    T = Template(ptcodec.decrypt(pkt_bytes))
    by_ref = {}
    devices = []
    for d in T.devs:
        eng = d.find("ENGINE")
        model = eng.find("TYPE").get("model")
        if model == "Power Distribution Device":
            continue
        name = eng.findtext("NAME")
        by_ref[eng.findtext("SAVE_REF_ID")] = name
        lg = d.find("WORKSPACE/LOGICAL")
        e = {"name": name, "model": model,
             "x": float(lg.findtext("X")), "y": float(lg.findtext("Y"))}
        port = next((p for p in d.iter("PORT") if p.findtext("IP")), None)
        if port is not None and T.dev_type(d) in ("pc", "server", "laptop"):
            net = ipaddress.ip_interface("%s/%s" % (port.findtext("IP"), port.findtext("SUBNET")))
            e["ip"] = str(net)
            if port.findtext("PORT_GATEWAY"):
                e["gateway"] = port.findtext("PORT_GATEWAY")
        rc = eng.find("RUNNINGCONFIG")
        if rc is not None and len(rc):
            # сравниваем с конфигом "чистого" устройства той же модели в этом файле
            keep = []
            for h, sub in _sections([l.text or "" for l in rc]):
                if BOILER.match(h) or h.startswith("hostname") or not h.strip():
                    continue
                sub = [s for s in sub if not SUB_DEFAULT.match(s)]
                if h.startswith(("interface ", "router ", "vlan ", "ip dhcp pool ")):
                    if sub:
                        keep += [h] + sub
                else:
                    keep += [h] + sub
            if keep:
                e["config"] = "\n".join(keep) + "\n"
        devices.append(e)
    links = []
    for l in T.links:
        c = l.find("CABLE")
        p = [x.text for x in c.findall("PORT")]
        links.append([by_ref.get(c.findtext("FROM"), "?"), p[0],
                      by_ref.get(c.findtext("TO"), "?"), p[1]])
    return {"devices": devices, "links": links}


class _Lit(str):
    pass


def _lit_rep(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(_Lit, _lit_rep)


class _Flow(list):
    pass


yaml.add_representer(_Flow, lambda d, v: d.represent_sequence(
    "tag:yaml.org,2002:seq", v, flow_style=True))


def main(a):
    if len(a) == 5 and a[1] == "build":
        topo = yaml.safe_load(open(a[2], encoding="utf-8"))
        out, nd, nl = build(topo, open(a[3], "rb").read())
        open(a[4], "wb").write(out)
        print("OK: %s — устройств %d, линков %d" % (a[4], nd, nl))
    elif len(a) == 4 and a[1] == "export":
        data = export(open(a[2], "rb").read())
        for d in data["devices"]:
            if "config" in d:
                d["config"] = _Lit(d["config"])
        data["links"] = [_Flow(l) for l in data["links"]]
        with open(a[3], "w", encoding="utf-8") as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False, width=200)
        print("OK: %s — устройств %d, линков %d" % (a[3], len(data["devices"]), len(data["links"])))
    elif len(a) >= 6 and a[1] == "addmodel":
        out, added = add_models(open(a[2], "rb").read(), open(a[3], "rb").read(), a[4:-1])
        open(a[-1], "wb").write(out)
        print("OK: %s — добавлены модели: %s" % (a[-1], ", ".join(added) or "нет (уже были)"))
    elif len(a) == 3 and a[1] == "models":
        T = Template(ptcodec.decrypt(open(a[2], "rb").read()))
        for m, d in T.proto.items():
            if m == "Power Distribution Device":
                continue
            print("%-14s %-8s %s" % (m, d.findtext("ENGINE/TYPE"), ", ".join(port_map(d))))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
