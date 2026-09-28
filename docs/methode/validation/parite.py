"""Parité de calcul ClawkWerk / outils d'auto-évaluation officiels CyFun 2025.

Pour chaque niveau et chaque jeu de réponses : les mêmes notes (Documentation,
Implementation ou N/A) par exigence sont saisies dans l'outil officiel (calcul
par LibreOffice via UNO, classeur d'origine non modifié sur disque) et dans
ClawkWerk (questionnaire + overrides N/A, preuves vides). Comparaison des
maturités par catégorie (documentation, implémentation, catégorie), de la
maturité totale, des Key Measures et du verdict."""
import json, os, random, re, subprocess, sys, time, uno
from com.sun.star.beans import PropertyValue
sys.path.insert(0, os.path.dirname(__file__))
from officiel import exigences, FICHIERS

D = os.environ.get("PARITE_TRAVAIL", "parite-travail")      # répertoire de travail
BIN = os.environ.get("CLAWKWERK_BIN", "orchestrator")       # orchestrateur compilé
KEYS = {1: "none", 2: "adhoc", 3: "defined", 4: "managed", 5: "optimizing"}
SEUILS = {"basic": (2.5, 0, 2.5), "important": (3, 0, 3), "essential": (3, 3, 3.5)}

def preparer():
    """Périmètre factice (un hôte Linux, aucune preuve) : chaque contrôle est
    alors noté par le questionnaire, y compris les scannables (repli)."""
    os.makedirs(os.path.join(D, "empty-evidence"), exist_ok=True)
    json.dump({"client": "Parite CCB", "provided_by": "validation", "hosts": [{"id": "H1", "os": "linux", "role": "server",
               "address": "h1.invalid", "transport": "ssh", "port": 22, "cred_ref": "c"}]}, open(os.path.join(D, "scope.json"), "w"))
    json.dump({}, open(os.path.join(D, "vide.json"), "w"))
    for niveau in ("basic", "important", "essential"):
        r = subprocess.run([BIN, "-scope", os.path.join(D, "scope.json"), "-evidence", os.path.join(D, "empty-evidence"),
                            "-responses", os.path.join(D, "vide.json"), "-level", niveau, "-out", os.path.join(D, f"ck-{niveau}-vide.json")],
                           capture_output=True, text=True)
        open(os.path.join(D, f"err-{niveau}.txt"), "w").write(r.stderr)

def questions(niveau):
    t = open(os.path.join(D, f"err-{niveau}.txt")).read()
    return [x for x in re.search(r"\[(.*?)\]", t, re.S).group(1).split() if x.count("/") == 2]

# Identifiants écrits différemment selon l'outil officiel (BASIC : ID.AM-5.1,
# DE.CM-03-1 ; IMPORTANT/ESSENTIAL : ID.AM-05.1, DE.CM-03.1, ID.AM-03.2).
# ClawkWerk garde une seule écriture par exigence.
ALIAS = {"ID.AM-05.1": "ID.AM-5.1", "DE.CM-03.1": "DE.CM-03-1", "ID.AM-03.2": "ID.AM-03-2", "ID.AM-03-3": "ID.AM-03.3"}

def scenarios(niveau, ex):
    km = {x["id"] for x in ex if x["km"]}
    ids = [x["id"] for x in ex]
    rnd = random.Random(20260928 + len(ids))
    s = {}
    s["tout-conforme"] = {i: (rnd.choice([4, 5]), rnd.choice([4, 5])) for i in ids}
    s["tout-non-conforme"] = {i: (1, 1) for i in ids}
    m = {i: (rnd.randint(1, 5), rnd.randint(1, 5)) for i in ids}
    for i in rnd.sample(sorted(km), 2):
        m[i] = (1, 2)  # Key Measures en échec
    for i in rnd.sample(sorted(set(ids) - km), max(2, len(ids) // 10)):
        m[i] = "NA"    # exigences non applicables (hors Key Measures)
    s["mixte-KM-en-echec-NA"] = m
    s["limite-seuils"] = {}
    k, _, t = SEUILS[niveau]
    for i in ids:  # KM exactement au seuil (2,5 = 2+3 ; 3 = 3+3), le reste autour du total
        s["limite-seuils"][i] = ((2, 3) if k == 2.5 else (3, 3)) if i in km else (rnd.randint(2, 5), rnd.randint(2, 5))
    return s

# ---------- ClawkWerk ----------
def clawkwerk(niveau, sc, qs, tag):
    resp, ov = {}, {}
    for q in qs:
        cid, axe, _ = q.split("/", 2)
        v = sc[cid]
        d, i = (3, 3) if v == "NA" else v
        resp[q] = KEYS[d if axe == "documentation" else i]
        if v == "NA":
            ov[cid] = {"na": True, "reason": "non applicable (jeu de parité)"}
    rp, op, out = (os.path.join(D, "run", f"{niveau}-{tag}-{n}.json") for n in ("resp", "ov", "out"))
    os.makedirs(os.path.dirname(rp), exist_ok=True)
    json.dump(resp, open(rp, "w")); json.dump(ov, open(op, "w"))
    args = [BIN, "-scope", os.path.join(D, "scope.json"), "-evidence", os.path.join(D, "empty-evidence"),
            "-responses", rp, "-level", niveau, "-out", out]
    if ov:
        args += ["-overrides", op]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(r.stderr)
    c = json.load(open(out))["conformity"]
    cats = {x["category"]: (x["documentation_maturity"], x["implementation_maturity"], x["maturity"]) for x in c["categories"]}
    return c, cats

# ---------- Outil officiel (LibreOffice) ----------
def lo_desktop():
    local = uno.getComponentContext()
    res = local.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local)
    for _ in range(60):
        try:
            ctx = res.resolve("uno:pipe,name=paritecyfun;urp;StarOffice.ComponentContext")
            return ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
        except Exception:
            time.sleep(1)
    raise SystemExit("LibreOffice injoignable")

def prop(n, v):
    p = PropertyValue(); p.Name = n; p.Value = v; return p

def colname(n):
    r = ""
    while n:
        n, m = divmod(n - 1, 26); r = chr(65 + m) + r
    return r

def methode_documentee(doc, niveau, ex):
    """Réécrit EN MÉMOIRE (jamais enregistré) les formules de sous-catégorie et de
    catégorie des feuilles de fonction selon la méthode publiée par le CCB :
    moyenne par sous-catégorie (N/A = seuil Key Measure), puis moyenne des
    sous-catégories par catégorie. Sert à isoler les anomalies du classeur."""
    na = SEUILS[niveau][0]
    basic = niveau == "basic"
    cD, cI = (6, 7) if basic else (7, 8)
    cSD = cD + 2
    for fn in sorted({x["fonction"] for x in ex}):
        ws = doc.Sheets.getByName(fn)
        rows = [x for x in ex if x["fonction"] == fn]
        r0, r1 = min(x["ligne"] for x in rows), max(x["ligne"] for x in rows)
        rng = ws.getCellRangeByName(f"{colname(cSD)}{r0}:{colname(cSD + 3)}{r1}")
        for r in range(r0, r1 + 1):
            for c in range(cSD, cSD + 4):
                ws.getCellRangeByName(f"{colname(c)}{r}:{colname(c)}{r1}").merge(False)
        rng.clearContents(1 | 2 | 4 | 16)  # valeurs, dates, textes, formules
        subs, cats = {}, {}
        for x in rows:
            subs.setdefault((x["cat"], x["sous_cat"]), []).append(x["ligne"])
        for (cat, sc), lines in subs.items():
            first = min(lines); cats.setdefault(cat, []).append(first)
            for off, src in ((0, cD), (1, cI)):
                terms = ",".join(f'IF(OR(${colname(cD)}{l}="N/A";${colname(cI)}{l}="N/A");{na};${colname(src)}{l})' for l in sorted(lines))
                ws.getCellByPosition(cSD - 1 + off, first - 1).setFormula(f"=AVERAGE({terms})".replace(",", ";"))
        for cat, firsts in cats.items():
            first = min(x["ligne"] for x in rows if x["cat"] == cat)
            for off in (0, 1):
                refs = ";".join(f"{colname(cSD + off)}{l}" for l in sorted(firsts))
                ws.getCellByPosition(cSD + 1 + off, first - 1).setFormula(f"=AVERAGE({refs})")

def officiel(desk, niveau, ex, sc, corrige=False):
    url = uno.systemPathToFileUrl(FICHIERS[niveau])
    doc = desk.loadComponentFromURL(url, "_blank", 0, (prop("Hidden", True), prop("ReadOnly", True)))
    try:
        sh = doc.Sheets
        if corrige:
            methode_documentee(doc, niveau, ex)
        for x in ex:
            ws = sh.getByName(x["fonction"])
            v = sc[x["id"]]
            for col, val in ((x["col_doc"], v if v == "NA" else v[0]), (x["col_impl"], v if v == "NA" else v[1])):
                cell = ws.getCellByPosition(col - 1, x["ligne"] - 1)
                if val == "NA":
                    cell.setString("N/A")
                else:
                    cell.setValue(val)
        doc.calculateAll()
        summ = [sh.getByIndex(i) for i in range(sh.Count) if "Summary" in sh.getByIndex(i).Name][0]
        g = lambda c, r: summ.getCellByPosition(c, r)
        cats = {}
        for r in range(4, 40):
            name = g(1, r).getString()
            m = re.search(r"\(([A-Z]{2}\.[A-Z]{2})\)", name)
            if m and g(3, r).getFormula():
                cats[m.group(1)] = (g(4, r).getValue(), g(5, r).getValue(), g(3, r).getValue(), g(3, r).getString())
        total = g(12, 3).getValue()
        kms = {}
        for c0 in (11, 18, 25):  # blocs L, S, Z
            for r in range(20, 45):
                rid = g(c0, r).getString().strip()
                if re.match(r"^[A-Z]{2}\.[A-Z]{2}-", rid):
                    rid = ALIAS.get(rid, rid)
                    kms[rid] = (g(c0 + 3, r).getValue(), g(c0 + 3, r).getString(), g(c0 + 2, r).getValue())
        return cats, total, kms
    finally:
        doc.close(True)

def main():
    preparer()
    subprocess.Popen(["soffice", "--headless", "--invisible", "--norestore", "--nologo",
                      "-env:UserInstallation=file://" + os.path.abspath(os.path.join(D, "lo-profil")),
                      "--accept=pipe,name=paritecyfun;urp;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    desk = lo_desktop()
    bilan = []
    try:
        for niveau in ("basic", "important", "essential"):
            ex = exigences(niveau); qs = questions(niveau)
            for x in ex:
                x["id"] = ALIAS.get(x["id"], x["id"])
            kmT, catT, totT = SEUILS[niveau]
            for tag, sc in scenarios(niveau, ex).items():
              c, ccats = clawkwerk(niveau, sc, qs, tag)
              for variante in ("outil-officiel", "methode-documentee"):
                ocats, ototal, okms = officiel(desk, niveau, ex, sc, corrige=(variante == "methode-documentee"))
                ecarts = []
                if set(ccats) != set(ocats):
                    ecarts.append(f"catégories différentes : {sorted(set(ccats) ^ set(ocats))}")
                for k in sorted(set(ccats) & set(ocats)):
                    for i, lab in enumerate(("doc", "impl", "catégorie")):
                        if abs(ccats[k][i] - ocats[k][i]) > 1e-9:
                            ecarts.append(f"{k} {lab} : ClawkWerk {ccats[k][i]:.6f} / officiel {ocats[k][i]:.6f}")
                if abs(c["total_maturity"] - ototal) > 1e-9:
                    ecarts.append(f"total : ClawkWerk {c['total_maturity']:.6f} / officiel {ototal:.6f}")
                # Key Measures : non conformes selon l'outil officiel (O < seuil)
                nc_off = sorted(k.strip() for k, (v, s, t) in okms.items() if s not in ("#DIV/0!", "") and v < t - 1e-12)
                err_off = sorted(k.strip() for k, (v, s, t) in okms.items() if s.startswith("#") or s == "")
                nc_ck = sorted(c.get("non_conform_key_measures") or [])
                if nc_off != nc_ck:
                    ecarts.append(f"KM non conformes : ClawkWerk {nc_ck} / officiel {nc_off}")
                if len(okms) != sum(x["km"] for x in ex):
                    ecarts.append(f"nombre de KM au Summary : {len(okms)}")
                ncat_off = sorted(k for k, v in ocats.items() if catT and v[2] < catT - 1e-12)
                verdict_off = (ototal >= totT - 1e-12) and not nc_off and not err_off and not ncat_off
                if verdict_off != c["conform"]:
                    ecarts.append(f"verdict : ClawkWerk {c['conform']} / officiel {verdict_off}")
                if catT and sorted(c.get("non_conform_categories") or []) != ncat_off:
                    ecarts.append(f"catégories sous le seuil : ClawkWerk {c.get('non_conform_categories')} / officiel {ncat_off}")
                ligne = dict(niveau=niveau, jeu=tag, variante=variante, total_ck=round(c["total_maturity"], 6), total_officiel=round(ototal, 6),
                             verdict_ck=c["conform"], verdict_officiel=verdict_off, km_nc=nc_ck, km_erreur_officiel=err_off,
                             categories=len(ocats), ecarts=ecarts)
                bilan.append(ligne)
                print(f"{niveau:9} {tag:22} {variante:18} total CK {c['total_maturity']:.4f} / off {ototal:.4f} | verdict CK {c['conform']} / off {verdict_off} | KM NC {len(nc_ck)} | cat {len(ocats)} | écarts {len(ecarts)}")
                for e in ecarts:
                    print("     ", e)
    finally:
        try:
            desk.terminate()
        except Exception:
            pass
    json.dump(bilan, open(os.path.join(D, "bilan-parite.json"), "w"), indent=1, ensure_ascii=False)
    for v in ("outil-officiel", "methode-documentee"):
        n = sum(1 for b in bilan if b["variante"] == v and b["ecarts"])
        print("RESULTAT", v, "PARITE TOTALE" if n == 0 else f"{n} jeu(x) avec écarts")

if __name__ == "__main__":
    main()
